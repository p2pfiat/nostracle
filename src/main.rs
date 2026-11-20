use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use nostracle::{config::Config, oracle, price, storage::FileStorage};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(version, about = "DLC price oracle on nostr (NIP-88)")]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new oracle key and an empty event database.
    Init,
    /// Print the oracle public key (hex x-only, and npub).
    Pubkey,
    /// Fetch and aggregate current prices without signing anything.
    Price,
    /// Run the oracle loop.
    Run {
        /// Announce and attest locally but do not publish to relays.
        #[arg(long)]
        dry_run: bool,
        /// Run a single tick and exit.
        #[arg(long)]
        once: bool,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;
    match cli.cmd {
        Cmd::Init => {
            if cfg.key_file.exists() || cfg.db_file.exists() {
                bail!("{:?} or {:?} already exists; refusing to overwrite", cfg.key_file, cfg.db_file);
            }
            let key = kormir::bitcoin::secp256k1::SecretKey::new(&mut rand::thread_rng());
            if let Some(d) = cfg.key_file.parent() {
                std::fs::create_dir_all(d)?;
            }
            std::fs::write(&cfg.key_file, hex::encode(key.secret_bytes()))?;
            drop(FileStorage::open(&cfg.db_file)?);
            // Persist an empty state so `run` sees the db exists.
            std::fs::write(&cfg.db_file, r#"{"next_nonce_index":0,"events":{}}"#)?;
            println!("created {:?} and {:?}. Back up BOTH.", cfg.key_file, cfg.db_file);
        }
        Cmd::Pubkey => {
            let key = oracle::load_key(&cfg.key_file)?;
            let keys = nostr_sdk::Keys::new(nostr_sdk::SecretKey::from_slice(&key.secret_bytes())?);
            use nostr_sdk::ToBech32;
            println!("{}\n{}", keys.public_key().to_hex(), keys.public_key().to_bech32()?);
        }
        Cmd::Price => {
            let http = reqwest::Client::new();
            for &f in &cfg.pairs {
                let quotes = price::fetch_quotes(&http, f).await;
                for q in &quotes {
                    println!("{:>9} {} {:>12.2}", q.source, f.code(), q.price);
                }
                match price::aggregate(&quotes, cfg.min_sources, cfg.max_deviation) {
                    Ok(p) => println!("{:>9} {} {:>12.2}\n", "AGGREGATE", f.code(), p),
                    Err(e) => println!("{:>9} {} unavailable: {e:#}\n", "AGGREGATE", f.code()),
                }
            }
        }
        Cmd::Run { dry_run, once } => {
            let tick = Duration::from_secs(cfg.tick_secs);
            let svc = oracle::Service::new(cfg, !dry_run).await?;
            log::info!("oracle pubkey {}", svc.oracle.public_key());
            if let Err(e) = svc.publish_profile().await {
                log::warn!("profile: {e:#}");
            }
            loop {
                if let Err(e) = svc.tick().await {
                    log::error!("tick: {e:#}");
                }
                if once {
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(tick) => {}
                    _ = tokio::signal::ctrl_c() => { log::info!("shutting down"); break; }
                }
            }
        }
    }
    Ok(())
}
