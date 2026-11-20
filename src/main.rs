use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use nostr_sdk::prelude::*;
use nostracle::{config::Config, nip88, oracle, price, storage::FileStorage};
use std::collections::HashMap;
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
    /// Health check for monitoring. Prints JSON; exit code 1 if unhealthy.
    Status,
    /// Fetch an oracle's events from the relays and verify them like a DLC client.
    Verify {
        /// Oracle pubkey (hex or npub). Defaults to this oracle's key.
        #[arg(long)]
        pubkey: Option<String>,
        /// Only events created in the last N seconds.
        #[arg(long, default_value_t = 86400)]
        since_secs: u64,
    },
    /// Skip the nonce counter ahead. REQUIRED after restoring an older db backup.
    BumpNonces {
        #[arg(long)]
        by: u32,
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
            FileStorage::create(&cfg.db_file)?;
            println!("created {:?} and {:?}. Back up BOTH.", cfg.key_file, cfg.db_file);
        }
        Cmd::Pubkey => {
            let keys = own_keys(&cfg)?;
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
        Cmd::Status => {
            let s = oracle::status(&cfg)?;
            println!("{}", serde_json::to_string_pretty(&s)?);
            if !s.healthy {
                std::process::exit(1);
            }
        }
        Cmd::Verify { pubkey, since_secs } => {
            let pk = match pubkey {
                Some(p) => PublicKey::parse(&p)?,
                None => own_keys(&cfg)?.public_key(),
            };
            std::process::exit(verify(&cfg, pk, since_secs).await?);
        }
        Cmd::BumpNonces { by } => {
            let st = FileStorage::open(&cfg.db_file)?;
            println!("next nonce index now {}", st.bump_nonces(by)?);
        }
    }
    Ok(())
}

fn own_keys(cfg: &Config) -> Result<Keys> {
    let key = oracle::load_key(&cfg.key_file)?;
    Ok(Keys::new(SecretKey::from_slice(&key.secret_bytes())?))
}

/// Returns the process exit code: 0 if everything verified.
async fn verify(cfg: &Config, pk: PublicKey, since_secs: u64) -> Result<i32> {
    let client = Client::default();
    for r in &cfg.relays {
        client.add_relay(r.as_str()).await?;
    }
    client.connect().await;
    client.wait_for_connection(Duration::from_secs(10)).await;
    let since = Timestamp::from(oracle::now().saturating_sub(since_secs));
    let filter = Filter::new()
        .author(pk)
        .kinds([Kind::Custom(nip88::KIND_ANNOUNCEMENT), Kind::Custom(nip88::KIND_ATTESTATION)])
        .since(since);
    let events = client
        .fetch_events(filter, Duration::from_secs(20))
        .await
        .context("fetch events")?;
    client.disconnect().await;

    let (anns, atts): (Vec<Event>, Vec<Event>) = events
        .into_iter()
        .partition(|e| e.kind == Kind::Custom(nip88::KIND_ANNOUNCEMENT));
    let mut bad = 0;
    let mut by_id = HashMap::new();
    for e in &anns {
        match nip88::verify_announcement(e) {
            Ok(a) => {
                by_id.insert(e.id, (e, a));
            }
            Err(err) => {
                bad += 1;
                println!("INVALID announcement {}: {err:#}", e.id);
            }
        }
    }
    let mut ok_att = 0;
    for e in &atts {
        let ann_id = e.tags.event_ids().next().copied();
        let Some((ann_ev, ann)) = ann_id.and_then(|id| by_id.get(&id)) else {
            println!("attestation {} references an announcement not fetched (older than --since-secs?)", e.id);
            continue;
        };
        match nip88::verify_attestation(e, ann_ev, ann) {
            Ok((att, v)) => {
                ok_att += 1;
                println!("ok  {} = {v}", att.event_id);
            }
            Err(err) => {
                bad += 1;
                println!("INVALID attestation {}: {err:#}", e.id);
            }
        }
    }
    println!(
        "{} announcements valid, {ok_att} attestations valid, {bad} invalid (pubkey {})",
        by_id.len(),
        pk.to_bech32()?
    );
    Ok(if bad == 0 && !by_id.is_empty() { 0 } else { 1 })
}
