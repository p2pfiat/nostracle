use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use nostr_sdk::prelude::*;
use nostracle::zaps::{self, BuyerMessage};
use nostracle::{config::Config, feeds, nip88, oracle, price, storage::FileStorage};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(version, about = "DLC price oracle on nostr (draft DLC oracle NIP, kinds 88/89)")]
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
    /// Buy an attestation or custom event from an oracle with a zap.
    /// Prints a Lightning invoice to pay, then waits for the delivery.
    Buy {
        /// Oracle pubkey (hex or npub).
        #[arg(long)]
        oracle: String,
        /// Event to buy, e.g. btcusd-1798000000.
        #[arg(long, conflicts_with = "custom", required_unless_present = "custom")]
        event_id: Option<String>,
        /// Custom event, as `USD:1798000000`.
        #[arg(long)]
        custom: Option<String>,
        /// Amount to pay, as stated in the oracle's profile.
        #[arg(long)]
        sats: u64,
        /// Buyer key file (hex); created if missing. Keep it to receive the delivery.
        #[arg(long, default_value = "data/buyer.key")]
        key_file: PathBuf,
        /// Stop waiting after this many seconds.
        #[arg(long, default_value_t = 900)]
        timeout_secs: u64,
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
            let nostr_feeds = feeds::fetch_feeds(&cfg.nostr_feeds, oracle::now()).await;
            for &f in &cfg.pairs {
                let quotes = feeds::collect_quotes(&http, f, &nostr_feeds).await;
                for q in &quotes {
                    println!("{:>9} {} {:>12.2}", q.source, f.code(), q.price);
                }
                match price::aggregate(&quotes, cfg.min_sources, cfg.min_agreeing, cfg.max_deviation) {
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
        Cmd::Buy { oracle: o, event_id, custom, sats, key_file, timeout_secs } => {
            let oracle_pk = PublicKey::parse(&o)?;
            let keys = buyer_keys(&key_file)?;
            std::process::exit(
                buy(&cfg, keys, oracle_pk, event_id, custom, sats, timeout_secs).await?,
            );
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

fn buyer_keys(path: &std::path::Path) -> Result<Keys> {
    if path.exists() {
        return Ok(Keys::parse(std::fs::read_to_string(path)?.trim())?);
    }
    let keys = Keys::generate();
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(path, keys.secret_key().to_secret_hex())?;
    println!("created buyer key {path:?}");
    Ok(keys)
}

/// Zap flow for buyers. Returns the process exit code.
async fn buy(
    cfg: &Config,
    keys: Keys,
    oracle_pk: PublicKey,
    event_id: Option<String>,
    custom: Option<String>,
    sats: u64,
    timeout_secs: u64,
) -> Result<i32> {
    let client = Client::new(keys.clone());
    for r in &cfg.relays {
        client.add_relay(r.as_str()).await?;
    }
    client.connect().await;
    client.wait_for_connection(Duration::from_secs(10)).await;

    let metadata = client
        .fetch_metadata(oracle_pk, Duration::from_secs(15))
        .await?
        .context("oracle has no profile")?;
    let lud16 = metadata.lud16.context("oracle profile has no Lightning address")?;
    let http = reqwest::Client::new();
    let pay = zaps::resolve_lud16(&http, &lud16).await?;
    let msat = sats.checked_mul(1000).context("amount too large")?;
    anyhow::ensure!(
        msat >= pay.min_sendable && msat <= pay.max_sendable,
        "amount outside what {lud16} accepts"
    );

    let mut tags = vec![
        Tag::public_key(oracle_pk),
        Tag::custom(TagKind::custom("amount"), [msat.to_string()]),
        Tag::custom(TagKind::custom("relays"), cfg.relays.iter().cloned()),
    ];
    let (wanted, comment) = match (event_id, custom) {
        (Some(id), _) => {
            let filter = Filter::new()
                .author(oracle_pk)
                .kind(Kind::Custom(nip88::KIND_ANNOUNCEMENT));
            let anns = client.fetch_events(filter, Duration::from_secs(20)).await?;
            let ann = anns
                .iter()
                .find(|e| {
                    nip88::verify_announcement(e)
                        .map(|a| a.oracle_event.event_id == id)
                        .unwrap_or(false)
                })
                .with_context(|| format!("no valid announcement for {id}"))?;
            tags.push(Tag::event(ann.id));
            (id, String::new())
        }
        (None, Some(c)) => {
            let (pair, maturity) = c.split_once(':').context("--custom must be PAIR:MATURITY")?;
            let comment = format!("custom {pair} {maturity}");
            let (fiat, m) = zaps::parse_custom(&comment).context("invalid --custom")?;
            (oracle::event_id(fiat, m as u64), comment)
        }
        _ => bail!("give --event-id or --custom"),
    };
    let request = EventBuilder::new(Kind::ZapRequest, comment).tags(tags).sign_with_keys(&keys)?;
    let invoice: serde_json::Value = http
        .get(&pay.callback)
        .query(&[("amount", msat.to_string()), ("nostr", request.as_json())])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let pr = invoice["pr"].as_str().context("LNURL callback returned no invoice")?;
    println!("Pay this invoice ({sats} sats):\n\n{pr}\n\nWaiting for delivery of {wanted}...");

    let deadline = oracle::now() + timeout_secs;
    // NIP-59 randomises gift wrap timestamps up to two days into the past.
    let since = Timestamp::from(oracle::now().saturating_sub(3 * 86400));
    let filter = Filter::new().kind(Kind::GiftWrap).pubkey(keys.public_key()).since(since);
    while oracle::now() < deadline {
        for wrap in client.fetch_events(filter.clone(), Duration::from_secs(10)).await?.iter() {
            let Ok(gift) = client.unwrap_gift_wrap(wrap).await else { continue };
            if gift.sender != oracle_pk {
                continue;
            }
            let Ok(msg) = serde_json::from_str::<BuyerMessage>(&gift.rumor.content) else { continue };
            match msg {
                BuyerMessage::Attestation { event_id, announcement_id, attestation } if event_id == wanted => {
                    let att = Event::from_json(&attestation)?;
                    let ann_id = EventId::from_hex(&announcement_id)?;
                    let anns = client
                        .fetch_events(Filter::new().id(ann_id), Duration::from_secs(15))
                        .await?;
                    let ann_ev = anns.first().context("announcement not found on relays")?;
                    let ann = nip88::verify_announcement(ann_ev)?;
                    anyhow::ensure!(ann.oracle_public_key.serialize() == oracle_pk.to_bytes(), "wrong oracle key");
                    let (_, value) = nip88::verify_attestation(&att, ann_ev, &ann)?;
                    println!("verified attestation {event_id} = {value}\n{attestation}");
                    return Ok(0);
                }
                BuyerMessage::Error { payment_hash, message } => {
                    println!("oracle message for payment {payment_hash}: {message}");
                }
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    println!("timed out; the delivery stays on the relays, so run again with the same key file");
    Ok(1)
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
