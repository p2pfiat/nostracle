//! The oracle service: announce upcoming price events, attest at maturity,
//! publish both to nostr (NIP-88 kinds 88 / 89), rebroadcast, archive.

use crate::config::Config;
use crate::nip88;
use crate::price::{self, Fiat};
use crate::storage::{maturity, FileStorage};
use anyhow::{anyhow, Context, Result};
use kormir::storage::Storage;
use kormir::{EventDescriptor, Oracle};
use nostr_sdk::prelude::*;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Max nostr events sent per tick, and the pause between sends: relays
/// (e.g. relay.damus.io) ban clients that burst. A fresh start with the default
/// series (~280 announcements) is published over ~7 minutes.
const PUBLISH_BATCH: usize = 20;
const SEND_SPACING: Duration = Duration::from_millis(1000);
/// Periodically rebroadcast events whose maturity is within this window of now.
/// Far-future announcements are only re-sent while under the relay quorum.
const REBROADCAST_WINDOW: u64 = 2 * 86400;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Event id for a pair and maturity, e.g. `btcusd-1763650800`.
pub fn event_id(fiat: Fiat, maturity: u64) -> String {
    format!("{}-{maturity}", fiat.pair())
}

/// Maturities strictly after `now`, aligned to `interval`, up to `now + horizon`.
pub fn upcoming_maturities(now: u64, interval: u64, horizon: u64) -> Vec<u64> {
    let first = (now / interval + 1) * interval;
    (0..)
        .map(|i| first + i * interval)
        .take_while(|m| *m <= now + horizon)
        .collect()
}

/// Union of all series' upcoming maturities, sorted, deduplicated.
pub fn all_maturities(cfg: &Config, now: u64) -> Vec<u64> {
    let set: BTreeSet<u64> = cfg
        .series
        .iter()
        .flat_map(|s| upcoming_maturities(now, s.interval_secs, s.horizon_secs))
        .collect();
    set.into_iter().collect()
}

pub fn load_key(path: &Path) -> Result<kormir::bitcoin::secp256k1::SecretKey> {
    let s = std::fs::read_to_string(path).with_context(|| format!("read key {path:?}"))?;
    let bytes = hex::decode(s.trim()).context("key file is not hex")?;
    kormir::bitcoin::secp256k1::SecretKey::from_slice(&bytes).context("invalid secret key")
}

pub fn heartbeat_path(cfg: &Config) -> PathBuf {
    cfg.db_file.with_extension("heartbeat")
}

fn unit_of(ev: &kormir::storage::OracleEventData) -> Option<String> {
    match &ev.announcement.oracle_event.event_descriptor {
        EventDescriptor::DigitDecompositionEvent(d) => Some(d.unit.clone()),
        _ => None,
    }
}

pub struct Service {
    pub cfg: Config,
    pub oracle: Oracle<FileStorage>,
    http: reqwest::Client,
    nostr: Option<Client>,
}

impl Service {
    /// `publish = false` runs everything except talking to relays.
    pub async fn new(cfg: Config, publish: bool) -> Result<Self> {
        let key = load_key(&cfg.key_file)?;
        anyhow::ensure!(
            cfg.db_file.exists(),
            "event db {:?} missing. Starting without it could reuse nonces and leak the \
             oracle key. Restore it from backup (then run `bump-nonces`), or run \
             `nostracle init` for a NEW key.",
            cfg.db_file
        );
        let storage = FileStorage::open(&cfg.db_file)?;
        let oracle = Oracle::from_signing_key(storage, key).map_err(|e| anyhow!("{e}"))?;
        let http = reqwest::Client::builder()
            .user_agent(concat!("nostracle/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let nostr = if publish {
            let client = Client::new(oracle.nostr_keys());
            for r in &cfg.relays {
                client.add_relay(r.as_str()).await?;
            }
            client.connect().await;
            client.wait_for_connection(Duration::from_secs(10)).await;
            Some(client)
        } else {
            None
        };
        Ok(Self { cfg, oracle, http, nostr })
    }

    pub async fn publish_profile(&self) -> Result<()> {
        let Some(client) = &self.nostr else { return Ok(()) };
        let p = &self.cfg.profile;
        let pairs: Vec<_> = self.cfg.pairs.iter().map(|f| format!("BTC/{}", f.code())).collect();
        let series: Vec<_> = self
            .cfg
            .series
            .iter()
            .map(|s| format!("every {}s, {}s ahead", s.interval_secs, s.horizon_secs))
            .collect();
        let about = p.about.clone().unwrap_or_else(|| {
            format!(
                "DLC price oracle (NIP-88 kinds 88/89). Pairs: {}. Series: {}. Event id \
                 <pair>-<unix maturity>, {} binary digits, unit = whole fiat units. Median of \
                 Kraken, Bitstamp, Coinbase, Bitfinex.",
                pairs.join(", "),
                series.join("; "),
                self.cfg.num_digits
            )
        });
        let mut md = Metadata::new()
            .name(p.name.clone().unwrap_or_else(|| "nostracle".into()))
            .about(about);
        if let Some(l) = &p.lud16 {
            md = md.lud16(l);
        }
        if let Some(w) = &p.website {
            if let Ok(url) = Url::parse(w) {
                md = md.website(url);
            }
        }
        let ev = EventBuilder::metadata(&md).sign_with_keys(&self.oracle.nostr_keys())?;
        client.send_event(&ev).await?;
        Ok(())
    }

    /// One pass of announce -> attest -> publish -> archive. Safe to call repeatedly.
    pub async fn tick(&self) -> Result<()> {
        let t = now();
        self.announce(t).await?;
        self.attest(t).await?;
        self.publish(t).await?;
        let n = self
            .oracle
            .storage
            .archive_before(t.saturating_sub(self.cfg.archive_after_secs))?;
        if n > 0 {
            log::info!("archived {n} events");
        }
        std::fs::write(heartbeat_path(&self.cfg), t.to_string())?;
        Ok(())
    }

    async fn announce(&self, t: u64) -> Result<()> {
        for &fiat in &self.cfg.pairs {
            for m in all_maturities(&self.cfg, t) {
                let id = event_id(fiat, m);
                if self.oracle.storage.get_event(id.clone()).await.map_err(|e| anyhow!("{e}"))?.is_some() {
                    continue;
                }
                self.oracle
                    .create_numeric_event(
                        id.clone(),
                        self.cfg.num_digits,
                        false,
                        0,
                        fiat.code().to_string(),
                        m as u32,
                    )
                    .await
                    .map_err(|e| anyhow!("announce {id}: {e}"))?;
                log::debug!("announced {id}");
            }
        }
        Ok(())
    }

    async fn attest(&self, t: u64) -> Result<()> {
        let mut prices: HashMap<String, Option<i64>> = HashMap::new();
        for ev in self.oracle.storage.list_events() {
            let m = maturity(&ev);
            if !ev.signatures.is_empty() || m > t || self.oracle.storage.is_missed(&ev.event_id) {
                continue;
            }
            if t > m + self.cfg.max_attest_delay_secs {
                log::error!(
                    "MISSED {}: no reliable price within {}s of maturity; contracts will refund",
                    ev.event_id,
                    self.cfg.max_attest_delay_secs
                );
                self.oracle.storage.mark_missed(&ev.event_id)?;
                continue;
            }
            let fiat = match unit_of(&ev).as_deref() {
                Some("USD") => Fiat::Usd,
                Some("EUR") => Fiat::Eur,
                other => {
                    log::warn!("{}: unsupported unit {other:?}", ev.event_id);
                    continue;
                }
            };
            if !prices.contains_key(fiat.code()) {
                let quotes = price::fetch_quotes(&self.http, fiat).await;
                let p = match price::aggregate(&quotes, self.cfg.min_sources, self.cfg.max_deviation) {
                    Ok(p) => Some(p.round() as i64),
                    Err(e) => {
                        log::warn!("no reliable {} price: {e:#}", fiat.code());
                        None
                    }
                };
                prices.insert(fiat.code().to_string(), p);
            }
            let Some(p) = prices[fiat.code()] else { continue };
            self.oracle
                .sign_numeric_event(ev.event_id.clone(), p)
                .await
                .map_err(|e| anyhow!("attest {}: {e}", ev.event_id))?;
            log::info!("attested {} = {p} {}", ev.event_id, fiat.code());
        }
        Ok(())
    }

    /// Send `ev` to all relays; returns how many accepted it.
    async fn send(&self, client: &Client, ev: &Event) -> usize {
        let res = client.send_event(ev).await;
        tokio::time::sleep(SEND_SPACING).await;
        match res {
            Ok(out) => {
                for (relay, err) in &out.failed {
                    log::warn!("{relay} rejected {}: {err}", ev.id);
                }
                out.success.len()
            }
            Err(e) => {
                log::warn!("send {}: {e}", ev.id);
                0
            }
        }
    }

    async fn publish(&self, t: u64) -> Result<()> {
        let Some(client) = &self.nostr else { return Ok(()) };
        let keys = self.oracle.nostr_keys();
        let need = self.cfg.min_relay_acks;
        let mut budget = PUBLISH_BATCH;
        let mut events = self.oracle.storage.list_events();
        // Most urgent first: nearest maturity.
        events.sort_by_key(maturity);
        for ev in events {
            if budget == 0 {
                break;
            }
            let id = ev.event_id.clone();
            let rec = self.oracle.storage.nostr_record(&id);
            let unit = unit_of(&ev).unwrap_or_default();

            let ann_ev = match rec.announcement.clone() {
                Some(e) => e,
                None => {
                    let e = nip88::announcement_event(&keys, &ev.announcement, &self.cfg.relays)?;
                    self.oracle.storage.update_nostr(&id, |r| r.announcement = Some(e.clone()))?;
                    e
                }
            };
            let att_ev = match (&rec.attestation, ev.attestation()) {
                (Some(e), _) => Some(e.clone()),
                (None, Some(att)) => {
                    let e = nip88::attestation_event(&keys, &att, &unit, ann_ev.id)?;
                    self.oracle.storage.update_nostr(&id, |r| r.attestation = Some(e.clone()))?;
                    Some(e)
                }
                (None, None) => None,
            };

            let m = maturity(&ev);
            let rebroadcast = m + REBROADCAST_WINDOW >= t
                && m <= t + REBROADCAST_WINDOW
                && rec.last_broadcast + self.cfg.rebroadcast_secs <= t;
            let send_ann = rec.announcement_acks < need || rebroadcast;
            let send_att = att_ev.is_some() && (rec.attestation_acks < need || rebroadcast);
            if !send_ann && !send_att {
                continue;
            }

            let mut ann_acks = rec.announcement_acks;
            let mut att_acks = rec.attestation_acks;
            if send_ann {
                budget -= 1;
                ann_acks = ann_acks.max(self.send(client, &ann_ev).await);
            }
            if let (true, Some(a)) = (send_att, &att_ev) {
                budget = budget.saturating_sub(1);
                att_acks = att_acks.max(self.send(client, a).await);
                if att_acks >= need && rec.attestation_acks < need {
                    log::info!("published attestation {id} ({att_acks} relays)");
                }
            }
            if ann_acks < need {
                log::warn!("announcement {id}: only {ann_acks}/{need} relays accepted");
            }
            self.oracle.storage.update_nostr(&id, |r| {
                r.announcement_acks = ann_acks;
                r.attestation_acks = att_acks;
                r.last_broadcast = t;
            })?;
        }
        Ok(())
    }
}

/// Health summary for monitoring, computed from the db without the key.
#[derive(Debug, serde::Serialize)]
pub struct Status {
    pub healthy: bool,
    pub problems: Vec<String>,
    pub last_tick_age_secs: Option<u64>,
    pub next_nonce_index: u32,
    pub events_live: usize,
    pub announced_not_published: usize,
    pub overdue_unattested: Vec<String>,
    pub attested_not_published: Vec<String>,
    pub missed: Vec<String>,
    pub latest_announced_maturity: Option<u64>,
}

pub fn status(cfg: &Config) -> Result<Status> {
    let t = now();
    let st = FileStorage::open(&cfg.db_file)?;
    let last_tick = std::fs::read_to_string(heartbeat_path(cfg))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());
    let events = st.list_events();
    let mut s = Status {
        healthy: true,
        problems: vec![],
        last_tick_age_secs: last_tick.map(|lt| t.saturating_sub(lt)),
        next_nonce_index: st.next_nonce_index(),
        events_live: events.len(),
        announced_not_published: 0,
        overdue_unattested: vec![],
        attested_not_published: vec![],
        missed: st.missed(),
        latest_announced_maturity: events.iter().map(maturity).max(),
    };
    for ev in &events {
        let rec = st.nostr_record(&ev.event_id);
        if rec.announcement_acks < cfg.min_relay_acks {
            s.announced_not_published += 1;
        }
        let m = maturity(ev);
        // grace: one tick plus a minute for price fetching
        if ev.signatures.is_empty() && t > m + cfg.tick_secs + 60 && !s.missed.contains(&ev.event_id) {
            s.overdue_unattested.push(ev.event_id.clone());
        }
        if !ev.signatures.is_empty() && rec.attestation_acks < cfg.min_relay_acks {
            s.attested_not_published.push(ev.event_id.clone());
        }
    }
    match s.last_tick_age_secs {
        None => s.problems.push("no heartbeat: oracle never ran".into()),
        Some(a) if a > 3 * cfg.tick_secs + 60 => s.problems.push(format!("last tick {a}s ago")),
        _ => {}
    }
    if !s.overdue_unattested.is_empty() {
        s.problems.push(format!("{} events overdue for attestation", s.overdue_unattested.len()));
    }
    if !s.attested_not_published.is_empty() {
        s.problems.push(format!(
            "{} attestations not yet on {} relays",
            s.attested_not_published.len(),
            cfg.min_relay_acks
        ));
    }
    let soon_unpublished = events
        .iter()
        .filter(|e| maturity(e) <= t + 86400)
        .filter(|e| st.nostr_record(&e.event_id).announcement_acks < cfg.min_relay_acks)
        .count();
    if soon_unpublished > 0 {
        s.problems.push(format!(
            "{soon_unpublished} announcements maturing within 24h not yet on {} relays",
            cfg.min_relay_acks
        ));
    }
    if !s.missed.is_empty() {
        s.problems.push(format!("{} missed events in the last {}s", s.missed.len(), cfg.archive_after_secs));
    }
    let max_h = cfg.series.iter().map(|x| x.horizon_secs).max().unwrap_or(0);
    if let Some(latest) = s.latest_announced_maturity {
        let min_i = cfg.series.iter().map(|x| x.interval_secs).max().unwrap_or(0);
        if latest + min_i + 3600 < t + max_h {
            s.problems.push("announcement horizon not covered".into());
        }
    }
    s.healthy = s.problems.is_empty();
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maturities_are_aligned_and_future() {
        let ms = upcoming_maturities(7_250, 3600, 3 * 3600);
        assert_eq!(ms, vec![10_800, 14_400, 18_000]);
        // exactly on a boundary: that boundary is not "upcoming"
        assert_eq!(upcoming_maturities(3600, 3600, 3600), vec![7200]);
    }

    #[test]
    fn series_union_dedups_shared_maturities() {
        let mut cfg: Config = toml::from_str(r#"relays = ["wss://a"]
            min_relay_acks = 1"#)
        .unwrap();
        cfg.series = vec![
            crate::config::Series { interval_secs: 3600, horizon_secs: 86400 },
            crate::config::Series { interval_secs: 86400, horizon_secs: 3 * 86400 },
        ];
        let t = 86400 * 100 + 10; // just after midnight
        let ms = all_maturities(&cfg, t);
        assert_eq!(ms.len(), 24 + 2); // 24 hourly (incl. next midnight) + 2 more daily
        assert!(ms.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn event_ids() {
        assert_eq!(event_id(Fiat::Eur, 1_763_650_800), "btceur-1763650800");
    }
}
