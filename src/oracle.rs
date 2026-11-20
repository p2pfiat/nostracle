//! The oracle service: announce upcoming price events, attest at maturity,
//! and publish both to nostr (NIP-88 kinds 88 / 89).

use crate::config::Config;
use crate::price::{self, Fiat};
use crate::storage::FileStorage;
use anyhow::{anyhow, Context, Result};
use kormir::nostr_events::{create_announcement_event, create_attestation_event};
use kormir::storage::Storage;
use kormir::{EventDescriptor, Oracle};
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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

pub fn load_key(path: &Path) -> Result<kormir::bitcoin::secp256k1::SecretKey> {
    let s = std::fs::read_to_string(path).with_context(|| format!("read key {path:?}"))?;
    let bytes = hex::decode(s.trim()).context("key file is not hex")?;
    kormir::bitcoin::secp256k1::SecretKey::from_slice(&bytes).context("invalid secret key")
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
             oracle key. Restore it from backup, or run `nostracle init` for a NEW key.",
            cfg.db_file
        );
        let storage = FileStorage::open(&cfg.db_file)?;
        let oracle = Oracle::from_signing_key(storage, key).map_err(|e| anyhow!("{e}"))?;
        let http = reqwest::Client::builder()
            .user_agent(concat!("nostracle/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let nostr = if publish {
            let keys = oracle.nostr_keys();
            let client = Client::new(keys);
            for r in &cfg.relays {
                client.add_relay(r.as_str()).await?;
            }
            client.connect().await;
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
        let about = p.about.clone().unwrap_or_else(|| {
            format!(
                "DLC price oracle (NIP-88). Pairs: {}. Event every {}s, id <pair>-<unix maturity>, \
                 {} binary digits, unit = whole fiat units. Median of Kraken, Bitstamp, Coinbase, \
                 Bitfinex.",
                pairs.join(", "),
                self.cfg.interval_secs,
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

    /// One pass of announce -> attest -> publish. Safe to call repeatedly.
    pub async fn tick(&self) -> Result<()> {
        let t = now();
        self.announce(t).await?;
        self.attest(t).await?;
        self.publish().await?;
        Ok(())
    }

    async fn announce(&self, t: u64) -> Result<()> {
        for &fiat in &self.cfg.pairs {
            for m in upcoming_maturities(t, self.cfg.interval_secs, self.cfg.horizon_secs) {
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
                log::info!("announced {id}");
            }
        }
        Ok(())
    }

    async fn attest(&self, t: u64) -> Result<()> {
        let mut prices: HashMap<String, Option<i64>> = HashMap::new();
        for ev in self.oracle.storage.list_events() {
            if !ev.signatures.is_empty() {
                continue;
            }
            let oe = &ev.announcement.oracle_event;
            let maturity = oe.event_maturity_epoch as u64;
            if maturity > t || t > maturity + self.cfg.max_attest_delay_secs {
                continue;
            }
            let EventDescriptor::DigitDecompositionEvent(d) = &oe.event_descriptor else {
                continue;
            };
            let fiat = match d.unit.as_str() {
                "USD" => Fiat::Usd,
                "EUR" => Fiat::Eur,
                other => {
                    log::warn!("{}: unknown unit {other}", ev.event_id);
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

    async fn publish(&self) -> Result<()> {
        let Some(client) = &self.nostr else { return Ok(()) };
        let keys = self.oracle.nostr_keys();
        for ev in self.oracle.storage.list_events() {
            let ann_id = match &ev.announcement_event_id {
                Some(id) => id.clone(),
                None => {
                    let ne = create_announcement_event(&keys, &ev.announcement)?;
                    match client.send_event(&ne).await {
                        Ok(_) => {
                            let id = ne.id.to_hex();
                            self.oracle
                                .storage
                                .set_nostr_ids(&ev.event_id, Some(id.clone()), None)
                                .map_err(|e| anyhow!("{e}"))?;
                            id
                        }
                        Err(e) => {
                            log::warn!("publish announcement {}: {e}", ev.event_id);
                            continue;
                        }
                    }
                }
            };
            if ev.attestation_event_id.is_some() {
                continue;
            }
            let Some(att) = ev.attestation() else { continue };
            let ne = create_attestation_event(&keys, &att, EventId::from_hex(&ann_id)?)?;
            match client.send_event(&ne).await {
                Ok(_) => self
                    .oracle
                    .storage
                    .set_nostr_ids(&ev.event_id, None, Some(ne.id.to_hex()))
                    .map_err(|e| anyhow!("{e}"))?,
                Err(e) => log::warn!("publish attestation {}: {e}", ev.event_id),
            }
        }
        Ok(())
    }
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
    fn event_ids() {
        assert_eq!(event_id(Fiat::Eur, 1_763_650_800), "btceur-1763650800");
    }
}
