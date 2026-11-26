//! The oracle service: announce upcoming price events, attest at maturity,
//! publish both to nostr (draft DLC oracle NIP, kinds 88 / 89), rebroadcast, archive.

use crate::config::Config;
use crate::dispute;
use crate::feeds::{self, Feeds};
use crate::nip88;
use crate::price::{self, Fiat};
use crate::social;
use crate::storage::{maturity, FileStorage, Payment, PaymentStatus};
use crate::zaps::{self, BuyerMessage, VerifiedZap, ZapTarget};
use anyhow::{anyhow, Context, Result};
use kormir::storage::Storage;
use kormir::{EventDescriptor, Oracle};
use nostr_sdk::prelude::*;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap, HashSet};
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
/// How far back zap receipts are read after a restart.
const ZAP_SCAN_WINDOW: u64 = 7 * 86400;
/// Payment records outlive the scan window, so a replayed receipt is recognised.
const PAYMENT_RETENTION: u64 = 30 * 86400;

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
    oracle_sk: kormir::bitcoin::secp256k1::SecretKey,
    http: reqwest::Client,
    nostr: Option<Client>,
    /// Key of our Lightning address provider, which signs zap receipts.
    zapper: Option<PublicKey>,
    last_zap_scan: Cell<u64>,
    seen_dispute_wraps: RefCell<HashSet<EventId>>,
}

/// May this event's attestation be published for everyone at time `t`?
pub fn attestation_is_public(cfg: &Config, maturity: u64, t: u64) -> bool {
    match &cfg.pricing {
        None => true,
        Some(p) => p.public_attestation_delay_secs.is_some_and(|d| t >= maturity + d),
    }
}

pub fn relay_list_event(keys: &Keys, relays: &[String]) -> Result<Event> {
    let mut list: Vec<(RelayUrl, Option<RelayMetadata>)> = Vec::new();
    for r in relays {
        if let Ok(url) = RelayUrl::parse(r) {
            list.push((url, None));
        }
    }
    Ok(EventBuilder::relay_list(list).sign_with_keys(keys)?)
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
        let zapper = match (&cfg.pricing, publish) {
            (Some(p), true) => Some(match &p.zapper_pubkey {
                Some(k) => PublicKey::parse(k).context("pricing.zapper_pubkey")?,
                None => {
                    let addr = cfg.profile.lud16.as_deref().unwrap_or_default();
                    zaps::resolve_zapper(&http, addr)
                        .await
                        .with_context(|| format!("look up zap provider of {addr}"))?
                }
            }),
            _ => None,
        };
        Ok(Self {
            cfg,
            oracle,
            oracle_sk: key,
            http,
            nostr,
            zapper,
            last_zap_scan: Cell::new(0),
            seen_dispute_wraps: RefCell::new(HashSet::new()),
        })
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
        let pricing = match &self.cfg.pricing {
            None => "Attestations are public.".to_string(),
            Some(x) => format!(
                "Zap an announcement {} sats to receive its attestation by private message. \
                 Zap this profile {} sats with comment `custom <USD|EUR> <unix maturity>` for a \
                 custom event.",
                x.attestation_sats, x.custom_event_sats
            ),
        };
        let about = p.about.clone().unwrap_or_else(|| {
            format!(
                "DLC price oracle (draft DLC oracle NIP, kinds 88/89). Pairs: {}. Series: {}. Event id \
                 <pair>-<unix maturity>, {} binary digits, unit = whole fiat units. Median of \
                 Kraken, Bitstamp, Coinbase, Bitfinex, Delphi, PriceStr. {pricing}",
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
        let rl = relay_list_event(&self.oracle.nostr_keys(), &self.cfg.relays)?;
        client.send_event(&rl).await?;
        Ok(())
    }

    /// One pass of announce -> attest -> publish -> archive. Safe to call repeatedly.
    pub async fn tick(&self) -> Result<()> {
        let t = now();
        self.announce(t).await?;
        // A failing relay or zap scan must never hold up attesting.
        if let Err(e) = self.process_zaps(t).await {
            log::warn!("zap scan: {e:#}");
        }
        if let Err(e) = self.process_disputes(t).await {
            log::warn!("dispute scan: {e:#}");
        }
        self.attest(t).await?;
        self.publish(t).await?;
        self.deliver().await?;
        self.oracle.storage.archive_payments_before(t.saturating_sub(PAYMENT_RETENTION))?;
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
        let mut nostr_feeds: Option<Feeds> = None;
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
                if nostr_feeds.is_none() {
                    nostr_feeds = Some(feeds::fetch_feeds(&self.cfg.nostr_feeds, t).await);
                }
                let current = nostr_feeds.as_ref().expect("just fetched");
                let quotes = feeds::collect_quotes(&self.http, fiat, current).await;
                let p = match price::aggregate(
                    &quotes,
                    self.cfg.min_sources,
                    self.cfg.min_agreeing,
                    self.cfg.max_deviation,
                ) {
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
                    let fee = self.cfg.pricing.as_ref().map(|p| p.attestation_sats);
                    let e = nip88::announcement_event(&keys, &ev.announcement, &self.cfg.relays, fee)?;
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
            let public = attestation_is_public(&self.cfg, m, t);
            let send_att = public && att_ev.is_some() && (rec.attestation_acks < need || rebroadcast);
            let last_social = self.oracle.storage.last_social_post(&unit);
            let can_social = self.cfg.social_feed.enabled
                && public
                && ev.attestation().is_some()
                && rec.social_note_acks < need
                && (rec.social_note.is_some()
                    || t >= last_social.saturating_add(self.cfg.social_feed.min_interval_secs));
            if !send_ann && !send_att && !can_social {
                continue;
            }

            let mut ann_acks = rec.announcement_acks;
            let mut att_acks = rec.attestation_acks;
            let mut social_acks = rec.social_note_acks;
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
            if can_social {
                let social_ev = match rec.social_note.clone() {
                    Some(e) => Some(e),
                    None => match (Fiat::from_code(&unit), ev.attestation()) {
                        (Some(fiat), Some(att)) => match social::decode_attested_price(&att) {
                            Ok(price_fiat) => {
                                let note = social::price_note(
                                    &keys,
                                    fiat,
                                    price_fiat,
                                    Some(&id),
                                    &self.cfg.social_feed,
                                    att_ev.as_ref().map(|a| a.id),
                                )?;
                                self.oracle
                                    .storage
                                    .update_nostr(&id, |r| r.social_note = Some(note.clone()))?;
                                Some(note)
                            }
                            Err(e) => {
                                log::warn!("social note decode {id}: {e:#}");
                                None
                            }
                        },
                        _ => None,
                    },
                };
                if let Some(note) = &social_ev {
                    budget = budget.saturating_sub(1);
                    social_acks = social_acks.max(self.send(client, note).await);
                    if social_acks >= need && rec.social_note_acks < need {
                        self.oracle.storage.set_last_social_post(&unit, t)?;
                        log::info!("published social price note for {id} ({social_acks} relays)");
                    }
                }
            }
            if ann_acks < need {
                log::warn!("announcement {id}: only {ann_acks}/{need} relays accepted");
            }
            self.oracle.storage.update_nostr(&id, |r| {
                r.announcement_acks = ann_acks;
                r.attestation_acks = att_acks;
                r.social_note_acks = social_acks;
                r.last_broadcast = t;
            })?;
        }
        Ok(())
    }

    /// Read new zap receipts and record what they pay for.
    async fn process_zaps(&self, t: u64) -> Result<()> {
        let (Some(client), Some(zapper)) = (&self.nostr, self.zapper) else { return Ok(()) };
        let oracle_pk = self.oracle.nostr_keys().public_key();
        let last = self.last_zap_scan.get();
        // Overlap scans: receipts can reach a relay late. Payment hashes dedup.
        let since = if last == 0 { t.saturating_sub(ZAP_SCAN_WINDOW) } else { last.saturating_sub(3600) };
        let filter = Filter::new()
            .kind(Kind::ZapReceipt)
            .author(zapper)
            .pubkey(oracle_pk)
            .since(Timestamp::from(since));
        let receipts = client.fetch_events(filter, Duration::from_secs(10)).await?;
        for r in receipts.iter() {
            match zaps::verify_receipt(r, &zapper, &oracle_pk) {
                Ok(zap) if self.oracle.storage.has_payment(&zap.payment_hash) => {}
                Ok(zap) => self.handle_zap(zap, t).await?,
                Err(e) => log::warn!("ignoring zap receipt {}: {e:#}", r.id),
            }
        }
        self.last_zap_scan.set(t);
        Ok(())
    }

    async fn handle_zap(&self, zap: VerifiedZap, t: u64) -> Result<()> {
        let Some(pricing) = self.cfg.pricing.clone() else { return Ok(()) };
        let st = &self.oracle.storage;
        let outcome: Result<String, String> = match zap.target {
            ZapTarget::Tip => {
                log::info!("tip of {} sats", zap.sats);
                st.insert_payment(payment(&zap, None, t, PaymentStatus::Tip))?;
                return Ok(());
            }
            ZapTarget::Announcement(id) => {
                let found = st.list_events().into_iter().find(|e| {
                    st.nostr_record(&e.event_id).announcement.is_some_and(|a| a.id == id)
                });
                match found {
                    None => Err("zapped event is not a live announcement".to_string()),
                    Some(_) if zap.sats < pricing.attestation_sats => Err(format!(
                        "paid {} sats, an attestation costs {}",
                        zap.sats, pricing.attestation_sats
                    )),
                    Some(e) if st.is_missed(&e.event_id) => {
                        Err("this event was missed and will never be attested".to_string())
                    }
                    Some(e) => Ok(e.event_id),
                }
            }
            ZapTarget::Custom { fiat, maturity } => {
                let m = maturity as u64;
                if zap.sats < pricing.custom_event_sats {
                    Err(format!(
                        "paid {} sats, a custom event costs {}",
                        zap.sats, pricing.custom_event_sats
                    ))
                } else if !self.cfg.pairs.contains(&fiat) {
                    Err(format!("pair {} is not offered", fiat.code()))
                } else if m < t + pricing.custom_min_lead_secs
                    || m > t + pricing.custom_max_horizon_secs
                {
                    Err(format!(
                        "maturity must be {}s to {}s from now",
                        pricing.custom_min_lead_secs, pricing.custom_max_horizon_secs
                    ))
                } else {
                    let id = event_id(fiat, m);
                    self.ensure_custom_event(&id, fiat, maturity).await?;
                    Ok(id)
                }
            }
        };
        let buyer_msg = match outcome {
            Ok(id) => {
                st.insert_payment(payment(&zap, Some(id.clone()), t, PaymentStatus::Pending))?;
                let ev = st.list_events().into_iter().find(|e| e.event_id == id);
                let ann = st.nostr_record(&id).announcement;
                log::info!("paid: {id}, {} sats", zap.sats);
                match (ev, ann) {
                    (Some(ev), Some(ann)) => BuyerMessage::Paid {
                        event_id: id,
                        announcement_id: ann.id.to_hex(),
                        maturity: maturity(&ev) as u32,
                    },
                    _ => return Ok(()),
                }
            }
            Err(message) => {
                log::warn!("rejected zap {} ({} sats): {message}", zap.payment_hash, zap.sats);
                st.insert_payment(payment(&zap, None, t, PaymentStatus::Rejected(message.clone())))?;
                BuyerMessage::Error { payment_hash: zap.payment_hash.clone(), message }
            }
        };
        // Best effort: the attestation itself is retried until delivered.
        if let Err(e) = self.send_dm(zap.buyer, &buyer_msg).await {
            log::warn!("message to buyer: {e:#}");
        }
        Ok(())
    }

    /// Create (if needed) a custom event and publish its announcement now.
    async fn ensure_custom_event(&self, id: &str, fiat: Fiat, maturity: u32) -> Result<()> {
        let st = &self.oracle.storage;
        let existing = st.get_event(id.to_string()).await.map_err(|e| anyhow!("{e}"))?;
        let data = match existing {
            Some(d) => d,
            None => {
                self.oracle
                    .create_numeric_event(
                        id.to_string(),
                        self.cfg.num_digits,
                        false,
                        0,
                        fiat.code().to_string(),
                        maturity,
                    )
                    .await
                    .map_err(|e| anyhow!("custom event {id}: {e}"))?;
                st.get_event(id.to_string())
                    .await
                    .map_err(|e| anyhow!("{e}"))?
                    .ok_or_else(|| anyhow!("custom event {id} not stored"))?
            }
        };
        if st.nostr_record(id).announcement.is_none() {
            let fee = self.cfg.pricing.as_ref().map(|p| p.attestation_sats);
            let e = nip88::announcement_event(
                &self.oracle.nostr_keys(),
                &data.announcement,
                &self.cfg.relays,
                fee,
            )?;
            st.update_nostr(id, |r| r.announcement = Some(e.clone()))?;
            if let Some(client) = &self.nostr {
                let acks = self.send(client, &e).await;
                st.update_nostr(id, |r| r.announcement_acks = acks)?;
            }
        }
        Ok(())
    }

    /// Deliver attestations to everyone who paid for them.
    async fn deliver(&self) -> Result<()> {
        if self.nostr.is_none() {
            return Ok(());
        }
        let st = &self.oracle.storage;
        let keys = self.oracle.nostr_keys();
        for p in st.payments().into_iter().filter(|p| p.status == PaymentStatus::Pending) {
            let id = p.event_id.clone().unwrap_or_default();
            let ev = st.get_event(id.clone()).await.map_err(|e| anyhow!("{e}"))?;
            let buyer = PublicKey::parse(&p.buyer)?;
            let Some(ev) = ev else {
                st.set_payment_status(&p.payment_hash, PaymentStatus::Failed("event not found".into()))?;
                continue;
            };
            if st.is_missed(&id) {
                let message = "this event was missed and will never be attested".to_string();
                log::error!("REFUND DUE: {} sats, payment {}: {message}", p.sats, p.payment_hash);
                let msg = BuyerMessage::Error { payment_hash: p.payment_hash.clone(), message: message.clone() };
                if self.send_dm(buyer, &msg).await.is_ok() {
                    st.set_payment_status(&p.payment_hash, PaymentStatus::Failed(message))?;
                }
                continue;
            }
            let Some(att) = ev.attestation() else { continue };
            let rec = st.nostr_record(&id);
            let Some(ann) = rec.announcement else { continue };
            let att_ev = match rec.attestation {
                Some(e) => e,
                None => {
                    let unit = unit_of(&ev).unwrap_or_default();
                    let e = nip88::attestation_event(&keys, &att, &unit, ann.id)?;
                    st.update_nostr(&id, |r| r.attestation = Some(e.clone()))?;
                    e
                }
            };
            let msg = BuyerMessage::Attestation {
                event_id: id.clone(),
                announcement_id: ann.id.to_hex(),
                attestation: att_ev.as_json(),
            };
            match self.send_dm(buyer, &msg).await {
                Ok(()) => {
                    st.set_payment_status(&p.payment_hash, PaymentStatus::Delivered)?;
                    log::info!("delivered attestation {id}");
                }
                Err(e) => log::warn!("deliver {id}: {e:#}"),
            }
        }
        Ok(())
    }

    /// Listen for incoming NIP-17 `sign_dispute` RPC requests (BIP-342 Leaf 2 On-Demand Disputes)
    /// and reply with a verified BIP-340 Schnorr signature at the live aggregated spot price.
    async fn process_disputes(&self, t: u64) -> Result<()> {
        let Some(client) = &self.nostr else { return Ok(()) };
        let own_pk = self.oracle.nostr_keys().public_key();
        let filter = Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(own_pk)
            .since(Timestamp::from(t.saturating_sub(600)))
            .limit(50);
        let events = client
            .fetch_events(filter, Duration::from_secs(4))
            .await
            .context("fetch kind-1059 dispute requests")?;

        let mut cached_feeds: Option<Feeds> = None;
        let mut cached_spots: HashMap<String, Result<f64, String>> = HashMap::new();
        let min_fee_sats = self.cfg.pricing.as_ref().map(|p| p.attestation_sats).unwrap_or(0);

        for ev in events.into_iter() {
            if !self.seen_dispute_wraps.borrow_mut().insert(ev.id) {
                continue;
            }
            let Ok(unwrapped) = client.unwrap_gift_wrap(&ev).await else {
                continue;
            };
            let Some(rpc) = dispute::parse_dispute_rpc(&unwrapped.rumor.content) else {
                continue;
            };
            let cur_code = rpc.params.currency.to_uppercase();
            let fiat_opt = self
                .cfg
                .pairs
                .iter()
                .copied()
                .find(|p| p.code().eq_ignore_ascii_case(&cur_code));
            let reply_json = match fiat_opt {
                None => serde_json::to_string(&dispute::DisputeRpcResponse {
                    msg_type: "p2pfiat-rpc-res".into(),
                    req_id: rpc.req_id.clone(),
                    ok: false,
                    result: None,
                    error: Some(format!("unsupported currency {cur_code}")),
                })
                .unwrap_or_default(),
                Some(fiat) => {
                    if !cached_spots.contains_key(&cur_code) {
                        if cached_feeds.is_none() {
                            cached_feeds = Some(feeds::fetch_feeds(&self.cfg.nostr_feeds, t).await);
                        }
                        let quotes = feeds::collect_quotes(
                            &self.http,
                            fiat,
                            cached_feeds.as_ref().expect("just fetched"),
                        )
                        .await;
                        let agg = price::aggregate(
                            &quotes,
                            self.cfg.min_sources,
                            self.cfg.min_agreeing,
                            self.cfg.max_deviation,
                        )
                        .map_err(|e| format!("{e:#}"));
                        cached_spots.insert(cur_code.clone(), agg);
                    }
                    match cached_spots.get(&cur_code) {
                        Some(Ok(live_spot)) => {
                            log::info!(
                                "signing on-demand dispute {} ({cur_code} @ {live_spot:.2})",
                                rpc.params.contract_id
                            );
                            dispute::build_dispute_rpc_reply(
                                &self.oracle_sk,
                                &rpc,
                                *live_spot,
                                min_fee_sats,
                            )
                        }
                        Some(Err(err)) => serde_json::to_string(&dispute::DisputeRpcResponse {
                            msg_type: "p2pfiat-rpc-res".into(),
                            req_id: rpc.req_id.clone(),
                            ok: false,
                            result: None,
                            error: Some(format!("price unavailable: {err}")),
                        })
                        .unwrap_or_default(),
                        None => continue,
                    }
                }
            };
            if let Err(e) = client.send_private_msg(unwrapped.sender, reply_json, []).await {
                log::warn!("dispute reply to {}: {e:#}", unwrapped.sender);
            }
        }
        Ok(())
    }

    /// Send a NIP-17 private message; succeeds once a relay accepted it.
    async fn send_dm(&self, to: PublicKey, msg: &BuyerMessage) -> Result<()> {
        let client = self.nostr.as_ref().ok_or_else(|| anyhow!("no relays"))?;
        let out = client
            .send_private_msg(to, serde_json::to_string(msg)?, [])
            .await?;
        tokio::time::sleep(SEND_SPACING).await;
        anyhow::ensure!(!out.success.is_empty(), "no relay accepted the message");
        Ok(())
    }
}

fn payment(zap: &VerifiedZap, event_id: Option<String>, t: u64, status: PaymentStatus) -> Payment {
    Payment {
        payment_hash: zap.payment_hash.clone(),
        buyer: zap.buyer.to_hex(),
        event_id,
        sats: zap.sats,
        created_at: t,
        status,
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
    pub payments_pending: usize,
    pub deliveries_overdue: Vec<String>,
    /// Paid, but rejected or undeliverable: consider refunding these.
    pub refunds_to_review: Vec<String>,
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
        payments_pending: 0,
        deliveries_overdue: vec![],
        refunds_to_review: vec![],
    };
    for p in st.payments() {
        match &p.status {
            PaymentStatus::Pending => {
                s.payments_pending += 1;
                let signed = p.event_id.as_ref().is_some_and(|id| {
                    events.iter().any(|e| e.event_id == *id && !e.signatures.is_empty())
                });
                if signed {
                    s.deliveries_overdue.push(p.payment_hash.clone());
                }
            }
            PaymentStatus::Rejected(why) | PaymentStatus::Failed(why) => {
                s.refunds_to_review.push(format!("{} ({} sats): {why}", p.payment_hash, p.sats));
            }
            _ => {}
        }
    }
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
        if !ev.signatures.is_empty()
            && attestation_is_public(cfg, m, t)
            && rec.attestation_acks < cfg.min_relay_acks
        {
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
    if !s.deliveries_overdue.is_empty() {
        s.problems.push(format!("{} paid attestations not delivered", s.deliveries_overdue.len()));
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
