//! Price feeds read from nostr, used as extra quotes in the median:
//! - **Delphi** estimates BTC/USD from on-chain transactions.
//! - **PriceStr** is a signed multi-source median.
//!
//! Both quote USD. For EUR they are converted with PriceStr's published rate, or
//! with the rate implied by the exchanges if PriceStr is unavailable.

use crate::config::NostrFeeds;
use crate::price::{self, Fiat, Quote};
use anyhow::{anyhow, bail, ensure, Context, Result};
use nostr_sdk::prelude::*;
use std::collections::HashSet;
use std::time::Duration;

pub const KIND_DELPHI_AUDIT: u16 = 8078;
pub const KIND_PRICESTR: u16 = 30078;
const DELPHI_WINDOW: &str = "chain-1h";
/// Tolerated clock difference for feed timestamps.
const MAX_FUTURE_SECS: u64 = 120;

#[derive(Debug, Clone, PartialEq)]
pub struct DelphiReading {
    pub usd: f64,
    pub age_secs: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PriceStrReading {
    pub usd: f64,
    /// EUR per USD, as published in the feed.
    pub eur_per_usd: Option<f64>,
    pub age_secs: u64,
}

/// Latest feed readings, or why each one is unavailable.
#[derive(Debug, Clone)]
pub struct Feeds {
    pub delphi: Result<DelphiReading, String>,
    pub pricestr: Result<PriceStrReading, String>,
}

impl Feeds {
    pub fn disabled() -> Self {
        Self { delphi: Err("disabled".into()), pricestr: Err("disabled".into()) }
    }
}

fn is_valid_price(p: f64) -> bool {
    p.is_finite() && p > 0.0
}

fn age(ev: &Event, now: u64, max_age: u64) -> Result<u64> {
    let created = ev.created_at.as_secs();
    ensure!(created <= now + MAX_FUTURE_SECS, "timestamp is in the future");
    let a = now.saturating_sub(created);
    ensure!(a <= max_age, "older than {max_age}s");
    Ok(a)
}

/// Newest valid chain-1h audit from Delphi, skipping audits replaced after a reorg.
pub fn read_delphi(events: &[Event], publisher: &PublicKey, now: u64, max_age: u64) -> Result<DelphiReading> {
    let own: Vec<&Event> = events
        .iter()
        .filter(|e| e.kind == Kind::Custom(KIND_DELPHI_AUDIT) && e.pubkey == *publisher)
        .filter(|e| e.verify().is_ok())
        .collect();
    let replaced: HashSet<EventId> = own.iter().flat_map(|e| e.tags.event_ids().copied()).collect();
    let mut newest: Option<(u64, f64)> = None;
    let mut last_error = anyhow!("no audit found");
    for e in own.iter().filter(|e| !replaced.contains(&e.id)) {
        let parsed = (|| -> Result<(u64, f64)> {
            let a = age(e, now, max_age)?;
            let v: serde_json::Value = serde_json::from_str(&e.content).context("audit is not JSON")?;
            ensure!(v["window"] == DELPHI_WINDOW, "wrong window");
            let p = v["price"].as_f64().context("audit has no price")?;
            ensure!(is_valid_price(p), "invalid price");
            Ok((a, p))
        })();
        match parsed {
            Ok((a, p)) if newest.is_none_or(|(b, _)| a < b) => newest = Some((a, p)),
            Ok(_) => {}
            Err(err) => last_error = err,
        }
    }
    let (age_secs, usd) = newest.ok_or(last_error)?;
    Ok(DelphiReading { usd, age_secs })
}

/// Newest valid BTC/USD reading from PriceStr.
pub fn read_pricestr(events: &[Event], publisher: &PublicKey, now: u64, max_age: u64) -> Result<PriceStrReading> {
    let mut candidates: Vec<&Event> = events
        .iter()
        .filter(|e| e.kind == Kind::Custom(KIND_PRICESTR) && e.pubkey == *publisher)
        .filter(|e| e.verify().is_ok())
        .collect();
    candidates.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    let mut last_error = anyhow!("no reading found");
    for e in candidates {
        let parsed = (|| -> Result<PriceStrReading> {
            let age_secs = age(e, now, max_age)?;
            let currency = e
                .tags
                .iter()
                .map(|t| t.as_slice())
                .find(|t| t.first().is_some_and(|k| k == "currency"))
                .and_then(|t| t.get(1));
            if currency.map(String::as_str) != Some("USD") {
                bail!("not a USD reading");
            }
            let v: serde_json::Value = serde_json::from_str(&e.content).context("not JSON")?;
            let usd = v["median"].as_f64().context("no median")?;
            ensure!(is_valid_price(usd), "invalid median");
            let eur_per_usd = v["fxRates"]["EUR"].as_f64().filter(|x| is_valid_price(*x));
            Ok(PriceStrReading { usd, eur_per_usd, age_secs })
        })();
        match parsed {
            Ok(r) => return Ok(r),
            Err(err) => last_error = err,
        }
    }
    Err(last_error)
}

/// The nostr feeds as quotes in `fiat`. `exchange_rate` is EUR per USD implied by
/// the exchanges, used when PriceStr publishes no rate.
pub fn nostr_quotes(fiat: Fiat, feeds: &Feeds, exchange_rate: Option<f64>) -> Vec<Quote> {
    let published = feeds.pricestr.as_ref().ok().and_then(|r| r.eur_per_usd);
    let rate = match fiat {
        Fiat::Usd => Some(1.0),
        Fiat::Eur => published.or(exchange_rate),
    };
    let Some(rate) = rate else { return vec![] };
    let mut out = vec![];
    if let Ok(r) = &feeds.delphi {
        out.push(Quote { source: "delphi", price: r.usd * rate });
    }
    if let Ok(r) = &feeds.pricestr {
        out.push(Quote { source: "pricestr", price: r.usd * rate });
    }
    out
}

/// All quotes for one currency: exchanges plus nostr feeds.
pub async fn collect_quotes(http: &reqwest::Client, fiat: Fiat, feeds: &Feeds) -> Vec<Quote> {
    let mut quotes = price::fetch_quotes(http, fiat).await;
    let has_rate = feeds.pricestr.as_ref().is_ok_and(|r| r.eur_per_usd.is_some());
    let exchange_rate = if fiat == Fiat::Eur && !has_rate && feeds.delphi.is_ok() {
        let usd = price::fetch_quotes(http, Fiat::Usd).await;
        match (
            price::aggregate(&quotes, 3, 3, 0.01),
            price::aggregate(&usd, 3, 3, 0.01),
        ) {
            (Ok(e), Ok(u)) => Some(e / u),
            _ => None,
        }
    } else {
        None
    };
    quotes.extend(nostr_quotes(fiat, feeds, exchange_rate));
    quotes
}

/// Read both feeds through a separate, read-only client, so that these relays
/// never receive the oracle's events. An unreachable feed is reported, not fatal.
pub async fn fetch_feeds(cfg: &NostrFeeds, now: u64) -> Feeds {
    if !cfg.enabled {
        return Feeds::disabled();
    }
    let client = Client::default();
    let mut urls: Vec<String> = cfg.pricestr_relays.clone();
    urls.push(cfg.delphi_relay.clone());
    for u in &urls {
        if let Err(e) = client.add_relay(u.as_str()).await {
            log::warn!("feed relay {u}: {e}");
        }
    }
    client.connect().await;
    client.wait_for_connection(Duration::from_secs(5)).await;

    let delphi = async {
        let publisher = PublicKey::parse(&cfg.delphi_pubkey)?;
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_DELPHI_AUDIT))
            .author(publisher)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::W), DELPHI_WINDOW)
            .since(Timestamp::from(now.saturating_sub(cfg.delphi_max_age_secs)))
            .limit(30);
        let events = client
            .fetch_events_from([cfg.delphi_relay.as_str()], filter, Duration::from_secs(8))
            .await?;
        read_delphi(&events.to_vec(), &publisher, now, cfg.delphi_max_age_secs)
    }
    .await
    .map_err(|e: anyhow::Error| format!("{e:#}"));

    let pricestr = async {
        let publisher = PublicKey::parse(&cfg.pricestr_pubkey)?;
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_PRICESTR))
            .author(publisher)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::T), "pricestr")
            .since(Timestamp::from(now.saturating_sub(cfg.pricestr_max_age_secs)))
            .limit(10);
        let relays: Vec<&str> = cfg.pricestr_relays.iter().map(String::as_str).collect();
        let events = client
            .fetch_events_from(relays, filter, Duration::from_secs(8))
            .await?;
        read_pricestr(&events.to_vec(), &publisher, now, cfg.pricestr_max_age_secs)
    }
    .await
    .map_err(|e: anyhow::Error| format!("{e:#}"));

    client.disconnect().await;
    if let Err(e) = &delphi {
        log::warn!("delphi feed unavailable: {e}");
    }
    if let Err(e) = &pricestr {
        log::warn!("pricestr feed unavailable: {e}");
    }
    Feeds { delphi, pricestr }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feeds(eur: Option<f64>) -> Feeds {
        Feeds {
            delphi: Ok(DelphiReading { usd: 60_000.0, age_secs: 600 }),
            pricestr: Ok(PriceStrReading { usd: 61_000.0, eur_per_usd: eur, age_secs: 10 }),
        }
    }

    #[test]
    fn usd_quotes_are_unconverted() {
        let q = nostr_quotes(Fiat::Usd, &feeds(Some(0.9)), None);
        assert_eq!((q[0].source, q[0].price), ("delphi", 60_000.0));
        assert_eq!((q[1].source, q[1].price), ("pricestr", 61_000.0));
    }

    #[test]
    fn eur_prefers_the_published_rate() {
        let q = nostr_quotes(Fiat::Eur, &feeds(Some(0.9)), Some(0.5));
        assert_eq!(q[0].price, 54_000.0);
        let q = nostr_quotes(Fiat::Eur, &feeds(None), Some(0.5));
        assert_eq!(q[0].price, 30_000.0);
        assert!(nostr_quotes(Fiat::Eur, &feeds(None), None).is_empty());
    }

    #[test]
    fn unavailable_feeds_add_no_quotes() {
        assert!(nostr_quotes(Fiat::Usd, &Feeds::disabled(), None).is_empty());
    }
}
