use crate::price::Fiat;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Hex-encoded 32-byte oracle secret key (also the nostr identity).
    #[serde(default = "d_key_file")]
    pub key_file: PathBuf,
    /// Event database. Losing it while keeping the key risks nonce reuse.
    #[serde(default = "d_db_file")]
    pub db_file: PathBuf,
    pub relays: Vec<String>,
    /// An event counts as published once this many relays accepted it.
    #[serde(default = "d_min_relay_acks")]
    pub min_relay_acks: usize,
    /// Re-send recent events to all relays this often, for relays that missed them.
    #[serde(default = "d_rebroadcast")]
    pub rebroadcast_secs: u64,
    #[serde(default = "d_pairs")]
    pub pairs: Vec<Fiat>,
    /// Event series. Maturities shared between series are one event.
    #[serde(default = "d_series")]
    pub series: Vec<Series>,
    /// Binary digits of the attested price (20 -> max 1_048_575).
    #[serde(default = "d_digits")]
    pub num_digits: u16,
    /// Quotes needed in total (exchanges plus nostr feeds) before attesting.
    #[serde(default = "d_min_sources")]
    pub min_sources: usize,
    /// Of those, how many must lie within `max_deviation` of the median.
    #[serde(default = "d_min_agreeing")]
    pub min_agreeing: usize,
    /// Allowed relative deviation from the median (0.01 = 1%).
    #[serde(default = "d_max_dev")]
    pub max_deviation: f64,
    /// Do not attest an event more than this long after maturity: a much later
    /// price would misrepresent the event. Contracts fall back to refund.
    #[serde(default = "d_max_delay")]
    pub max_attest_delay_secs: u64,
    /// Move finished events to the archive file this long after maturity.
    #[serde(default = "d_archive_after")]
    pub archive_after_secs: u64,
    /// Main loop period, in seconds.
    #[serde(default = "d_tick")]
    pub tick_secs: u64,
    #[serde(default)]
    pub profile: Profile,
    /// Paid attestations over zaps. Without this section attestations are public.
    pub pricing: Option<Pricing>,
    /// Price feeds read from nostr, used as extra quotes in the median.
    #[serde(default)]
    pub nostr_feeds: NostrFeeds,
    /// Optional kind-1 social feed posts of attested prices (BTC/USD, USD/BTC, ...).
    #[serde(default)]
    pub social_feed: SocialFeed,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SocialFeed {
    /// Post attested public prices as Nostr kind-1 text notes.
    pub enabled: bool,
    /// Minimum spacing between kind-1 posts per currency pair (default: 3600s).
    pub min_interval_secs: u64,
    /// Also include the inverse pair (e.g. USD/BTC & sats/USD) in text and tags.
    pub include_inverse: bool,
    /// Extra hashtags appended to every social price note.
    pub hashtags: Vec<String>,
    /// Nostr npubs (or `nostr:npub...`) to mention in every social price note (NIP-27 + `p` tag).
    pub mentions: Vec<String>,
}

impl Default for SocialFeed {
    fn default() -> Self {
        Self {
            enabled: false,
            min_interval_secs: 3600,
            include_inverse: true,
            hashtags: vec!["nostracle".into(), "p2pfiat".into()],
            mentions: vec![],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NostrFeeds {
    pub enabled: bool,
    pub delphi_pubkey: String,
    pub delphi_relay: String,
    /// Ignore Delphi audits older than this.
    pub delphi_max_age_secs: u64,
    pub pricestr_pubkey: String,
    pub pricestr_relays: Vec<String>,
    /// Ignore PriceStr readings older than this.
    pub pricestr_max_age_secs: u64,
    /// Also read the p2pFiat Nostr Offer Book (kind 38384) as a price source,
    /// aggregated via liquidity- & near-zero-yield-weighted median.
    pub orderbook_enabled: bool,
    pub orderbook_relays: Vec<String>,
    pub orderbook_tag: String,
    /// Minimum distinct verified LPs required before the orderbook yields a quote.
    pub orderbook_min_lps: usize,
    /// Ignore orderbook offers older than this.
    pub orderbook_max_age_secs: u64,
    /// Ignore offers with |fundingRateBpsPerDay| above this threshold.
    pub orderbook_max_abs_funding_bps: f64,
}

impl Default for NostrFeeds {
    fn default() -> Self {
        Self {
            enabled: true,
            delphi_pubkey: "bc94c9ed60c870e0b826bd4adf839f667404d5a5e3d852c2e0ff05c7609e9be0".into(),
            delphi_relay: "wss://rof.illuminodes.com".into(),
            delphi_max_age_secs: 3 * 3600,
            pricestr_pubkey: "c6326ba648f2645f419a63e03c525b3547688a3aadab82c9678c18258eb71239".into(),
            pricestr_relays: vec!["wss://relay.damus.io".into(), "wss://relay.primal.net".into()],
            pricestr_max_age_secs: 120,
            orderbook_enabled: false,
            orderbook_relays: vec![
                "wss://relay.damus.io".into(),
                "wss://nos.lol".into(),
                "wss://relay.primal.net".into(),
            ],
            orderbook_tag: "p2pfiat-offer".into(),
            orderbook_min_lps: 3,
            orderbook_max_age_secs: 180,
            orderbook_max_abs_funding_bps: 20.0,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pricing {
    /// Zap on an announcement that buys its attestation.
    pub attestation_sats: u64,
    /// Zap that creates a custom event; includes its attestation.
    pub custom_event_sats: u64,
    /// Custom maturities must be at least this far ahead.
    #[serde(default = "d_custom_lead")]
    pub custom_min_lead_secs: u64,
    /// Custom maturities can be at most this far ahead.
    #[serde(default = "d_custom_horizon")]
    pub custom_max_horizon_secs: u64,
    /// Publish attestations for everyone this long after maturity. Unset: never.
    pub public_attestation_delay_secs: Option<u64>,
    /// Key that signs zap receipts. Unset: looked up from `profile.lud16`.
    pub zapper_pubkey: Option<String>,
}

/// A schedule of events: one per `interval_secs` (aligned to unix time, so
/// 86400 = daily at 00:00 UTC), announced `horizon_secs` ahead.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Series {
    pub interval_secs: u64,
    pub horizon_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: Option<String>,
    pub about: Option<String>,
    /// Lightning address to receive zaps.
    pub lud16: Option<String>,
    pub website: Option<String>,
}

fn d_key_file() -> PathBuf {
    "data/oracle.key".into()
}
fn d_db_file() -> PathBuf {
    "data/events.json".into()
}
fn d_min_relay_acks() -> usize {
    2
}
fn d_rebroadcast() -> u64 {
    6 * 3600
}
fn d_pairs() -> Vec<Fiat> {
    vec![Fiat::Usd, Fiat::Eur]
}
fn d_series() -> Vec<Series> {
    vec![
        // short-term: hourly, 2 days ahead
        Series { interval_secs: 3600, horizon_secs: 2 * 86400 },
        // contract maturities: daily 00:00 UTC, 90 days ahead
        Series { interval_secs: 86400, horizon_secs: 90 * 86400 },
    ]
}
fn d_digits() -> u16 {
    20
}
fn d_min_sources() -> usize {
    5
}
fn d_min_agreeing() -> usize {
    3
}
fn d_max_dev() -> f64 {
    0.01
}
fn d_max_delay() -> u64 {
    3600
}
fn d_archive_after() -> u64 {
    7 * 86400
}
fn d_custom_lead() -> u64 {
    600
}
fn d_custom_horizon() -> u64 {
    365 * 86400
}
fn d_tick() -> u64 {
    30
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path).with_context(|| format!("read {path:?}"))?;
        let cfg: Config = toml::from_str(&s).with_context(|| format!("parse {path:?}"))?;
        cfg.check()?;
        Ok(cfg)
    }

    pub fn check(&self) -> Result<()> {
        anyhow::ensure!(!self.series.is_empty(), "at least one [[series]] required");
        for s in &self.series {
            anyhow::ensure!(s.interval_secs >= 60, "series interval_secs must be >= 60");
            anyhow::ensure!(s.horizon_secs >= s.interval_secs, "series horizon < interval");
        }
        anyhow::ensure!(self.num_digits > 0 && self.num_digits <= 32, "num_digits out of range");
        anyhow::ensure!(self.min_agreeing >= 1, "min_agreeing must be >= 1");
        anyhow::ensure!(
            self.min_agreeing <= self.min_sources,
            "min_agreeing cannot exceed min_sources"
        );
        let available = crate::price::ALL_SOURCES.len()
            + if self.nostr_feeds.enabled {
                2 + if self.nostr_feeds.orderbook_enabled { 1 } else { 0 }
            } else {
                0
            };
        anyhow::ensure!(
            self.min_sources <= available,
            "min_sources ({}) exceeds the {available} available feeds",
            self.min_sources
        );
        if self.nostr_feeds.enabled && self.nostr_feeds.orderbook_enabled {
            anyhow::ensure!(
                self.nostr_feeds.orderbook_min_lps >= 1,
                "nostr_feeds.orderbook_min_lps must be >= 1"
            );
            anyhow::ensure!(
                self.nostr_feeds.orderbook_max_abs_funding_bps >= 0.0,
                "nostr_feeds.orderbook_max_abs_funding_bps must be >= 0"
            );
        }
        anyhow::ensure!(self.min_relay_acks >= 1, "min_relay_acks must be >= 1");
        anyhow::ensure!(
            self.min_relay_acks <= self.relays.len(),
            "min_relay_acks ({}) > number of relays ({})",
            self.min_relay_acks,
            self.relays.len()
        );
        anyhow::ensure!(
            self.archive_after_secs > self.max_attest_delay_secs,
            "archive_after_secs must exceed max_attest_delay_secs"
        );
        if let Some(p) = &self.pricing {
            anyhow::ensure!(
                p.attestation_sats > 0 && p.custom_event_sats > 0,
                "prices must be > 0"
            );
            anyhow::ensure!(
                p.zapper_pubkey.is_some() || self.profile.lud16.is_some(),
                "[pricing] needs profile.lud16 (or zapper_pubkey) to receive zaps"
            );
        }
        if self.social_feed.enabled {
            anyhow::ensure!(
                self.social_feed.min_interval_secs >= 60,
                "social_feed.min_interval_secs must be >= 60 to avoid relay rate-limits"
            );
        }
        Ok(())
    }
}
