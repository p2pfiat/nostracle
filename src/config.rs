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
    /// Quotes that must agree before attesting.
    #[serde(default = "d_min_sources")]
    pub min_sources: usize,
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
        anyhow::ensure!(self.min_sources >= 1, "min_sources must be >= 1");
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
        Ok(())
    }
}
