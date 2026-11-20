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
    #[serde(default = "d_pairs")]
    pub pairs: Vec<Fiat>,
    /// Spacing between event maturities, in seconds.
    #[serde(default = "d_interval")]
    pub interval_secs: u64,
    /// How far ahead announcements are published, in seconds.
    #[serde(default = "d_horizon")]
    pub horizon_secs: u64,
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
    /// Main loop period, in seconds.
    #[serde(default = "d_tick")]
    pub tick_secs: u64,
    #[serde(default)]
    pub profile: Profile,
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
fn d_pairs() -> Vec<Fiat> {
    vec![Fiat::Usd, Fiat::Eur]
}
fn d_interval() -> u64 {
    3600
}
fn d_horizon() -> u64 {
    48 * 3600
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
fn d_tick() -> u64 {
    30
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path).with_context(|| format!("read {path:?}"))?;
        let cfg: Config = toml::from_str(&s).with_context(|| format!("parse {path:?}"))?;
        anyhow::ensure!(cfg.interval_secs >= 60, "interval_secs must be >= 60");
        anyhow::ensure!(cfg.num_digits > 0 && cfg.num_digits <= 32, "num_digits out of range");
        anyhow::ensure!(cfg.min_sources >= 1, "min_sources must be >= 1");
        Ok(cfg)
    }
}
