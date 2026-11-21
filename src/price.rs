//! Spot price collection from exchanges and robust aggregation of all quotes.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use std::time::Duration;

/// A fiat currency nostracle can attest BTC prices in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Fiat {
    Usd,
    Eur,
}

impl Fiat {
    pub fn code(self) -> &'static str {
        match self {
            Fiat::Usd => "USD",
            Fiat::Eur => "EUR",
        }
    }

    /// Lowercase pair name used in event ids, e.g. `btcusd`.
    pub fn pair(self) -> String {
        format!("btc{}", self.code().to_lowercase())
    }
}

/// Exchanges with public, unauthenticated ticker endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Kraken,
    Bitstamp,
    Coinbase,
    Bitfinex,
}

pub const ALL_SOURCES: [Source; 4] = [
    Source::Kraken,
    Source::Bitstamp,
    Source::Coinbase,
    Source::Bitfinex,
];

impl Source {
    pub fn name(self) -> &'static str {
        match self {
            Source::Kraken => "kraken",
            Source::Bitstamp => "bitstamp",
            Source::Coinbase => "coinbase",
            Source::Bitfinex => "bitfinex",
        }
    }

    fn url(self, fiat: Fiat) -> String {
        let c = fiat.code();
        match self {
            Source::Kraken => format!("https://api.kraken.com/0/public/Ticker?pair=XBT{c}"),
            Source::Bitstamp => {
                format!("https://www.bitstamp.net/api/v2/ticker/btc{}/", c.to_lowercase())
            }
            Source::Coinbase => format!("https://api.coinbase.com/v2/prices/BTC-{c}/spot"),
            Source::Bitfinex => format!("https://api-pub.bitfinex.com/v2/ticker/tBTC{c}"),
        }
    }

    /// Extract the last trade price from the exchange's JSON response.
    pub fn parse(self, v: &Value) -> Result<f64> {
        let num = |x: &Value| -> Result<f64> {
            match x {
                Value::String(s) => s.parse::<f64>().context("not a number"),
                Value::Number(n) => n.as_f64().ok_or_else(|| anyhow!("not a number")),
                _ => bail!("unexpected price type"),
            }
        };
        let price = match self {
            Source::Kraken => {
                if let Some(errs) = v["error"].as_array() {
                    if !errs.is_empty() {
                        bail!("kraken error: {errs:?}");
                    }
                }
                let result = v["result"].as_object().ok_or_else(|| anyhow!("no result"))?;
                let (_, t) = result.iter().next().ok_or_else(|| anyhow!("empty result"))?;
                num(&t["c"][0])?
            }
            Source::Bitstamp => num(&v["last"])?,
            Source::Coinbase => num(&v["data"]["amount"])?,
            // [BID, BID_SIZE, ASK, ASK_SIZE, DAILY_CHANGE, DAILY_CHANGE_REL, LAST_PRICE, ...]
            Source::Bitfinex => num(&v[6])?,
        };
        if !(price.is_finite() && price > 0.0) {
            bail!("non-positive price {price}");
        }
        Ok(price)
    }
}

#[derive(Debug, Clone)]
pub struct Quote {
    pub source: &'static str,
    pub price: f64,
}

/// Fetch quotes from all sources concurrently. Failures are logged and skipped.
pub async fn fetch_quotes(http: &reqwest::Client, fiat: Fiat) -> Vec<Quote> {
    let futs = ALL_SOURCES.iter().map(|&s| async move {
        let res: Result<f64> = async {
            let v: Value = http
                .get(s.url(fiat))
                .timeout(Duration::from_secs(10))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            s.parse(&v)
        }
        .await;
        match res {
            Ok(price) => Some(Quote { source: s.name(), price }),
            Err(e) => {
                log::warn!("{} {}: {e:#}", s.name(), fiat.code());
                None
            }
        }
    });
    let mut out = Vec::new();
    for f in futs {
        if let Some(q) = f.await {
            out.push(q);
        }
    }
    out
}

fn median(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

/// Robust aggregate: take the median, drop quotes deviating more than
/// `max_deviation` (fraction, e.g. 0.01 = 1%) from it, require at least
/// `min_agreeing` survivors and return the median of the survivors.
///
/// With at least 5 quotes and 3 agreeing, two wrong quotes cannot set the price.
pub fn aggregate(
    quotes: &[Quote],
    min_sources: usize,
    min_agreeing: usize,
    max_deviation: f64,
) -> Result<f64> {
    if quotes.len() < min_sources {
        bail!("only {} quotes, need {min_sources}", quotes.len());
    }
    let mut prices: Vec<f64> = quotes.iter().map(|q| q.price).collect();
    prices.sort_by(|a, b| a.total_cmp(b));
    let m = median(&prices);
    let mut kept: Vec<f64> = prices
        .into_iter()
        .filter(|p| ((p - m) / m).abs() <= max_deviation)
        .collect();
    if kept.len() < min_agreeing {
        bail!(
            "only {} of {} quotes within {:.2}% of median {m:.2}: {quotes:?}",
            kept.len(),
            quotes.len(),
            max_deviation * 100.0
        );
    }
    kept.sort_by(|a, b| a.total_cmp(b));
    Ok(median(&kept))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn q(p: f64) -> Quote {
        Quote { source: "t", price: p }
    }

    #[test]
    fn aggregate_drops_outlier() {
        let quotes = [q(100_000.0), q(100_050.0), q(99_980.0), q(120_000.0)];
        let p = aggregate(&quotes, 4, 3, 0.01).unwrap();
        assert_eq!(p, 100_000.0);
    }

    #[test]
    fn aggregate_requires_quorum() {
        assert!(aggregate(&[q(1.0), q(1.0)], 5, 3, 0.01).is_err());
        // two of four agree, two wildly off -> not enough survivors
        let quotes = [q(100.0), q(100.0), q(150.0), q(50.0)];
        assert!(aggregate(&quotes, 4, 3, 0.01).is_err());
    }

    #[test]
    fn two_bad_feeds_cannot_set_the_price() {
        let honest = [q(60_000.0), q(60_100.0), q(59_950.0)];
        for bad in [[1.0, 1.0], [1e9, 1e9], [1.0, 1e9], [59_000.0, 59_000.0]] {
            let mut quotes = honest.to_vec();
            quotes.extend(bad.map(q));
            let p = aggregate(&quotes, 5, 3, 0.01).unwrap();
            assert!((59_950.0..=60_100.0).contains(&p), "{bad:?} moved price to {p}");
        }
    }

    #[test]
    fn five_feeds_are_required() {
        let four = [q(60_000.0), q(60_000.0), q(60_000.0), q(60_000.0)];
        assert!(aggregate(&four, 5, 3, 0.01).is_err());
    }

    #[test]
    fn three_bad_of_five_are_not_accepted_when_they_disagree() {
        let quotes = [q(60_000.0), q(60_000.0), q(1.0), q(1e9), q(5e8)];
        assert!(aggregate(&quotes, 5, 3, 0.01).is_err());
    }

    #[test]
    fn parse_sources() {
        let kraken = json!({"error": [], "result": {"XXBTZUSD": {"c": ["97123.4", "0.01"]}}});
        assert_eq!(Source::Kraken.parse(&kraken).unwrap(), 97123.4);
        assert!(Source::Kraken.parse(&json!({"error": ["EQuery:Unknown asset pair"]})).is_err());
        assert_eq!(Source::Bitstamp.parse(&json!({"last": "97000"})).unwrap(), 97000.0);
        assert_eq!(
            Source::Coinbase.parse(&json!({"data": {"amount": "96999.5"}})).unwrap(),
            96999.5
        );
        let bfx = json!([1, 2, 3, 4, 5, 6, 97001.0, 8, 9, 10]);
        assert_eq!(Source::Bitfinex.parse(&bfx).unwrap(), 97001.0);
        assert!(Source::Bitstamp.parse(&json!({"last": "-1"})).is_err());
    }
}
