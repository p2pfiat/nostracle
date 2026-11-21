//! Feed parsing and fetching against a local relay. No public relays.
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::*;
use nostracle::config::NostrFeeds;
use nostracle::feeds::{fetch_feeds, read_delphi, read_pricestr, KIND_DELPHI_AUDIT, KIND_PRICESTR};
use nostracle::oracle::now;
use std::time::Duration;

fn audit(keys: &Keys, price: f64, created: u64, replaces: Option<EventId>) -> Event {
    let mut tags = vec![
        Tag::custom(TagKind::custom("w"), ["chain-1h"]),
        Tag::custom(TagKind::custom("h"), ["976899"]),
    ];
    if let Some(id) = replaces {
        tags.push(Tag::event(id));
    }
    let content = serde_json::json!({ "window": "chain-1h", "price": price }).to_string();
    EventBuilder::new(Kind::Custom(KIND_DELPHI_AUDIT), content)
        .tags(tags)
        .custom_created_at(Timestamp::from(created))
        .sign_with_keys(keys)
        .unwrap()
}

fn reading(keys: &Keys, median: f64, created: u64, currency: &str) -> Event {
    let content = serde_json::json!({
        "median": median,
        "sources": { "kraken": median },
        "fxRates": { "EUR": 0.91 },
    })
    .to_string();
    EventBuilder::new(Kind::Custom(KIND_PRICESTR), content)
        .tags([
            Tag::identifier(format!("pricestr/{created}")),
            Tag::custom(TagKind::custom("t"), ["pricestr"]),
            Tag::custom(TagKind::custom("currency"), [currency]),
        ])
        .custom_created_at(Timestamp::from(created))
        .sign_with_keys(keys)
        .unwrap()
}

#[test]
fn delphi_rules() {
    let keys = Keys::generate();
    let pk = keys.public_key();
    let t = now();

    let old = audit(&keys, 50_000.0, t - 1200, None);
    let new = audit(&keys, 60_000.0, t - 600, None);
    assert_eq!(read_delphi(&[old.clone(), new.clone()], &pk, t, 3600).unwrap().usd, 60_000.0);

    // Another author cannot inject a price, even if it is the newest.
    let forged = audit(&Keys::generate(), 1.0, t - 10, None);
    assert_eq!(read_delphi(&[new.clone(), forged], &pk, t, 3600).unwrap().usd, 60_000.0);

    // A reorg replacement removes the audit it names.
    let replacement = audit(&keys, 59_000.0, t - 700, Some(new.id));
    assert_eq!(read_delphi(&[new.clone(), replacement], &pk, t, 3600).unwrap().usd, 59_000.0);

    // Too old, from the future, or invalid: unavailable.
    assert!(read_delphi(&[audit(&keys, 60_000.0, t - 7200, None)], &pk, t, 3600).is_err());
    assert!(read_delphi(&[audit(&keys, 60_000.0, t + 3600, None)], &pk, t, 3600).is_err());
    assert!(read_delphi(&[audit(&keys, -5.0, t - 10, None)], &pk, t, 3600).is_err());
}

#[test]
fn pricestr_rules() {
    let keys = Keys::generate();
    let pk = keys.public_key();
    let t = now();

    let r = read_pricestr(&[reading(&keys, 60_000.0, t - 10, "USD")], &pk, t, 120).unwrap();
    assert_eq!((r.usd, r.eur_per_usd), (60_000.0, Some(0.91)));

    // Newest valid reading wins; other currencies and other authors are ignored.
    let events = [
        reading(&keys, 59_000.0, t - 30, "USD"),
        reading(&keys, 60_000.0, t - 10, "USD"),
        reading(&keys, 1.0, t - 5, "JPY"),
        reading(&Keys::generate(), 2.0, t - 1, "USD"),
    ];
    assert_eq!(read_pricestr(&events, &pk, t, 120).unwrap().usd, 60_000.0);

    assert!(read_pricestr(&[reading(&keys, 60_000.0, t - 600, "USD")], &pk, t, 120).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn fetches_both_feeds_from_a_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let (delphi, pricestr) = (Keys::generate(), Keys::generate());
    let t = now();

    let client = Client::default();
    client.add_relay(url.as_str()).await.unwrap();
    client.connect().await;
    client.wait_for_connection(Duration::from_secs(5)).await;
    client.send_event(&audit(&delphi, 60_000.0, t - 600, None)).await.unwrap();
    client.send_event(&reading(&pricestr, 60_500.0, t - 5, "USD")).await.unwrap();

    let cfg = NostrFeeds {
        delphi_pubkey: delphi.public_key().to_hex(),
        delphi_relay: url.clone(),
        pricestr_pubkey: pricestr.public_key().to_hex(),
        pricestr_relays: vec![url.clone()],
        ..NostrFeeds::default()
    };
    let feeds = fetch_feeds(&cfg, t).await;
    assert_eq!(feeds.delphi.unwrap().usd, 60_000.0);
    assert_eq!(feeds.pricestr.unwrap().usd, 60_500.0);

    // An unreachable relay reports "unavailable" instead of failing.
    let down = NostrFeeds {
        delphi_relay: "ws://127.0.0.1:1".into(),
        pricestr_relays: vec!["ws://127.0.0.1:1".into()],
        ..cfg
    };
    let feeds = fetch_feeds(&down, t).await;
    assert!(feeds.delphi.is_err() && feeds.pricestr.is_err());
}
