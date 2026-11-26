use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::*;
use nostracle::config::SocialFeed;
use nostracle::oracle;
use nostracle::price::Fiat;
use nostracle::social;
use std::time::Duration;

#[test]
fn price_note_formats_both_pairs_and_tags() {
    let keys = Keys::generate();
    let mention_keys = Keys::generate();
    let mention_npub = mention_keys.public_key().to_bech32().unwrap();
    let cfg = SocialFeed {
        enabled: true,
        min_interval_secs: 3600,
        include_inverse: true,
        hashtags: vec!["nostracle".into(), "p2pfiat".into()],
        mentions: vec![format!("nostr:{mention_npub}")],
    };
    let att_id = EventId::all_zeros();
    let ev = social::price_note(
        &keys,
        Fiat::Usd,
        96_500,
        Some("btcusd-1764028800"),
        &cfg,
        Some(att_id),
    )
    .unwrap();

    assert_eq!(ev.kind, Kind::TextNote);
    assert!(ev.verify().is_ok());
    assert!(ev.content.contains("BTC/USD: 96500 USD"));
    assert!(ev.content.contains("USD/BTC: 0.00001036 BTC (1036 sats/USD)"));
    assert!(ev.content.contains("Event: btcusd-1764028800"));
    assert!(ev.content.contains(&format!("#BTCUSD #USDBTC #nostracle #p2pfiat nostr:{mention_npub}")));

    let tags: Vec<Vec<String>> = ev.tags.iter().map(|t| t.as_slice().to_vec()).collect();
    assert!(tags.contains(&vec!["p".into(), mention_keys.public_key().to_hex()]));
    assert!(tags.contains(&vec!["t".into(), "btcusd".into()]));
    assert!(tags.contains(&vec!["t".into(), "usdbtc".into()]));
    assert!(tags.contains(&vec!["t".into(), "nostracle".into()]));
    assert!(tags.contains(&vec!["t".into(), "p2pfiat".into()]));
    assert!(tags.contains(&vec!["pair".into(), "BTC/USD".into()]));
    assert!(tags.contains(&vec!["inverse_pair".into(), "USD/BTC".into()]));
    assert!(tags.contains(&vec!["price".into(), "96500".into()]));
    assert!(tags.contains(&vec!["sats_per_unit".into(), "1036".into()]));
    assert!(tags.contains(&vec!["e".into(), att_id.to_hex(), String::new(), "mention".into()]));
}

#[test]
fn price_note_without_inverse_omits_inverse_pair() {
    let keys = Keys::generate();
    let cfg = SocialFeed {
        enabled: true,
        min_interval_secs: 3600,
        include_inverse: false,
        hashtags: vec![],
        mentions: vec![],
    };
    let ev = social::price_note(&keys, Fiat::Eur, 90_000, None, &cfg, None).unwrap();
    assert!(ev.content.contains("BTC/EUR: 90000 EUR"));
    assert!(!ev.content.contains("EUR/BTC"));
    let tags: Vec<Vec<String>> = ev.tags.iter().map(|t| t.as_slice().to_vec()).collect();
    assert!(tags.contains(&vec!["t".into(), "btceur".into()]));
    assert!(!tags.contains(&vec!["t".into(), "eurbtc".into()]));
}

#[tokio::test]
async fn social_price_note_roundtrips_over_relay_by_both_pair_hashtags() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await;

    let keys = Keys::generate();
    let client = Client::new(keys.clone());
    client.add_relay(url.as_str()).await.unwrap();
    client.connect().await;
    client.wait_for_connection(Duration::from_secs(5)).await;

    let cfg = SocialFeed { enabled: true, ..SocialFeed::default() };
    let ev = social::price_note(&keys, Fiat::Usd, 100_000, Some("btcusd-1764028800"), &cfg, None).unwrap();
    let out = client.send_event(&ev).await.unwrap();
    assert_eq!(out.success.len(), 1);

    let by_btcusd = client
        .fetch_events(
            Filter::new().kind(Kind::TextNote).author(keys.public_key()).hashtag("btcusd"),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(by_btcusd.len(), 1);
    assert_eq!(by_btcusd.first().unwrap().id, ev.id);

    let by_usdbtc = client
        .fetch_events(
            Filter::new().kind(Kind::TextNote).author(keys.public_key()).hashtag("usdbtc"),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(by_usdbtc.len(), 1);
    assert_eq!(by_usdbtc.first().unwrap().id, ev.id);

    client.disconnect().await;
}

#[test]
fn relay_list_event_builds_nip65() {
    let keys = Keys::generate();
    let relays = vec![
        "wss://relay.primal.net".to_string(),
        "wss://relay.damus.io".to_string(),
        "wss://nos.lol".to_string(),
    ];
    let ev = oracle::relay_list_event(&keys, &relays).unwrap();
    assert_eq!(ev.kind, Kind::RelayList);
    assert!(ev.verify().is_ok());
    let r_tags: Vec<String> = ev
        .tags
        .iter()
        .filter_map(|t| {
            let s = t.as_slice();
            (s.first().map(String::as_str) == Some("r")).then(|| s.get(1).cloned()).flatten()
        })
        .collect();
    assert_eq!(r_tags.len(), 3);
    assert!(r_tags.iter().any(|r| r.contains("relay.primal.net")));
    assert!(r_tags.iter().any(|r| r.contains("relay.damus.io")));
    assert!(r_tags.iter().any(|r| r.contains("nos.lol")));
}
