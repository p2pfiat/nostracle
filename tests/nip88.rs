//! The events nostracle publishes must pass the checks a DLC client runs.
use kormir::bitcoin::secp256k1::SecretKey;
use kormir::Oracle;
use nostr_sdk::prelude::*;
use nostracle::{nip88, storage::FileStorage};

async fn setup() -> (tempfile::TempDir, Oracle<FileStorage>, Event, Event) {
    let dir = tempfile::tempdir().unwrap();
    let st = FileStorage::create(dir.path().join("events.json")).unwrap();
    let oracle = Oracle::from_signing_key(st, SecretKey::from_slice(&[9u8; 32]).unwrap()).unwrap();
    let ann = oracle
        .create_numeric_event("btceur-2000".into(), 20, false, 0, "EUR".into(), 2000)
        .await
        .unwrap();
    let att = oracle.sign_numeric_event("btceur-2000".into(), 54_321).await.unwrap();
    let keys = oracle.nostr_keys();
    let relays = vec!["wss://relay.example".to_string()];
    let ann_ev = nip88::announcement_event(&keys, &ann, &relays).unwrap();
    let att_ev = nip88::attestation_event(&keys, &att, "EUR", ann_ev.id).unwrap();
    (dir, oracle, ann_ev, att_ev)
}

fn tag<'a>(ev: &'a Event, name: &str) -> Vec<&'a [String]> {
    ev.tags.iter().map(|t| t.as_slice()).filter(|s| s[0] == name).collect()
}

#[tokio::test(flavor = "current_thread")]
async fn events_roundtrip_and_verify() {
    let (_d, oracle, ann_ev, att_ev) = setup().await;
    assert_eq!(ann_ev.kind, Kind::Custom(88));
    assert_eq!(att_ev.kind, Kind::Custom(89));
    // draft tags
    assert_eq!(tag(&ann_ev, "relays")[0][1..], ["wss://relay.example".to_string()]);
    assert_eq!(tag(&ann_ev, "title").len(), 1);
    assert_eq!(tag(&ann_ev, "description").len(), 1);
    let n: Vec<_> = tag(&ann_ev, "n").iter().map(|v| v[1].clone()).collect();
    assert_eq!(n, ["BTC", "EUR"]);
    assert_eq!(tag(&att_ev, "e")[0][1], ann_ev.id.to_hex());

    let ann = nip88::verify_announcement(&ann_ev).unwrap();
    assert_eq!(ann.oracle_public_key, oracle.public_key());
    let (att, value) = nip88::verify_attestation(&att_ev, &ann_ev, &ann).unwrap();
    assert_eq!(value, 54_321);
    assert_eq!(att.event_id, "btceur-2000");
}

#[tokio::test(flavor = "current_thread")]
async fn tampering_is_detected() {
    let (_d, oracle, ann_ev, att_ev) = setup().await;
    let keys = oracle.nostr_keys();
    let ann = nip88::verify_announcement(&ann_ev).unwrap();

    // Attestation from a different oracle key, properly nostr-signed, must fail:
    // clients validate against the key inside the DLC payload.
    let other = Oracle::from_signing_key(
        FileStorage::create(_d.path().join("other.json")).unwrap(),
        SecretKey::from_slice(&[3u8; 32]).unwrap(),
    )
    .unwrap();
    other
        .create_numeric_event("btceur-2000".into(), 20, false, 0, "EUR".into(), 2000)
        .await
        .unwrap();
    let forged = other.sign_numeric_event("btceur-2000".into(), 99_999).await.unwrap();
    let forged_ev = nip88::attestation_event(&keys, &forged, "EUR", ann_ev.id).unwrap();
    assert!(nip88::verify_attestation(&forged_ev, &ann_ev, &ann).is_err());

    // Wrong e tag
    let unrelated = EventBuilder::text_note("x").sign_with_keys(&keys).unwrap();
    assert!(nip88::verify_attestation(&att_ev, &unrelated, &ann).is_err());

    // Edited content breaks the nostr signature
    let mut j: serde_json::Value = serde_json::from_str(&att_ev.as_json()).unwrap();
    j["content"] = serde_json::Value::String("AAAA".into());
    let edited = Event::from_json(j.to_string()).unwrap();
    assert!(nip88::verify_attestation(&edited, &ann_ev, &ann).is_err());
}
