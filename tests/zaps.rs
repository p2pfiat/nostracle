//! Full paid flow against a real (local) nostr relay: announce, zap, attest,
//! private delivery. No public relays and no real payments.
use kormir::bitcoin::hashes::{sha256, Hash};
use kormir::bitcoin::secp256k1::{Secp256k1, SecretKey as BtcSecretKey};
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::*;
use nostracle::config::Config;
use nostracle::oracle::{attestation_is_public, Service};
use nostracle::storage::{FileStorage, PaymentStatus};
use nostracle::zaps::{self, BuyerMessage, ZapTarget};
use nostracle::{nip88, oracle};
use std::time::Duration;

fn bolt11(description: &str, msat: u64, seed: u8) -> String {
    let secp = Secp256k1::new();
    let node = BtcSecretKey::from_slice(&[42u8; 32]).unwrap();
    InvoiceBuilder::new(Currency::Bitcoin)
        .description_hash(sha256::Hash::hash(description.as_bytes()))
        .payment_hash(sha256::Hash::hash(&[seed]))
        .payment_secret(PaymentSecret([seed; 32]))
        .duration_since_epoch(Duration::from_secs(oracle::now()))
        .min_final_cltv_expiry_delta(144)
        .amount_milli_satoshis(msat)
        .build_signed(|m| secp.sign_ecdsa_recoverable(m, &node))
        .unwrap()
        .to_string()
}

fn zap_request(buyer: &Keys, oracle: PublicKey, target: Option<EventId>, comment: &str, msat: u64) -> Event {
    let mut tags = vec![
        Tag::public_key(oracle),
        Tag::custom(TagKind::custom("amount"), [msat.to_string()]),
    ];
    if let Some(id) = target {
        tags.push(Tag::event(id));
    }
    EventBuilder::new(Kind::ZapRequest, comment).tags(tags).sign_with_keys(buyer).unwrap()
}

fn receipt(zapper: &Keys, oracle: PublicKey, request: &Event, invoice: String) -> Event {
    let mut tags = vec![
        Tag::public_key(oracle),
        Tag::custom(TagKind::custom("bolt11"), [invoice]),
        Tag::custom(TagKind::custom("description"), [request.as_json()]),
    ];
    if let Some(id) = request.tags.event_ids().next() {
        tags.push(Tag::event(*id));
    }
    EventBuilder::new(Kind::ZapReceipt, "").tags(tags).sign_with_keys(zapper).unwrap()
}

fn paid(zapper: &Keys, oracle: PublicKey, buyer: &Keys, target: Option<EventId>, comment: &str, sats: u64, seed: u8) -> Event {
    let msat = sats * 1000;
    let req = zap_request(buyer, oracle, target, comment, msat);
    let inv = bolt11(&req.as_json(), msat, seed);
    receipt(zapper, oracle, &req, inv)
}

#[test]
fn receipt_checks() {
    let (zapper, oracle_k, buyer) = (Keys::generate(), Keys::generate(), Keys::generate());
    let o = oracle_k.public_key();
    let id = EventId::all_zeros();

    let ok = paid(&zapper, o, &buyer, Some(id), "", 100, 1);
    let z = zaps::verify_receipt(&ok, &zapper.public_key(), &o).unwrap();
    assert_eq!((z.sats, z.buyer, z.target), (100, buyer.public_key(), ZapTarget::Announcement(id)));

    // signed by someone other than our provider
    let forged = paid(&Keys::generate(), o, &buyer, Some(id), "", 100, 2);
    assert!(zaps::verify_receipt(&forged, &zapper.public_key(), &o).is_err());

    // for another recipient
    assert!(zaps::verify_receipt(&ok, &zapper.public_key(), &Keys::generate().public_key()).is_err());

    // a real invoice reused with a different zap request
    let req_a = zap_request(&buyer, o, Some(id), "", 100_000);
    let req_b = zap_request(&buyer, o, None, "custom USD 1900000000", 100_000);
    let reused = receipt(&zapper, o, &req_b, bolt11(&req_a.as_json(), 100_000, 3));
    assert!(zaps::verify_receipt(&reused, &zapper.public_key(), &o).is_err());

    // invoice amount differs from the zap request
    let req = zap_request(&buyer, o, Some(id), "", 100_000);
    let cheap = receipt(&zapper, o, &req, bolt11(&req.as_json(), 1_000, 4));
    assert!(zaps::verify_receipt(&cheap, &zapper.public_key(), &o).is_err());

    // plain profile zap is a tip
    let tip = paid(&zapper, o, &buyer, None, "thanks!", 21, 5);
    assert_eq!(zaps::verify_receipt(&tip, &zapper.public_key(), &o).unwrap().target, ZapTarget::Tip);
}

async fn inbox(client: &Client, buyer: &Keys, oracle: PublicKey) -> Vec<BuyerMessage> {
    let f = Filter::new().kind(Kind::GiftWrap).pubkey(buyer.public_key());
    let wraps = client.fetch_events(f, Duration::from_secs(3)).await.unwrap();
    let mut out = vec![];
    for w in wraps.iter() {
        let Ok(g) = UnwrappedGift::from_gift_wrap(buyer, w).await else { continue };
        if g.sender == oracle {
            out.push(serde_json::from_str(&g.rumor.content).unwrap());
        }
    }
    out
}

#[tokio::test(flavor = "current_thread")]
async fn paid_flow_on_local_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let (key_file, db_file) = (dir.path().join("o.key"), dir.path().join("events.json"));
    let oracle_secret = [11u8; 32];
    std::fs::write(&key_file, hex::encode(oracle_secret)).unwrap();
    FileStorage::create(&db_file).unwrap();
    let zapper = Keys::generate();
    let toml = format!(
        r#"key_file = {key:?}
db_file = {db:?}
relays = [{url:?}]
min_relay_acks = 1
pairs = ["USD"]
[[series]]
interval_secs = 86400
horizon_secs = 86400
[pricing]
attestation_sats = 100
custom_event_sats = 1000
zapper_pubkey = "{zap}"
"#,
        key = key_file.to_str().unwrap(),
        db = db_file.to_str().unwrap(),
        zap = zapper.public_key().to_hex()
    );
    let cfg: Config = toml::from_str(&toml).unwrap();
    cfg.check().unwrap();
    assert!(!attestation_is_public(&cfg, 0, u32::MAX as u64), "private by default");

    let svc = Service::new(cfg, true).await.unwrap();
    svc.tick().await.unwrap();
    let o = svc.oracle.nostr_keys().public_key();
    let st = &svc.oracle.storage;
    let ev = st.list_events().remove(0);
    let id = ev.event_id.clone();
    let ann_ev = st.nostr_record(&id).announcement.unwrap();

    let buyer = Keys::generate();
    let client = Client::new(zapper.clone());
    client.add_relay(url.as_str()).await.unwrap();
    client.connect().await;
    client.wait_for_connection(Duration::from_secs(5)).await;

    // Underpaid: rejected, nothing owed to deliver.
    client.send_event(&paid(&zapper, o, &buyer, Some(ann_ev.id), "", 99, 10)).await.unwrap();
    // Correct price, before maturity: accepted and waiting.
    let good = paid(&zapper, o, &buyer, Some(ann_ev.id), "", 100, 11);
    client.send_event(&good).await.unwrap();
    svc.tick().await.unwrap();
    let pending = |s: &FileStorage| s.payments().iter().filter(|p| p.status == PaymentStatus::Pending).count();
    assert_eq!(pending(st), 1);
    assert_eq!(st.payments().len(), 2);
    assert!(st.payments().iter().any(|p| matches!(p.status, PaymentStatus::Rejected(_))));

    // Attest (normally done at maturity), then deliver privately.
    svc.oracle.sign_numeric_event(id.clone(), 59_136).await.unwrap();
    svc.tick().await.unwrap();
    assert_eq!(pending(st), 0);

    let msgs = inbox(&client, &buyer, o).await;
    let att_json = msgs
        .iter()
        .find_map(|m| match m {
            BuyerMessage::Attestation { attestation, .. } => Some(attestation.clone()),
            _ => None,
        })
        .expect("attestation delivered");
    let att = Event::from_json(att_json).unwrap();
    let ann = nip88::verify_announcement(&ann_ev).unwrap();
    assert_eq!(nip88::verify_attestation(&att, &ann_ev, &ann).unwrap().1, 59_136);
    assert!(msgs.iter().any(|m| matches!(m, BuyerMessage::Error { .. })), "underpayment reported");

    // The attestation is NOT public.
    let public = client
        .fetch_events(Filter::new().kind(Kind::Custom(89)), Duration::from_secs(2))
        .await
        .unwrap();
    assert!(public.is_empty(), "attestation leaked to the relay");

    // Replaying the same receipt delivers nothing new.
    client.send_event(&good).await.unwrap();
    svc.tick().await.unwrap();
    assert_eq!(st.payments().len(), 2);
    assert_eq!(inbox(&client, &buyer, o).await.len(), msgs.len());

    // Custom event: created by the zap, attestation included.
    let m = oracle::now() + 5000;
    let custom = format!("custom USD {m}");
    client.send_event(&paid(&zapper, o, &buyer, None, &custom, 1000, 12)).await.unwrap();
    // Custom maturity too soon: rejected and no event created.
    let soon = format!("custom USD {}", oracle::now() + 5);
    client.send_event(&paid(&zapper, o, &buyer, None, &soon, 1000, 13)).await.unwrap();
    svc.tick().await.unwrap();
    let cid = format!("btcusd-{m}");
    assert!(st.list_events().iter().any(|e| e.event_id == cid));
    assert_eq!(st.list_events().len(), 2);
    let pub_anns = client
        .fetch_events(Filter::new().kind(Kind::Custom(88)), Duration::from_secs(2))
        .await
        .unwrap();
    assert!(pub_anns.iter().any(|e| nip88::verify_announcement(e).unwrap().oracle_event.event_id == cid));
    svc.oracle.sign_numeric_event(cid.clone(), 60_000).await.unwrap();
    svc.tick().await.unwrap();
    assert_eq!(pending(st), 0);
    assert!(inbox(&client, &buyer, o).await.iter().any(
        |x| matches!(x, BuyerMessage::Attestation { event_id, .. } if *event_id == cid)
    ));
}
