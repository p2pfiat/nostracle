use kormir::bitcoin::secp256k1::SecretKey;
use kormir::storage::Storage;
use kormir::Oracle;
use nostracle::storage::FileStorage;

fn key() -> SecretKey {
    SecretKey::from_slice(&[7u8; 32]).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn announce_attest_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.json");

    {
        let oracle = Oracle::from_signing_key(FileStorage::open(&db).unwrap(), key()).unwrap();
        let ann = oracle
            .create_numeric_event("btcusd-1000".into(), 20, false, 0, "USD".into(), 1000)
            .await
            .unwrap();
        assert_eq!(ann.oracle_event.oracle_nonces.len(), 20);
        ann.validate(&kormir::bitcoin::secp256k1::Secp256k1::new()).unwrap();

        let att = oracle.sign_numeric_event("btcusd-1000".into(), 97_123).await.unwrap();
        assert_eq!(att.signatures.len(), 20);
        // Each signature commits to the announced nonce (R = first 32 bytes).
        for (sig, nonce) in att.signatures.iter().zip(&ann.oracle_event.oracle_nonces) {
            assert_eq!(&sig.as_ref()[..32], &nonce.serialize()[..]);
        }
        // binary digits of 97123, most significant first
        let bits: String = att.outcomes.concat();
        assert_eq!(u64::from_str_radix(&bits, 2).unwrap(), 97_123);
    }

    // Reopen from disk: state is persisted.
    let storage = FileStorage::open(&db).unwrap();
    let next = storage.get_next_nonce_indexes(1).await.unwrap();
    assert_eq!(next, vec![20], "nonce counter must survive restart");

    let oracle = Oracle::from_signing_key(storage, key()).unwrap();
    let err = oracle.sign_numeric_event("btcusd-1000".into(), 1).await.unwrap_err();
    assert!(matches!(err, kormir::error::Error::EventAlreadySigned));

    // Re-announcing the same event id is refused (would burn fresh nonces under an existing id).
    assert!(oracle
        .create_numeric_event("btcusd-1000".into(), 20, false, 0, "USD".into(), 1000)
        .await
        .is_err());
}
