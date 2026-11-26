//! Human- and machine-readable Nostr social price posts (`kind: 1`).
//!
//! Publishes attested (or live) BTC/fiat and inverse fiat/BTC rates to the
//! oracle's public Nostr social feed so anyone following its `npub` in Primal,
//! Damus, Amethyst, or `njump.me` can audit its price history directly.

use crate::config::SocialFeed;
use crate::price::Fiat;
use anyhow::{bail, Result};
use kormir::OracleAttestation;
use nostr_sdk::prelude::*;

/// Decode the unsigned integer price from a kormir binary digit-decomposition attestation.
pub fn decode_attested_price(att: &OracleAttestation) -> Result<u64> {
    let bits = att.outcomes.concat();
    if bits.is_empty() || bits.chars().any(|c| c != '0' && c != '1') {
        bail!("unexpected outcome digits {bits:?}");
    }
    Ok(u64::from_str_radix(&bits, 2)?)
}

/// Build and sign a Nostr `kind: 1` text note for `fiat` at `price_fiat` (whole fiat units per BTC).
///
/// Includes both `BTC/<FIAT>` and (when `cfg.include_inverse` is true) the inverse
/// `<FIAT>/BTC` rate + sats per fiat unit, plus structured tags (`t`, `pair`,
/// `inverse_pair`, `price`, `unit`, `sats_per_unit`, and optional `e` mention of
/// the NIP-88 kind-89 attestation).
pub fn price_note(
    keys: &Keys,
    fiat: Fiat,
    price_fiat: u64,
    event_id: Option<&str>,
    cfg: &SocialFeed,
    attestation_event_id: Option<EventId>,
) -> Result<Event> {
    let code = fiat.code();
    let pair_slash = format!("BTC/{code}");
    let pair_tag = fiat.pair(); // e.g. "btcusd"
    let pair_upper = pair_tag.to_uppercase(); // e.g. "BTCUSD"

    let inv_slash = format!("{code}/BTC");
    let inv_tag = fiat.inverse_pair(); // e.g. "usdbtc"
    let inv_upper = inv_tag.to_uppercase(); // e.g. "USDBTC"

    let sats_per_unit = if price_fiat > 0 {
        (100_000_000.0 / price_fiat as f64).round() as u64
    } else {
        0
    };
    let btc_per_unit = if price_fiat > 0 {
        1.0 / price_fiat as f64
    } else {
        0.0
    };

    let mut lines = vec![format!("{pair_slash}: {price_fiat} {code}")];
    if cfg.include_inverse && price_fiat > 0 {
        lines.push(format!(
            "{inv_slash}: {btc_per_unit:.8} BTC ({sats_per_unit} sats/{code})"
        ));
    }
    if let Some(ev_id) = event_id {
        lines.push(format!("Event: {ev_id}"));
    }

    let mut hash_tokens = vec![format!("#{pair_upper}")];
    if cfg.include_inverse {
        hash_tokens.push(format!("#{inv_upper}"));
    }
    for h in &cfg.hashtags {
        let clean = h.trim().trim_start_matches('#');
        if !clean.is_empty() {
            hash_tokens.push(format!("#{clean}"));
        }
    }
    let mut mention_pks: Vec<(PublicKey, String)> = Vec::new();
    for m in &cfg.mentions {
        let stripped = m.trim().trim_start_matches("nostr:");
        if let Ok(pk) = PublicKey::parse(stripped) {
            let Ok(npub) = pk.to_bech32();
            hash_tokens.push(format!("nostr:{npub}"));
            mention_pks.push((pk, npub));
        }
    }
    lines.push(hash_tokens.join(" "));
    let content = lines.join("\n");

    let mut tags = vec![
        Tag::hashtag(pair_tag),
        Tag::custom(TagKind::custom("pair"), [pair_slash]),
        Tag::custom(TagKind::custom("price"), [price_fiat.to_string()]),
        Tag::custom(TagKind::custom("unit"), [code]),
    ];
    if cfg.include_inverse {
        tags.push(Tag::hashtag(inv_tag));
        tags.push(Tag::custom(TagKind::custom("inverse_pair"), [inv_slash]));
        if price_fiat > 0 {
            tags.push(Tag::custom(
                TagKind::custom("sats_per_unit"),
                [sats_per_unit.to_string()],
            ));
        }
    }
    for h in &cfg.hashtags {
        let clean = h.trim().trim_start_matches('#').to_lowercase();
        if !clean.is_empty() {
            tags.push(Tag::hashtag(clean));
        }
    }
    for (pk, _) in mention_pks {
        tags.push(Tag::public_key(pk));
    }
    if let Some(ev_id) = event_id {
        tags.push(Tag::custom(TagKind::custom("event_id"), [ev_id]));
    }
    if let Some(att_id) = attestation_event_id {
        tags.push(Tag::custom(
            TagKind::e(),
            [att_id.to_hex(), String::new(), "mention".to_string()],
        ));
    }

    Ok(EventBuilder::text_note(content).tags(tags).sign_with_keys(keys)?)
}
