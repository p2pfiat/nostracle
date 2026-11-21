//! NIP-88 style DLC oracle events (draft: nostr-protocol/nips#1681, successor #2394).
//!
//! - announcement, kind 88: content = base64(dlcspecs `oracle_announcement`),
//!   tags `relays`, `title`, `description`, two `n` tags (base, quote)
//! - attestation, kind 89: content = base64(dlcspecs `oracle_attestation`),
//!   tag `e` = nostr id of the announcement event, two `n` tags
//!
//! Content bytes are the same as kormir's, so kormir-based clients keep working.
//! Per the draft, clients must validate against the oracle key *inside* the
//! DLC payload, not the nostr event key; `verify_*` below do exactly that.

use anyhow::{anyhow, bail, ensure, Context, Result};
use kormir::bitcoin::secp256k1::Secp256k1;
use kormir::{EventDescriptor, OracleAnnouncement, OracleAttestation, Readable, Writeable};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use nostr_sdk::prelude::*;

pub const KIND_ANNOUNCEMENT: u16 = 88;
pub const KIND_ATTESTATION: u16 = 89;

fn unit_of(ann: &OracleAnnouncement) -> Option<&str> {
    match &ann.oracle_event.event_descriptor {
        EventDescriptor::DigitDecompositionEvent(d) => Some(d.unit.as_str()),
        _ => None,
    }
}

fn n_tags(unit: &str) -> [Tag; 2] {
    [
        Tag::custom(TagKind::custom("n"), ["BTC"]),
        Tag::custom(TagKind::custom("n"), [unit]),
    ]
}

pub(crate) fn tag_values<'a>(ev: &'a Event, name: &str) -> Vec<&'a [String]> {
    ev.tags
        .iter()
        .map(|t| t.as_slice())
        .filter(|s| s.first().map(|k| k == name).unwrap_or(false))
        .map(|s| &s[1..])
        .collect()
}

pub fn announcement_event(
    keys: &Keys,
    ann: &OracleAnnouncement,
    relays: &[String],
) -> Result<Event> {
    let unit = unit_of(ann).ok_or_else(|| anyhow!("only numeric events supported"))?;
    let maturity = ann.oracle_event.event_maturity_epoch;
    let when = Timestamp::from(maturity as u64).to_human_datetime();
    let mut tags = vec![
        Tag::custom(TagKind::custom("relays"), relays.iter().cloned()),
        Tag::custom(TagKind::custom("title"), [format!("BTC/{unit} at {when}")]),
        Tag::custom(
            TagKind::custom("description"),
            [format!(
                "BTC price in whole {unit}, median of several exchanges, attested at \
                 maturity {maturity} (unix). Event id {}.",
                ann.oracle_event.event_id
            )],
        ),
    ];
    tags.extend(n_tags(unit));
    Ok(EventBuilder::new(Kind::Custom(KIND_ANNOUNCEMENT), B64.encode(ann.encode()))
        .tags(tags)
        .sign_with_keys(keys)?)
}

pub fn attestation_event(
    keys: &Keys,
    att: &OracleAttestation,
    unit: &str,
    announcement_id: EventId,
) -> Result<Event> {
    let mut tags = vec![Tag::event(announcement_id)];
    tags.extend(n_tags(unit));
    Ok(EventBuilder::new(Kind::Custom(KIND_ATTESTATION), B64.encode(att.encode()))
        .tags(tags)
        .sign_with_keys(keys)?)
}

/// Client-side check of a kind-88 event, as a DLC wallet would do it.
pub fn verify_announcement(ev: &Event) -> Result<OracleAnnouncement> {
    ensure!(ev.kind == Kind::Custom(KIND_ANNOUNCEMENT), "not kind 88");
    ev.verify().context("nostr signature")?;
    let bytes = B64.decode(ev.content.trim()).context("content not base64")?;
    let ann = OracleAnnouncement::read(&mut std::io::Cursor::new(bytes))
        .map_err(|e| anyhow!("decode announcement: {e:?}"))?;
    ann.validate(&Secp256k1::verification_only())
        .map_err(|e| anyhow!("announcement signature: {e:?}"))?;
    if let Some(unit) = unit_of(&ann) {
        let n: Vec<_> = tag_values(ev, "n").into_iter().filter_map(|v| v.first()).collect();
        if !n.is_empty() {
            ensure!(n.len() == 2 && n[0] == "BTC" && n[1] == unit, "n tags {n:?} != BTC/{unit}");
        }
    }
    Ok(ann)
}

/// Client-side check of a kind-89 event against its announcement.
/// Returns the attested value.
pub fn verify_attestation(
    ev: &Event,
    ann_event: &Event,
    ann: &OracleAnnouncement,
) -> Result<(OracleAttestation, i64)> {
    ensure!(ev.kind == Kind::Custom(KIND_ATTESTATION), "not kind 89");
    ev.verify().context("nostr signature")?;
    let e = tag_values(ev, "e");
    ensure!(
        e.iter().any(|v| v.first() == Some(&ann_event.id.to_hex())),
        "e tag does not reference the announcement"
    );
    let bytes = B64.decode(ev.content.trim()).context("content not base64")?;
    let att = OracleAttestation::read(&mut std::io::Cursor::new(bytes))
        .map_err(|e| anyhow!("decode attestation: {e:?}"))?;
    ensure!(att.event_id == ann.oracle_event.event_id, "event_id mismatch");
    att.validate(&Secp256k1::verification_only(), ann)
        .map_err(|e| anyhow!("attestation signatures: {e:?}"))?;
    let bits = att.outcomes.concat();
    if bits.chars().any(|c| c != '0' && c != '1') {
        bail!("unexpected outcome digits {bits}");
    }
    let value = i64::from_str_radix(&bits, 2)?;
    Ok((att, value))
}
