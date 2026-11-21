//! Paid attestations over NIP-57 zaps.
//!
//! A buyer zaps a kind-88 announcement (one attestation) or the oracle's profile
//! with `custom <USD|EUR> <unix maturity>` as the zap comment (a custom event).
//! The buyer's Lightning address provider publishes a kind-9735 receipt; the
//! oracle checks it and delivers the attestation by NIP-17 private message.

use crate::nip88::tag_values;
use crate::price::Fiat;
use anyhow::{anyhow, bail, ensure, Context, Result};
use kormir::bitcoin::hashes::{sha256, Hash};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// What a verified zap pays for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZapTarget {
    Announcement(EventId),
    Custom { fiat: Fiat, maturity: u32 },
    /// A profile zap without an order: a donation.
    Tip,
}

#[derive(Debug, Clone)]
pub struct VerifiedZap {
    pub payment_hash: String,
    pub buyer: PublicKey,
    pub sats: u64,
    pub target: ZapTarget,
}

/// Messages the oracle sends to buyers, as JSON in NIP-17 private messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BuyerMessage {
    /// Payment accepted; the attestation follows at maturity.
    Paid { event_id: String, announcement_id: String, maturity: u32 },
    /// `attestation` is the signed kind-89 event as JSON. It is not public.
    Attestation { event_id: String, announcement_id: String, attestation: String },
    Error { payment_hash: String, message: String },
}

pub fn parse_custom(comment: &str) -> Option<(Fiat, u32)> {
    let mut parts = comment.split_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("custom") {
        return None;
    }
    let fiat = match parts.next()?.to_ascii_uppercase().as_str() {
        "USD" => Fiat::Usd,
        "EUR" => Fiat::Eur,
        _ => return None,
    };
    let maturity = parts.next()?.parse().ok()?;
    parts.next().is_none().then_some((fiat, maturity))
}

fn single<'a>(ev: &'a Event, name: &str) -> Result<&'a str> {
    let v = tag_values(ev, name);
    ensure!(v.len() == 1, "expected one {name} tag, found {}", v.len());
    v[0].first().map(String::as_str).ok_or_else(|| anyhow!("empty {name} tag"))
}

/// Full NIP-57 receipt check. `zapper` is the `nostrPubkey` of the oracle's
/// Lightning address provider: only it can attest that an invoice was paid.
pub fn verify_receipt(receipt: &Event, zapper: &PublicKey, oracle: &PublicKey) -> Result<VerifiedZap> {
    ensure!(receipt.kind == Kind::ZapReceipt, "not a zap receipt");
    ensure!(receipt.pubkey == *zapper, "receipt not signed by our zap provider");
    receipt.verify().context("receipt signature")?;
    ensure!(single(receipt, "p")? == oracle.to_hex(), "receipt is for another recipient");

    let description = single(receipt, "description")?;
    let request = Event::from_json(description).context("zap request")?;
    ensure!(request.kind == Kind::ZapRequest, "description is not a zap request");
    request.verify().context("zap request signature")?;
    ensure!(single(&request, "p")? == oracle.to_hex(), "zap request is for another recipient");

    let invoice = Bolt11Invoice::from_str(single(receipt, "bolt11")?)
        .map_err(|e| anyhow!("bad bolt11: {e}"))?;
    let Bolt11InvoiceDescriptionRef::Hash(hash) = invoice.description() else {
        bail!("invoice has no description hash");
    };
    ensure!(
        hash.0 == sha256::Hash::hash(description.as_bytes()),
        "invoice is not bound to this zap request"
    );
    let msat = invoice.amount_milli_satoshis().ok_or_else(|| anyhow!("invoice has no amount"))?;
    if let Some(a) = tag_values(&request, "amount").first().and_then(|v| v.first()) {
        ensure!(a.parse::<u64>().ok() == Some(msat), "amount differs from zap request");
    }

    let e = tag_values(&request, "e");
    ensure!(e.len() <= 1, "zap request has several e tags");
    let target = match e.first().and_then(|v| v.first()) {
        Some(id) => {
            let id = EventId::from_hex(id).context("bad e tag")?;
            if let Some(r) = tag_values(receipt, "e").first().and_then(|v| v.first()) {
                ensure!(*r == id.to_hex(), "receipt and request e tags differ");
            }
            ZapTarget::Announcement(id)
        }
        None => match parse_custom(&request.content) {
            Some((fiat, maturity)) => ZapTarget::Custom { fiat, maturity },
            None => ZapTarget::Tip,
        },
    };
    Ok(VerifiedZap {
        payment_hash: invoice.payment_hash().to_string(),
        buyer: request.pubkey,
        sats: msat / 1000,
        target,
    })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LnurlPay {
    pub callback: String,
    pub min_sendable: u64,
    pub max_sendable: u64,
    #[serde(default)]
    pub allows_nostr: bool,
    pub nostr_pubkey: Option<String>,
}

/// Look up a Lightning address (LUD-16).
pub async fn resolve_lud16(http: &reqwest::Client, address: &str) -> Result<LnurlPay> {
    let (name, domain) = address
        .split_once('@')
        .ok_or_else(|| anyhow!("{address} is not a Lightning address"))?;
    let url = format!("https://{domain}/.well-known/lnurlp/{name}");
    let pay: LnurlPay = http
        .get(url)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("LNURL response")?;
    ensure!(pay.allows_nostr, "{address} does not support zaps");
    Ok(pay)
}

/// The key that signs zap receipts for this Lightning address.
pub async fn resolve_zapper(http: &reqwest::Client, address: &str) -> Result<PublicKey> {
    let pay = resolve_lud16(http, address).await?;
    let pk = pay.nostr_pubkey.ok_or_else(|| anyhow!("{address} has no nostrPubkey"))?;
    Ok(PublicKey::parse(&pk)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_comment() {
        assert_eq!(parse_custom("custom USD 1798000000"), Some((Fiat::Usd, 1_798_000_000)));
        assert_eq!(parse_custom("CUSTOM eur 5"), Some((Fiat::Eur, 5)));
        assert_eq!(parse_custom("thanks!"), None);
        assert_eq!(parse_custom("custom GBP 5"), None);
        assert_eq!(parse_custom("custom USD 5 extra"), None);
        assert_eq!(parse_custom("custom USD 99999999999"), None);
    }
}
