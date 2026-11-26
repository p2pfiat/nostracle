//! On-Demand BIP-342 Dispute signing for long-term Arkade DLC contracts (Leaf 3).
//!
//! When a counterparty goes offline mid-term (e.g. day 5 of a 30-day contract) or BTC drops
//! >= 50% (early liquidation), a user or Watchtower submits a `DisputeRequest` containing the
//! BIP-342 Tapscript sighash of the payout tx. Each oracle in the `k-of-n` quorum independently:
//! 1. Verifies the dispute fee (`fee_paid_sats >= min_fee_sats`),
//! 2. Computes the fair payout at the live aggregated spot price (including pro-rata yield/funding),
//! 3. Signs the 32-byte BIP-342 sighash with its BIP-340 Schnorr key.

use anyhow::{bail, Context, Result};
use kormir::bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

const DUST_SATS: u64 = 350;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeRequest {
    pub contract_id: String,
    pub currency: String,
    /// `"short"` (Stable USD/EUR) or `"long"` (2x Long BTC).
    #[serde(default = "default_side")]
    pub side: String,
    pub total_collateral_sats: u64,
    pub notional_fiat: f64,
    pub opened_at: u64,
    pub dispute_timestamp: u64,
    pub funding_rate_bps_per_day: f64,
    pub bounty_sats: u64,
    pub fee_paid_sats: u64,
    /// 32-byte BIP-342 Tapscript sighash (64 hex chars).
    pub sighash_hex: String,
}

fn default_side() -> String {
    "short".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeResponse {
    pub contract_id: String,
    pub oracle_pubkey_hex: String,
    pub currency: String,
    pub live_spot_price: f64,
    pub user_payout_sats: u64,
    pub lp_payout_sats: u64,
    pub bounty_sats: u64,
    pub accrued_fiat: f64,
    pub sighash_hex: String,
    /// 64-byte BIP-340 Schnorr signature (128 hex chars) over `sighash_hex`.
    pub signature_hex: String,
}

fn compute_fiat_payout_sats(target_fiat: f64, spot_price: f64, distributable: u64) -> u64 {
    let raw = ((target_fiat.max(0.01) / spot_price) * 1e8).round() as u64;
    let max_out = distributable.saturating_sub(DUST_SATS);
    raw.clamp(DUST_SATS, max_out.max(DUST_SATS))
}

/// Independently compute fair `(user_payout_sats, lp_payout_sats, accrued_fiat)` at `live_spot_price`.
pub fn compute_dispute_payouts(req: &DisputeRequest, live_spot_price: f64) -> Result<(u64, u64, f64)> {
    if !live_spot_price.is_finite() || live_spot_price <= 0.0 {
        bail!("live_spot_price must be > 0");
    }
    if req.dispute_timestamp < req.opened_at {
        bail!("dispute_timestamp precedes opened_at");
    }
    if req.total_collateral_sats < req.bounty_sats + DUST_SATS * 2 {
        bail!("total_collateral_sats too small after watchtower bounty");
    }
    let distributable = req.total_collateral_sats - req.bounty_sats;
    let elapsed_secs = (req.dispute_timestamp - req.opened_at) as f64;
    let accrued_fiat = req.notional_fiat * (req.funding_rate_bps_per_day / 10_000.0) * (elapsed_secs / 86_400.0);

    let (user_sats, lp_sats) = if req.side.eq_ignore_ascii_case("long") {
        let lp_target = (req.notional_fiat - accrued_fiat).max(0.01);
        let lp = compute_fiat_payout_sats(lp_target, live_spot_price, distributable);
        (distributable - lp, lp)
    } else {
        let user_target = (req.notional_fiat + accrued_fiat).max(0.01);
        let user = compute_fiat_payout_sats(user_target, live_spot_price, distributable);
        (user, distributable - user)
    };
    Ok((user_sats, lp_sats, accrued_fiat))
}

/// Verify fee payment and sign an On-Demand BIP-342 Dispute sighash with BIP-340 Schnorr.
pub fn evaluate_and_sign_dispute(
    oracle_sk: &SecretKey,
    req: &DisputeRequest,
    live_spot_price: f64,
    min_fee_sats: u64,
) -> Result<DisputeResponse> {
    if req.fee_paid_sats < min_fee_sats {
        bail!(
            "dispute fee too low: paid {} sats, minimum {} sats",
            req.fee_paid_sats,
            min_fee_sats
        );
    }
    let sighash_bytes = hex::decode(req.sighash_hex.trim()).context("invalid sighash_hex")?;
    if sighash_bytes.len() != 32 {
        bail!("sighash_hex must be 32 bytes, got {}", sighash_bytes.len());
    }
    let (user_payout_sats, lp_payout_sats, accrued_fiat) =
        compute_dispute_payouts(req, live_spot_price)?;

    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, oracle_sk);
    let (xonly, _) = kp.x_only_public_key();
    let msg = Message::from_digest_slice(&sighash_bytes).context("invalid 32-byte digest")?;
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
    secp.verify_schnorr(&sig, &msg, &xonly)
        .context("self-verification of BIP-340 dispute signature failed")?;

    Ok(DisputeResponse {
        contract_id: req.contract_id.clone(),
        oracle_pubkey_hex: hex::encode(xonly.serialize()),
        currency: req.currency.to_uppercase(),
        live_spot_price,
        user_payout_sats,
        lp_payout_sats,
        bounty_sats: req.bounty_sats,
        accrued_fiat,
        sighash_hex: req.sighash_hex.trim().to_lowercase(),
        signature_hex: hex::encode(sig.as_ref()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sk() -> SecretKey {
        SecretKey::from_slice(&[0x22; 32]).unwrap()
    }

    fn base_req() -> DisputeRequest {
        DisputeRequest {
            contract_id: "pos-demo-1".into(),
            currency: "USD".into(),
            side: "short".into(),
            total_collateral_sats: 333_334,
            notional_fiat: 100.0,
            opened_at: 1_795_000_000,
            dispute_timestamp: 1_795_000_000 + 5 * 86_400,
            funding_rate_bps_per_day: 3.0,
            bounty_sats: 600,
            fee_paid_sats: 150,
            sighash_hex: "ab".repeat(32),
        }
    }

    #[test]
    fn signs_mid_term_anytime_exit() {
        let sk = test_sk();
        let req = base_req();
        let res = evaluate_and_sign_dispute(&sk, &req, 72_000.0, 100).unwrap();
        let user_usd = (res.user_payout_sats as f64 / 1e8) * 72_000.0;
        assert!((user_usd - 100.15).abs() < 0.05, "got {user_usd}");
        assert_eq!(res.signature_hex.len(), 128);
    }

    #[test]
    fn early_liquidation_pays_full_pool_to_stable() {
        let sk = test_sk();
        let req = base_req();
        let res = evaluate_and_sign_dispute(&sk, &req, 27_000.0, 100).unwrap();
        assert_eq!(res.user_payout_sats, 333_334 - 600 - DUST_SATS);
        assert_eq!(res.lp_payout_sats, DUST_SATS);
    }

    #[test]
    fn supports_2x_long_side() {
        let sk = test_sk();
        let mut req = base_req();
        req.side = "long".into();
        req.funding_rate_bps_per_day = -3.0;
        let res = evaluate_and_sign_dispute(&sk, &req, 72_000.0, 100).unwrap();
        // BTC +20% -> 2x Long user gets ~$140 minus bounty & small funding
        let user_usd = (res.user_payout_sats as f64 / 1e8) * 72_000.0;
        assert!(user_usd > 138.5 && user_usd < 140.5, "got {user_usd}");
    }

    #[test]
    fn rejects_underpaid_dispute_fee() {
        let sk = test_sk();
        let mut req = base_req();
        req.fee_paid_sats = 50;
        assert!(evaluate_and_sign_dispute(&sk, &req, 72_000.0, 100).is_err());
    }
}
