//! On-Demand BIP-342 Dispute signing for long-term Arkade DLC contracts (Leaf 2).
//!
//! When a counterparty goes offline mid-term (e.g. day 5 of a 30-day contract) or BTC drops
//! >= 50% (early liquidation), a user or Watchtower submits a `DisputeRequest` containing:
//! - A **2-party signed Contract Manifest** (`user_manifest_sig_hex` + `lp_manifest_sig_hex`)
//!   binding the immutable contract terms (`vtxo_outpoint`, `notional`, `funding_bps`, `opened_at`,
//!   `user_payout_script`, `lp_payout_script`, `vtxo_pk_script`, `dispute_script`) to both
//!   `user_pubkey` and `lp_pubkey` via BIP-340 Schnorr signatures.
//! - The full unsigned Bitcoin payout transaction (`raw_tx_hex`).
//!
//! Each oracle in the `k-of-n` quorum independently:
//! 1. Verifies the dispute fee (`fee_paid_sats >= min_fee_sats`),
//! 2. Verifies BOTH BIP-340 Schnorr signatures (`user_manifest_sig` & `lp_manifest_sig`) over
//!    the canonical tagged hash `SHA256(tag||tag||canonical_manifest)`, preventing address spoofing
//!    or terms forgery by either party or a Watchtower,
//! 3. Deserializes `raw_tx_hex` and verifies input outpoint + exact payout scriptPubKeys,
//! 4. Verifies payout amounts fall within the ±1% volatility band around the oracle's own live
//!    aggregated spot price with exact collateral conservation,
//! 5. Independently computes the BIP-341/BIP-342 Tapscript sighash (`SIGHASH_DEFAULT`, leaf 0xc0)
//!    and signs ONLY that computed sighash with its BIP-340 Schnorr key.

use anyhow::{bail, ensure, Context, Result};
use kormir::bitcoin::consensus::deserialize;
use kormir::bitcoin::hashes::{sha256, Hash};
use kormir::bitcoin::secp256k1::schnorr::Signature as SchnorrSig;
use kormir::bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use kormir::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use kormir::bitcoin::taproot::{LeafVersion, TapLeafHash};
use kormir::bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

const DUST_SATS: u64 = 350;
const PAYOUT_TOLERANCE_SATS: u64 = 1;
/// Maximum allowed L1 miner fee (5,000 sats) deducted from the contract pool for a Leaf 2
/// dispute transaction so it passes Bitcoin L1 mempool relay without enabling fee-burn griefing.
const MAX_MINER_FEE_SATS: u64 = 5_000;
/// Maximum allowed spot price drift (±1%) between the client's tx build time and each
/// oracle's live tick so a k-of-n quorum can still converge on one tx during volatile crashes
/// while rejecting any meaningful theft attempt.
const MAX_SPOT_DRIFT_RATIO: f64 = 0.01;
const MANIFEST_TAG: &[u8] = b"p2pfiat/dispute-manifest/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeRequest {
    pub contract_id: String,
    /// Spent DLC VTXO outpoint (`<txid>:<vout>`).
    pub vtxo_outpoint: String,
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
    /// Optional Bitcoin L1 miner fee (0..=5000 sats) left as `inputs - outputs` for mempool relay.
    #[serde(default)]
    pub miner_fee_sats: u64,
    pub fee_paid_sats: u64,
    /// User x-only secp256k1 public key (64 hex chars).
    pub user_pubkey_hex: String,
    /// LP x-only secp256k1 public key (64 hex chars).
    pub lp_pubkey_hex: String,
    /// User BIP-340 Schnorr signature (128 hex chars) over the canonical Contract Manifest hash.
    pub user_manifest_sig_hex: String,
    /// LP BIP-340 Schnorr signature (128 hex chars) over the canonical Contract Manifest hash.
    pub lp_manifest_sig_hex: String,
    /// Full unsigned consensus-serialized Bitcoin payout transaction (hex).
    pub raw_tx_hex: String,
    /// Spent DLC VTXO P2TR `scriptPubKey` (hex).
    pub vtxo_pk_script_hex: String,
    /// BIP-342 Leaf 2 Tapscript (`<csv> OP_CSV OP_DROP <O1> OP_CHECKSIG ... <k> OP_GREATERTHANOREQUAL`).
    pub dispute_script_hex: String,
    /// Contract-bound User payout `scriptPubKey` (hex).
    pub user_payout_script_hex: String,
    /// Contract-bound LP payout `scriptPubKey` (hex).
    pub lp_payout_script_hex: String,
    /// Optional client-computed 32-byte BIP-342 sighash (64 hex chars); if present, must
    /// match the oracle's independently computed sighash byte-for-byte.
    #[serde(default)]
    pub sighash_hex: Option<String>,
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

/// Compute the deterministic BIP-340 tagged hash (`p2pfiat/dispute-manifest/v1`) binding
/// all immutable contract terms and payout scripts so neither party can spoof outputs.
pub fn compute_manifest_hash(req: &DisputeRequest) -> [u8; 32] {
    let notional_cents = (req.notional_fiat * 100.0).round() as i64;
    let funding_bps_x100 = (req.funding_rate_bps_per_day * 100.0).round() as i64;
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        req.contract_id.trim(),
        req.vtxo_outpoint.trim().to_lowercase(),
        req.currency.trim().to_uppercase(),
        req.side.trim().to_lowercase(),
        req.total_collateral_sats,
        notional_cents,
        req.opened_at,
        funding_bps_x100,
        req.user_pubkey_hex.trim().to_lowercase(),
        req.lp_pubkey_hex.trim().to_lowercase(),
        req.vtxo_pk_script_hex.trim().to_lowercase(),
        req.dispute_script_hex.trim().to_lowercase(),
        req.user_payout_script_hex.trim().to_lowercase(),
        req.lp_payout_script_hex.trim().to_lowercase(),
    );
    let tag_hash = sha256::Hash::hash(MANIFEST_TAG);
    let mut preimage = Vec::with_capacity(64 + canonical.len());
    preimage.extend_from_slice(tag_hash.as_byte_array());
    preimage.extend_from_slice(tag_hash.as_byte_array());
    preimage.extend_from_slice(canonical.as_bytes());
    sha256::Hash::hash(&preimage).to_byte_array()
}

fn verify_manifest_signatures(req: &DisputeRequest) -> Result<()> {
    let secp = Secp256k1::verification_only();
    let hash = compute_manifest_hash(req);
    let msg = Message::from_digest(hash);

    let user_pk_bytes = hex::decode(req.user_pubkey_hex.trim()).context("invalid user_pubkey_hex")?;
    let user_pk = XOnlyPublicKey::from_slice(&user_pk_bytes).context("invalid user x-only pubkey")?;
    let user_sig_bytes =
        hex::decode(req.user_manifest_sig_hex.trim()).context("invalid user_manifest_sig_hex")?;
    let user_sig = SchnorrSig::from_slice(&user_sig_bytes).context("invalid user manifest sig")?;
    secp.verify_schnorr(&user_sig, &msg, &user_pk)
        .context("user_manifest_sig verification failed — contract terms or payout scripts tampered")?;

    let lp_pk_bytes = hex::decode(req.lp_pubkey_hex.trim()).context("invalid lp_pubkey_hex")?;
    let lp_pk = XOnlyPublicKey::from_slice(&lp_pk_bytes).context("invalid lp x-only pubkey")?;
    let lp_sig_bytes =
        hex::decode(req.lp_manifest_sig_hex.trim()).context("invalid lp_manifest_sig_hex")?;
    let lp_sig = SchnorrSig::from_slice(&lp_sig_bytes).context("invalid lp manifest sig")?;
    secp.verify_schnorr(&lp_sig, &msg, &lp_pk)
        .context("lp_manifest_sig verification failed — contract terms or payout scripts tampered")?;

    Ok(())
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
    if req.miner_fee_sats > MAX_MINER_FEE_SATS {
        bail!(
            "miner_fee_sats {} exceeds maximum allowed {}",
            req.miner_fee_sats,
            MAX_MINER_FEE_SATS
        );
    }
    if req.total_collateral_sats < req.bounty_sats + req.miner_fee_sats + DUST_SATS * 2 {
        bail!("total_collateral_sats too small after watchtower bounty and miner fee");
    }
    let distributable = req.total_collateral_sats - req.bounty_sats - req.miner_fee_sats;
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

/// Independently verify the 2-party signed Contract Manifest, verify tx outputs against
/// the live fair payout (±1% volatility band), recompute the BIP-342 Tapscript sighash,
/// and sign with BIP-340 Schnorr.
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

    // 1. Cryptographically verify BOTH User and LP signed the exact contract manifest
    verify_manifest_signatures(req)?;

    let (expected_user, _expected_lp, accrued_fiat) =
        compute_dispute_payouts(req, live_spot_price)?;

    // 2. Deserialize and validate the Bitcoin transaction structure & spent outpoint
    let raw_tx_bytes = hex::decode(req.raw_tx_hex.trim()).context("invalid raw_tx_hex")?;
    let tx: Transaction =
        deserialize(&raw_tx_bytes).context("failed to deserialize Bitcoin dispute transaction")?;
    ensure!(
        tx.input.len() == 1,
        "dispute tx must have exactly 1 input (got {})",
        tx.input.len()
    );
    let expected_outpoint = OutPoint::from_str(req.vtxo_outpoint.trim())
        .context("invalid vtxo_outpoint (expected txid:vout)")?;
    ensure!(
        tx.input[0].previous_output == expected_outpoint,
        "input[0] outpoint {} does not match signed manifest vtxo_outpoint {}",
        tx.input[0].previous_output,
        expected_outpoint
    );
    let expected_outs = if req.bounty_sats > 0 { 3 } else { 2 };
    ensure!(
        tx.output.len() == expected_outs,
        "dispute tx must have exactly {expected_outs} outputs (got {})",
        tx.output.len()
    );

    // 3. Verify output amounts fall within the ±1% volatility band around `live_spot_price`
    //    and preserve exact collateral conservation (no hidden fee burn or theft).
    let (user_lo, _, _) = compute_dispute_payouts(req, live_spot_price * (1.0 - MAX_SPOT_DRIFT_RATIO))?;
    let (user_hi, _, _) = compute_dispute_payouts(req, live_spot_price * (1.0 + MAX_SPOT_DRIFT_RATIO))?;
    let min_user = user_lo.min(user_hi).saturating_sub(PAYOUT_TOLERANCE_SATS);
    let max_user = user_lo.max(user_hi).saturating_add(PAYOUT_TOLERANCE_SATS);

    let actual_user = tx.output[0].value.to_sat();
    let actual_lp = tx.output[1].value.to_sat();
    ensure!(
        actual_user >= min_user && actual_user <= max_user,
        "output[0] user payout mismatch: tx has {actual_user} sats, fair band is [{min_user}..={max_user}] (center {expected_user}) at spot {live_spot_price:.2}"
    );
    if req.bounty_sats > 0 {
        let actual_bounty = tx.output[2].value.to_sat();
        ensure!(
            actual_bounty == req.bounty_sats,
            "output[2] watchtower bounty mismatch: tx has {actual_bounty} sats, expected {} sats",
            req.bounty_sats
        );
    }
    ensure!(
        actual_user + actual_lp + req.bounty_sats + req.miner_fee_sats == req.total_collateral_sats,
        "dispute tx outputs + miner_fee ({}) must exactly equal total_collateral_sats ({})",
        actual_user + actual_lp + req.bounty_sats + req.miner_fee_sats,
        req.total_collateral_sats
    );

    // 4. Enforce exact match between tx output scripts and the 2-party signed manifest scripts
    let u_bytes =
        hex::decode(req.user_payout_script_hex.trim()).context("invalid user_payout_script_hex")?;
    let l_bytes =
        hex::decode(req.lp_payout_script_hex.trim()).context("invalid lp_payout_script_hex")?;
    ensure!(!u_bytes.is_empty() && !l_bytes.is_empty(), "payout scripts must be non-empty");
    ensure!(
        tx.output[0].script_pubkey.as_bytes() == u_bytes.as_slice(),
        "output[0] script_pubkey does not match manifest user_payout_script_hex"
    );
    ensure!(
        tx.output[1].script_pubkey.as_bytes() == l_bytes.as_slice(),
        "output[1] script_pubkey does not match manifest lp_payout_script_hex"
    );

    // 5. Independently compute the BIP-341 / BIP-342 Tapscript sighash (SIGHASH_DEFAULT, leaf 0xc0)
    let vtxo_pk_bytes =
        hex::decode(req.vtxo_pk_script_hex.trim()).context("invalid vtxo_pk_script_hex")?;
    let dispute_script_bytes =
        hex::decode(req.dispute_script_hex.trim()).context("invalid dispute_script_hex")?;
    ensure!(!vtxo_pk_bytes.is_empty(), "vtxo_pk_script_hex must be non-empty");
    ensure!(!dispute_script_bytes.is_empty(), "dispute_script_hex must be non-empty");

    let prevout = TxOut {
        value: Amount::from_sat(req.total_collateral_sats),
        script_pubkey: ScriptBuf::from_bytes(vtxo_pk_bytes),
    };
    let dispute_script = ScriptBuf::from_bytes(dispute_script_bytes);
    let leaf_hash = TapLeafHash::from_script(&dispute_script, LeafVersion::TapScript);

    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::Default,
        )
        .context("failed to compute BIP-342 tapscript sighash")?;
    let sighash_bytes: [u8; 32] = sighash.to_byte_array();
    let computed_sighash_hex = hex::encode(sighash_bytes);

    if let Some(claimed) = &req.sighash_hex {
        let trimmed = claimed.trim().to_lowercase();
        if !trimmed.is_empty() {
            ensure!(
                trimmed == computed_sighash_hex,
                "sighash mismatch: client claimed {trimmed}, oracle computed {computed_sighash_hex}"
            );
        }
    }

    // 6. Sign ONLY the oracle-computed BIP-342 sighash with BIP-340 Schnorr
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, oracle_sk);
    let (xonly, _) = kp.x_only_public_key();
    let msg = Message::from_digest(sighash_bytes);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
    secp.verify_schnorr(&sig, &msg, &xonly)
        .context("self-verification of BIP-340 dispute signature failed")?;

    Ok(DisputeResponse {
        contract_id: req.contract_id.clone(),
        oracle_pubkey_hex: hex::encode(xonly.serialize()),
        currency: req.currency.to_uppercase(),
        live_spot_price,
        user_payout_sats: actual_user,
        lp_payout_sats: actual_lp,
        bounty_sats: req.bounty_sats,
        accrued_fiat,
        sighash_hex: computed_sighash_hex,
        signature_hex: hex::encode(sig.as_ref()),
    })
}

/// NIP-17 RPC envelope compatible with p2pFiat's `Nip17Peer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeRpcRequest {
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(rename = "reqId")]
    pub req_id: String,
    pub method: String,
    pub params: DisputeRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeRpcResponse {
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(rename = "reqId")]
    pub req_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<DisputeResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Try to parse a NIP-17 rumor content string as a `sign_dispute` RPC request.
/// Returns `None` for unrelated DMs so other NIP-17 traffic is ignored cleanly.
pub fn parse_dispute_rpc(content: &str) -> Option<DisputeRpcRequest> {
    let v: serde_json::Value = serde_json::from_str(content).ok()?;
    if v.get("type")?.as_str()? != "p2pfiat-rpc-req" {
        return None;
    }
    if v.get("method")?.as_str()? != "sign_dispute" {
        return None;
    }
    serde_json::from_value(v).ok()
}

/// Evaluate & sign a Leaf 2 dispute with a persistent 1-signature-per-`vtxo_outpoint` lock.
///
/// Security invariants:
/// - Verifies BOTH User and LP manifest signatures *before* checking/recording the lock
///   (so an unauthenticated attacker cannot DoS-lock a legitimate contract's outpoint).
/// - If `vtxo_outpoint` was already signed:
///   - Idempotently returns the cached `DisputeResponse` if the requested `sighash_hex` matches
///     (safe against Nostr relay retries / duplicate delivery).
///   - Rejects any request for a *different* transaction/sighash (eliminates the free-option
///     / cherry-picking attack across multiple timestamps or spot prices).
pub fn evaluate_and_sign_dispute_locked(
    oracle_sk: &SecretKey,
    req: &DisputeRequest,
    live_spot_price: f64,
    min_fee_sats: u64,
    storage: &crate::storage::FileStorage,
) -> Result<DisputeResponse> {
    // 1. Always verify 2-party manifest first so forged requests cannot touch the lock table
    verify_manifest_signatures(req)?;

    // 2. Check existing single-sign lock for this vtxo_outpoint
    if let Some(existing) = storage.get_dispute_lock(&req.vtxo_outpoint) {
        let requested_sh = match req.sighash_hex.as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => s.to_lowercase(),
            _ => {
                // Compute BIP-342 sighash from raw_tx_hex so retries without sighash_hex still work idempotently
                let raw_tx_bytes = hex::decode(req.raw_tx_hex.trim()).context("invalid raw_tx_hex")?;
                let tx: Transaction = deserialize(&raw_tx_bytes).context("invalid dispute tx")?;
                let vtxo_pk_bytes = hex::decode(req.vtxo_pk_script_hex.trim())?;
                let dispute_script_bytes = hex::decode(req.dispute_script_hex.trim())?;
                let prevout = TxOut {
                    value: Amount::from_sat(req.total_collateral_sats),
                    script_pubkey: ScriptBuf::from_bytes(vtxo_pk_bytes),
                };
                let dispute_script = ScriptBuf::from_bytes(dispute_script_bytes);
                let leaf_hash = TapLeafHash::from_script(&dispute_script, LeafVersion::TapScript);
                let sh = SighashCache::new(&tx)
                    .taproot_script_spend_signature_hash(
                        0,
                        &Prevouts::All(&[prevout]),
                        leaf_hash,
                        TapSighashType::Default,
                    )
                    .context("compute retry sighash")?;
                hex::encode(sh.to_byte_array())
            }
        };
        if requested_sh == existing.sighash_hex {
            return Ok(existing);
        }
        bail!(
            "vtxo_outpoint {} already signed for dispute with sighash {} (single-sign lock prevents cherry-picking)",
            req.vtxo_outpoint,
            existing.sighash_hex
        );
    }

    // 3. Evaluate, sign, and atomically persist the lock before returning the signature
    let resp = evaluate_and_sign_dispute(oracle_sk, req, live_spot_price, min_fee_sats)?;
    storage.record_dispute_lock(&req.vtxo_outpoint, resp)
}

/// Build a JSON `p2pfiat-rpc-res` reply for a parsed `DisputeRpcRequest` (stateless helper).
pub fn build_dispute_rpc_reply(
    oracle_sk: &SecretKey,
    rpc: &DisputeRpcRequest,
    live_spot_price: f64,
    min_fee_sats: u64,
) -> String {
    let reply = match evaluate_and_sign_dispute(oracle_sk, &rpc.params, live_spot_price, min_fee_sats) {
        Ok(res) => DisputeRpcResponse {
            msg_type: "p2pfiat-rpc-res".into(),
            req_id: rpc.req_id.clone(),
            ok: true,
            result: Some(res),
            error: None,
        },
        Err(e) => DisputeRpcResponse {
            msg_type: "p2pfiat-rpc-res".into(),
            req_id: rpc.req_id.clone(),
            ok: false,
            result: None,
            error: Some(format!("{e:#}")),
        },
    };
    serde_json::to_string(&reply).unwrap_or_default()
}

/// Build a JSON `p2pfiat-rpc-res` reply enforced by the persistent single-sign-per-VTXO lock.
pub fn build_dispute_rpc_reply_locked(
    oracle_sk: &SecretKey,
    rpc: &DisputeRpcRequest,
    live_spot_price: f64,
    min_fee_sats: u64,
    storage: &crate::storage::FileStorage,
) -> String {
    let reply = match evaluate_and_sign_dispute_locked(
        oracle_sk,
        &rpc.params,
        live_spot_price,
        min_fee_sats,
        storage,
    ) {
        Ok(res) => DisputeRpcResponse {
            msg_type: "p2pfiat-rpc-res".into(),
            req_id: rpc.req_id.clone(),
            ok: true,
            result: Some(res),
            error: None,
        },
        Err(e) => DisputeRpcResponse {
            msg_type: "p2pfiat-rpc-res".into(),
            req_id: rpc.req_id.clone(),
            ok: false,
            result: None,
            error: Some(format!("{e:#}")),
        },
    };
    serde_json::to_string(&reply).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kormir::bitcoin::absolute::LockTime;
    use kormir::bitcoin::consensus::serialize;
    use kormir::bitcoin::transaction::Version;
    use kormir::bitcoin::{Sequence, TxIn, Txid, Witness};

    fn oracle_sk() -> SecretKey {
        SecretKey::from_slice(&[0x22; 32]).unwrap()
    }
    fn user_sk() -> SecretKey {
        SecretKey::from_slice(&[0x33; 32]).unwrap()
    }
    fn lp_sk() -> SecretKey {
        SecretKey::from_slice(&[0x44; 32]).unwrap()
    }

    fn p2tr_script(fill: u8) -> ScriptBuf {
        let mut bytes = vec![0x51, 0x20];
        bytes.extend_from_slice(&[fill; 32]);
        ScriptBuf::from_bytes(bytes)
    }

    fn sign_manifest(req: &mut DisputeRequest) {
        let secp = Secp256k1::new();
        let u_kp = Keypair::from_secret_key(&secp, &user_sk());
        let l_kp = Keypair::from_secret_key(&secp, &lp_sk());
        req.user_pubkey_hex = hex::encode(u_kp.x_only_public_key().0.serialize());
        req.lp_pubkey_hex = hex::encode(l_kp.x_only_public_key().0.serialize());
        let msg = Message::from_digest(compute_manifest_hash(req));
        req.user_manifest_sig_hex = hex::encode(secp.sign_schnorr_no_aux_rand(&msg, &u_kp).as_ref());
        req.lp_manifest_sig_hex = hex::encode(secp.sign_schnorr_no_aux_rand(&msg, &l_kp).as_ref());
    }

    fn build_valid_req(side: &str, funding: f64, live_spot: f64, bounty: u64) -> DisputeRequest {
        let outpoint = OutPoint::new(Txid::all_zeros(), 0);
        let mut req = DisputeRequest {
            contract_id: "pos-demo-1".into(),
            vtxo_outpoint: outpoint.to_string(),
            currency: "USD".into(),
            side: side.into(),
            total_collateral_sats: 333_334,
            notional_fiat: 100.0,
            opened_at: 1_795_000_000,
            dispute_timestamp: 1_795_000_000 + 5 * 86_400,
            funding_rate_bps_per_day: funding,
            bounty_sats: bounty,
            miner_fee_sats: 350,
            fee_paid_sats: 150,
            user_pubkey_hex: String::new(),
            lp_pubkey_hex: String::new(),
            user_manifest_sig_hex: String::new(),
            lp_manifest_sig_hex: String::new(),
            raw_tx_hex: String::new(),
            vtxo_pk_script_hex: hex::encode(p2tr_script(0xaa).as_bytes()),
            dispute_script_hex: hex::encode([0x51u8]),
            user_payout_script_hex: hex::encode(p2tr_script(0x11).as_bytes()),
            lp_payout_script_hex: hex::encode(p2tr_script(0x22).as_bytes()),
            sighash_hex: None,
        };
        sign_manifest(&mut req);
        let (u_sats, l_sats, _) = compute_dispute_payouts(&req, live_spot).unwrap();
        let mut outputs = vec![
            TxOut { value: Amount::from_sat(u_sats), script_pubkey: p2tr_script(0x11) },
            TxOut { value: Amount::from_sat(l_sats), script_pubkey: p2tr_script(0x22) },
        ];
        if bounty > 0 {
            outputs.push(TxOut { value: Amount::from_sat(bounty), script_pubkey: p2tr_script(0x33) });
        }
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus((1 << 22) | 4),
                witness: Witness::new(),
            }],
            output: outputs,
        };
        req.raw_tx_hex = hex::encode(serialize(&tx));
        req
    }

    #[test]
    fn signs_mid_term_anytime_exit_with_verified_manifest_and_bip342_sighash() {
        let sk = oracle_sk();
        let req = build_valid_req("short", 3.0, 72_000.0, 600);
        let res = evaluate_and_sign_dispute(&sk, &req, 72_000.0, 100).unwrap();
        let user_usd = (res.user_payout_sats as f64 / 1e8) * 72_000.0;
        assert!((user_usd - 100.15).abs() < 0.05, "got {user_usd}");
        assert_eq!(res.signature_hex.len(), 128);
        assert_eq!(res.sighash_hex.len(), 64);
    }

    #[test]
    fn early_liquidation_pays_full_pool_to_stable() {
        let sk = oracle_sk();
        let req = build_valid_req("short", 3.0, 27_000.0, 600);
        let res = evaluate_and_sign_dispute(&sk, &req, 27_000.0, 100).unwrap();
        assert_eq!(res.user_payout_sats, 333_334 - 600 - 350 - DUST_SATS);
        assert_eq!(res.lp_payout_sats, DUST_SATS);
    }

    #[test]
    fn supports_2x_long_side() {
        let sk = oracle_sk();
        let req = build_valid_req("long", -3.0, 72_000.0, 600);
        let res = evaluate_and_sign_dispute(&sk, &req, 72_000.0, 100).unwrap();
        let user_usd = (res.user_payout_sats as f64 / 1e8) * 72_000.0;
        assert!(user_usd > 138.5 && user_usd < 140.5, "got {user_usd}");
    }

    #[test]
    fn rejects_underpaid_dispute_fee() {
        let sk = oracle_sk();
        let mut req = build_valid_req("short", 3.0, 72_000.0, 600);
        req.fee_paid_sats = 25;
        assert!(evaluate_and_sign_dispute(&sk, &req, 72_000.0, 100).is_err());
    }

    #[test]
    fn rejects_tampered_output_theft_attempt() {
        let sk = oracle_sk();
        let req = build_valid_req("short", 3.0, 40_000.0, 600);
        let err = evaluate_and_sign_dispute(&sk, &req, 72_000.0, 100).unwrap_err();
        assert!(err.to_string().contains("payout mismatch"), "unexpected err: {err}");
    }

    #[test]
    fn rejects_tampered_sighash_claim() {
        let sk = oracle_sk();
        let mut req = build_valid_req("short", 3.0, 72_000.0, 600);
        req.sighash_hex = Some("ff".repeat(32));
        let err = evaluate_and_sign_dispute(&sk, &req, 72_000.0, 100).unwrap_err();
        assert!(err.to_string().contains("sighash mismatch"), "unexpected err: {err}");
    }

    #[test]
    fn accepts_volatile_spot_within_1pct_band_and_rejects_outside() {
        let sk = oracle_sk();
        let req_ok = build_valid_req("short", 3.0, 71_600.0, 600);
        assert!(evaluate_and_sign_dispute(&sk, &req_ok, 72_000.0, 100).is_ok());

        let req_bad = build_valid_req("short", 3.0, 70_000.0, 600);
        assert!(evaluate_and_sign_dispute(&sk, &req_bad, 72_000.0, 100).is_err());
    }

    #[test]
    fn rejects_spoofed_payout_address_attack() {
        let sk = oracle_sk();
        let mut req = build_valid_req("short", 3.0, 72_000.0, 600);
        // Attacker swaps lp_payout_script_hex to their own script without LP's signature
        req.lp_payout_script_hex = hex::encode(p2tr_script(0x99).as_bytes());
        let err = evaluate_and_sign_dispute(&sk, &req, 72_000.0, 100).unwrap_err();
        assert!(err.to_string().contains("manifest_sig verification failed"), "unexpected err: {err}");
    }

    #[test]
    fn rejects_forged_notional_in_manifest() {
        let sk = oracle_sk();
        let mut req = build_valid_req("short", 3.0, 72_000.0, 600);
        // Attacker claims $200 notional instead of the signed $100
        req.notional_fiat = 200.0;
        let err = evaluate_and_sign_dispute(&sk, &req, 72_000.0, 100).unwrap_err();
        assert!(err.to_string().contains("manifest_sig verification failed"), "unexpected err: {err}");
    }

    #[test]
    fn rejects_excessive_miner_fee_burn() {
        let sk = oracle_sk();
        let mut req = build_valid_req("short", 3.0, 72_000.0, 600);
        req.miner_fee_sats = MAX_MINER_FEE_SATS + 1;
        let err = evaluate_and_sign_dispute(&sk, &req, 72_000.0, 100).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum allowed"), "unexpected err: {err}");
    }

    #[test]
    fn enforces_single_sign_per_vtxo_outpoint_lock() {
        let sk = oracle_sk();
        let dir = std::env::temp_dir().join(format!(
            "nostracle-dispute-lock-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let db_path = dir.join("events.json");
        let storage = crate::storage::FileStorage::open(&db_path).unwrap();

        // 1. Forged manifest request must NOT lock the vtxo_outpoint
        let mut forged = build_valid_req("short", 3.0, 72_000.0, 600);
        forged.notional_fiat = 999.0;
        assert!(evaluate_and_sign_dispute_locked(&sk, &forged, 72_000.0, 100, &storage).is_err());
        assert!(storage.get_dispute_lock(&forged.vtxo_outpoint).is_none());

        // 2. First valid dispute at $72,000 succeeds and locks the vtxo_outpoint
        let req1 = build_valid_req("short", 3.0, 72_000.0, 600);
        let res1 = evaluate_and_sign_dispute_locked(&sk, &req1, 72_000.0, 100, &storage).unwrap();

        // 3. Exact same sighash retry (e.g. Nostr relay redelivery) returns cached signature idempotently
        let res_retry = evaluate_and_sign_dispute_locked(&sk, &req1, 60_000.0, 100, &storage).unwrap();
        assert_eq!(res_retry.signature_hex, res1.signature_hex);
        assert_eq!(res_retry.sighash_hex, res1.sighash_hex);

        // 4. Second dispute for the SAME vtxo_outpoint at a different price ($60,000) is REJECTED
        let req2 = build_valid_req("short", 3.0, 60_000.0, 600);
        let err = evaluate_and_sign_dispute_locked(&sk, &req2, 60_000.0, 100, &storage).unwrap_err();
        assert!(
            err.to_string().contains("single-sign lock prevents cherry-picking"),
            "unexpected err: {err}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
