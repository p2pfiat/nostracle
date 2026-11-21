//! Crash-safe JSON file storage for kormir, plus nostr publication state.
//!
//! Safety-critical invariants for a DLC oracle:
//! 1. A nonce index is never handed out twice (would leak the oracle key
//!    if both are ever signed). The counter is persisted *before* indexes are
//!    returned.
//! 2. An event is never signed twice with different outcomes (same key leak).
//!    `save_signatures` refuses if signatures already exist.
//!
//! Every mutation rewrites the whole file via write-to-temp + rename. Finished
//! events are moved to an append-only archive so the live file stays small.

use anyhow::{Context, Result};
use kormir::error::Error as KError;
use kormir::storage::{OracleEventData, Storage};
use kormir::{OracleAnnouncement, Signature};
use nostr_sdk::Event;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Signed nostr events for one oracle event and how many relays took them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NostrRecord {
    pub announcement: Option<Event>,
    pub announcement_acks: usize,
    pub attestation: Option<Event>,
    pub attestation_acks: usize,
    pub last_broadcast: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    /// Paid; attestation still to be delivered.
    Pending,
    Delivered,
    /// A donation, nothing owed.
    Tip,
    /// Not accepted (e.g. underpaid). The operator may want to refund it.
    Rejected(String),
    /// Accepted, but the attestation can never be delivered. Refund it.
    Failed(String),
}

/// One zap, keyed by payment hash so that a receipt is only ever counted once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    pub payment_hash: String,
    pub buyer: String,
    pub event_id: Option<String>,
    pub sats: u64,
    pub created_at: u64,
    pub status: PaymentStatus,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    next_nonce_index: u32,
    events: BTreeMap<String, OracleEventData>,
    #[serde(default)]
    nostr: BTreeMap<String, NostrRecord>,
    /// Events that reached `max_attest_delay` without a reliable price.
    #[serde(default)]
    missed: BTreeSet<String>,
    #[serde(default)]
    payments: BTreeMap<String, Payment>,
}

pub struct FileStorage {
    path: PathBuf,
    state: Mutex<State>,
}

pub fn maturity(ev: &OracleEventData) -> u64 {
    ev.announcement.oracle_event.event_maturity_epoch as u64
}

impl FileStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let state = if path.exists() {
            let bytes = std::fs::read(&path).with_context(|| format!("read {path:?}"))?;
            serde_json::from_slice(&bytes).with_context(|| format!("parse {path:?}"))?
        } else {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            State::default()
        };
        Ok(Self { path, state: Mutex::new(state) })
    }

    /// Create an empty database file; fails if one exists.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        anyhow::ensure!(!path.exists(), "{path:?} already exists");
        let s = Self::open(path)?;
        s.persist(&s.state.lock().unwrap()).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(s)
    }

    pub fn archive_path(&self) -> PathBuf {
        self.path.with_extension("archive.jsonl")
    }

    fn persist(&self, state: &State) -> Result<(), KError> {
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(state).map_err(|_| KError::Internal)?;
        let write = || -> std::io::Result<()> {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)
        };
        write().map_err(|e| {
            log::error!("persist {:?}: {e}", self.path);
            KError::StorageFailure
        })
    }

    pub fn list_events(&self) -> Vec<OracleEventData> {
        self.state.lock().unwrap().events.values().cloned().collect()
    }

    pub fn next_nonce_index(&self) -> u32 {
        self.state.lock().unwrap().next_nonce_index
    }

    pub fn nostr_record(&self, event_id: &str) -> NostrRecord {
        self.state.lock().unwrap().nostr.get(event_id).cloned().unwrap_or_default()
    }

    pub fn update_nostr(&self, event_id: &str, f: impl FnOnce(&mut NostrRecord)) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        f(st.nostr.entry(event_id.to_string()).or_default());
        self.persist(&st).map_err(|e| anyhow::anyhow!("{e}"))
    }

    pub fn is_missed(&self, event_id: &str) -> bool {
        self.state.lock().unwrap().missed.contains(event_id)
    }

    pub fn mark_missed(&self, event_id: &str) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        if st.missed.insert(event_id.to_string()) {
            self.persist(&st).map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        Ok(())
    }

    pub fn missed(&self) -> Vec<String> {
        self.state.lock().unwrap().missed.iter().cloned().collect()
    }

    pub fn has_payment(&self, payment_hash: &str) -> bool {
        self.state.lock().unwrap().payments.contains_key(payment_hash)
    }

    pub fn insert_payment(&self, payment: Payment) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        st.payments.entry(payment.payment_hash.clone()).or_insert(payment);
        self.persist(&st).map_err(|e| anyhow::anyhow!("{e}"))
    }

    pub fn payments(&self) -> Vec<Payment> {
        self.state.lock().unwrap().payments.values().cloned().collect()
    }

    pub fn set_payment_status(&self, payment_hash: &str, status: PaymentStatus) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        let p = st
            .payments
            .get_mut(payment_hash)
            .ok_or_else(|| anyhow::anyhow!("unknown payment {payment_hash}"))?;
        p.status = status;
        self.persist(&st).map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Skip the nonce counter ahead. Run after restoring an older backup so
    /// that nonces handed out after the backup are never reused.
    pub fn bump_nonces(&self, by: u32) -> Result<u32> {
        let mut st = self.state.lock().unwrap();
        st.next_nonce_index = st
            .next_nonce_index
            .checked_add(by)
            .filter(|n| *n < (1 << 31))
            .ok_or_else(|| anyhow::anyhow!("nonce index would overflow"))?;
        self.persist(&st).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(st.next_nonce_index)
    }

    /// Move finished payments older than `cutoff` to the archive file.
    /// `cutoff` must be older than the zap receipt scan window, or a replayed
    /// receipt could be counted again.
    pub fn archive_payments_before(&self, cutoff: u64) -> Result<usize> {
        let mut st = self.state.lock().unwrap();
        let old: Vec<String> = st
            .payments
            .values()
            .filter(|p| p.created_at < cutoff && p.status != PaymentStatus::Pending)
            .map(|p| p.payment_hash.clone())
            .collect();
        if old.is_empty() {
            return Ok(0);
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.archive_path())?;
        for id in &old {
            writeln!(f, "{}", serde_json::json!({ "payment": st.payments.get(id) }))?;
        }
        f.sync_all()?;
        for id in &old {
            st.payments.remove(id);
        }
        self.persist(&st).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(old.len())
    }

    /// Move events with maturity before `cutoff` to the archive file.
    /// Returns how many were archived.
    pub fn archive_before(&self, cutoff: u64) -> Result<usize> {
        let mut st = self.state.lock().unwrap();
        let old: Vec<String> = st
            .events
            .values()
            .filter(|e| maturity(e) < cutoff)
            // keep events a buyer is still waiting for
            .filter(|e| {
                !st.payments.values().any(|p| {
                    p.status == PaymentStatus::Pending
                        && p.event_id.as_deref() == Some(e.event_id.as_str())
                })
            })
            .map(|e| e.event_id.clone())
            .collect();
        if old.is_empty() {
            return Ok(0);
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.archive_path())?;
        for id in &old {
            let ev = st.events.get(id).unwrap();
            let line = serde_json::json!({
                "event": ev,
                "nostr": st.nostr.get(id),
                "missed": st.missed.contains(id),
            });
            writeln!(f, "{line}")?;
        }
        f.sync_all()?;
        for id in &old {
            st.events.remove(id);
            st.nostr.remove(id);
            st.missed.remove(id);
        }
        self.persist(&st).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(old.len())
    }
}

impl Storage for FileStorage {
    async fn get_next_nonce_indexes(&self, num: usize) -> Result<Vec<u32>, KError> {
        let mut st = self.state.lock().unwrap();
        let start = st.next_nonce_index;
        let end = start
            .checked_add(num as u32)
            .filter(|n| *n < (1 << 31)) // hardened derivation limit
            .ok_or(KError::Internal)?;
        st.next_nonce_index = end;
        self.persist(&st)?;
        Ok((start..end).collect())
    }

    async fn save_announcement(
        &self,
        announcement: OracleAnnouncement,
        indexes: Vec<u32>,
    ) -> Result<String, KError> {
        let mut st = self.state.lock().unwrap();
        let event_id = announcement.oracle_event.event_id.clone();
        if st.events.contains_key(&event_id) {
            log::error!("announcement {event_id} already exists");
            return Err(KError::Internal);
        }
        st.events.insert(
            event_id.clone(),
            OracleEventData {
                event_id: event_id.clone(),
                announcement,
                indexes,
                signatures: Vec::new(),
                announcement_event_id: None,
                attestation_event_id: None,
            },
        );
        self.persist(&st)?;
        Ok(event_id)
    }

    async fn save_signatures(
        &self,
        event_id: String,
        sigs: Vec<(String, Signature)>,
    ) -> Result<OracleEventData, KError> {
        let mut st = self.state.lock().unwrap();
        let ev = st.events.get_mut(&event_id).ok_or(KError::NotFound)?;
        if !ev.signatures.is_empty() {
            return Err(KError::EventAlreadySigned);
        }
        ev.signatures = sigs;
        let out = ev.clone();
        self.persist(&st)?;
        Ok(out)
    }

    async fn get_event(&self, event_id: String) -> Result<Option<OracleEventData>, KError> {
        Ok(self.state.lock().unwrap().events.get(&event_id).cloned())
    }
}
