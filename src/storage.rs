//! Crash-safe JSON file storage for kormir.
//!
//! Safety-critical invariants for a DLC oracle:
//! 1. A nonce index is never handed out twice (would leak the oracle key
//!    if both are ever signed). The counter is persisted *before* indexes are
//!    returned.
//! 2. An event is never signed twice with different outcomes (same key leak).
//!    `save_signatures` refuses if signatures already exist.
//!
//! Every mutation rewrites the whole file via write-to-temp + rename.

use anyhow::{Context, Result};
use kormir::error::Error as KError;
use kormir::storage::{OracleEventData, Storage};
use kormir::{OracleAnnouncement, Signature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    next_nonce_index: u32,
    events: BTreeMap<String, OracleEventData>,
}

pub struct FileStorage {
    path: PathBuf,
    state: Mutex<State>,
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

    fn persist(&self, state: &State) -> Result<(), KError> {
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(state).map_err(|_| KError::Internal)?;
        std::fs::write(&tmp, bytes).map_err(|e| {
            log::error!("write {tmp:?}: {e}");
            KError::StorageFailure
        })?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            log::error!("rename {tmp:?}: {e}");
            KError::StorageFailure
        })
    }

    pub fn list_events(&self) -> Vec<OracleEventData> {
        self.state.lock().unwrap().events.values().cloned().collect()
    }

    /// Record the nostr event ids under which announcement/attestation were published.
    pub fn set_nostr_ids(
        &self,
        event_id: &str,
        announcement: Option<String>,
        attestation: Option<String>,
    ) -> Result<(), KError> {
        let mut st = self.state.lock().unwrap();
        let ev = st.events.get_mut(event_id).ok_or(KError::NotFound)?;
        if announcement.is_some() {
            ev.announcement_event_id = announcement;
        }
        if attestation.is_some() {
            ev.attestation_event_id = attestation;
        }
        self.persist(&st)
    }
}

impl Storage for FileStorage {
    async fn get_next_nonce_indexes(&self, num: usize) -> Result<Vec<u32>, KError> {
        let mut st = self.state.lock().unwrap();
        let start = st.next_nonce_index;
        let end = start.checked_add(num as u32).ok_or(KError::Internal)?;
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
