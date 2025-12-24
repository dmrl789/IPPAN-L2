#![forbid(unsafe_code)]

use l2_core::finality::SubmitState;
use serde::{Deserialize, Serialize};
use sled::transaction::{ConflictableTransactionError, TransactionError, TransactionalTree};
use std::collections::BTreeSet;
use std::path::Path;

const TREE_NAME: &str = "fin-node-audit";
const LAST_SEQ_KEY: &[u8] = b"audit:last_seq";
const EVENT_PREFIX: &[u8] = b"audit:event:";
const ENVELOPE_PREFIX: &[u8] = b"audit:envelope:";

#[derive(Debug, thiserror::Error)]
pub enum AuditStoreError {
    #[error("db error: {0}")]
    Db(#[from] sled::Error),
    #[error("serde error: {0}")]
    Serde(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSubjectsV1 {
    /// Dataset ids (hex32).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dataset_ids: Vec<String>,
    /// Asset ids (hex32).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub asset_ids: Vec<String>,
    /// Account ids (string).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<String>,
}

impl AuditSubjectsV1 {
    pub fn normalize(mut self) -> Self {
        self.dataset_ids.sort();
        self.dataset_ids.dedup();
        self.asset_ids.sort();
        self.asset_ids.dedup();
        self.accounts.sort();
        self.accounts.dedup();
        self
    }

    pub fn contains_account(&self, account: &str) -> bool {
        self.accounts.iter().any(|a| a == account)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecordV1 {
    pub schema_version: u32,
    pub seq: u64,
    pub occurred_at_unix_secs: u64,
    pub epoch: u64,
    pub hub: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purchase_id: Option<String>,
    /// blake3(canonical envelope bytes), hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_hash: Option<String>,
    /// Bundle-relative receipt path (preferred) or receipt key reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submit_state: Option<SubmitState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "AuditSubjectsV1::is_empty")]
    pub subjects: AuditSubjectsV1,
}

impl AuditSubjectsV1 {
    fn is_empty(&self) -> bool {
        self.dataset_ids.is_empty() && self.asset_ids.is_empty() && self.accounts.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct AuditStore {
    tree: sled::Tree,
}

impl AuditStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditStoreError> {
        let db = sled::open(path)?;
        let tree = db.open_tree(TREE_NAME)?;
        Ok(Self { tree })
    }

    #[allow(dead_code)]
    pub fn open_temporary() -> Result<Self, AuditStoreError> {
        let db = sled::Config::new().temporary(true).open()?;
        let tree = db.open_tree(TREE_NAME)?;
        Ok(Self { tree })
    }

    pub fn append_event(&self, mut e: EventRecordV1) -> Result<u64, AuditStoreError> {
        e.schema_version = 1;
        e.subjects = e.subjects.normalize();

        let r: Result<u64, TransactionError<String>> =
            self.tree.transaction(|t: &TransactionalTree| {
                let last = seq_get(t).map_err(|e| {
                    ConflictableTransactionError::Abort(format!("read last_seq failed: {e}"))
                })?;
                let next = last.saturating_add(1);
                let mut e2 = e.clone();
                e2.seq = next;
                let bytes = serde_json::to_vec(&e2).map_err(|e| {
                    ConflictableTransactionError::Abort(format!("event json encode failed: {e}"))
                })?;

                t.insert(LAST_SEQ_KEY, next.to_be_bytes().to_vec())?;
                t.insert(event_key(next), bytes)?;
                Ok(next)
            });

        match r {
            Ok(seq) => Ok(seq),
            Err(TransactionError::Storage(e)) => Err(AuditStoreError::Db(e)),
            Err(TransactionError::Abort(s)) => Err(AuditStoreError::Serde(s)),
        }
    }

    /// Persist canonical envelope bytes if absent (best-effort).
    pub fn put_envelope_if_absent(
        &self,
        hub: &str,
        action_id_hex: &str,
        bytes: &[u8],
    ) -> Result<(), AuditStoreError> {
        let key = envelope_key(hub, action_id_hex);
        let cas = self
            .tree
            .compare_and_swap(key, None as Option<&[u8]>, Some(bytes))?;
        if cas.is_err() {
            // Already present; do not overwrite.
        }
        Ok(())
    }

    pub fn get_envelope(
        &self,
        hub: &str,
        action_id_hex: &str,
    ) -> Result<Option<Vec<u8>>, AuditStoreError> {
        Ok(self
            .tree
            .get(envelope_key(hub, action_id_hex))?
            .map(|v| v.to_vec()))
    }

    #[allow(dead_code)]
    pub fn iter_events(&self) -> Result<Vec<EventRecordV1>, AuditStoreError> {
        let mut out = Vec::new();
        for r in self.tree.scan_prefix(EVENT_PREFIX) {
            let (_k, v) = r?;
            let e: EventRecordV1 = serde_json::from_slice(&v)
                .map_err(|e| AuditStoreError::Serde(format!("event decode failed: {e}")))?;
            out.push(e);
        }
        Ok(out)
    }

    pub fn iter_events_filtered(
        &self,
        from_epoch: Option<u64>,
        to_epoch: Option<u64>,
        hubs: &BTreeSet<String>,
        dataset_id: Option<&str>,
        asset_id: Option<&str>,
        account: Option<&str>,
    ) -> Result<Vec<EventRecordV1>, AuditStoreError> {
        let mut out = Vec::new();
        for r in self.tree.scan_prefix(EVENT_PREFIX) {
            let (_k, v) = r?;
            let e: EventRecordV1 = serde_json::from_slice(&v)
                .map_err(|e| AuditStoreError::Serde(format!("event decode failed: {e}")))?;

            if let Some(min) = from_epoch {
                if e.epoch < min {
                    continue;
                }
            }
            if let Some(max) = to_epoch {
                if e.epoch > max {
                    continue;
                }
            }
            if !hubs.is_empty() && !hubs.contains(&e.hub) {
                continue;
            }
            if let Some(ds) = dataset_id {
                if !e.subjects.dataset_ids.iter().any(|x| x == ds) {
                    continue;
                }
            }
            if let Some(asst) = asset_id {
                if !e.subjects.asset_ids.iter().any(|x| x == asst) {
                    continue;
                }
            }
            if let Some(acct) = account {
                if !e.subjects.contains_account(acct) {
                    continue;
                }
            }

            out.push(e);
        }
        Ok(out)
    }

    /// Best-effort flush.
    #[allow(dead_code)]
    pub fn flush(&self) -> Result<(), AuditStoreError> {
        self.tree.flush()?;
        Ok(())
    }

    /// Prune events older than `cutoff_unix_secs` (best-effort).
    ///
    /// Returns number of deleted events.
    ///
    /// Notes:
    /// - This does **not** delete stored envelopes.
    /// - Assumes `occurred_at_unix_secs` is roughly non-decreasing with `seq`.
    pub fn prune_events_older_than(
        &self,
        cutoff_unix_secs: u64,
        max_delete: usize,
    ) -> Result<usize, AuditStoreError> {
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for (scanned, r) in self.tree.scan_prefix(EVENT_PREFIX).enumerate() {
            if scanned >= max_delete {
                break;
            }
            let (k, v) = r?;
            let e: EventRecordV1 = serde_json::from_slice(&v)
                .map_err(|e| AuditStoreError::Serde(format!("event decode failed: {e}")))?;
            if e.occurred_at_unix_secs < cutoff_unix_secs {
                keys.push(k.to_vec());
                continue;
            }
            break;
        }
        let mut deleted = 0usize;
        for k in keys {
            let _ = self.tree.remove(k)?;
            deleted += 1;
        }
        Ok(deleted)
    }
}

fn seq_get(t: &TransactionalTree) -> Result<u64, sled::transaction::UnabortableTransactionError> {
    let Some(v) = t.get(LAST_SEQ_KEY)? else {
        return Ok(0);
    };
    if v.len() != 8 {
        return Ok(0);
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&v);
    Ok(u64::from_be_bytes(b))
}

fn event_key(seq: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(EVENT_PREFIX.len() + 8);
    k.extend_from_slice(EVENT_PREFIX);
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

fn envelope_key(hub: &str, action_id_hex: &str) -> Vec<u8> {
    // Stored key ordering: prefix + hub + "/" + action_id hex
    let mut k = Vec::with_capacity(ENVELOPE_PREFIX.len() + hub.len() + 1 + action_id_hex.len());
    k.extend_from_slice(ENVELOPE_PREFIX);
    k.extend_from_slice(hub.as_bytes());
    k.push(b'/');
    k.extend_from_slice(action_id_hex.as_bytes());
    k
}
