#![forbid(unsafe_code)]

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sled::transaction::ConflictableTransactionError;
use sled::transaction::TransactionError;
use sled::transaction::TransactionalTree;
use std::path::Path;

pub const BOOTSTRAP_CHANGELOG_VERSION_V1: u32 = 1;

const META_BASE_SNAPSHOT_ID: &[u8] = b"meta:base_snapshot_id";
const META_EPOCH_KEY: &[u8] = b"meta:epoch";
const META_SEQ_KEY: &[u8] = b"meta:seq";

const CHANGELOG_PREFIX: &[u8] = b"changelog:";

#[derive(Debug, thiserror::Error)]
pub enum BootstrapStoreError {
    #[error("db error: {0}")]
    Db(#[from] sled::Error),
    #[error("decode error: {0}")]
    Decode(String),
}

/// Change record emitted for filesystem-scoped bootstrap state (receipts/linkage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapChangelogEntryV1 {
    pub schema_version: u32,
    pub epoch: u64,
    pub seq: u64,
    pub store: String,
    pub op: String,
    pub key_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_b64: Option<String>,
    pub value_hash: String,
}

#[derive(Debug, Clone)]
pub struct BootstrapStore {
    tree: sled::Tree,
}

impl BootstrapStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BootstrapStoreError> {
        let db = sled::open(path)?;
        let tree = db.open_tree("fin-node-bootstrap")?;
        Ok(Self { tree })
    }

    pub fn base_snapshot_id(&self) -> Result<Option<String>, BootstrapStoreError> {
        let Some(v) = self.tree.get(META_BASE_SNAPSHOT_ID)? else {
            return Ok(None);
        };
        let s = String::from_utf8(v.to_vec()).map_err(|e| {
            BootstrapStoreError::Decode(format!("invalid utf8 base_snapshot_id: {e}"))
        })?;
        Ok(Some(s))
    }

    pub fn set_base_snapshot_id(&self, base_snapshot_id: &str) -> Result<(), BootstrapStoreError> {
        self.tree
            .insert(META_BASE_SNAPSHOT_ID, base_snapshot_id.as_bytes())?;
        Ok(())
    }

    pub fn epoch(&self) -> Result<u64, BootstrapStoreError> {
        Ok(epoch_get(&self.tree)?)
    }

    pub fn set_epoch(&self, epoch: u64) -> Result<(), BootstrapStoreError> {
        self.tree
            .insert(META_EPOCH_KEY, epoch.to_be_bytes().to_vec())?;
        Ok(())
    }

    pub fn export_changelog_epoch_v1(
        &self,
        epoch: u64,
    ) -> Result<Vec<BootstrapChangelogEntryV1>, BootstrapStoreError> {
        let mut out = Vec::new();
        let prefix = changelog_epoch_prefix(epoch);
        for r in self.tree.scan_prefix(prefix) {
            let (_k, v) = r?;
            let e: BootstrapChangelogEntryV1 = serde_json::from_slice(&v).map_err(|e| {
                BootstrapStoreError::Decode(format!("changelog decode failed: {e}"))
            })?;
            out.push(e);
        }
        Ok(out)
    }

    pub fn delete_changelog_epoch(&self, epoch: u64) -> Result<(), BootstrapStoreError> {
        let prefix = changelog_epoch_prefix(epoch);
        let keys: Vec<Vec<u8>> = self
            .tree
            .scan_prefix(prefix)
            .filter_map(|r| r.ok().map(|(k, _)| k.to_vec()))
            .collect();
        for k in keys {
            let _ = self.tree.remove(k)?;
        }
        Ok(())
    }

    pub fn record_put(
        &self,
        store: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), BootstrapStoreError> {
        self.record(store, "put", key, Some(value))
    }

    pub fn record_del(&self, store: &str, key: &[u8]) -> Result<(), BootstrapStoreError> {
        self.record(store, "del", key, None)
    }

    fn record(
        &self,
        store: &str,
        op: &str,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Result<(), BootstrapStoreError> {
        let store_s = store.to_string();
        let op_s = op.to_string();
        let key_hex = hex::encode(key);
        let value_b64 = value.map(|v| base64::engine::general_purpose::STANDARD.encode(v));
        let value_hash = value
            .map(|v| blake3::hash(v).to_hex().to_string())
            .unwrap_or_default();

        let r: Result<(), TransactionError<String>> = self.tree.transaction(|t| {
            let mut ctx = BootstrapTxCtx::load(t)
                .map_err(|e| ConflictableTransactionError::Abort(e.to_string()))?;
            ctx.next_seq = ctx.next_seq.saturating_add(1);
            let entry_key = changelog_entry_key(ctx.epoch, ctx.next_seq);

            let entry = BootstrapChangelogEntryV1 {
                schema_version: BOOTSTRAP_CHANGELOG_VERSION_V1,
                epoch: ctx.epoch,
                seq: ctx.next_seq,
                store: store_s.clone(),
                op: op_s.clone(),
                key_hex: key_hex.clone(),
                value_b64: value_b64.clone(),
                value_hash: value_hash.clone(),
            };
            let bytes = serde_json::to_vec(&entry)
                .map_err(|e| ConflictableTransactionError::Abort(e.to_string()))?;
            t.insert(entry_key, bytes)?;
            ctx.store(t)
                .map_err(|e| ConflictableTransactionError::Abort(e.to_string()))?;
            Ok(())
        });
        match r {
            Ok(()) => Ok(()),
            Err(TransactionError::Storage(e)) => Err(BootstrapStoreError::Db(e)),
            Err(TransactionError::Abort(e)) => Err(BootstrapStoreError::Decode(e)),
        }
    }
}

fn epoch_get(tree: &sled::Tree) -> Result<u64, sled::Error> {
    let Some(v) = tree.get(META_EPOCH_KEY)? else {
        return Ok(0);
    };
    if v.len() != 8 {
        return Ok(0);
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(v.as_ref());
    Ok(u64::from_be_bytes(b))
}

fn seq_get(t: &TransactionalTree) -> Result<u64, sled::transaction::UnabortableTransactionError> {
    let Some(v) = t.get(META_SEQ_KEY)? else {
        return Ok(0);
    };
    if v.len() != 8 {
        return Ok(0);
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(v.as_ref());
    Ok(u64::from_be_bytes(b))
}

fn epoch_get_tx(
    t: &TransactionalTree,
) -> Result<u64, sled::transaction::UnabortableTransactionError> {
    let Some(v) = t.get(META_EPOCH_KEY)? else {
        return Ok(0);
    };
    if v.len() != 8 {
        return Ok(0);
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(v.as_ref());
    Ok(u64::from_be_bytes(b))
}

fn changelog_epoch_prefix(epoch: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(CHANGELOG_PREFIX.len() + 8 + 1);
    p.extend_from_slice(CHANGELOG_PREFIX);
    p.extend_from_slice(&epoch.to_be_bytes());
    p.push(b':');
    p
}

fn changelog_entry_key(epoch: u64, seq: u64) -> Vec<u8> {
    let mut k = changelog_epoch_prefix(epoch);
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

struct BootstrapTxCtx {
    epoch: u64,
    next_seq: u64,
}

impl BootstrapTxCtx {
    fn load(t: &TransactionalTree) -> Result<Self, sled::transaction::UnabortableTransactionError> {
        Ok(Self {
            epoch: epoch_get_tx(t)?,
            next_seq: seq_get(t)?,
        })
    }

    fn store(
        &self,
        t: &TransactionalTree,
    ) -> Result<(), sled::transaction::UnabortableTransactionError> {
        t.insert(META_SEQ_KEY, self.next_seq.to_be_bytes().to_vec())?;
        Ok(())
    }
}
