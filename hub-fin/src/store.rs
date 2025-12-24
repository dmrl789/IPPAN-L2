#![forbid(unsafe_code)]

use crate::actions::CreateAssetV1;
use crate::types::{ActionId, AmountU128, AssetId32};
use base64::Engine as _;
use l2_core::storage_encryption::{KeyProvider, SledValueCipher};
use sled::transaction::ConflictableTransactionError;
use sled::transaction::TransactionError;
use sled::IVec;
use sled::Transactional;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

pub const CHANGELOG_VERSION_V1: u32 = 1;

const CHANGELOG_EPOCH_KEY: &[u8] = b"changelog_epoch";
const CHANGELOG_SEQ_KEY: &[u8] = b"changelog_seq";
const CHANGELOG_PREFIX: &[u8] = b"changelog:";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("db error: {0}")]
    Db(#[from] sled::Error),
    #[error("decode error: {0}")]
    Decode(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangelogOp {
    Put,
    Del,
}

impl ChangelogOp {
    fn as_str(self) -> &'static str {
        match self {
            ChangelogOp::Put => "put",
            ChangelogOp::Del => "del",
        }
    }
}

/// A single deterministic change record written to the changelog.
///
/// This is an operational artifact used for incremental snapshots / bootstrap.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChangelogEntryV1 {
    pub schema_version: u32,
    pub epoch: u64,
    pub seq: u64,
    pub op: String,
    /// Raw sled key bytes (hex-encoded).
    pub key_hex: String,
    /// Present only for `put`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_b64: Option<String>,
    /// blake3 hash of value bytes (empty for deletes).
    pub value_hash: String,
}

#[derive(Debug, Clone)]
pub struct FinStore {
    tree: sled::Tree,
    changelog: sled::Tree,
    cipher: Option<SledValueCipher>,
}

impl FinStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_encryption(path, None, false)
    }

    pub fn open_with_encryption(
        path: impl AsRef<Path>,
        provider: Option<Arc<dyn KeyProvider>>,
        allow_plaintext_read: bool,
    ) -> Result<Self, StoreError> {
        let db = sled::open(path)?;
        let tree = db.open_tree("hub-fin")?;
        let changelog = db.open_tree("hub-fin-changelog")?;
        let cipher = provider.map(|p| SledValueCipher::new(p, "hub-fin", allow_plaintext_read));
        Ok(Self {
            tree,
            changelog,
            cipher,
        })
    }

    pub(crate) fn value_cipher(&self) -> Option<&SledValueCipher> {
        self.cipher.as_ref()
    }

    fn encrypt_for_store(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
        let Some(c) = self.cipher.as_ref() else {
            return Ok(plaintext.to_vec());
        };
        c.encrypt_value(key, plaintext)
            .map_err(|e| StoreError::Decode(format!("encrypt failed: {e}")))
    }

    fn decrypt_for_store(&self, key: &[u8], stored: &[u8]) -> Result<Vec<u8>, StoreError> {
        let Some(c) = self.cipher.as_ref() else {
            return Ok(stored.to_vec());
        };
        c.decrypt_value(key, stored)
            .map_err(|e| StoreError::Decode(format!("decrypt failed: {e}")))
    }

    fn get_plain(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let Some(v) = self.tree.get(key)? else {
            return Ok(None);
        };
        let plain = self.decrypt_for_store(key, v.as_ref())?;
        Ok(Some(plain))
    }

    pub fn get_asset(&self, asset_id: AssetId32) -> Result<Option<CreateAssetV1>, StoreError> {
        let key = keys::asset(asset_id);
        let Some(v) = self.get_plain(&key)? else {
            return Ok(None);
        };
        serde_json::from_slice::<CreateAssetV1>(&v)
            .map(Some)
            .map_err(|e| StoreError::Decode(format!("failed decoding asset json: {e}")))
    }

    pub fn put_asset(&self, asset: &CreateAssetV1) -> Result<(), StoreError> {
        let key = keys::asset(asset.asset_id);
        let bytes = serde_json::to_vec(asset)
            .map_err(|e| StoreError::Decode(format!("failed encoding asset json: {e}")))?;
        self.tx_put(&key, &bytes)?;
        Ok(())
    }

    pub fn get_balance(
        &self,
        asset_id: AssetId32,
        account: &str,
    ) -> Result<AmountU128, StoreError> {
        let key = keys::balance(asset_id, account);
        let Some(v) = self.get_plain(&key)? else {
            return Ok(AmountU128(0));
        };
        decode_u128_be(&IVec::from(v))
            .map(AmountU128)
            .map_err(StoreError::Decode)
    }

    pub fn set_balance(
        &self,
        asset_id: AssetId32,
        account: &str,
        amount: AmountU128,
    ) -> Result<(), StoreError> {
        let key = keys::balance(asset_id, account);
        let bytes = encode_u128_be(amount.0).to_vec();
        self.tx_put(&key, &bytes)?;
        Ok(())
    }

    pub fn is_applied(&self, action_id: ActionId) -> Result<bool, StoreError> {
        Ok(self.tree.contains_key(keys::applied(action_id))?)
    }

    pub fn get_state_version(&self) -> Result<Option<u32>, StoreError> {
        let Some(v) = self.get_plain(keys::state_version())? else {
            return Ok(None);
        };
        let s = String::from_utf8(v)
            .map_err(|e| StoreError::Decode(format!("invalid utf8 state_version: {e}")))?;
        let n = s
            .parse::<u32>()
            .map_err(|e| StoreError::Decode(format!("invalid state_version integer: {e}")))?;
        Ok(Some(n))
    }

    pub fn set_state_version(&self, v: u32) -> Result<(), StoreError> {
        let key = keys::state_version();
        let bytes = v.to_string().into_bytes();
        self.tx_put(key, &bytes)?;
        Ok(())
    }

    /// Create/update an operator delegation for a given `(from, operator, asset_id)` tuple.
    pub fn set_delegation(
        &self,
        from_account: &str,
        operator_account: &str,
        asset_id: AssetId32,
    ) -> Result<(), StoreError> {
        let key = keys::delegation(from_account, operator_account, asset_id);
        self.tx_put(&key, b"1")?;
        Ok(())
    }

    /// Revoke an operator delegation for a given `(from, operator, asset_id)` tuple.
    pub fn revoke_delegation(
        &self,
        from_account: &str,
        operator_account: &str,
        asset_id: AssetId32,
    ) -> Result<(), StoreError> {
        let key = keys::delegation(from_account, operator_account, asset_id);
        self.tx_del(&key)?;
        Ok(())
    }

    pub fn has_delegation(
        &self,
        from_account: &str,
        operator_account: &str,
        asset_id: AssetId32,
    ) -> Result<bool, StoreError> {
        Ok(self
            .tree
            .contains_key(keys::delegation(from_account, operator_account, asset_id))?)
    }

    /// Add an account to the transfer allowlist for an asset.
    pub fn add_transfer_allow(&self, asset_id: AssetId32, account: &str) -> Result<(), StoreError> {
        let key = keys::transfer_allow(asset_id, account);
        self.tx_put(&key, b"1")?;
        Ok(())
    }

    /// Add an account to the transfer denylist for an asset.
    pub fn add_transfer_deny(&self, asset_id: AssetId32, account: &str) -> Result<(), StoreError> {
        let key = keys::transfer_deny(asset_id, account);
        self.tx_put(&key, b"1")?;
        Ok(())
    }

    pub fn is_transfer_allowlisted(
        &self,
        asset_id: AssetId32,
        account: &str,
    ) -> Result<bool, StoreError> {
        Ok(self
            .tree
            .contains_key(keys::transfer_allow(asset_id, account))?)
    }

    pub fn is_transfer_denylisted(
        &self,
        asset_id: AssetId32,
        account: &str,
    ) -> Result<bool, StoreError> {
        Ok(self
            .tree
            .contains_key(keys::transfer_deny(asset_id, account))?)
    }

    pub fn mark_applied(&self, action_id: ActionId) -> Result<(), StoreError> {
        let key = keys::applied(action_id);
        self.tx_put(&key, b"1")?;
        Ok(())
    }

    pub fn put_receipt(&self, action_id: ActionId, receipt_json: &[u8]) -> Result<(), StoreError> {
        let key = keys::apply_receipt(action_id);
        self.tx_put(&key, receipt_json)?;
        Ok(())
    }

    pub fn get_receipt(&self, action_id: ActionId) -> Result<Option<Vec<u8>>, StoreError> {
        let key = keys::apply_receipt(action_id);
        self.get_plain(&key)
    }

    /// Store a fin-node receipt (includes L1 submission metadata).
    pub fn put_final_receipt(
        &self,
        action_id: ActionId,
        receipt_json: &[u8],
    ) -> Result<(), StoreError> {
        let key = keys::receipt(action_id);
        self.tx_put(&key, receipt_json)?;
        Ok(())
    }

    pub fn get_final_receipt(&self, action_id: ActionId) -> Result<Option<Vec<u8>>, StoreError> {
        let key = keys::receipt(action_id);
        self.get_plain(&key)
    }

    /// Low-level write used by bootstrap restore (bypasses changelog).
    pub fn raw_put(&self, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        let stored = self.encrypt_for_store(key, value)?;
        self.tree.insert(key, stored)?;
        Ok(())
    }

    /// Low-level delete used by bootstrap restore (bypasses changelog).
    pub fn raw_del(&self, key: &[u8]) -> Result<(), StoreError> {
        let _ = self.tree.remove(key)?;
        Ok(())
    }

    pub fn changelog_epoch(&self) -> Result<u64, StoreError> {
        Ok(changelog_epoch_get(&self.changelog)?)
    }

    pub fn set_changelog_epoch(&self, epoch: u64) -> Result<(), StoreError> {
        self.changelog
            .insert(CHANGELOG_EPOCH_KEY, epoch.to_be_bytes().to_vec())?;
        Ok(())
    }

    /// Drain all changelog entries for a specific epoch.
    ///
    /// Ordering is deterministic by `(epoch, seq)` as encoded in the changelog key.
    pub fn export_changelog_epoch_v1(
        &self,
        epoch: u64,
    ) -> Result<Vec<ChangelogEntryV1>, StoreError> {
        let mut out = Vec::new();
        let prefix = changelog_epoch_prefix(epoch);
        for r in self.changelog.scan_prefix(prefix) {
            let (_k, v) = r?;
            let e: ChangelogEntryV1 = serde_json::from_slice(&v)
                .map_err(|e| StoreError::Decode(format!("changelog decode failed: {e}")))?;
            out.push(e);
        }
        Ok(out)
    }

    pub fn delete_changelog_epoch(&self, epoch: u64) -> Result<(), StoreError> {
        let prefix = changelog_epoch_prefix(epoch);
        let keys: Vec<Vec<u8>> = self
            .changelog
            .scan_prefix(prefix)
            .filter_map(|r| r.ok().map(|(k, _)| k.to_vec()))
            .collect();
        for k in keys {
            let _ = self.changelog.remove(k)?;
        }
        Ok(())
    }

    pub(crate) fn tree(&self) -> &sled::Tree {
        &self.tree
    }

    pub(crate) fn changelog_tree(&self) -> &sled::Tree {
        &self.changelog
    }

    /// Flush pending writes to disk (best-effort).
    pub fn flush(&self) -> Result<(), StoreError> {
        self.tree.flush()?;
        Ok(())
    }

    /// Export the underlying sled tree as a deterministic KV stream (v1).
    ///
    /// Format (repeated records, big-endian lengths):
    /// - u32 key_len
    /// - u32 val_len
    /// - key bytes
    /// - val bytes
    ///
    /// Ordering: lexicographic by raw key bytes (sled iteration order).
    ///
    /// This is intended for operational snapshots (audit/recovery), not consensus.
    pub fn export_kv_v1<W: Write>(&self, w: &mut W) -> Result<(), StoreError> {
        for r in self.tree.iter() {
            let (k, v) = r?;
            let plain = self
                .decrypt_for_store(k.as_ref(), v.as_ref())
                .map_err(|e| StoreError::Decode(format!("kv export decrypt failed: {e}")))?;
            write_kv_record_v1(w, k.as_ref(), plain.as_slice())
                .map_err(|e| StoreError::Decode(format!("kv export write failed: {e}")))?;
        }
        Ok(())
    }

    /// Clear the underlying tree (dangerous).
    ///
    /// Intended for snapshot restore with explicit operator confirmation.
    pub fn clear_all(&self) -> Result<(), StoreError> {
        self.tree.clear()?;
        Ok(())
    }

    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.tree.is_empty())
    }

    /// Import a deterministic KV stream written by `export_kv_v1`.
    ///
    /// This overwrites any existing keys found in the stream.
    pub fn import_kv_v1(bytes: &[u8], path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let store = Self::open(path)?;
        for (k, v) in read_kv_records_v1(bytes)
            .map_err(|e| StoreError::Decode(format!("kv import decode failed: {e}")))?
        {
            // Snapshot import must not emit changelog entries (bootstrap deltas are separate).
            let stored = store.encrypt_for_store(&k, &v)?;
            store.tree.insert(k, stored)?;
        }
        Ok(store)
    }

    /// Import a deterministic KV stream written by `export_kv_v1` into this store.
    pub fn import_kv_v1_into(&self, bytes: &[u8]) -> Result<(), StoreError> {
        for (k, v) in read_kv_records_v1(bytes)
            .map_err(|e| StoreError::Decode(format!("kv import decode failed: {e}")))?
        {
            // Snapshot import must not emit changelog entries (bootstrap deltas are separate).
            let stored = self.encrypt_for_store(&k, &v)?;
            self.tree.insert(k, stored)?;
        }
        Ok(())
    }

    fn tx_put(&self, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        let stored = self.encrypt_for_store(key, value)?;
        let r: Result<(), TransactionError<String>> =
            (&self.tree, &self.changelog).transaction(|(t, c)| {
                let mut ctx = ChangelogTxCtx::load(c)
                    .map_err(|e| ConflictableTransactionError::Abort(e.to_string()))?;
                t.insert(key, stored.as_slice())?;
                ctx.record_put(c, key, value)
                    .map_err(|e| ConflictableTransactionError::Abort(e.to_string()))?;
                ctx.store(c)
                    .map_err(|e| ConflictableTransactionError::Abort(e.to_string()))?;
                Ok(())
            });
        match r {
            Ok(()) => Ok(()),
            Err(TransactionError::Storage(e)) => Err(StoreError::Db(e)),
            Err(TransactionError::Abort(e)) => {
                Err(StoreError::Decode(format!("changelog tx aborted: {e}")))
            }
        }
    }

    fn tx_del(&self, key: &[u8]) -> Result<(), StoreError> {
        let r: Result<(), TransactionError<String>> =
            (&self.tree, &self.changelog).transaction(|(t, c)| {
                let mut ctx = ChangelogTxCtx::load(c)
                    .map_err(|e| ConflictableTransactionError::Abort(e.to_string()))?;
                let _ = t.remove(key)?;
                ctx.record_del(c, key)
                    .map_err(|e| ConflictableTransactionError::Abort(e.to_string()))?;
                ctx.store(c)
                    .map_err(|e| ConflictableTransactionError::Abort(e.to_string()))?;
                Ok(())
            });
        match r {
            Ok(()) => Ok(()),
            Err(TransactionError::Storage(e)) => Err(StoreError::Db(e)),
            Err(TransactionError::Abort(e)) => {
                Err(StoreError::Decode(format!("changelog tx aborted: {e}")))
            }
        }
    }
}

pub mod keys {
    use super::*;

    pub fn asset(asset_id: AssetId32) -> Vec<u8> {
        format!("asset:{}", asset_id.to_hex()).into_bytes()
    }

    pub fn balance(asset_id: AssetId32, account: &str) -> Vec<u8> {
        format!("bal:{}:{account}", asset_id.to_hex()).into_bytes()
    }

    pub fn applied(action_id: ActionId) -> Vec<u8> {
        format!("applied:{}", action_id.to_hex()).into_bytes()
    }

    pub fn state_version() -> &'static [u8] {
        b"state_version"
    }

    pub fn delegation(from_account: &str, operator_account: &str, asset_id: AssetId32) -> Vec<u8> {
        format!(
            "delegation:{from_account}:{operator_account}:{}",
            asset_id.to_hex()
        )
        .into_bytes()
    }

    pub fn transfer_allow(asset_id: AssetId32, account: &str) -> Vec<u8> {
        format!("transfer_allow:{}:{account}", asset_id.to_hex()).into_bytes()
    }

    pub fn transfer_deny(asset_id: AssetId32, account: &str) -> Vec<u8> {
        format!("transfer_deny:{}:{account}", asset_id.to_hex()).into_bytes()
    }

    pub fn receipt(action_id: ActionId) -> Vec<u8> {
        format!("receipt:{}", action_id.to_hex()).into_bytes()
    }

    pub fn apply_receipt(action_id: ActionId) -> Vec<u8> {
        format!("apply_receipt:{}", action_id.to_hex()).into_bytes()
    }
}

fn encode_u128_be(v: u128) -> [u8; 16] {
    v.to_be_bytes()
}

fn decode_u128_be(v: &IVec) -> Result<u128, String> {
    if v.len() != 16 {
        return Err(format!("expected 16 bytes for u128, got {}", v.len()));
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(v.as_ref());
    Ok(u128::from_be_bytes(b))
}

fn changelog_epoch_get(changelog: &sled::Tree) -> Result<u64, sled::Error> {
    let Some(v) = changelog.get(CHANGELOG_EPOCH_KEY)? else {
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

pub(crate) struct ChangelogTxCtx {
    epoch: u64,
    next_seq: u64,
}

impl ChangelogTxCtx {
    pub(crate) fn load(
        changelog: &sled::transaction::TransactionalTree,
    ) -> Result<Self, sled::transaction::UnabortableTransactionError> {
        let epoch = changelog
            .get(CHANGELOG_EPOCH_KEY)?
            .and_then(|v| (v.len() == 8).then_some(v))
            .map(|v| {
                let mut b = [0u8; 8];
                b.copy_from_slice(v.as_ref());
                u64::from_be_bytes(b)
            })
            .unwrap_or(0);

        let seq = changelog
            .get(CHANGELOG_SEQ_KEY)?
            .and_then(|v| (v.len() == 8).then_some(v))
            .map(|v| {
                let mut b = [0u8; 8];
                b.copy_from_slice(v.as_ref());
                u64::from_be_bytes(b)
            })
            .unwrap_or(0);
        Ok(Self {
            epoch,
            next_seq: seq,
        })
    }

    pub(crate) fn store(
        &self,
        changelog: &sled::transaction::TransactionalTree,
    ) -> Result<(), sled::transaction::UnabortableTransactionError> {
        changelog.insert(CHANGELOG_SEQ_KEY, self.next_seq.to_be_bytes().to_vec())?;
        Ok(())
    }

    pub(crate) fn record_put(
        &mut self,
        changelog: &sled::transaction::TransactionalTree,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), sled::transaction::UnabortableTransactionError> {
        self.next_seq = self.next_seq.saturating_add(1);
        let entry_key = changelog_entry_key(self.epoch, self.next_seq);
        let value_hash = blake3::hash(value).to_hex().to_string();
        let entry = ChangelogEntryV1 {
            schema_version: CHANGELOG_VERSION_V1,
            epoch: self.epoch,
            seq: self.next_seq,
            op: ChangelogOp::Put.as_str().to_string(),
            key_hex: hex::encode(key),
            value_b64: Some(base64::engine::general_purpose::STANDARD.encode(value)),
            value_hash,
        };
        let bytes = serde_json::to_vec(&entry).unwrap_or_default();
        changelog.insert(entry_key, bytes)?;
        Ok(())
    }

    pub(crate) fn record_del(
        &mut self,
        changelog: &sled::transaction::TransactionalTree,
        key: &[u8],
    ) -> Result<(), sled::transaction::UnabortableTransactionError> {
        self.next_seq = self.next_seq.saturating_add(1);
        let entry_key = changelog_entry_key(self.epoch, self.next_seq);
        let entry = ChangelogEntryV1 {
            schema_version: CHANGELOG_VERSION_V1,
            epoch: self.epoch,
            seq: self.next_seq,
            op: ChangelogOp::Del.as_str().to_string(),
            key_hex: hex::encode(key),
            value_b64: None,
            value_hash: String::new(),
        };
        let bytes = serde_json::to_vec(&entry).unwrap_or_default();
        changelog.insert(entry_key, bytes)?;
        Ok(())
    }
}

fn write_kv_record_v1<W: Write>(w: &mut W, k: &[u8], v: &[u8]) -> std::io::Result<()> {
    let k_len = u32::try_from(k.len()).unwrap_or(u32::MAX);
    let v_len = u32::try_from(v.len()).unwrap_or(u32::MAX);
    w.write_all(&k_len.to_be_bytes())?;
    w.write_all(&v_len.to_be_bytes())?;
    w.write_all(k)?;
    w.write_all(v)?;
    Ok(())
}

type KvPairs = Vec<(Vec<u8>, Vec<u8>)>;

fn read_kv_records_v1(mut bytes: &[u8]) -> Result<KvPairs, String> {
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 8 {
            return Err("truncated kv record header".to_string());
        }
        let k_len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let v_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
        bytes = &bytes[8..];
        if bytes.len() < k_len.saturating_add(v_len) {
            return Err("truncated kv record payload".to_string());
        }
        let k = bytes[..k_len].to_vec();
        let v = bytes[k_len..k_len + v_len].to_vec();
        bytes = &bytes[k_len + v_len..];
        out.push((k, v));
    }
    Ok(out)
}

#[cfg(test)]
mod changelog_tests {
    use super::*;

    #[test]
    fn writes_emit_deterministic_changelog_entries() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FinStore::open(tmp.path()).expect("open");

        store.set_changelog_epoch(7).expect("epoch");
        store
            .add_transfer_allow(crate::types::Hex32([1u8; 32]), "acc-a")
            .expect("put");
        store
            .add_transfer_deny(crate::types::Hex32([1u8; 32]), "acc-b")
            .expect("put2");

        let entries = store.export_changelog_epoch_v1(7).expect("export");
        assert_eq!(entries.len(), 2);
        assert!(entries[0].seq < entries[1].seq);
        assert_eq!(entries[0].epoch, 7);
        assert_eq!(entries[0].op, "put");
        assert!(!entries[0].key_hex.is_empty());
        assert!(entries[0].value_b64.is_some());
    }
}
