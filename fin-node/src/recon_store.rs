#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sled::transaction::ConflictableTransactionError;
use sled::transaction::TransactionError;
use sled::Transactional;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

pub const RECON_CHANGELOG_VERSION_V1: u32 = 1;

const CHANGELOG_EPOCH_KEY: &[u8] = b"changelog_epoch";
const CHANGELOG_SEQ_KEY: &[u8] = b"changelog_seq";
const CHANGELOG_PREFIX: &[u8] = b"changelog:";

#[derive(Debug, thiserror::Error)]
pub enum ReconStoreError {
    #[error("db error: {0}")]
    Db(#[from] sled::Error),
    #[error("serde error: {0}")]
    Serde(String),
}

/// A single deterministic change record written to the recon changelog.
///
/// This is an operational artifact used for incremental snapshots / bootstrap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconChangelogEntryV1 {
    pub schema_version: u32,
    pub epoch: u64,
    pub seq: u64,
    pub op: String,
    pub key_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_b64: Option<String>,
    pub value_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconKind {
    FinAction,
    DataAction,
    LinkagePurchase,
}

impl ReconKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ReconKind::FinAction => "fin_action",
            ReconKind::DataAction => "data_action",
            ReconKind::LinkagePurchase => "linkage_purchase",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconMetadata {
    /// Unix seconds when this item should be checked next.
    pub next_check_at: u64,
    /// Number of attempts performed so far.
    pub attempts: u32,
    /// Last observed error string (sanitized, non-sensitive).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_error: String,
}

impl ReconMetadata {
    pub fn new(now_secs: u64) -> Self {
        Self {
            next_check_at: now_secs,
            attempts: 0,
            last_error: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconItem {
    pub kind: ReconKind,
    pub id: String,
    pub meta: ReconMetadata,
}

#[derive(Debug, Clone)]
pub struct ReconStore {
    tree: sled::Tree,
    changelog: sled::Tree,
}

impl ReconStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReconStoreError> {
        let db = sled::open(path)?;
        let tree = db.open_tree("fin-node-recon")?;
        let changelog = db.open_tree("fin-node-recon-changelog")?;
        Ok(Self { tree, changelog })
    }

    #[allow(dead_code)]
    pub fn open_temporary() -> Result<Self, ReconStoreError> {
        let db = sled::Config::new().temporary(true).open()?;
        let tree = db.open_tree("fin-node-recon")?;
        let changelog = db.open_tree("fin-node-recon-changelog")?;
        Ok(Self { tree, changelog })
    }

    pub fn enqueue(
        &self,
        kind: ReconKind,
        id: &str,
        meta: &ReconMetadata,
    ) -> Result<(), ReconStoreError> {
        let k = key_pending(kind, id);
        let v = encode_meta(meta)?;
        self.tx_put(&k, &v)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn upsert_now(
        &self,
        kind: ReconKind,
        id: &str,
        now_secs: u64,
    ) -> Result<(), ReconStoreError> {
        let meta = ReconMetadata::new(now_secs);
        self.enqueue(kind, id, &meta)
    }

    #[allow(dead_code)]
    pub fn get(&self, kind: ReconKind, id: &str) -> Result<Option<ReconMetadata>, ReconStoreError> {
        let v = self.tree.get(key_pending(kind, id))?;
        let Some(v) = v else { return Ok(None) };
        Ok(Some(decode_meta(&v)?))
    }

    pub fn update(
        &self,
        kind: ReconKind,
        id: &str,
        meta: &ReconMetadata,
    ) -> Result<(), ReconStoreError> {
        self.enqueue(kind, id, meta)
    }

    pub fn dequeue(&self, kind: ReconKind, id: &str) -> Result<(), ReconStoreError> {
        let k = key_pending(kind, id);
        self.tx_del(&k)?;
        Ok(())
    }

    /// List pending items in stable key order with cursor pagination.
    ///
    /// Cursor format: `"{kind}:{id}"` where `kind` is snake_case (e.g. `fin_action`).
    pub fn list_pending_page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<ReconItem>, Option<String>), ReconStoreError> {
        let prefix = b"recon:pending:";
        let start = if let Some(after) = after {
            let mut s = Vec::new();
            s.extend_from_slice(prefix);
            s.extend_from_slice(after.as_bytes());
            s.push(0);
            s
        } else {
            prefix.to_vec()
        };

        let mut out = Vec::new();
        let mut next_cursor = None;

        for r in self.tree.range(start..) {
            let (k, v) = r?;
            if !k.starts_with(prefix) {
                break;
            }
            if let Some((kind, id)) = decode_key(&k) {
                out.push(ReconItem {
                    kind,
                    id,
                    meta: decode_meta(&v)?,
                });
            }
            if out.len() > limit {
                // Truncate to limit and compute next cursor from the last kept item.
                out.truncate(limit);
                if let Some(last) = out.last() {
                    next_cursor = Some(format!("{}:{}", last.kind.as_str(), last.id));
                }
                break;
            }
        }
        Ok((out, next_cursor))
    }

    /// Fetch up to `limit` due items (where `next_check_at <= now_secs`), sorted deterministically.
    pub fn fetch_due(
        &self,
        now_secs: u64,
        limit: usize,
        max_scan: usize,
    ) -> Result<Vec<ReconItem>, ReconStoreError> {
        let mut due: Vec<ReconItem> = Vec::new();
        for r in self.tree.scan_prefix(b"recon:pending:") {
            if due.len() >= max_scan {
                break;
            }
            let (k, v) = r?;
            let Some((kind, id)) = decode_key(&k) else {
                continue;
            };
            let meta = decode_meta(&v)?;
            if meta.next_check_at <= now_secs {
                due.push(ReconItem { kind, id, meta });
            }
        }
        due.sort_by(|a, b| {
            (a.meta.next_check_at, a.kind.as_str(), a.id.as_str()).cmp(&(
                b.meta.next_check_at,
                b.kind.as_str(),
                b.id.as_str(),
            ))
        });
        if due.len() > limit {
            due.truncate(limit);
        }
        Ok(due)
    }

    pub fn counts_by_kind(
        &self,
        max_scan: usize,
    ) -> Result<BTreeMap<ReconKind, u64>, ReconStoreError> {
        let mut m: BTreeMap<ReconKind, u64> = BTreeMap::new();
        for (scanned, r) in self.tree.scan_prefix(b"recon:pending:").enumerate() {
            if scanned >= max_scan {
                break;
            }
            let (k, _) = r?;
            if let Some((kind, _id)) = decode_key(&k) {
                *m.entry(kind).or_insert(0) += 1;
            }
        }
        Ok(m)
    }

    /// Flush pending writes to disk (best-effort).
    pub fn flush(&self) -> Result<(), ReconStoreError> {
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
    pub fn export_kv_v1<W: Write>(&self, w: &mut W) -> Result<(), ReconStoreError> {
        for r in self.tree.iter() {
            let (k, v) = r?;
            write_kv_record_v1(w, k.as_ref(), v.as_ref())
                .map_err(|e| ReconStoreError::Serde(e.to_string()))?;
        }
        Ok(())
    }

    /// Clear all recon entries (dangerous).
    pub fn clear_all(&self) -> Result<(), ReconStoreError> {
        self.tree.clear()?;
        Ok(())
    }

    pub fn is_empty(&self) -> Result<bool, ReconStoreError> {
        Ok(self.tree.is_empty())
    }

    /// Import a deterministic KV stream written by `export_kv_v1`.
    ///
    /// This overwrites any existing keys found in the stream.
    pub fn import_kv_v1(&self, bytes: &[u8]) -> Result<(), ReconStoreError> {
        for (k, v) in read_kv_records_v1(bytes).map_err(ReconStoreError::Serde)? {
            self.tree.insert(k, v)?;
        }
        Ok(())
    }

    /// Low-level write used by bootstrap restore (bypasses changelog).
    pub fn raw_put(&self, key: &[u8], value: &[u8]) -> Result<(), ReconStoreError> {
        self.tree.insert(key, value)?;
        Ok(())
    }

    /// Low-level delete used by bootstrap restore (bypasses changelog).
    pub fn raw_del(&self, key: &[u8]) -> Result<(), ReconStoreError> {
        let _ = self.tree.remove(key)?;
        Ok(())
    }

    pub fn changelog_epoch(&self) -> Result<u64, ReconStoreError> {
        Ok(changelog_epoch_get(&self.changelog)?)
    }

    pub fn set_changelog_epoch(&self, epoch: u64) -> Result<(), ReconStoreError> {
        self.changelog
            .insert(CHANGELOG_EPOCH_KEY, epoch.to_be_bytes().to_vec())?;
        Ok(())
    }

    pub fn export_changelog_epoch_v1(
        &self,
        epoch: u64,
    ) -> Result<Vec<ReconChangelogEntryV1>, ReconStoreError> {
        let mut out = Vec::new();
        let prefix = changelog_epoch_prefix(epoch);
        for r in self.changelog.scan_prefix(prefix) {
            let (_k, v) = r?;
            let e: ReconChangelogEntryV1 = serde_json::from_slice(&v)
                .map_err(|e| ReconStoreError::Serde(format!("changelog decode failed: {e}")))?;
            out.push(e);
        }
        Ok(out)
    }

    pub fn delete_changelog_epoch(&self, epoch: u64) -> Result<(), ReconStoreError> {
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

    fn tx_put(&self, key: &[u8], value: &[u8]) -> Result<(), ReconStoreError> {
        let r: Result<(), TransactionError<String>> =
            (&self.tree, &self.changelog).transaction(|(t, c)| {
                let mut ctx = ReconChangelogTxCtx::load(c)
                    .map_err(|e| ConflictableTransactionError::Abort(e.to_string()))?;
                t.insert(key, value)?;
                ctx.record_put(c, key, value)
                    .map_err(|e| ConflictableTransactionError::Abort(e.to_string()))?;
                ctx.store(c)
                    .map_err(|e| ConflictableTransactionError::Abort(e.to_string()))?;
                Ok(())
            });
        match r {
            Ok(()) => Ok(()),
            Err(TransactionError::Storage(e)) => Err(ReconStoreError::Db(e)),
            Err(TransactionError::Abort(e)) => {
                Err(ReconStoreError::Serde(format!("changelog tx aborted: {e}")))
            }
        }
    }

    fn tx_del(&self, key: &[u8]) -> Result<(), ReconStoreError> {
        let r: Result<(), TransactionError<String>> =
            (&self.tree, &self.changelog).transaction(|(t, c)| {
                let mut ctx = ReconChangelogTxCtx::load(c)
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
            Err(TransactionError::Storage(e)) => Err(ReconStoreError::Db(e)),
            Err(TransactionError::Abort(e)) => {
                Err(ReconStoreError::Serde(format!("changelog tx aborted: {e}")))
            }
        }
    }
}

fn key_pending(kind: ReconKind, id: &str) -> Vec<u8> {
    format!("recon:pending:{}:{id}", kind.as_str()).into_bytes()
}

fn decode_key(k: &[u8]) -> Option<(ReconKind, String)> {
    let s = std::str::from_utf8(k).ok()?;
    let s = s.strip_prefix("recon:pending:")?;
    let mut it = s.splitn(2, ':');
    let kind_s = it.next()?;
    let id = it.next()?.to_string();
    let kind = match kind_s {
        "fin_action" => ReconKind::FinAction,
        "data_action" => ReconKind::DataAction,
        "linkage_purchase" => ReconKind::LinkagePurchase,
        _ => return None,
    };
    Some((kind, id))
}

fn encode_meta(meta: &ReconMetadata) -> Result<Vec<u8>, ReconStoreError> {
    serde_json::to_vec(meta).map_err(|e| ReconStoreError::Serde(e.to_string()))
}

fn decode_meta(v: &[u8]) -> Result<ReconMetadata, ReconStoreError> {
    serde_json::from_slice(v).map_err(|e| ReconStoreError::Serde(e.to_string()))
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

struct ReconChangelogTxCtx {
    epoch: u64,
    next_seq: u64,
}

impl ReconChangelogTxCtx {
    fn load(
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

    fn store(
        &self,
        changelog: &sled::transaction::TransactionalTree,
    ) -> Result<(), sled::transaction::UnabortableTransactionError> {
        changelog.insert(CHANGELOG_SEQ_KEY, self.next_seq.to_be_bytes().to_vec())?;
        Ok(())
    }

    fn record_put(
        &mut self,
        changelog: &sled::transaction::TransactionalTree,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), sled::transaction::UnabortableTransactionError> {
        self.next_seq = self.next_seq.saturating_add(1);
        let entry_key = changelog_entry_key(self.epoch, self.next_seq);
        let value_hash = blake3::hash(value).to_hex().to_string();
        let entry = ReconChangelogEntryV1 {
            schema_version: RECON_CHANGELOG_VERSION_V1,
            epoch: self.epoch,
            seq: self.next_seq,
            op: "put".to_string(),
            key_hex: hex::encode(key),
            value_b64: Some(base64::engine::general_purpose::STANDARD.encode(value)),
            value_hash,
        };
        let bytes = serde_json::to_vec(&entry).unwrap_or_default();
        changelog.insert(entry_key, bytes)?;
        Ok(())
    }

    fn record_del(
        &mut self,
        changelog: &sled::transaction::TransactionalTree,
        key: &[u8],
    ) -> Result<(), sled::transaction::UnabortableTransactionError> {
        self.next_seq = self.next_seq.saturating_add(1);
        let entry_key = changelog_entry_key(self.epoch, self.next_seq);
        let entry = ReconChangelogEntryV1 {
            schema_version: RECON_CHANGELOG_VERSION_V1,
            epoch: self.epoch,
            seq: self.next_seq,
            op: "del".to_string(),
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
mod tests {
    use super::*;

    #[test]
    fn list_pending_page_uses_cursor() {
        let store = ReconStore::open_temporary().expect("tmp recon");
        let meta = ReconMetadata::new(0);
        store
            .enqueue(ReconKind::FinAction, "aa", &meta)
            .expect("enqueue");
        store
            .enqueue(ReconKind::FinAction, "bb", &meta)
            .expect("enqueue");
        store
            .enqueue(ReconKind::FinAction, "cc", &meta)
            .expect("enqueue");

        let (p1, next) = store.list_pending_page(None, 2).expect("page1");
        assert_eq!(p1.len(), 2);
        assert!(next.is_some());

        let (p2, _) = store.list_pending_page(next.as_deref(), 2).expect("page2");
        assert_eq!(p2.len(), 1);
    }
}
