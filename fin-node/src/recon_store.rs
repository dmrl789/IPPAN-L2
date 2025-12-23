#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

use serde::{Deserialize, Serialize};
use sled::IVec;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ReconStoreError {
    #[error("db error: {0}")]
    Db(#[from] sled::Error),
    #[error("serde error: {0}")]
    Serde(String),
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
}

impl ReconStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReconStoreError> {
        let db = sled::open(path)?;
        let tree = db.open_tree("fin-node-recon")?;
        Ok(Self { tree })
    }

    #[allow(dead_code)]
    pub fn open_temporary() -> Result<Self, ReconStoreError> {
        let db = sled::Config::new().temporary(true).open()?;
        let tree = db.open_tree("fin-node-recon")?;
        Ok(Self { tree })
    }

    pub fn enqueue(
        &self,
        kind: ReconKind,
        id: &str,
        meta: &ReconMetadata,
    ) -> Result<(), ReconStoreError> {
        self.tree
            .insert(key_pending(kind, id), IVec::from(encode_meta(meta)?))?;
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
        let _ = self.tree.remove(key_pending(kind, id))?;
        Ok(())
    }

    /// List all pending items, bounded by `limit`.
    pub fn list_pending(&self, limit: usize) -> Result<Vec<ReconItem>, ReconStoreError> {
        let mut out = Vec::new();
        for r in self.tree.scan_prefix(b"recon:pending:") {
            let (k, v) = r?;
            if out.len() >= limit {
                break;
            }
            if let Some((kind, id)) = decode_key(&k) {
                out.push(ReconItem {
                    kind,
                    id,
                    meta: decode_meta(&v)?,
                });
            }
        }
        Ok(out)
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
