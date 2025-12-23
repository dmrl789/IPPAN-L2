#![forbid(unsafe_code)]
// Uses integer-only scoring (no floats).

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum MirrorHealthError {
    #[error("db error: {0}")]
    Db(#[from] sled::Error),
    #[error("decode error: {0}")]
    Decode(String),
}

#[derive(Debug, Clone)]
pub struct MirrorHealthStore {
    tree: sled::Tree,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorHealthV1 {
    pub schema_version: u32,
    pub source: String,
    pub successes: u64,
    pub timeouts: u64,
    pub hash_mismatches: u64,
    pub avg_latency_ms: u64,
    pub score: i64,
    #[serde(default)]
    pub last_updated_ms: u64,
    #[serde(default)]
    pub last_hash_mismatch_ms: u64,
}

impl Default for MirrorHealthV1 {
    fn default() -> Self {
        Self {
            schema_version: 1,
            source: String::new(),
            successes: 0,
            timeouts: 0,
            hash_mismatches: 0,
            avg_latency_ms: 0,
            score: 0,
            last_updated_ms: 0,
            last_hash_mismatch_ms: 0,
        }
    }
}

impl MirrorHealthStore {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, MirrorHealthError> {
        let db = sled::open(path)?;
        let tree = db.open_tree("fin-node-bootstrap-mirror-health")?;
        Ok(Self { tree })
    }

    pub fn list(&self) -> Result<Vec<MirrorHealthV1>, MirrorHealthError> {
        let mut out = Vec::new();
        for r in self.tree.iter() {
            let (_k, v) = r?;
            let rec: MirrorHealthV1 = serde_json::from_slice(&v)
                .map_err(|e| MirrorHealthError::Decode(e.to_string()))?;
            out.push(rec);
        }
        out.sort_by(|a, b| b.score.cmp(&a.score).then(a.source.cmp(&b.source)));
        Ok(out)
    }

    pub fn reset(&self) -> Result<(), MirrorHealthError> {
        self.tree.clear()?;
        Ok(())
    }

    pub fn record_success(&self, source: &str, latency_ms: u64, now_ms: u64) -> Result<(), MirrorHealthError> {
        let mut rec = self.get_or_default(source)?;
        rec.successes = rec.successes.saturating_add(1);
        rec.avg_latency_ms = ewma_u64(rec.avg_latency_ms, latency_ms, 8);
        rec.score = rec.score.saturating_add(10);
        // Small latency penalty (integer).
        rec.score = rec.score.saturating_sub(i64::try_from(rec.avg_latency_ms / 250).unwrap_or(i64::MAX));
        rec.last_updated_ms = now_ms;
        self.put(&rec)?;
        Ok(())
    }

    pub fn record_timeout(&self, source: &str, now_ms: u64) -> Result<(), MirrorHealthError> {
        let mut rec = self.get_or_default(source)?;
        rec.timeouts = rec.timeouts.saturating_add(1);
        rec.score = rec.score.saturating_sub(5);
        rec.last_updated_ms = now_ms;
        self.put(&rec)?;
        Ok(())
    }

    pub fn record_hash_mismatch(&self, source: &str, now_ms: u64) -> Result<(), MirrorHealthError> {
        let mut rec = self.get_or_default(source)?;
        rec.hash_mismatches = rec.hash_mismatches.saturating_add(1);
        rec.score = rec.score.saturating_sub(100);
        rec.last_updated_ms = now_ms;
        rec.last_hash_mismatch_ms = now_ms;
        self.put(&rec)?;
        Ok(())
    }

    pub fn score_for(&self, source: &str) -> i64 {
        self.get(source).ok().flatten().map(|r| r.score).unwrap_or(0)
    }

    pub fn quarantined_recent_mismatch(&self, source: &str, now_ms: u64, window_ms: u64) -> bool {
        self.get(source)
            .ok()
            .flatten()
            .map(|r| now_ms.saturating_sub(r.last_hash_mismatch_ms) < window_ms)
            .unwrap_or(false)
    }

    fn get(&self, source: &str) -> Result<Option<MirrorHealthV1>, MirrorHealthError> {
        let k = key_for_source(source);
        let Some(v) = self.tree.get(k)? else { return Ok(None) };
        let rec: MirrorHealthV1 = serde_json::from_slice(&v)
            .map_err(|e| MirrorHealthError::Decode(e.to_string()))?;
        Ok(Some(rec))
    }

    fn get_or_default(&self, source: &str) -> Result<MirrorHealthV1, MirrorHealthError> {
        Ok(self.get(source)?.unwrap_or_else(|| MirrorHealthV1 {
            source: source.to_string(),
            ..MirrorHealthV1::default()
        }))
    }

    fn put(&self, rec: &MirrorHealthV1) -> Result<(), MirrorHealthError> {
        let k = key_for_source(&rec.source);
        let bytes = serde_json::to_vec(rec).map_err(|e| MirrorHealthError::Decode(e.to_string()))?;
        self.tree.insert(k, bytes)?;
        Ok(())
    }
}

fn key_for_source(source: &str) -> Vec<u8> {
    let h = blake3::hash(source.as_bytes()).to_hex().to_string();
    format!("bootstrap:mirror_health:{h}").into_bytes()
}

fn ewma_u64(prev: u64, cur: u64, alpha_den: u64) -> u64 {
    if prev == 0 {
        return cur;
    }
    // prev*(alpha_den-1)/alpha_den + cur/alpha_den
    prev.saturating_mul(alpha_den.saturating_sub(1))
        .saturating_div(alpha_den)
        .saturating_add(cur.saturating_div(alpha_den))
}

