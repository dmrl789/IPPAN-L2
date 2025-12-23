#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::ha::lock_provider::{LeaderInfo, LeaderLockProvider, LockProviderError, LockState};

const TREE_NAME: &str = "fin-node-ha";
const LOCK_KEY: &[u8] = b"ha:leader_lock";

#[derive(Debug, thiserror::Error)]
pub enum LeaderLockError {
    #[error("db error: {0}")]
    Db(#[from] sled::Error),
    #[error("serde error: {0}")]
    Serde(String),
}

impl From<LeaderLockError> for LockProviderError {
    fn from(e: LeaderLockError) -> Self {
        // Sled/serde errors are backend errors; callers should rely on logs + metrics.
        LockProviderError::Backend(e.to_string())
    }
}

pub trait Clock: Send + Sync + 'static {
    fn now_ms(&self) -> u64;
}

#[derive(Debug, Clone)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaderLease {
    pub holder_id: String,
    pub acquired_at_ms: u64,
    pub renew_at_ms: u64,
    pub expires_at_ms: u64,
    pub lease_ms: u64,
}

impl LeaderLease {
    fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

#[derive(Clone)]
pub struct LeaderLock {
    tree: sled::Tree,
    holder_id: String,
    lease_ms: u64,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for LeaderLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaderLock")
            .field("holder_id", &self.holder_id)
            .field("lease_ms", &self.lease_ms)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    Leader,
    Follower,
}

impl LeaderLock {
    pub fn open(
        db_dir: impl AsRef<std::path::Path>,
        holder_id: String,
        lease_ms: u64,
    ) -> Result<Self, LeaderLockError> {
        let db = sled::open(db_dir)?;
        Self::new(db, holder_id, lease_ms, Arc::new(SystemClock))
    }

    pub fn new(
        db: sled::Db,
        holder_id: String,
        lease_ms: u64,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, LeaderLockError> {
        let tree = db.open_tree(TREE_NAME)?;
        Ok(Self {
            tree,
            holder_id,
            lease_ms: lease_ms.max(1),
            clock,
        })
    }

    pub fn read_lease(&self) -> Result<Option<LeaderLease>, LeaderLockError> {
        let Some(v) = self.tree.get(LOCK_KEY)? else {
            return Ok(None);
        };
        Ok(Some(decode_lease(&v)?))
    }

    /// Best-effort acquire: if missing or expired, attempt CAS to become leader.
    pub fn try_acquire(&self) -> Result<Role, LeaderLockError> {
        let now = self.clock.now_ms();
        let cur = self.tree.get(LOCK_KEY)?;
        let cur_lease = cur.as_ref().map(|v| decode_lease(v.as_ref())).transpose()?;

        let can_acquire = match &cur_lease {
            None => true,
            Some(l) => l.is_expired(now),
        };
        if !can_acquire {
            return Ok(Role::Follower);
        }

        let acquired_at_ms = cur_lease.as_ref().map(|l| l.acquired_at_ms).unwrap_or(now);
        let new = LeaderLease {
            holder_id: self.holder_id.clone(),
            acquired_at_ms,
            renew_at_ms: now,
            expires_at_ms: now.saturating_add(self.lease_ms),
            lease_ms: self.lease_ms,
        };
        let new_bytes = encode_lease(&new)?;

        let expected = cur.as_ref().map(|v| v.as_ref());
        let cas = self
            .tree
            .compare_and_swap(LOCK_KEY, expected, Some(new_bytes))?;

        if cas.is_ok() && self.is_current_holder()? {
            Ok(Role::Leader)
        } else {
            Ok(Role::Follower)
        }
    }

    /// Renew the lease if we're currently the holder. Returns `true` if we remain leader.
    pub fn renew(&self) -> Result<bool, LeaderLockError> {
        let now = self.clock.now_ms();
        let cur = self.tree.get(LOCK_KEY)?;
        let Some(cur_bytes) = cur else {
            return Ok(false);
        };
        let cur_lease = decode_lease(&cur_bytes)?;
        if cur_lease.holder_id != self.holder_id {
            return Ok(false);
        }
        // If already expired, step down immediately (another node may acquire).
        if cur_lease.is_expired(now) {
            return Ok(false);
        }

        let next = LeaderLease {
            holder_id: self.holder_id.clone(),
            acquired_at_ms: cur_lease.acquired_at_ms,
            renew_at_ms: now,
            expires_at_ms: now.saturating_add(self.lease_ms),
            lease_ms: self.lease_ms,
        };
        let next_bytes = encode_lease(&next)?;

        let cas =
            self.tree
                .compare_and_swap(LOCK_KEY, Some(cur_bytes.as_ref()), Some(next_bytes))?;

        Ok(cas.is_ok() && self.is_current_holder()?)
    }

    fn is_current_holder(&self) -> Result<bool, LeaderLockError> {
        let now = self.clock.now_ms();
        let Some(v) = self.tree.get(LOCK_KEY)? else {
            return Ok(false);
        };
        let lease = decode_lease(&v)?;
        Ok(lease.holder_id == self.holder_id && !lease.is_expired(now))
    }
}

impl LeaderLockProvider for LeaderLock {
    fn provider_type(&self) -> &'static str {
        "sled"
    }

    fn try_acquire(&self, node_id: &str) -> crate::ha::lock_provider::Result<LockState> {
        if node_id != self.holder_id {
            return Err(LockProviderError::Misconfigured(format!(
                "node_id mismatch: provider holder_id={} but requested node_id={}",
                self.holder_id, node_id
            )));
        }
        let role = LeaderLock::try_acquire(self)?;
        Ok(match role {
            Role::Leader => LockState::Acquired,
            Role::Follower => LockState::NotLeader,
        })
    }

    fn renew(&self, node_id: &str) -> crate::ha::lock_provider::Result<LockState> {
        if node_id != self.holder_id {
            return Err(LockProviderError::Misconfigured(format!(
                "node_id mismatch: provider holder_id={} but requested node_id={}",
                self.holder_id, node_id
            )));
        }

        let now = self.clock.now_ms();
        let lease = self.read_lease()?;
        let Some(lease) = lease else {
            return Ok(LockState::Expired);
        };
        if lease.holder_id != node_id {
            return Ok(LockState::NotLeader);
        }
        if lease.is_expired(now) {
            return Ok(LockState::Expired);
        }

        let ok = LeaderLock::renew(self)?;
        if ok {
            return Ok(LockState::Acquired);
        }

        // Lost CAS / ownership: re-read to disambiguate.
        let after = self.read_lease()?;
        match after {
            None => Ok(LockState::Expired),
            Some(l) if l.holder_id != node_id => Ok(LockState::NotLeader),
            Some(l) if l.is_expired(now) => Ok(LockState::Expired),
            Some(_) => Ok(LockState::NotLeader),
        }
    }

    fn release(&self, node_id: &str) -> crate::ha::lock_provider::Result<()> {
        if node_id != self.holder_id {
            return Err(LockProviderError::Misconfigured(format!(
                "node_id mismatch: provider holder_id={} but requested node_id={}",
                self.holder_id, node_id
            )));
        }
        let cur = self.tree.get(LOCK_KEY).map_err(LeaderLockError::Db)?;
        let Some(cur_bytes) = cur else {
            return Ok(());
        };
        let cur_lease = decode_lease(&cur_bytes)?;
        if cur_lease.holder_id != node_id {
            return Ok(());
        }
        let _ = self
            .tree
            .compare_and_swap(
                LOCK_KEY,
                Some(cur_bytes.as_ref()),
                Option::<sled::IVec>::None,
            )
            .map_err(LeaderLockError::Db)?;
        Ok(())
    }

    fn current_holder(&self) -> crate::ha::lock_provider::Result<Option<LeaderInfo>> {
        let now = self.clock.now_ms();
        let lease = self.read_lease()?;
        let Some(lease) = lease else {
            return Ok(None);
        };
        if lease.is_expired(now) {
            return Ok(None);
        }
        Ok(Some(LeaderInfo {
            node_id: lease.holder_id,
            expires_at_ms: lease.expires_at_ms,
        }))
    }
}

fn encode_lease(l: &LeaderLease) -> Result<Vec<u8>, LeaderLockError> {
    serde_json::to_vec(l).map_err(|e| LeaderLockError::Serde(e.to_string()))
}

fn decode_lease(v: &[u8]) -> Result<LeaderLease, LeaderLockError> {
    serde_json::from_slice(v).map_err(|e| LeaderLockError::Serde(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestClock(std::sync::atomic::AtomicU64);

    impl TestClock {
        fn new(ms: u64) -> Self {
            Self(std::sync::atomic::AtomicU64::new(ms))
        }
        fn set(&self, ms: u64) {
            self.0.store(ms, std::sync::atomic::Ordering::SeqCst);
        }
        fn advance(&self, delta: u64) {
            self.0.fetch_add(delta, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[test]
    fn leader_lock_acquire_and_renew_and_expire() {
        let db = sled::Config::new().temporary(true).open().expect("db");
        let clock = Arc::new(TestClock::new(1_000));

        let a = LeaderLock::new(db.clone(), "node-a".to_string(), 15_000, clock.clone())
            .expect("lock a");
        let b = LeaderLock::new(db, "node-b".to_string(), 15_000, clock.clone()).expect("lock b");

        assert_eq!(a.try_acquire().unwrap(), Role::Leader);
        assert_eq!(b.try_acquire().unwrap(), Role::Follower);

        // Renew keeps leadership.
        clock.advance(1_000);
        assert!(a.renew().unwrap());
        assert!(!b.renew().unwrap());

        // After expiry, b can steal, and a must step down.
        // We renewed at t=2000, so expiry is 2000 + lease_ms.
        clock.set(2_000 + 15_000 + 1);
        assert_eq!(b.try_acquire().unwrap(), Role::Leader);
        assert!(!a.renew().unwrap());
    }
}
