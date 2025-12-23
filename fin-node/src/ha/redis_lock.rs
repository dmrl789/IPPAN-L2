#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

use crate::ha::lock_provider::{
    LeaderInfo, LeaderLockProvider, LockProviderError, LockState, Result,
};
use std::sync::Arc;
use std::time::Duration;

/// Redis leader lock provider.
///
/// Algorithm:
/// - Acquire: `SET key value NX PX lease_ms`
/// - Renew: verify ownership via `GET`; then `SET key value XX PX lease_ms`
/// - Release: Lua CAS delete (delete only if value matches node_id)
///
/// Notes:
/// - We store only `node_id` as the value (no non-deterministic metadata).
/// - `current_holder()` uses `GET` + `PTTL` to compute `expires_at_ms`.
#[derive(Debug, Clone)]
pub struct RedisLockProvider {
    backend: Arc<dyn RedisBackend>,
    key: String,
    lease_ms: u64,
}

impl RedisLockProvider {
    pub fn connect_and_validate(
        url: String,
        key: String,
        lease_ms: u64,
        connect_timeout_ms: u64,
    ) -> Result<Self> {
        if url.trim().is_empty() {
            return Err(LockProviderError::Misconfigured(
                "redis url is empty".to_string(),
            ));
        }
        if key.trim().is_empty() {
            return Err(LockProviderError::Misconfigured(
                "redis key is empty".to_string(),
            ));
        }
        let lease_ms = lease_ms.max(1);
        let backend = Arc::new(RealRedisBackend::connect(url, connect_timeout_ms.max(1))?);
        backend.ping()?;
        Ok(Self {
            backend,
            key,
            lease_ms,
        })
    }

    #[cfg(test)]
    fn for_test(backend: Arc<dyn RedisBackend>, key: &str, lease_ms: u64) -> Self {
        Self {
            backend,
            key: key.to_string(),
            lease_ms: lease_ms.max(1),
        }
    }

    fn now_ms() -> u64 {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
    }
}

impl LeaderLockProvider for RedisLockProvider {
    fn provider_type(&self) -> &'static str {
        "redis"
    }

    fn try_acquire(&self, node_id: &str) -> Result<LockState> {
        let ok = self.backend.set_nx_px(&self.key, node_id, self.lease_ms)?;
        Ok(if ok {
            LockState::Acquired
        } else {
            LockState::NotLeader
        })
    }

    fn renew(&self, node_id: &str) -> Result<LockState> {
        let cur = self.backend.get(&self.key)?;
        let Some(cur) = cur else {
            return Ok(LockState::Expired);
        };
        if cur != node_id {
            return Ok(LockState::NotLeader);
        }
        let ok = self.backend.set_xx_px(&self.key, node_id, self.lease_ms)?;
        Ok(if ok {
            LockState::Acquired
        } else {
            // Key expired between GET and SET.
            LockState::Expired
        })
    }

    fn release(&self, node_id: &str) -> Result<()> {
        self.backend.del_if_value(&self.key, node_id)?;
        Ok(())
    }

    fn current_holder(&self) -> Result<Option<LeaderInfo>> {
        let holder = self.backend.get(&self.key)?;
        let Some(node_id) = holder else {
            return Ok(None);
        };
        let ttl_ms = self.backend.pttl_ms(&self.key)?;
        match ttl_ms {
            None => Ok(None),
            Some(0) => Ok(None),
            Some(ttl_ms) => {
                let expires_at_ms = Self::now_ms().saturating_add(ttl_ms);
                Ok(Some(LeaderInfo {
                    node_id,
                    expires_at_ms,
                }))
            }
        }
    }
}

trait RedisBackend: Send + Sync + std::fmt::Debug + 'static {
    fn ping(&self) -> Result<()>;
    fn set_nx_px(&self, key: &str, value: &str, lease_ms: u64) -> Result<bool>;
    fn set_xx_px(&self, key: &str, value: &str, lease_ms: u64) -> Result<bool>;
    fn get(&self, key: &str) -> Result<Option<String>>;
    /// Returns remaining TTL in milliseconds. `None` means key missing.
    fn pttl_ms(&self, key: &str) -> Result<Option<u64>>;
    fn del_if_value(&self, key: &str, value: &str) -> Result<()>;
}

#[derive(Debug)]
struct RealRedisBackend {
    client: redis::Client,
    timeout: Duration,
}

impl RealRedisBackend {
    fn connect(url: String, connect_timeout_ms: u64) -> Result<Self> {
        let client = redis::Client::open(url.as_str())
            .map_err(|e| LockProviderError::Misconfigured(e.to_string()))?;
        Ok(Self {
            client,
            timeout: Duration::from_millis(connect_timeout_ms),
        })
    }

    fn with_conn<T>(
        &self,
        f: impl FnOnce(&mut redis::Connection) -> redis::RedisResult<T>,
    ) -> Result<T> {
        let mut conn = self
            .client
            .get_connection_with_timeout(self.timeout)
            .map_err(map_redis_err)?;
        // Best-effort IO timeouts.
        let _ = conn.set_read_timeout(Some(self.timeout));
        let _ = conn.set_write_timeout(Some(self.timeout));
        f(&mut conn).map_err(map_redis_err)
    }
}

impl RedisBackend for RealRedisBackend {
    fn ping(&self) -> Result<()> {
        self.with_conn(|c| redis::cmd("PING").query::<String>(c))?;
        Ok(())
    }

    fn set_nx_px(&self, key: &str, value: &str, lease_ms: u64) -> Result<bool> {
        let r: Option<String> = self.with_conn(|c| {
            redis::cmd("SET")
                .arg(key)
                .arg(value)
                .arg("NX")
                .arg("PX")
                .arg(lease_ms)
                .query(c)
        })?;
        Ok(r.is_some())
    }

    fn set_xx_px(&self, key: &str, value: &str, lease_ms: u64) -> Result<bool> {
        let r: Option<String> = self.with_conn(|c| {
            redis::cmd("SET")
                .arg(key)
                .arg(value)
                .arg("XX")
                .arg("PX")
                .arg(lease_ms)
                .query(c)
        })?;
        Ok(r.is_some())
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        self.with_conn(|c| redis::cmd("GET").arg(key).query(c))
    }

    fn pttl_ms(&self, key: &str) -> Result<Option<u64>> {
        // PTTL returns:
        // -2 if key does not exist
        // -1 if key exists but has no associated expire
        let ms: i64 = self.with_conn(|c| redis::cmd("PTTL").arg(key).query(c))?;
        if ms == -2 {
            return Ok(None);
        }
        if ms == -1 {
            return Err(LockProviderError::Misconfigured(
                "redis key has no TTL (expected PX lease)".to_string(),
            ));
        }
        if ms <= 0 {
            return Ok(Some(0));
        }
        Ok(Some(u64::try_from(ms).unwrap_or(u64::MAX)))
    }

    fn del_if_value(&self, key: &str, value: &str) -> Result<()> {
        // Atomic CAS delete: only delete if value matches.
        let script = r#"
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
else
  return 0
end
"#;
        let _deleted: i64 = self.with_conn(|c| {
            redis::cmd("EVAL")
                .arg(script)
                .arg(1)
                .arg(key)
                .arg(value)
                .query(c)
        })?;
        Ok(())
    }
}

fn map_redis_err(e: redis::RedisError) -> LockProviderError {
    let msg = e.to_string();
    let m = msg.to_ascii_lowercase();
    if m.contains("timed out") || m.contains("timeout") {
        return LockProviderError::Timeout(msg);
    }
    if m.contains("connection") || m.contains("broken pipe") || m.contains("connection refused") {
        return LockProviderError::Connection(msg);
    }
    LockProviderError::Backend(msg)
}

// ===== tests (CI-safe; no real redis required) =====

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Mutex;

#[cfg(test)]
#[derive(Debug)]
struct FakeRedisBackend {
    // key -> (value, expires_at_ms)
    inner: Mutex<HashMap<String, (String, u64)>>,
    now_ms: std::sync::atomic::AtomicU64,
}

#[cfg(test)]
impl FakeRedisBackend {
    fn new(now_ms: u64) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            now_ms: std::sync::atomic::AtomicU64::new(now_ms),
        }
    }

    fn set_now(&self, now_ms: u64) {
        self.now_ms
            .store(now_ms, std::sync::atomic::Ordering::SeqCst);
    }

    fn now(&self) -> u64 {
        self.now_ms.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn gc_expired_locked(&self, m: &mut HashMap<String, (String, u64)>) {
        let now = self.now();
        m.retain(|_, (_v, exp)| now < *exp);
    }
}

#[cfg(test)]
impl RedisBackend for FakeRedisBackend {
    fn ping(&self) -> Result<()> {
        Ok(())
    }

    fn set_nx_px(&self, key: &str, value: &str, lease_ms: u64) -> Result<bool> {
        let mut m = self.inner.lock().unwrap();
        self.gc_expired_locked(&mut m);
        if m.contains_key(key) {
            return Ok(false);
        }
        let exp = self.now().saturating_add(lease_ms.max(1));
        m.insert(key.to_string(), (value.to_string(), exp));
        Ok(true)
    }

    fn set_xx_px(&self, key: &str, value: &str, lease_ms: u64) -> Result<bool> {
        let mut m = self.inner.lock().unwrap();
        self.gc_expired_locked(&mut m);
        let Some((cur, exp)) = m.get_mut(key) else {
            return Ok(false);
        };
        if cur != value {
            // In real redis we verify ownership before calling SET XX;
            // return false to ensure caller steps down.
            return Ok(false);
        }
        *exp = self.now().saturating_add(lease_ms.max(1));
        Ok(true)
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        let mut m = self.inner.lock().unwrap();
        self.gc_expired_locked(&mut m);
        Ok(m.get(key).map(|(v, _)| v.clone()))
    }

    fn pttl_ms(&self, key: &str) -> Result<Option<u64>> {
        let mut m = self.inner.lock().unwrap();
        self.gc_expired_locked(&mut m);
        let Some((_v, exp)) = m.get(key) else {
            return Ok(None);
        };
        Ok(Some(exp.saturating_sub(self.now())))
    }

    fn del_if_value(&self, key: &str, value: &str) -> Result<()> {
        let mut m = self.inner.lock().unwrap();
        self.gc_expired_locked(&mut m);
        let Some((cur, _exp)) = m.get(key) else {
            return Ok(());
        };
        if cur == value {
            m.remove(key);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redis_provider_single_leader_invariant_and_expiry() {
        let fake = Arc::new(FakeRedisBackend::new(1_000));
        let p = RedisLockProvider::for_test(fake.clone(), "k", 15_000);

        assert_eq!(p.try_acquire("node-a").unwrap(), LockState::Acquired);
        assert_eq!(p.try_acquire("node-b").unwrap(), LockState::NotLeader);
        assert_eq!(
            p.current_holder().unwrap().unwrap().node_id,
            "node-a".to_string()
        );

        // Renew keeps leadership and extends TTL.
        fake.set_now(2_000);
        assert_eq!(p.renew("node-a").unwrap(), LockState::Acquired);
        assert_eq!(p.renew("node-b").unwrap(), LockState::NotLeader);

        // After expiry, another node can acquire; old leader renew sees Expired.
        fake.set_now(2_000 + 15_000 + 1);
        assert_eq!(p.try_acquire("node-b").unwrap(), LockState::Acquired);
        assert_eq!(p.renew("node-a").unwrap(), LockState::NotLeader);
    }

    #[test]
    fn redis_provider_release_is_ownership_checked() {
        let fake = Arc::new(FakeRedisBackend::new(1_000));
        let p = RedisLockProvider::for_test(fake.clone(), "k", 15_000);

        assert_eq!(p.try_acquire("node-a").unwrap(), LockState::Acquired);
        p.release("node-b").unwrap(); // should not delete
        assert_eq!(p.try_acquire("node-b").unwrap(), LockState::NotLeader);

        p.release("node-a").unwrap(); // deletes
        assert_eq!(p.try_acquire("node-b").unwrap(), LockState::Acquired);
    }
}
