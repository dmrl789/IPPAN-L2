#![forbid(unsafe_code)]

pub mod leader_lock;
pub mod lock_provider;
pub mod supervisor;

#[cfg(feature = "ha-redis")]
pub mod redis_lock;

#[cfg(feature = "ha-consul")]
pub mod consul_lock;

use crate::config::{HaConfig, HaLockProvider};
use crate::ha::lock_provider::LeaderLockProvider;
use std::sync::Arc;

pub fn build_lock_provider(cfg: &HaConfig) -> Result<Option<Arc<dyn LeaderLockProvider>>, String> {
    if !cfg.enabled {
        return Ok(None);
    }
    cfg.validate()?;

    match cfg.lock.provider {
        HaLockProvider::Sled => {
            let lock =
                leader_lock::LeaderLock::open(&cfg.lock_db_dir, cfg.node_id.clone(), cfg.lease_ms)
                    .map_err(|e| format!("failed to open sled leader lock db: {e}"))?;
            Ok(Some(Arc::new(lock)))
        }
        HaLockProvider::Redis => {
            #[cfg(feature = "ha-redis")]
            {
                let lease_ms = cfg.lock.redis.lease_ms.unwrap_or(cfg.lease_ms);
                let provider = redis_lock::RedisLockProvider::connect_and_validate(
                    cfg.lock.redis.url.clone(),
                    cfg.lock.redis.key.clone(),
                    lease_ms,
                    cfg.lock.redis.connect_timeout_ms,
                )
                .map_err(|e| format!("failed to init redis lock provider: {e}"))?;
                Ok(Some(Arc::new(provider)))
            }
            #[cfg(not(feature = "ha-redis"))]
            {
                Err("ha.lock.provider=redis requires feature ha-redis".to_string())
            }
        }
        HaLockProvider::Consul => {
            #[cfg(feature = "ha-consul")]
            {
                let provider = consul_lock::ConsulLockProvider::connect_and_validate(
                    cfg.lock.consul.address.clone(),
                    cfg.lock.consul.key.clone(),
                    cfg.lock.consul.session_ttl.clone(),
                    cfg.node_id.clone(),
                )
                .map_err(|e| format!("failed to init consul lock provider: {e}"))?;
                Ok(Some(Arc::new(provider)))
            }
            #[cfg(not(feature = "ha-consul"))]
            {
                Err("ha.lock.provider=consul requires feature ha-consul".to_string())
            }
        }
    }
}
