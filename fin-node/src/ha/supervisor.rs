#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

use crate::config::{HaConfig, HaWriteMode};
use crate::ha::leader_lock::{LeaderLease, LeaderLock, Role};
use crate::metrics;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct HaState {
    cfg: HaConfig,
    inner: Arc<RwLock<HaInner>>,
}

#[derive(Debug, Clone)]
struct HaInner {
    is_leader: bool,
    leader_id: Option<String>,
    expires_at_ms: Option<u64>,
}

impl HaState {
    pub fn new(cfg: HaConfig) -> Self {
        let inner = HaInner {
            is_leader: false,
            leader_id: None,
            expires_at_ms: None,
        };
        Self {
            cfg,
            inner: Arc::new(RwLock::new(inner)),
        }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    pub fn node_id(&self) -> &str {
        &self.cfg.node_id
    }

    pub fn lease_ms(&self) -> u64 {
        self.cfg.lease_ms
    }

    pub fn write_mode(&self) -> HaWriteMode {
        self.cfg.write_mode
    }

    pub fn is_leader(&self) -> bool {
        self.inner.read().map(|g| g.is_leader).unwrap_or(false)
    }

    pub fn leader_id(&self) -> Option<String> {
        self.inner.read().ok().and_then(|g| g.leader_id.clone())
    }

    pub fn leader_url(&self) -> Option<String> {
        let leader_id = self.leader_id()?;
        self.cfg.leader_urls.get(&leader_id).cloned()
    }

    pub fn snapshot(&self) -> HaStatusSnapshot {
        let now_ms = now_ms();
        let g = self.inner.read().ok();
        let (is_leader, leader_id, expires_in_ms) = match g {
            Some(g) => {
                let expires_in = g
                    .expires_at_ms
                    .map(|x| x.saturating_sub(now_ms))
                    .unwrap_or(0);
                (g.is_leader, g.leader_id.clone(), expires_in)
            }
            None => (false, None, 0),
        };
        HaStatusSnapshot {
            enabled: self.cfg.enabled,
            node_id: self.cfg.node_id.clone(),
            is_leader,
            leader_id,
            lease_ms: self.cfg.lease_ms,
            expires_in_ms,
        }
    }

    pub(crate) fn set_from_lease(&self, is_leader: bool, lease: Option<LeaderLease>) {
        let mut g = self.inner.write().expect("ha state lock");
        g.is_leader = is_leader;
        g.leader_id = lease.as_ref().map(|l| l.holder_id.clone());
        g.expires_at_ms = lease.map(|l| l.expires_at_ms);
    }
}

#[derive(Debug, Serialize)]
pub struct HaStatusSnapshot {
    pub enabled: bool,
    pub node_id: String,
    pub is_leader: bool,
    pub leader_id: Option<String>,
    pub lease_ms: u64,
    pub expires_in_ms: u64,
}

pub struct HaSupervisor {
    state: Arc<HaState>,
    lock: Option<LeaderLock>,
    global_stop: Arc<AtomicBool>,
    leader_tasks: LeaderTasks,
}

#[derive(Default)]
struct LeaderTasks {
    stop: Option<Arc<AtomicBool>>,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl LeaderTasks {
    fn start<F: FnOnce(Arc<AtomicBool>) -> Vec<std::thread::JoinHandle<()>>>(&mut self, f: F) {
        let stop = Arc::new(AtomicBool::new(false));
        let handles = f(stop.clone());
        self.stop = Some(stop);
        self.handles = handles;
    }

    fn stop_and_join(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }

    fn is_running(&self) -> bool {
        self.stop.is_some()
    }
}

impl HaSupervisor {
    pub fn new(
        state: Arc<HaState>,
        lock: Option<LeaderLock>,
        global_stop: Arc<AtomicBool>,
    ) -> Self {
        // Ensure metrics are registered.
        let _ = &*metrics::HA_IS_LEADER;
        let _ = &*metrics::HA_LEADER_CHANGES_TOTAL;
        let _ = &*metrics::HA_LOCK_ACQUIRE_FAILURES_TOTAL;

        Self {
            state,
            lock,
            global_stop,
            leader_tasks: LeaderTasks::default(),
        }
    }

    /// One election/renew iteration (deterministic and test-friendly).
    pub fn tick<F>(&mut self, start_leader_tasks: F)
    where
        F: FnOnce(Arc<AtomicBool>) -> Vec<std::thread::JoinHandle<()>>,
    {
        if !self.state.enabled() {
            self.state.set_from_lease(false, None);
            metrics::HA_IS_LEADER.set(0);
            return;
        }
        let Some(lock) = self.lock.clone() else {
            // HA enabled but no lock configured (treated as follower).
            self.state.set_from_lease(false, None);
            metrics::HA_IS_LEADER.set(0);
            return;
        };

        let cur_lease = match lock.read_lease() {
            Ok(l) => l,
            Err(e) => {
                warn!(event = "ha_lock_read_failed", error = %e);
                self.step_down(&lock);
                return;
            }
        };

        if self.leader_tasks.is_running() {
            // Renew if leader; otherwise step down.
            match lock.renew() {
                Ok(true) => {
                    let lease = lock.read_lease().ok().flatten();
                    self.state.set_from_lease(true, lease);
                    metrics::HA_IS_LEADER.set(1);
                }
                Ok(false) => {
                    self.step_down(&lock);
                }
                Err(e) => {
                    warn!(event = "ha_lock_renew_failed", error = %e);
                    self.step_down(&lock);
                }
            }
            return;
        }

        // Follower: attempt to acquire when lease is missing/expired.
        let expired_or_missing = match &cur_lease {
            None => true,
            Some(l) => now_ms() >= l.expires_at_ms,
        };
        if expired_or_missing {
            match lock.try_acquire() {
                Ok(Role::Leader) => {
                    info!(event = "ha_became_leader", node_id = lock.holder_id());
                    metrics::HA_LEADER_CHANGES_TOTAL
                        .with_label_values(&["became_leader"])
                        .inc();
                    metrics::HA_IS_LEADER.set(1);
                    let lease = lock.read_lease().ok().flatten();
                    self.state.set_from_lease(true, lease);
                    self.leader_tasks.start(start_leader_tasks);
                    return;
                }
                Ok(Role::Follower) => {
                    metrics::HA_LOCK_ACQUIRE_FAILURES_TOTAL
                        .with_label_values(&["contended"])
                        .inc();
                }
                Err(e) => {
                    metrics::HA_LOCK_ACQUIRE_FAILURES_TOTAL
                        .with_label_values(&["error"])
                        .inc();
                    warn!(event = "ha_lock_acquire_failed", error = %e);
                }
            }
        }

        // Remain follower; publish current lease holder if known.
        self.state.set_from_lease(false, cur_lease);
        metrics::HA_IS_LEADER.set(0);
    }

    fn step_down(&mut self, lock: &LeaderLock) {
        if self.leader_tasks.is_running() {
            info!(event = "ha_stepping_down", node_id = lock.holder_id());
            metrics::HA_LEADER_CHANGES_TOTAL
                .with_label_values(&["stepped_down"])
                .inc();
        }
        self.leader_tasks.stop_and_join();
        let lease = lock.read_lease().ok().flatten();
        self.state.set_from_lease(false, lease);
        metrics::HA_IS_LEADER.set(0);
    }

    /// Spawn a background thread that runs election/renew until `global_stop` is set.
    pub fn spawn<F>(mut self, mut start_leader_tasks: F) -> std::thread::JoinHandle<()>
    where
        F: FnMut(Arc<AtomicBool>) -> Vec<std::thread::JoinHandle<()>> + Send + 'static,
    {
        std::thread::spawn(move || {
            let lease_ms = self.state.lease_ms().max(1);
            let period_ms = u64::max(250, lease_ms / 3);
            info!(
                event = "ha_supervisor_started",
                enabled = self.state.enabled(),
                node_id = self.state.node_id(),
                lease_ms,
                period_ms
            );
            while !self.global_stop.load(Ordering::Relaxed) {
                let f = |stop: Arc<AtomicBool>| start_leader_tasks(stop);
                self.tick(f);
                sleep_ms_chunked(period_ms, &self.global_stop);
            }
            // Ensure leader tasks stop.
            if let Some(lock) = self.lock.clone() {
                self.step_down(&lock);
            } else {
                self.leader_tasks.stop_and_join();
            }
            info!(event = "ha_supervisor_stopped");
        })
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

fn sleep_ms_chunked(ms: u64, stop: &Arc<AtomicBool>) {
    let mut slept = 0u64;
    while slept < ms && !stop.load(Ordering::Relaxed) {
        let step = u64::min(250, ms.saturating_sub(slept));
        std::thread::sleep(std::time::Duration::from_millis(step));
        slept += step;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ha::leader_lock::{Clock, LeaderLock};

    #[derive(Debug)]
    struct TestClock(std::sync::atomic::AtomicU64);

    impl TestClock {
        fn new(ms: u64) -> Self {
            Self(std::sync::atomic::AtomicU64::new(ms))
        }
        fn set(&self, ms: u64) {
            self.0.store(ms, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[test]
    fn supervisor_failover_is_bounded_by_ttl() {
        let db = sled::Config::new().temporary(true).open().expect("db");
        let clock = Arc::new(TestClock::new(1_000));

        let lock_a = LeaderLock::new(db.clone(), "node-a".to_string(), 15_000, clock.clone())
            .expect("lock a");
        let lock_b =
            LeaderLock::new(db, "node-b".to_string(), 15_000, clock.clone()).expect("lock b");

        let cfg = HaConfig {
            enabled: true,
            lease_ms: 15_000,
            node_id: "node-a".to_string(),
            ..HaConfig::default()
        };

        let state_a = Arc::new(HaState::new(cfg.clone()));
        let state_b = Arc::new(HaState::new(HaConfig {
            node_id: "node-b".to_string(),
            ..cfg
        }));

        let stop = Arc::new(AtomicBool::new(false));
        let mut sup_a = HaSupervisor::new(state_a.clone(), Some(lock_a), stop.clone());
        let mut sup_b = HaSupervisor::new(state_b.clone(), Some(lock_b), stop);

        let mut runs_a = 0u64;
        let mut runs_b = 0u64;

        sup_a.tick(|_t| {
            runs_a += 1;
            Vec::new()
        });
        sup_b.tick(|_t| {
            runs_b += 1;
            Vec::new()
        });

        assert!(state_a.is_leader() ^ state_b.is_leader());

        // Simulate A "crash": stop ticking A, let time advance beyond TTL, B should acquire.
        clock.set(1_000 + 15_000 + 1);
        sup_b.tick(|_t| {
            runs_b += 1;
            Vec::new()
        });

        // A won't observe step-down unless it ticks (in a real crash, the process would stop).
        sup_a.tick(|_t| {
            runs_a += 1;
            Vec::new()
        });

        assert!(state_b.is_leader());
        assert!(!state_a.is_leader());
        assert!(runs_a >= 1);
        assert!(runs_b >= 1);
    }

    #[test]
    fn write_mode_leader_only_blocks_followers() {
        let cfg = HaConfig {
            enabled: true,
            write_mode: HaWriteMode::LeaderOnly,
            node_id: "node-a".to_string(),
            ..HaConfig::default()
        };

        let state = HaState::new(cfg);
        state.set_from_lease(
            false,
            Some(LeaderLease {
                holder_id: "node-b".to_string(),
                acquired_at_ms: 0,
                renew_at_ms: 0,
                expires_at_ms: u64::MAX,
                lease_ms: 15_000,
            }),
        );

        assert!(!state.is_leader());
        assert_eq!(state.write_mode(), HaWriteMode::LeaderOnly);
        assert_eq!(state.leader_id(), Some("node-b".to_string()));
    }
}
