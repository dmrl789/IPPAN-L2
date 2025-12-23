#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

use crate::config::{HaConfig, HaWriteMode};
use crate::ha::lock_provider::{LeaderInfo, LeaderLockProvider, LockProviderError, LockState};
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

    pub(crate) fn set_from_holder(&self, is_leader: bool, holder: Option<LeaderInfo>) {
        let mut g = self.inner.write().expect("ha state lock");
        g.is_leader = is_leader;
        g.leader_id = holder.as_ref().map(|l| l.node_id.clone());
        g.expires_at_ms = holder.map(|l| l.expires_at_ms);
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
    lock: Option<Arc<dyn LeaderLockProvider>>,
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
        lock: Option<Arc<dyn LeaderLockProvider>>,
        global_stop: Arc<AtomicBool>,
    ) -> Self {
        // Ensure metrics are registered.
        let _ = &*metrics::HA_IS_LEADER;
        let _ = &*metrics::HA_LEADER_CHANGES_TOTAL;
        let _ = &*metrics::HA_LOCK_ACQUIRE_FAILURES_TOTAL;
        let _ = &*metrics::HA_LOCK_PROVIDER;
        let _ = &*metrics::HA_LOCK_ERRORS_TOTAL;

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
            self.state.set_from_holder(false, None);
            metrics::HA_IS_LEADER.set(0);
            return;
        }
        let Some(lock) = self.lock.clone() else {
            // HA enabled but no lock configured (treated as follower).
            self.state.set_from_holder(false, None);
            metrics::HA_IS_LEADER.set(0);
            return;
        };

        set_provider_metric(lock.provider_type());

        if self.leader_tasks.is_running() {
            // Renew if leader; otherwise step down.
            match lock.renew(self.state.node_id()) {
                Ok(LockState::Acquired) => {
                    let holder = lock.current_holder().ok().flatten();
                    self.state.set_from_holder(true, holder);
                    metrics::HA_IS_LEADER.set(1);
                }
                Ok(LockState::NotLeader | LockState::Expired | LockState::Error) => {
                    self.step_down(lock.as_ref(), None);
                }
                Err(e) => {
                    record_lock_error(lock.provider_type(), &e);
                    warn!(event = "ha_lock_renew_failed", error = %e);
                    self.step_down(lock.as_ref(), None);
                }
            }
            return;
        }

        // Follower: attempt to acquire when lease is missing/expired.
        let cur_holder = match lock.current_holder() {
            Ok(h) => h,
            Err(e) => {
                record_lock_error(lock.provider_type(), &e);
                warn!(event = "ha_lock_read_failed", error = %e);
                self.step_down(lock.as_ref(), None);
                return;
            }
        };

        let expired_or_missing = match &cur_holder {
            None => true,
            Some(l) => now_ms() >= l.expires_at_ms,
        };
        if expired_or_missing {
            match lock.try_acquire(self.state.node_id()) {
                Ok(LockState::Acquired) => {
                    info!(
                        event = "ha_became_leader",
                        node_id = self.state.node_id(),
                        provider = lock.provider_type()
                    );
                    metrics::HA_LEADER_CHANGES_TOTAL
                        .with_label_values(&["became_leader"])
                        .inc();
                    metrics::HA_IS_LEADER.set(1);
                    let holder = lock.current_holder().ok().flatten();
                    self.state.set_from_holder(true, holder);
                    self.leader_tasks.start(start_leader_tasks);
                    return;
                }
                Ok(LockState::NotLeader | LockState::Expired) => {
                    metrics::HA_LOCK_ACQUIRE_FAILURES_TOTAL
                        .with_label_values(&["contended"])
                        .inc();
                }
                Ok(LockState::Error) => {
                    metrics::HA_LOCK_ACQUIRE_FAILURES_TOTAL
                        .with_label_values(&["error"])
                        .inc();
                    metrics::HA_LOCK_ERRORS_TOTAL
                        .with_label_values(&[lock.provider_type(), "error_state"])
                        .inc();
                    warn!(
                        event = "ha_lock_acquire_failed",
                        error = "provider_error_state"
                    );
                }
                Err(e) => {
                    metrics::HA_LOCK_ACQUIRE_FAILURES_TOTAL
                        .with_label_values(&["error"])
                        .inc();
                    record_lock_error(lock.provider_type(), &e);
                    warn!(event = "ha_lock_acquire_failed", error = %e);
                }
            }
        }

        // Remain follower; publish current lease holder if known.
        let cur_holder = lock.current_holder().ok().flatten();
        self.state.set_from_holder(false, cur_holder);
        metrics::HA_IS_LEADER.set(0);
    }

    fn step_down(&mut self, lock: &dyn LeaderLockProvider, last_error: Option<&LockProviderError>) {
        if self.leader_tasks.is_running() {
            info!(
                event = "ha_stepping_down",
                node_id = self.state.node_id(),
                provider = lock.provider_type(),
                error = last_error.map(|e| e.to_string())
            );
            metrics::HA_LEADER_CHANGES_TOTAL
                .with_label_values(&["stepped_down"])
                .inc();
        }
        self.leader_tasks.stop_and_join();
        if let Err(e) = lock.release(self.state.node_id()) {
            record_lock_error(lock.provider_type(), &e);
            warn!(event = "ha_lock_release_failed", error = %e);
        }
        let holder = lock.current_holder().ok().flatten();
        self.state.set_from_holder(false, holder);
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
                self.step_down(lock.as_ref(), None);
            } else {
                self.leader_tasks.stop_and_join();
            }
            info!(event = "ha_supervisor_stopped");
        })
    }
}

fn set_provider_metric(provider: &'static str) {
    // Ensure the gauge is 1 for the active provider and 0 for others.
    // (We keep the label set small and stable for dashboards.)
    for p in ["sled", "redis", "consul", "unknown"] {
        let v = if p == provider { 1 } else { 0 };
        metrics::HA_LOCK_PROVIDER.with_label_values(&[p]).set(v);
    }
}

fn record_lock_error(provider: &'static str, err: &LockProviderError) {
    metrics::HA_LOCK_ERRORS_TOTAL
        .with_label_values(&[provider, err.reason()])
        .inc();
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
    use crate::ha::lock_provider::{LeaderLockProvider, LockProviderError, LockState};

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
        let mut sup_a = HaSupervisor::new(state_a.clone(), Some(Arc::new(lock_a)), stop.clone());
        let mut sup_b = HaSupervisor::new(state_b.clone(), Some(Arc::new(lock_b)), stop);

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
        state.set_from_holder(
            false,
            Some(LeaderInfo {
                node_id: "node-b".to_string(),
                expires_at_ms: u64::MAX,
            }),
        );

        assert!(!state.is_leader());
        assert_eq!(state.write_mode(), HaWriteMode::LeaderOnly);
        assert_eq!(state.leader_id(), Some("node-b".to_string()));
    }

    #[derive(Debug)]
    struct MockProvider {
        lease_ms: u64,
        now_ms: std::sync::atomic::AtomicU64,
        force_error: std::sync::atomic::AtomicBool,
        inner: std::sync::Mutex<Option<(String, u64)>>,
    }

    impl MockProvider {
        fn new(now_ms: u64, lease_ms: u64) -> Self {
            Self {
                lease_ms: lease_ms.max(1),
                now_ms: std::sync::atomic::AtomicU64::new(now_ms),
                force_error: std::sync::atomic::AtomicBool::new(false),
                inner: std::sync::Mutex::new(None),
            }
        }

        fn set_holder(&self, node_id: &str) {
            let now = self.now_ms.load(std::sync::atomic::Ordering::SeqCst);
            *self.inner.lock().unwrap() = Some((node_id.to_string(), now + self.lease_ms));
        }

        fn set_force_error(&self, v: bool) {
            self.force_error
                .store(v, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl LeaderLockProvider for MockProvider {
        fn provider_type(&self) -> &'static str {
            "mock"
        }

        fn try_acquire(&self, node_id: &str) -> crate::ha::lock_provider::Result<LockState> {
            if self.force_error.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(LockProviderError::Connection("forced".to_string()));
            }
            let now = self.now_ms.load(std::sync::atomic::Ordering::SeqCst);
            let mut g = self.inner.lock().unwrap();
            let can = match &*g {
                None => true,
                Some((_id, exp)) => now >= *exp,
            };
            if !can {
                return Ok(LockState::NotLeader);
            }
            *g = Some((node_id.to_string(), now + self.lease_ms));
            Ok(LockState::Acquired)
        }

        fn renew(&self, node_id: &str) -> crate::ha::lock_provider::Result<LockState> {
            if self.force_error.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(LockProviderError::Connection("forced".to_string()));
            }
            let now = self.now_ms.load(std::sync::atomic::Ordering::SeqCst);
            let mut g = self.inner.lock().unwrap();
            let Some((id, exp)) = &*g else {
                return Ok(LockState::Expired);
            };
            if now >= *exp {
                *g = None;
                return Ok(LockState::Expired);
            }
            if id != node_id {
                return Ok(LockState::NotLeader);
            }
            *g = Some((node_id.to_string(), now + self.lease_ms));
            Ok(LockState::Acquired)
        }

        fn release(&self, node_id: &str) -> crate::ha::lock_provider::Result<()> {
            let mut g = self.inner.lock().unwrap();
            if let Some((id, _)) = &*g {
                if id == node_id {
                    *g = None;
                }
            }
            Ok(())
        }

        fn current_holder(&self) -> crate::ha::lock_provider::Result<Option<LeaderInfo>> {
            if self.force_error.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(LockProviderError::Connection("forced".to_string()));
            }
            let now = self.now_ms.load(std::sync::atomic::Ordering::SeqCst);
            let mut g = self.inner.lock().unwrap();
            let Some((id, exp)) = &*g else {
                return Ok(None);
            };
            if now >= *exp {
                *g = None;
                return Ok(None);
            }
            Ok(Some(LeaderInfo {
                node_id: id.clone(),
                expires_at_ms: *exp,
            }))
        }
    }

    #[test]
    fn leader_steps_down_on_lost_lock() {
        let provider = Arc::new(MockProvider::new(1_000, 15_000));

        let cfg = HaConfig {
            enabled: true,
            lease_ms: 15_000,
            node_id: "node-a".to_string(),
            ..HaConfig::default()
        };
        let state = Arc::new(HaState::new(cfg));
        let stop = Arc::new(AtomicBool::new(false));
        let mut sup = HaSupervisor::new(state.clone(), Some(provider.clone()), stop);

        let mut starts = 0u64;
        sup.tick(|_t| {
            starts += 1;
            Vec::new()
        });
        assert!(state.is_leader());
        assert_eq!(starts, 1);

        // Simulate lock stolen by another node (split-brain / external takeover).
        provider.set_holder("node-b");
        sup.tick(|_t| Vec::new());
        assert!(!state.is_leader());
    }

    #[test]
    fn leader_steps_down_on_provider_error() {
        let provider = Arc::new(MockProvider::new(1_000, 15_000));

        let cfg = HaConfig {
            enabled: true,
            lease_ms: 15_000,
            node_id: "node-a".to_string(),
            ..HaConfig::default()
        };
        let state = Arc::new(HaState::new(cfg));
        let stop = Arc::new(AtomicBool::new(false));
        let mut sup = HaSupervisor::new(state.clone(), Some(provider.clone()), stop);

        sup.tick(|_t| Vec::new());
        assert!(state.is_leader());

        // Provider becomes unreachable after leadership acquired -> step down safely.
        provider.set_force_error(true);
        sup.tick(|_t| Vec::new());
        assert!(!state.is_leader());
    }
}
