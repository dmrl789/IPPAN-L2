//! Intent Protocol Observability Metrics.
//!
//! This module provides metrics for monitoring the cross-hub intent protocol.
//! All metrics use integer values to comply with the project's no-float policy.
//!
//! ## Key Metrics
//!
//! - Intent lifecycle counts (created, prepared, committed, aborted)
//! - Phase transition latencies (in milliseconds)
//! - Finality tracking
//! - Error rates by type
//!
//! ## Success Rate
//!
//! Success rate is expressed as basis points (0-10000) to avoid floats.
//! 10000 = 100.00%, 5000 = 50.00%, 0 = 0.00%

use l2_core::L2HubId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// Atomic counter for metrics.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// Increment the counter.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the current value.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    /// Add a specific value.
    pub fn add(&self, value: u64) {
        self.0.fetch_add(value, Ordering::Relaxed);
    }
}

/// Metrics for the intent protocol.
#[derive(Debug, Default)]
pub struct IntentMetrics {
    // ========== Lifecycle Counters ==========
    /// Total intents created.
    pub intents_created: Counter,
    /// Total intents prepared.
    pub intents_prepared: Counter,
    /// Total intents committed.
    pub intents_committed: Counter,
    /// Total intents aborted.
    pub intents_aborted: Counter,

    // ========== Error Counters ==========
    /// Total validation errors.
    pub validation_errors: Counter,
    /// Total prepare errors.
    pub prepare_errors: Counter,
    /// Total commit errors.
    pub commit_errors: Counter,
    /// Total abort errors.
    pub abort_errors: Counter,
    /// Total finality check failures.
    pub finality_check_failures: Counter,

    // ========== Latency Tracking ==========
    /// Sum of prepare latencies (ms).
    pub prepare_latency_ms_sum: Counter,
    /// Sum of commit latencies (ms).
    pub commit_latency_ms_sum: Counter,
    /// Sum of abort latencies (ms).
    pub abort_latency_ms_sum: Counter,

    // ========== Finality Metrics ==========
    /// Total intents whose prepare was finalised.
    pub prep_finality_achieved: Counter,
    /// Total intents committed after finality.
    pub commits_after_finality: Counter,

    // ========== Per-Hub Metrics ==========
    /// Pending intents by hub (updated periodically).
    hub_pending: RwLock<HashMap<L2HubId, u64>>,
}

impl IntentMetrics {
    /// Create a new metrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    // ========== Lifecycle Recording ==========

    /// Record an intent creation.
    pub fn record_create(&self) {
        self.intents_created.inc();
    }

    /// Record an intent prepare with latency.
    pub fn record_prepare(&self, latency_ms: u64) {
        self.intents_prepared.inc();
        self.prepare_latency_ms_sum.add(latency_ms);
    }

    /// Record an intent commit with latency.
    pub fn record_commit(&self, latency_ms: u64) {
        self.intents_committed.inc();
        self.commit_latency_ms_sum.add(latency_ms);
    }

    /// Record an intent abort with latency.
    pub fn record_abort(&self, latency_ms: u64) {
        self.intents_aborted.inc();
        self.abort_latency_ms_sum.add(latency_ms);
    }

    // ========== Error Recording ==========

    /// Record a validation error.
    pub fn record_validation_error(&self) {
        self.validation_errors.inc();
    }

    /// Record a prepare error.
    pub fn record_prepare_error(&self) {
        self.prepare_errors.inc();
    }

    /// Record a commit error.
    pub fn record_commit_error(&self) {
        self.commit_errors.inc();
    }

    /// Record an abort error.
    pub fn record_abort_error(&self) {
        self.abort_errors.inc();
    }

    /// Record a finality check failure.
    pub fn record_finality_check_failure(&self) {
        self.finality_check_failures.inc();
    }

    // ========== Finality Recording ==========

    /// Record that an intent's prepare was finalised.
    pub fn record_prep_finality(&self) {
        self.prep_finality_achieved.inc();
    }

    /// Record a commit that happened after finality.
    pub fn record_commit_after_finality(&self) {
        self.commits_after_finality.inc();
    }

    // ========== Hub Metrics ==========

    /// Update pending counts by hub.
    pub fn update_hub_pending(&self, counts: HashMap<L2HubId, u64>) {
        if let Ok(mut guard) = self.hub_pending.write() {
            *guard = counts;
        }
    }

    /// Get pending count for a specific hub.
    pub fn get_hub_pending(&self, hub: L2HubId) -> u64 {
        self.hub_pending
            .read()
            .ok()
            .and_then(|guard| guard.get(&hub).copied())
            .unwrap_or(0)
    }

    // ========== Snapshot ==========

    /// Get a snapshot of all metrics.
    pub fn snapshot(&self) -> IntentMetricsSnapshot {
        let hub_pending = self
            .hub_pending
            .read()
            .ok()
            .map(|guard| guard.clone())
            .unwrap_or_default();

        let prepared = self.intents_prepared.get();
        let committed = self.intents_committed.get();
        let aborted = self.intents_aborted.get();

        IntentMetricsSnapshot {
            intents_created: self.intents_created.get(),
            intents_prepared: prepared,
            intents_committed: committed,
            intents_aborted: aborted,
            validation_errors: self.validation_errors.get(),
            prepare_errors: self.prepare_errors.get(),
            commit_errors: self.commit_errors.get(),
            abort_errors: self.abort_errors.get(),
            finality_check_failures: self.finality_check_failures.get(),
            prepare_latency_ms_avg: if prepared > 0 {
                self.prepare_latency_ms_sum.get() / prepared
            } else {
                0
            },
            commit_latency_ms_avg: if committed > 0 {
                self.commit_latency_ms_sum.get() / committed
            } else {
                0
            },
            abort_latency_ms_avg: if aborted > 0 {
                self.abort_latency_ms_sum.get() / aborted
            } else {
                0
            },
            prep_finality_achieved: self.prep_finality_achieved.get(),
            commits_after_finality: self.commits_after_finality.get(),
            hub_pending,
        }
    }
}

/// Snapshot of intent metrics at a point in time.
///
/// All rates are expressed in basis points (0-10000) to avoid floats.
/// 10000 = 100.00%, 5000 = 50.00%, 0 = 0.00%
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentMetricsSnapshot {
    // Lifecycle counts
    pub intents_created: u64,
    pub intents_prepared: u64,
    pub intents_committed: u64,
    pub intents_aborted: u64,

    // Error counts
    pub validation_errors: u64,
    pub prepare_errors: u64,
    pub commit_errors: u64,
    pub abort_errors: u64,
    pub finality_check_failures: u64,

    // Average latencies (ms, integer)
    pub prepare_latency_ms_avg: u64,
    pub commit_latency_ms_avg: u64,
    pub abort_latency_ms_avg: u64,

    // Finality metrics
    pub prep_finality_achieved: u64,
    pub commits_after_finality: u64,

    // Per-hub pending
    pub hub_pending: HashMap<L2HubId, u64>,
}

impl IntentMetricsSnapshot {
    /// Get the total number of intents processed (terminal states).
    pub fn total_processed(&self) -> u64 {
        self.intents_committed.saturating_add(self.intents_aborted)
    }

    /// Get the total number of errors.
    pub fn total_errors(&self) -> u64 {
        self.validation_errors
            .saturating_add(self.prepare_errors)
            .saturating_add(self.commit_errors)
            .saturating_add(self.abort_errors)
    }

    /// Get the success rate in basis points (0-10000).
    ///
    /// 10000 = 100.00%, 5000 = 50.00%, 0 = 0.00%
    pub fn success_rate_bps(&self) -> u64 {
        let total = self.total_processed();
        if total == 0 {
            10000 // 100% success when nothing has failed
        } else {
            // committed * 10000 / total
            self.intents_committed.saturating_mul(10000) / total
        }
    }

    /// Check if any invariants are violated based on metrics.
    pub fn check_invariants(&self) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();

        // Invariant 1: committed + aborted <= prepared
        // This can temporarily be violated during processing, so we only check
        // when prepared > 0 and there's a significant mismatch
        let terminal = self.intents_committed.saturating_add(self.intents_aborted);
        if terminal > self.intents_prepared {
            violations.push(InvariantViolation {
                name: "terminal_vs_prepared".to_string(),
                description: format!(
                    "terminal ({}) > prepared ({})",
                    terminal, self.intents_prepared
                ),
                severity: InvariantSeverity::Error,
            });
        }

        // Invariant 2: prepared <= created
        if self.intents_prepared > self.intents_created {
            violations.push(InvariantViolation {
                name: "prepared_vs_created".to_string(),
                description: format!(
                    "prepared ({}) > created ({})",
                    self.intents_prepared, self.intents_created
                ),
                severity: InvariantSeverity::Error,
            });
        }

        // Invariant 3: commits_after_finality <= committed (when finality is required)
        if self.commits_after_finality > self.intents_committed {
            violations.push(InvariantViolation {
                name: "finality_commit_count".to_string(),
                description: format!(
                    "commits_after_finality ({}) > committed ({})",
                    self.commits_after_finality, self.intents_committed
                ),
                severity: InvariantSeverity::Error,
            });
        }

        violations
    }
}

/// An invariant violation detected in metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub name: String,
    pub description: String,
    pub severity: InvariantSeverity,
}

/// Severity level of an invariant violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvariantSeverity {
    /// Warning - may be transient.
    Warning,
    /// Error - should be investigated.
    Error,
    /// Critical - requires immediate attention.
    Critical,
}

/// Health status of the intent system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentHealthStatus {
    /// Whether the system is healthy.
    pub healthy: bool,
    /// Current metrics snapshot.
    pub metrics: IntentMetricsSnapshot,
    /// Any invariant violations.
    pub violations: Vec<InvariantViolation>,
    /// Human-readable status message.
    pub message: String,
}

impl IntentHealthStatus {
    /// Create a health status from metrics.
    pub fn from_metrics(metrics: IntentMetricsSnapshot) -> Self {
        let violations = metrics.check_invariants();
        let healthy = violations
            .iter()
            .all(|v| v.severity != InvariantSeverity::Critical);

        let success_pct = metrics.success_rate_bps() / 100; // Convert to whole percent for display
        let message = if violations.is_empty() {
            format!(
                "Intent system healthy. {} processed, {}% success rate",
                metrics.total_processed(),
                success_pct
            )
        } else {
            format!(
                "Intent system has {} violation(s). Check violations list.",
                violations.len()
            )
        };

        Self {
            healthy,
            metrics,
            violations,
            message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_operations() {
        let counter = Counter::default();
        assert_eq!(counter.get(), 0);

        counter.inc();
        assert_eq!(counter.get(), 1);

        counter.add(10);
        assert_eq!(counter.get(), 11);
    }

    #[test]
    fn metrics_lifecycle_recording() {
        let metrics = IntentMetrics::new();

        metrics.record_create();
        metrics.record_create();
        metrics.record_prepare(100);
        metrics.record_commit(50);
        metrics.record_abort(25);

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.intents_created, 2);
        assert_eq!(snapshot.intents_prepared, 1);
        assert_eq!(snapshot.intents_committed, 1);
        assert_eq!(snapshot.intents_aborted, 1);
    }

    #[test]
    fn metrics_error_recording() {
        let metrics = IntentMetrics::new();

        metrics.record_validation_error();
        metrics.record_prepare_error();
        metrics.record_commit_error();
        metrics.record_abort_error();
        metrics.record_finality_check_failure();

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.validation_errors, 1);
        assert_eq!(snapshot.prepare_errors, 1);
        assert_eq!(snapshot.commit_errors, 1);
        assert_eq!(snapshot.abort_errors, 1);
        assert_eq!(snapshot.finality_check_failures, 1);
        assert_eq!(snapshot.total_errors(), 4);
    }

    #[test]
    fn metrics_latency_averaging() {
        let metrics = IntentMetrics::new();

        metrics.record_prepare(100);
        metrics.record_prepare(200);
        metrics.record_prepare(300);

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.intents_prepared, 3);
        // Sum is 600, count is 3, average is 200
        assert_eq!(snapshot.prepare_latency_ms_avg, 200);
    }

    #[test]
    fn metrics_hub_pending() {
        let metrics = IntentMetrics::new();

        let mut counts = HashMap::new();
        counts.insert(L2HubId::Fin, 10);
        counts.insert(L2HubId::World, 5);

        metrics.update_hub_pending(counts);

        assert_eq!(metrics.get_hub_pending(L2HubId::Fin), 10);
        assert_eq!(metrics.get_hub_pending(L2HubId::World), 5);
        assert_eq!(metrics.get_hub_pending(L2HubId::Data), 0);
    }

    #[test]
    fn snapshot_success_rate_bps() {
        let metrics = IntentMetrics::new();

        // 80% success rate: 8 committed, 2 aborted
        for _ in 0..8 {
            metrics.record_create();
            metrics.record_prepare(10);
            metrics.record_commit(10);
        }
        for _ in 0..2 {
            metrics.record_create();
            metrics.record_prepare(10);
            metrics.record_abort(10);
        }

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.total_processed(), 10);
        assert_eq!(snapshot.success_rate_bps(), 8000); // 80.00%
    }

    #[test]
    fn snapshot_success_rate_empty() {
        let metrics = IntentMetrics::new();
        let snapshot = metrics.snapshot();

        // No intents processed = 100% success (nothing has failed)
        assert_eq!(snapshot.success_rate_bps(), 10000);
    }

    #[test]
    fn snapshot_invariant_checks_pass() {
        let metrics = IntentMetrics::new();

        // Normal lifecycle: created -> prepared -> committed
        for _ in 0..5 {
            metrics.record_create();
            metrics.record_prepare(10);
            metrics.record_commit(10);
        }

        let snapshot = metrics.snapshot();
        let violations = snapshot.check_invariants();

        assert!(violations.is_empty());
    }

    #[test]
    fn snapshot_invariant_violation_prepared_gt_created() {
        let snapshot = IntentMetricsSnapshot {
            intents_created: 5,
            intents_prepared: 10, // More prepared than created!
            intents_committed: 3,
            intents_aborted: 1,
            validation_errors: 0,
            prepare_errors: 0,
            commit_errors: 0,
            abort_errors: 0,
            finality_check_failures: 0,
            prepare_latency_ms_avg: 0,
            commit_latency_ms_avg: 0,
            abort_latency_ms_avg: 0,
            prep_finality_achieved: 0,
            commits_after_finality: 0,
            hub_pending: HashMap::new(),
        };

        let violations = snapshot.check_invariants();

        assert!(!violations.is_empty());
        assert!(violations.iter().any(|v| v.name == "prepared_vs_created"));
    }

    #[test]
    fn health_status_from_metrics() {
        let metrics = IntentMetrics::new();

        metrics.record_create();
        metrics.record_prepare(10);
        metrics.record_commit(10);

        let snapshot = metrics.snapshot();
        let health = IntentHealthStatus::from_metrics(snapshot);

        assert!(health.healthy);
        assert!(health.violations.is_empty());
    }

    #[test]
    fn health_status_with_violations() {
        let snapshot = IntentMetricsSnapshot {
            intents_created: 5,
            intents_prepared: 10, // Invariant violation
            intents_committed: 3,
            intents_aborted: 1,
            validation_errors: 0,
            prepare_errors: 0,
            commit_errors: 0,
            abort_errors: 0,
            finality_check_failures: 0,
            prepare_latency_ms_avg: 0,
            commit_latency_ms_avg: 0,
            abort_latency_ms_avg: 0,
            prep_finality_achieved: 0,
            commits_after_finality: 0,
            hub_pending: HashMap::new(),
        };

        let health = IntentHealthStatus::from_metrics(snapshot);

        assert!(health.healthy); // Error but not critical
        assert!(!health.violations.is_empty());
    }
}
