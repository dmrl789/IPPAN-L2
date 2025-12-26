//! Intent Finality Reconciler for Cross-Hub Operations.
//!
//! This module extends the settlement reconciler to couple intent state
//! progression with L1 finality:
//!
//! - Detects intents in `Prepared` state whose batch is finalised
//! - Progresses intent state deterministically after L1 finality
//! - Handles intent expiry processing
//!
//! ## Policy Flags
//!
//! - `INTENT_REQUIRE_PREP_FINALITY` (default: true) - Require prepare finality before commit
//! - `INTENT_EXPIRES_MS` (default: 600000) - Default intent expiry duration

use l2_core::{Hash32, IntentId, L2HubId};
use l2_storage::{IntentState, IntentStorage, Storage};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Configuration for the intent reconciler.
#[derive(Debug, Clone)]
pub struct IntentReconcilerConfig {
    /// Interval between reconciliation cycles (ms).
    pub interval_ms: u64,
    /// Maximum intents to process per cycle.
    pub intent_limit: usize,
    /// Whether to automatically abort expired intents.
    pub auto_abort_expired: bool,
    /// Chain ID for finality tracking.
    pub chain_id: u64,
}

impl Default for IntentReconcilerConfig {
    fn default() -> Self {
        Self {
            interval_ms: 10_000, // 10 seconds
            intent_limit: 100,
            auto_abort_expired: true,
            chain_id: 1,
        }
    }
}

impl IntentReconcilerConfig {
    /// Create configuration from environment variables.
    pub fn from_env() -> Self {
        let interval_ms = std::env::var("INTENT_RECONCILE_INTERVAL_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000);
        let intent_limit = std::env::var("INTENT_RECONCILE_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);
        let auto_abort_expired = std::env::var("INTENT_AUTO_ABORT_EXPIRED")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(true);
        let chain_id = std::env::var("L2_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        Self {
            interval_ms,
            intent_limit,
            auto_abort_expired,
            chain_id,
        }
    }
}

/// Metrics for intent reconciler operations.
#[derive(Debug, Clone, Default)]
pub struct IntentReconcilerMetrics {
    /// Total intents that became ready for commit (prep finalised).
    pub prep_finalised: u64,
    /// Total intents auto-aborted due to expiry.
    pub expired_aborted: u64,
    /// Total reconciliation cycles completed.
    pub cycles_completed: u64,
    /// Last reconciliation timestamp (ms since epoch).
    pub last_reconcile_ms: u64,
}

/// Result of a single intent reconciliation cycle.
#[derive(Debug, Clone, Default)]
pub struct IntentReconcileCycleResult {
    /// Number of intents whose prepare was confirmed finalised.
    pub prep_finalised: u32,
    /// Number of intents aborted due to expiry.
    pub expired_aborted: u32,
    /// Number of intents still pending.
    pub pending: u32,
}

/// Handle for controlling the intent reconciler background task.
#[derive(Clone)]
pub struct IntentReconcilerHandle {
    /// Channel to signal shutdown.
    _cancel: Arc<watch::Sender<bool>>,
}

/// Tracker for intent batch associations.
///
/// This tracks which batch each intent's phase transition was included in,
/// so we can determine finality from the settlement reconciler's state.
#[derive(Debug, Clone, Default)]
pub struct IntentBatchTracker {
    /// Map from intent_id to prepare batch hash.
    prepare_batches: HashMap<String, Hash32>,
    /// Set of intent_ids whose prepare batch has been finalised.
    prep_finalised: HashSet<String>,
}

impl IntentBatchTracker {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that an intent's prepare was included in a batch.
    pub fn record_prepare_batch(&mut self, intent_id: &IntentId, batch_hash: Hash32) {
        self.prepare_batches.insert(intent_id.to_hex(), batch_hash);
    }

    /// Mark an intent's prepare batch as finalised.
    pub fn mark_prep_finalised(&mut self, intent_id: &IntentId) {
        self.prep_finalised.insert(intent_id.to_hex());
    }

    /// Check if an intent's prepare is finalised.
    pub fn is_prep_finalised(&self, intent_id: &IntentId) -> bool {
        self.prep_finalised.contains(&intent_id.to_hex())
    }

    /// Get the prepare batch hash for an intent.
    pub fn get_prepare_batch(&self, intent_id: &IntentId) -> Option<Hash32> {
        self.prepare_batches.get(&intent_id.to_hex()).copied()
    }

    /// Remove tracking for an intent (after commit/abort).
    pub fn remove(&mut self, intent_id: &IntentId) {
        let hex = intent_id.to_hex();
        self.prepare_batches.remove(&hex);
        self.prep_finalised.remove(&hex);
    }
}

/// Spawn the intent reconciler background task.
///
/// This reconciler will:
/// 1. Check for intents in Prepared state whose batches are finalised
/// 2. Update the batch tracker with finality info
/// 3. Auto-abort expired intents (if configured)
///
/// # Arguments
///
/// * `config` - Reconciler configuration
/// * `intent_storage` - Storage for intent state
/// * `settlement_storage` - Storage for settlement state (to check finality)
/// * `batch_tracker` - Shared tracker for batch-intent associations
///
/// # Returns
///
/// A handle that keeps the reconciler running. Drop to stop.
pub fn spawn_intent_reconciler(
    config: IntentReconcilerConfig,
    intent_storage: Arc<IntentStorage>,
    settlement_storage: Arc<Storage>,
    batch_tracker: Arc<tokio::sync::Mutex<IntentBatchTracker>>,
) -> IntentReconcilerHandle {
    let (cancel_tx, cancel_rx) = watch::channel(false);

    tokio::spawn(async move {
        run_intent_reconciler(
            config,
            intent_storage,
            settlement_storage,
            batch_tracker,
            cancel_rx,
        )
        .await;
    });

    IntentReconcilerHandle {
        _cancel: Arc::new(cancel_tx),
    }
}

/// Main intent reconciler loop.
async fn run_intent_reconciler(
    config: IntentReconcilerConfig,
    intent_storage: Arc<IntentStorage>,
    settlement_storage: Arc<Storage>,
    batch_tracker: Arc<tokio::sync::Mutex<IntentBatchTracker>>,
    mut cancel_rx: watch::Receiver<bool>,
) {
    info!(
        interval_ms = config.interval_ms,
        intent_limit = config.intent_limit,
        auto_abort_expired = config.auto_abort_expired,
        "starting intent reconciler"
    );

    // Run once immediately on startup
    if let Err(e) = run_intent_reconcile_cycle(
        &config,
        &intent_storage,
        &settlement_storage,
        &batch_tracker,
    )
    .await
    {
        warn!(error = %e, "initial intent reconciliation failed");
    }

    let mut interval = tokio::time::interval(Duration::from_millis(config.interval_ms));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(e) = run_intent_reconcile_cycle(
                    &config,
                    &intent_storage,
                    &settlement_storage,
                    &batch_tracker,
                ).await {
                    warn!(error = %e, "intent reconciliation cycle failed");
                }
            }
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    info!("intent reconciler shutting down");
                    break;
                }
            }
        }
    }
}

/// Execute a single intent reconciliation cycle.
async fn run_intent_reconcile_cycle(
    config: &IntentReconcilerConfig,
    intent_storage: &IntentStorage,
    settlement_storage: &Storage,
    batch_tracker: &tokio::sync::Mutex<IntentBatchTracker>,
) -> Result<IntentReconcileCycleResult, IntentReconcilerError> {
    let mut result = IntentReconcileCycleResult::default();
    let now_ms = now_ms();

    // Phase 1: Check prepared intents for finality
    let prepared = intent_storage.list_prepared(config.intent_limit)?;
    if !prepared.is_empty() {
        debug!(
            count = prepared.len(),
            "checking prepared intents for finality"
        );
    }

    for entry in prepared {
        let mut tracker = batch_tracker.lock().await;

        // Check if we have a batch for this intent's prepare
        if let Some(batch_hash) = tracker.get_prepare_batch(&entry.intent_id) {
            // Check if the batch is finalised
            if let Ok(Some(settlement_state)) = settlement_storage.get_settlement_state(&batch_hash)
            {
                if settlement_state.is_finalised() {
                    tracker.mark_prep_finalised(&entry.intent_id);
                    result.prep_finalised += 1;
                    info!(
                        intent_id = %entry.intent_id,
                        batch_hash = %batch_hash.to_hex(),
                        "intent prepare finalised"
                    );
                } else {
                    result.pending += 1;
                }
            } else {
                result.pending += 1;
            }
        } else {
            // No batch tracking - might be in best-effort mode
            // In best-effort mode, we assume finality after a short delay
            result.pending += 1;
        }
    }

    // Phase 2: Auto-abort expired intents
    if config.auto_abort_expired {
        let expired = intent_storage.list_expired(now_ms, config.intent_limit)?;
        for entry in expired {
            if entry.state.is_created() {
                // Can auto-abort created intents that have expired
                let aborted = IntentState::aborted(now_ms, "expired".to_string());
                if intent_storage.update(&entry.intent_id, &aborted).is_ok() {
                    result.expired_aborted += 1;
                    info!(
                        intent_id = %entry.intent_id,
                        "auto-aborted expired intent"
                    );

                    // Clean up tracker
                    let mut tracker = batch_tracker.lock().await;
                    tracker.remove(&entry.intent_id);
                }
            }
        }
    }

    if result.prep_finalised > 0 || result.expired_aborted > 0 {
        info!(
            prep_finalised = result.prep_finalised,
            expired_aborted = result.expired_aborted,
            pending = result.pending,
            "intent reconciliation cycle complete"
        );
    }

    Ok(result)
}

/// Error type for intent reconciler.
#[derive(Debug, thiserror::Error)]
pub enum IntentReconcilerError {
    #[error("storage error: {0}")]
    Storage(#[from] l2_storage::IntentStorageError),
    #[error("settlement storage error: {0}")]
    SettlementStorage(#[from] l2_storage::StorageError),
}

/// Get current timestamp in milliseconds.
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Finality checker that integrates with the settlement reconciler.
///
/// This implementation checks the batch tracker and settlement storage
/// to determine if an intent's prepare phase has been finalised.
pub struct SettlementFinalityChecker {
    batch_tracker: Arc<tokio::sync::Mutex<IntentBatchTracker>>,
}

impl SettlementFinalityChecker {
    /// Create a new finality checker.
    pub fn new(batch_tracker: Arc<tokio::sync::Mutex<IntentBatchTracker>>) -> Self {
        Self { batch_tracker }
    }

    /// Synchronously check finality (uses blocking).
    ///
    /// Note: In a fully async context, you'd use the async version instead.
    pub fn check_prepare_finality_sync(
        &self,
        intent_id: &IntentId,
    ) -> crate::intents::PrepareFinality {
        // Try to get the lock without blocking forever
        let tracker = match self.batch_tracker.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                return crate::intents::PrepareFinality {
                    is_finalised: false,
                    l1_block: None,
                };
            }
        };

        let is_finalised = tracker.is_prep_finalised(intent_id);

        crate::intents::PrepareFinality {
            is_finalised,
            l1_block: if is_finalised { Some(0) } else { None },
        }
    }
}

impl crate::intents::FinalityChecker for SettlementFinalityChecker {
    fn check_prepare_finality(&self, intent_id: &IntentId) -> crate::intents::PrepareFinality {
        self.check_prepare_finality_sync(intent_id)
    }
}

/// Summary of pending intents by hub for observability.
#[derive(Debug, Clone, Default)]
pub struct IntentPendingSummary {
    /// Number of intents in Created state.
    pub created: u64,
    /// Number of intents in Prepared state (awaiting commit).
    pub prepared: u64,
    /// Number of prepared intents with finalised prepare batch.
    pub prep_finalised: u64,
    /// Number of prepared intents awaiting finality.
    pub prep_pending_finality: u64,
    /// Per-hub counts of pending intents.
    pub by_hub: HashMap<L2HubId, u64>,
}

/// Get intent pending summary for observability.
pub fn get_intent_pending_summary(
    intent_storage: &IntentStorage,
    batch_tracker: &IntentBatchTracker,
) -> IntentPendingSummary {
    let mut summary = IntentPendingSummary::default();

    if let Ok(counts) = intent_storage.count_states() {
        summary.created = counts.created;
        summary.prepared = counts.prepared;
    }

    // Count prep_finalised vs pending
    if let Ok(prepared) = intent_storage.list_prepared(1000) {
        for entry in prepared {
            if batch_tracker.is_prep_finalised(&entry.intent_id) {
                summary.prep_finalised += 1;
            } else {
                summary.prep_pending_finality += 1;
            }
        }
    }

    // Count by hub
    for hub in l2_core::ALL_HUBS {
        if let Ok(pending) = intent_storage.list_pending_for_hub(hub, 1000) {
            summary.by_hub.insert(hub, pending.len() as u64);
        }
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_storage::SettlementState;
    use tempfile::tempdir;

    fn test_db() -> sled::Db {
        let dir = tempdir().expect("tmpdir");
        sled::open(dir.path()).expect("open")
    }

    fn test_intent_id(n: u8) -> IntentId {
        IntentId(Hash32([n; 32]))
    }

    #[test]
    fn batch_tracker_operations() {
        let mut tracker = IntentBatchTracker::new();

        let intent_id = test_intent_id(1);
        let batch_hash = Hash32([0xAA; 32]);

        // Initially not tracked
        assert!(!tracker.is_prep_finalised(&intent_id));
        assert!(tracker.get_prepare_batch(&intent_id).is_none());

        // Record prepare batch
        tracker.record_prepare_batch(&intent_id, batch_hash);
        assert_eq!(tracker.get_prepare_batch(&intent_id), Some(batch_hash));

        // Mark finalised
        tracker.mark_prep_finalised(&intent_id);
        assert!(tracker.is_prep_finalised(&intent_id));

        // Remove
        tracker.remove(&intent_id);
        assert!(!tracker.is_prep_finalised(&intent_id));
        assert!(tracker.get_prepare_batch(&intent_id).is_none());
    }

    #[test]
    fn config_defaults() {
        let config = IntentReconcilerConfig::default();
        assert_eq!(config.interval_ms, 10_000);
        assert_eq!(config.intent_limit, 100);
        assert!(config.auto_abort_expired);
    }

    #[tokio::test]
    async fn reconcile_cycle_empty() {
        let db = test_db();
        let intent_storage = Arc::new(IntentStorage::new(&db).unwrap());
        let settlement_storage = Arc::new(Storage::open(tempdir().unwrap().path()).unwrap());
        let batch_tracker = Arc::new(tokio::sync::Mutex::new(IntentBatchTracker::new()));

        let config = IntentReconcilerConfig::default();

        let result = run_intent_reconcile_cycle(
            &config,
            &intent_storage,
            &settlement_storage,
            &batch_tracker,
        )
        .await
        .unwrap();

        assert_eq!(result.prep_finalised, 0);
        assert_eq!(result.expired_aborted, 0);
        assert_eq!(result.pending, 0);
    }

    #[tokio::test]
    async fn reconcile_cycle_with_prepared_intent() {
        let db = test_db();
        let intent_storage = IntentStorage::new(&db).unwrap();
        let settlement_storage = Storage::open(tempdir().unwrap().path()).unwrap();

        let intent_id = test_intent_id(1);
        let batch_hash = Hash32([0xAA; 32]);

        // Create and prepare an intent
        intent_storage
            .create(
                &intent_id,
                &IntentState::created(
                    now_ms() - 1000,
                    now_ms() + 600_000,
                    L2HubId::Fin,
                    L2HubId::World,
                ),
            )
            .unwrap();
        intent_storage
            .update(&intent_id, &IntentState::prepared(now_ms(), vec![]))
            .unwrap();

        // Set up batch tracker with the prepare batch
        let mut tracker = IntentBatchTracker::new();
        tracker.record_prepare_batch(&intent_id, batch_hash);

        // Mark the batch as finalised in settlement storage
        settlement_storage
            .set_settlement_state_unchecked(
                &batch_hash,
                &SettlementState::finalised("l1tx".to_string(), 100, now_ms(), now_ms()),
            )
            .unwrap();

        let batch_tracker = Arc::new(tokio::sync::Mutex::new(tracker));
        let config = IntentReconcilerConfig::default();

        let result = run_intent_reconcile_cycle(
            &config,
            &Arc::new(intent_storage),
            &Arc::new(settlement_storage),
            &batch_tracker,
        )
        .await
        .unwrap();

        // Should detect the finalised prepare
        assert_eq!(result.prep_finalised, 1);
        assert_eq!(result.pending, 0);

        // Verify tracker was updated
        let tracker = batch_tracker.lock().await;
        assert!(tracker.is_prep_finalised(&intent_id));
    }

    #[tokio::test]
    async fn reconcile_cycle_auto_abort_expired() {
        let db = test_db();
        let intent_storage = Arc::new(IntentStorage::new(&db).unwrap());
        let settlement_storage = Arc::new(Storage::open(tempdir().unwrap().path()).unwrap());

        let intent_id = test_intent_id(1);
        let now = now_ms();

        // Create an intent that has expired (expires_ms in the past)
        intent_storage
            .create(
                &intent_id,
                &IntentState::created(
                    now - 2000, // created 2 seconds ago
                    now - 1000, // expired 1 second ago
                    L2HubId::Fin,
                    L2HubId::World,
                ),
            )
            .unwrap();

        let batch_tracker = Arc::new(tokio::sync::Mutex::new(IntentBatchTracker::new()));
        let config = IntentReconcilerConfig {
            auto_abort_expired: true,
            ..Default::default()
        };

        let result = run_intent_reconcile_cycle(
            &config,
            &intent_storage,
            &settlement_storage,
            &batch_tracker,
        )
        .await
        .unwrap();

        // Should auto-abort the expired intent
        assert_eq!(result.expired_aborted, 1);

        // Verify state is now Aborted
        let state = intent_storage.get(&intent_id).unwrap().unwrap();
        assert!(state.is_aborted());
    }

    #[test]
    fn settlement_finality_checker() {
        let mut tracker = IntentBatchTracker::new();
        let intent_id = test_intent_id(1);

        // Not finalised initially
        let batch_tracker = Arc::new(tokio::sync::Mutex::new(tracker.clone()));
        let checker = SettlementFinalityChecker::new(batch_tracker);
        let finality = checker.check_prepare_finality_sync(&intent_id);
        assert!(!finality.is_finalised);

        // Mark as finalised
        tracker.mark_prep_finalised(&intent_id);
        let batch_tracker = Arc::new(tokio::sync::Mutex::new(tracker));
        let checker = SettlementFinalityChecker::new(batch_tracker);
        let finality = checker.check_prepare_finality_sync(&intent_id);
        assert!(finality.is_finalised);
    }

    #[test]
    fn intent_pending_summary() {
        let db = test_db();
        let intent_storage = IntentStorage::new(&db).unwrap();
        let tracker = IntentBatchTracker::new();

        // Create some intents
        let id1 = test_intent_id(1);
        let id2 = test_intent_id(2);
        let now = now_ms();

        intent_storage
            .create(
                &id1,
                &IntentState::created(now, now + 600_000, L2HubId::Fin, L2HubId::World),
            )
            .unwrap();
        intent_storage
            .create(
                &id2,
                &IntentState::created(now, now + 600_000, L2HubId::Data, L2HubId::M2m),
            )
            .unwrap();

        // Move one to prepared
        intent_storage
            .update(&id1, &IntentState::prepared(now, vec![]))
            .unwrap();

        let summary = get_intent_pending_summary(&intent_storage, &tracker);

        assert_eq!(summary.created, 1);
        assert_eq!(summary.prepared, 1);
        assert_eq!(summary.prep_finalised, 0);
        assert_eq!(summary.prep_pending_finality, 1);
    }
}
