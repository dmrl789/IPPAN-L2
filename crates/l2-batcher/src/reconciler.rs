//! L1 Inclusion & Finality Reconciler for settlement lifecycle.
//!
//! This module provides a background reconciler task that:
//! - Polls L1 to track batch inclusion and finality
//! - Handles node restarts and crash recovery
//! - Resolves batches by idempotency key
//! - Updates settlement state machine transitions
//!
//! ## Reconciliation Flow
//!
//! ```text
//! On Startup / Periodic:
//!   1. List batches in Submitted state
//!   2. For each, query L1 for inclusion status
//!   3. If included, transition to Included state
//!   4. List batches in Included state
//!   5. For each, query L1 for finality status
//!   6. If finalised, transition to Finalised state
//! ```
//!
//! ## Crash Safety
//!
//! The reconciler is fully idempotent. On restart:
//! - In-flight batches are rediscovered from storage
//! - L1 state is authoritative for inclusion/finality
//! - No duplicate submissions are possible (idempotency keys)

use std::sync::Arc;
use std::time::Duration;

use l2_core::Hash32;
use l2_storage::{SettlementState, SettlementStateCounts, Storage};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::async_l1_client::AsyncL1Client;

/// Configuration for the settlement reconciler.
#[derive(Debug, Clone)]
pub struct SettlementReconcilerConfig {
    /// Interval between reconciliation cycles (ms).
    pub interval_ms: u64,
    /// Maximum batches to reconcile per cycle.
    pub batch_limit: usize,
    /// Timeout for considering a submitted batch as stale (ms).
    /// Stale batches may be retried or marked as failed.
    pub stale_threshold_ms: u64,
    /// Maximum retries before marking as failed.
    pub max_retries: u32,
    /// Number of confirmations required for finality.
    pub finality_confirmations: u64,
    /// Hub identifier for tracking last finalised batch.
    pub hub: String,
    /// Chain ID for tracking last finalised batch.
    pub chain_id: u64,
}

impl Default for SettlementReconcilerConfig {
    fn default() -> Self {
        Self {
            interval_ms: 10_000, // 10 seconds
            batch_limit: 100,
            stale_threshold_ms: 300_000, // 5 minutes
            max_retries: 3,
            finality_confirmations: 6, // 6 blocks for finality
            hub: "fin".to_string(),
            chain_id: 1,
        }
    }
}

impl SettlementReconcilerConfig {
    /// Create configuration from environment variables.
    pub fn from_env() -> Self {
        let interval_ms = std::env::var("L2_RECONCILE_INTERVAL_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000);
        let batch_limit = std::env::var("L2_RECONCILE_BATCH_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);
        let stale_threshold_ms = std::env::var("L2_RECONCILE_STALE_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300_000);
        let max_retries = std::env::var("L2_RECONCILE_MAX_RETRIES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);
        let finality_confirmations = std::env::var("L2_FINALITY_CONFIRMATIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(6);
        let hub = std::env::var("L2_HUB").unwrap_or_else(|_| "fin".to_string());
        let chain_id = std::env::var("L2_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        Self {
            interval_ms,
            batch_limit,
            stale_threshold_ms,
            max_retries,
            finality_confirmations,
            hub,
            chain_id,
        }
    }
}

/// Handle for controlling the reconciler background task.
#[derive(Clone)]
pub struct SettlementReconcilerHandle {
    /// Channel to signal shutdown.
    _cancel: Arc<watch::Sender<bool>>,
}

/// Metrics for reconciler operations.
#[derive(Debug, Clone, Default)]
pub struct ReconcilerMetrics {
    /// Total batches recovered from Submitted to Included.
    pub batches_included: u64,
    /// Total batches recovered from Included to Finalised.
    pub batches_finalised: u64,
    /// Total batches marked as failed.
    pub batches_failed: u64,
    /// Total reconciliation cycles completed.
    pub cycles_completed: u64,
    /// Last reconciliation timestamp (ms since epoch).
    pub last_reconcile_ms: u64,
}

/// Result of a single reconciliation cycle.
#[derive(Debug, Clone, Default)]
pub struct ReconcileCycleResult {
    /// Number of batches transitioned to Included.
    pub included: u32,
    /// Number of batches transitioned to Finalised.
    pub finalised: u32,
    /// Number of batches marked as Failed.
    pub failed: u32,
    /// Number of batches that remain in-flight.
    pub in_flight: u32,
}

/// Spawn the settlement reconciler background task.
///
/// The reconciler will:
/// 1. Run immediately on startup (to recover from crashes)
/// 2. Run periodically based on `config.interval_ms`
/// 3. Query L1 for batch status updates
/// 4. Update settlement states accordingly
///
/// # Arguments
///
/// * `config` - Reconciler configuration
/// * `storage` - Storage for settlement state persistence
/// * `l1_client` - L1 client for querying inclusion/finality
///
/// # Returns
///
/// A handle that keeps the reconciler running. Drop to stop.
pub fn spawn_settlement_reconciler<C>(
    config: SettlementReconcilerConfig,
    storage: Arc<Storage>,
    l1_client: Option<C>,
) -> SettlementReconcilerHandle
where
    C: AsyncL1Client + Send + Sync + 'static,
{
    let (cancel_tx, cancel_rx) = watch::channel(false);

    tokio::spawn(async move {
        run_settlement_reconciler(config, storage, l1_client, cancel_rx).await;
    });

    SettlementReconcilerHandle {
        _cancel: Arc::new(cancel_tx),
    }
}

/// Main reconciler loop.
async fn run_settlement_reconciler<C>(
    config: SettlementReconcilerConfig,
    storage: Arc<Storage>,
    l1_client: Option<C>,
    mut cancel_rx: watch::Receiver<bool>,
) where
    C: AsyncL1Client + Send + Sync,
{
    info!(
        interval_ms = config.interval_ms,
        batch_limit = config.batch_limit,
        finality_confirmations = config.finality_confirmations,
        "starting settlement reconciler"
    );

    // Run once immediately on startup (crash recovery)
    if let Err(e) = run_reconcile_cycle(&config, &storage, &l1_client).await {
        warn!(error = %e, "initial reconciliation failed");
    }

    let mut interval = tokio::time::interval(Duration::from_millis(config.interval_ms));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(e) = run_reconcile_cycle(&config, &storage, &l1_client).await {
                    warn!(error = %e, "reconciliation cycle failed");
                }
            }
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    info!("settlement reconciler shutting down");
                    break;
                }
            }
        }
    }
}

/// Execute a single reconciliation cycle.
async fn run_reconcile_cycle<C>(
    config: &SettlementReconcilerConfig,
    storage: &Storage,
    l1_client: &Option<C>,
) -> Result<ReconcileCycleResult, crate::BatcherError>
where
    C: AsyncL1Client + Send + Sync,
{
    let mut result = ReconcileCycleResult::default();
    let now_ms = now_ms();

    // Phase 1: Reconcile Submitted batches (check for inclusion)
    let submitted = storage.list_settlement_submitted(config.batch_limit)?;
    if !submitted.is_empty() {
        debug!(count = submitted.len(), "reconciling submitted batches");
    }

    for entry in submitted {
        match reconcile_submitted(
            &entry.batch_hash,
            &entry.state,
            storage,
            l1_client,
            config,
            now_ms,
        )
        .await
        {
            Ok(ReconcileAction::Included) => result.included += 1,
            Ok(ReconcileAction::Failed) => result.failed += 1,
            Ok(ReconcileAction::NoChange) => result.in_flight += 1,
            Ok(ReconcileAction::Finalised) => {
                // Submitted batches shouldn't jump directly to Finalised,
                // but count it anyway if it happens
                result.finalised += 1;
            }
            Err(e) => {
                warn!(
                    batch_hash = %entry.batch_hash.to_hex(),
                    error = %e,
                    "failed to reconcile submitted batch"
                );
                result.in_flight += 1;
            }
        }
    }

    // Phase 2: Reconcile Included batches (check for finality)
    let included = storage.list_settlement_included(config.batch_limit)?;
    if !included.is_empty() {
        debug!(count = included.len(), "reconciling included batches");
    }

    for entry in included {
        match reconcile_included(
            &entry.batch_hash,
            &entry.state,
            storage,
            l1_client,
            config,
            now_ms,
        )
        .await
        {
            Ok(ReconcileAction::Finalised) => result.finalised += 1,
            Ok(ReconcileAction::Failed) => result.failed += 1,
            Ok(ReconcileAction::NoChange) => result.in_flight += 1,
            Ok(ReconcileAction::Included) => {
                // Already included, no state change
                result.in_flight += 1;
            }
            Err(e) => {
                warn!(
                    batch_hash = %entry.batch_hash.to_hex(),
                    error = %e,
                    "failed to reconcile included batch"
                );
                result.in_flight += 1;
            }
        }
    }

    if result.included > 0 || result.finalised > 0 || result.failed > 0 {
        info!(
            included = result.included,
            finalised = result.finalised,
            failed = result.failed,
            in_flight = result.in_flight,
            "reconciliation cycle complete"
        );
    }

    Ok(result)
}

/// Result of reconciling a single batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileAction {
    /// Batch transitioned to Included.
    Included,
    /// Batch transitioned to Finalised.
    Finalised,
    /// Batch marked as Failed.
    Failed,
    /// No state change (still in-flight).
    NoChange,
}

/// Reconcile a batch in Submitted state.
async fn reconcile_submitted<C>(
    batch_hash: &Hash32,
    state: &SettlementState,
    storage: &Storage,
    l1_client: &Option<C>,
    config: &SettlementReconcilerConfig,
    now_ms: u64,
) -> Result<ReconcileAction, crate::BatcherError>
where
    C: AsyncL1Client + Send + Sync,
{
    let (l1_tx_id, submitted_at_ms, idempotency_key) = match state {
        SettlementState::Submitted {
            l1_tx_id,
            submitted_at_ms,
            idempotency_key,
        } => (l1_tx_id.clone(), *submitted_at_ms, idempotency_key.clone()),
        _ => return Ok(ReconcileAction::NoChange),
    };

    // Check if batch is stale
    let age_ms = now_ms.saturating_sub(submitted_at_ms);
    if age_ms > config.stale_threshold_ms {
        warn!(
            batch_hash = %batch_hash.to_hex(),
            age_ms = age_ms,
            threshold_ms = config.stale_threshold_ms,
            "batch submission is stale, marking as failed"
        );
        let failed = SettlementState::failed(
            format!("submission timed out after {}ms", age_ms),
            now_ms,
            0,
            Some(state.clone()),
        );
        storage.set_settlement_state_unchecked(batch_hash, &failed)?;
        return Ok(ReconcileAction::Failed);
    }

    // Query L1 for inclusion status
    let Some(client) = l1_client else {
        // No L1 client - best effort mode
        debug!(
            batch_hash = %batch_hash.to_hex(),
            "no L1 client available, assuming inclusion (best-effort mode)"
        );
        let included = SettlementState::included(l1_tx_id, 0, now_ms, now_ms);
        storage.set_settlement_state(batch_hash, &included)?;
        return Ok(ReconcileAction::Included);
    };

    // Try to get inclusion status by idempotency key
    match client.get_batch_status(&idempotency_key).await {
        Ok(status) => {
            if status.included {
                let included = SettlementState::included(
                    status.l1_tx_id.unwrap_or(l1_tx_id),
                    status.l1_block.unwrap_or(0),
                    status.ippan_time.unwrap_or(now_ms),
                    now_ms,
                );
                storage.set_settlement_state(batch_hash, &included)?;
                info!(
                    batch_hash = %batch_hash.to_hex(),
                    l1_block = status.l1_block.unwrap_or(0),
                    "batch included in L1 block"
                );
                return Ok(ReconcileAction::Included);
            }
            // Not included yet - keep waiting
            Ok(ReconcileAction::NoChange)
        }
        Err(e) => {
            debug!(
                batch_hash = %batch_hash.to_hex(),
                error = %e,
                "failed to query L1 batch status"
            );
            Ok(ReconcileAction::NoChange)
        }
    }
}

/// Reconcile a batch in Included state.
async fn reconcile_included<C>(
    batch_hash: &Hash32,
    state: &SettlementState,
    storage: &Storage,
    l1_client: &Option<C>,
    config: &SettlementReconcilerConfig,
    now_ms: u64,
) -> Result<ReconcileAction, crate::BatcherError>
where
    C: AsyncL1Client + Send + Sync,
{
    let (l1_tx_id, l1_block, ippan_time) = match state {
        SettlementState::Included {
            l1_tx_id,
            l1_block,
            ippan_time,
            ..
        } => (l1_tx_id.clone(), *l1_block, *ippan_time),
        _ => return Ok(ReconcileAction::NoChange),
    };

    let Some(client) = l1_client else {
        // No L1 client - best effort mode, assume finalised after inclusion
        debug!(
            batch_hash = %batch_hash.to_hex(),
            "no L1 client available, assuming finality (best-effort mode)"
        );
        let finalised = SettlementState::finalised(l1_tx_id.clone(), l1_block, ippan_time, now_ms);
        storage.set_settlement_state(batch_hash, &finalised)?;
        // Update last finalised batch
        storage.set_last_finalised_batch(&config.hub, config.chain_id, batch_hash, now_ms)?;
        return Ok(ReconcileAction::Finalised);
    };

    // Query L1 for finality status
    match client.get_finality_status(l1_block).await {
        Ok(finality) => {
            if finality.confirmations >= config.finality_confirmations {
                let finalised =
                    SettlementState::finalised(l1_tx_id.clone(), l1_block, ippan_time, now_ms);
                storage.set_settlement_state(batch_hash, &finalised)?;
                // Update last finalised batch
                storage.set_last_finalised_batch(
                    &config.hub,
                    config.chain_id,
                    batch_hash,
                    now_ms,
                )?;
                info!(
                    batch_hash = %batch_hash.to_hex(),
                    l1_block = l1_block,
                    confirmations = finality.confirmations,
                    "batch finalised"
                );
                return Ok(ReconcileAction::Finalised);
            }
            // Not enough confirmations yet
            debug!(
                batch_hash = %batch_hash.to_hex(),
                confirmations = finality.confirmations,
                required = config.finality_confirmations,
                "awaiting finality"
            );
            Ok(ReconcileAction::NoChange)
        }
        Err(e) => {
            debug!(
                batch_hash = %batch_hash.to_hex(),
                error = %e,
                "failed to query L1 finality status"
            );
            Ok(ReconcileAction::NoChange)
        }
    }
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

/// Get current settlement state counts.
pub fn get_settlement_counts(storage: &Storage) -> SettlementStateCounts {
    storage.count_settlement_states().unwrap_or_default()
}

/// Get information about in-flight batches for /status endpoint.
pub fn get_in_flight_summary(storage: &Storage, limit: usize) -> InFlightSummary {
    let submitted = storage.list_settlement_submitted(limit).unwrap_or_default();
    let included = storage.list_settlement_included(limit).unwrap_or_default();

    InFlightSummary {
        submitted_count: submitted.len(),
        included_count: included.len(),
        oldest_submitted_ms: submitted
            .iter()
            .filter_map(|e| {
                if let SettlementState::Submitted {
                    submitted_at_ms, ..
                } = &e.state
                {
                    Some(*submitted_at_ms)
                } else {
                    None
                }
            })
            .min(),
        oldest_included_ms: included
            .iter()
            .filter_map(|e| {
                if let SettlementState::Included { included_at_ms, .. } = &e.state {
                    Some(*included_at_ms)
                } else {
                    None
                }
            })
            .min(),
    }
}

/// Summary of in-flight batches for observability.
#[derive(Debug, Clone, Default)]
pub struct InFlightSummary {
    /// Number of batches awaiting inclusion.
    pub submitted_count: usize,
    /// Number of batches awaiting finality.
    pub included_count: usize,
    /// Timestamp of oldest submitted batch (ms).
    pub oldest_submitted_ms: Option<u64>,
    /// Timestamp of oldest included batch (ms).
    pub oldest_included_ms: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_l1_client::BlockingL1ClientAdapter;
    use l2_core::l1_contract::mock_client::MockL1Client;
    use tempfile::tempdir;

    // Type alias for tests
    type TestL1Client = BlockingL1ClientAdapter<MockL1Client>;

    fn test_storage() -> Arc<Storage> {
        let dir = tempdir().expect("tmpdir");
        Arc::new(Storage::open(dir.path()).expect("open"))
    }

    #[test]
    fn config_defaults() {
        let config = SettlementReconcilerConfig::default();
        assert_eq!(config.interval_ms, 10_000);
        assert_eq!(config.batch_limit, 100);
        assert_eq!(config.finality_confirmations, 6);
    }

    #[tokio::test]
    async fn reconcile_cycle_empty_storage() {
        let storage = test_storage();
        let config = SettlementReconcilerConfig::default();
        let l1_client: Option<TestL1Client> = None;

        let result = run_reconcile_cycle(&config, &storage, &l1_client)
            .await
            .unwrap();

        assert_eq!(result.included, 0);
        assert_eq!(result.finalised, 0);
        assert_eq!(result.failed, 0);
        assert_eq!(result.in_flight, 0);
    }

    #[tokio::test]
    async fn reconcile_submitted_best_effort() {
        let storage = test_storage();
        let config = SettlementReconcilerConfig::default();
        let l1_client: Option<TestL1Client> = None;

        // Add a submitted batch
        let hash = Hash32([0xAA; 32]);
        let submitted = SettlementState::submitted("l1tx".to_string(), now_ms(), "key".to_string());
        storage
            .set_settlement_state_unchecked(&hash, &submitted)
            .unwrap();

        // Run reconciliation (no L1 client = best effort mode)
        // In best effort mode, submitted -> included in first phase
        // Then in second phase, included -> finalised
        // So after one full cycle, we expect:
        // - included: 1 (from submitted -> included)
        // - finalised: 1 (from included -> finalised in same cycle)
        let result = run_reconcile_cycle(&config, &storage, &l1_client)
            .await
            .unwrap();

        assert_eq!(result.included, 1);
        // In best effort mode, the batch also gets finalised in the same cycle
        // because it's first transitioned to Included, then the Included list
        // is checked and it's transitioned to Finalised
        assert_eq!(result.finalised, 1);

        // Verify state transition - should be finalised after full cycle
        let state = storage.get_settlement_state(&hash).unwrap().unwrap();
        assert!(state.is_finalised());
    }

    #[tokio::test]
    async fn reconcile_included_best_effort() {
        let storage = test_storage();
        let config = SettlementReconcilerConfig::default();
        let l1_client: Option<TestL1Client> = None;

        // Add an included batch
        let hash = Hash32([0xBB; 32]);
        let included = SettlementState::included("l1tx".to_string(), 100, now_ms(), now_ms());
        storage
            .set_settlement_state_unchecked(&hash, &included)
            .unwrap();

        // Run reconciliation
        let result = run_reconcile_cycle(&config, &storage, &l1_client)
            .await
            .unwrap();

        assert_eq!(result.included, 0);
        assert_eq!(result.finalised, 1);

        // Verify state transition
        let state = storage.get_settlement_state(&hash).unwrap().unwrap();
        assert!(state.is_finalised());

        // Verify last finalised batch was updated
        let last = storage
            .get_last_finalised_batch(&config.hub, config.chain_id)
            .unwrap();
        assert!(last.is_some());
        let (last_hash, _) = last.unwrap();
        assert_eq!(last_hash, hash);
    }

    #[tokio::test]
    async fn reconcile_stale_batch_fails() {
        let storage = test_storage();
        let config = SettlementReconcilerConfig {
            stale_threshold_ms: 100, // Very short for testing
            ..Default::default()
        };
        let l1_client: Option<TestL1Client> = None;

        // Add a batch submitted long ago
        let hash = Hash32([0xCC; 32]);
        let old_time = now_ms().saturating_sub(1000); // 1 second ago
        let submitted = SettlementState::submitted("l1tx".to_string(), old_time, "key".to_string());
        storage
            .set_settlement_state_unchecked(&hash, &submitted)
            .unwrap();

        // Run reconciliation
        let result = run_reconcile_cycle(&config, &storage, &l1_client)
            .await
            .unwrap();

        assert_eq!(result.failed, 1);

        // Verify state is Failed
        let state = storage.get_settlement_state(&hash).unwrap().unwrap();
        assert!(state.is_failed());
    }

    #[test]
    fn in_flight_summary_empty() {
        let storage = test_storage();
        let summary = get_in_flight_summary(&storage, 10);

        assert_eq!(summary.submitted_count, 0);
        assert_eq!(summary.included_count, 0);
        assert!(summary.oldest_submitted_ms.is_none());
        assert!(summary.oldest_included_ms.is_none());
    }

    #[test]
    fn in_flight_summary_with_batches() {
        let storage = test_storage();

        // Add some batches
        let now = now_ms();
        storage
            .set_settlement_state_unchecked(
                &Hash32([0x01; 32]),
                &SettlementState::submitted("tx1".to_string(), now - 1000, "k1".to_string()),
            )
            .unwrap();
        storage
            .set_settlement_state_unchecked(
                &Hash32([0x02; 32]),
                &SettlementState::submitted("tx2".to_string(), now - 500, "k2".to_string()),
            )
            .unwrap();
        storage
            .set_settlement_state_unchecked(
                &Hash32([0x03; 32]),
                &SettlementState::included("tx3".to_string(), 100, now, now - 200),
            )
            .unwrap();

        let summary = get_in_flight_summary(&storage, 10);

        assert_eq!(summary.submitted_count, 2);
        assert_eq!(summary.included_count, 1);
        assert_eq!(summary.oldest_submitted_ms, Some(now - 1000));
        assert_eq!(summary.oldest_included_ms, Some(now - 200));
    }
}
