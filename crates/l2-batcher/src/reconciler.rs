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
//!
//! ## Multi-Hub Support
//!
//! For multi-hub mode, the reconciler tracks per-hub settlement state:
//! - Per-hub in-flight counts
//! - Per-hub last finalised batch
//! - Per-hub fee totals (M2M hub only)

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use l2_core::{Hash32, L2HubId, ALL_HUBS};
use l2_storage::m2m::M2mStorage;
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
    /// Shared metrics (updated by the reconciler task).
    metrics: Arc<SharedReconcilerMetrics>,
}

/// Shared metrics exposed via the reconciler handle.
pub struct SharedReconcilerMetrics {
    /// Last reconciliation timestamp (ms since epoch).
    last_reconcile_ms: std::sync::atomic::AtomicU64,
    /// Last successful reconciliation timestamp (ms since epoch).
    last_reconcile_ok_ms: std::sync::atomic::AtomicU64,
    /// Last failed reconciliation timestamp (ms since epoch).
    last_reconcile_err_ms: std::sync::atomic::AtomicU64,
    /// Total cycles completed.
    cycles_completed: std::sync::atomic::AtomicU64,
}

impl Default for SharedReconcilerMetrics {
    fn default() -> Self {
        Self {
            last_reconcile_ms: std::sync::atomic::AtomicU64::new(0),
            last_reconcile_ok_ms: std::sync::atomic::AtomicU64::new(0),
            last_reconcile_err_ms: std::sync::atomic::AtomicU64::new(0),
            cycles_completed: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl SharedReconcilerMetrics {
    fn record_cycle_ok(&self) {
        let now = now_ms();
        self.last_reconcile_ms
            .store(now, std::sync::atomic::Ordering::Relaxed);
        self.last_reconcile_ok_ms
            .store(now, std::sync::atomic::Ordering::Relaxed);
        self.cycles_completed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_cycle_err(&self) {
        let now = now_ms();
        self.last_reconcile_ms
            .store(now, std::sync::atomic::Ordering::Relaxed);
        self.last_reconcile_err_ms
            .store(now, std::sync::atomic::Ordering::Relaxed);
        self.cycles_completed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl SettlementReconcilerHandle {
    /// Get the last reconciliation timestamp (ms since epoch).
    ///
    /// Returns 0 if no reconciliation has completed yet.
    pub fn last_reconcile_ms(&self) -> u64 {
        self.metrics
            .last_reconcile_ms
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the last successful reconciliation timestamp (ms since epoch).
    ///
    /// Returns 0 if no successful reconciliation has completed yet.
    pub fn last_reconcile_ok_ms(&self) -> u64 {
        self.metrics
            .last_reconcile_ok_ms
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the last failed reconciliation timestamp (ms since epoch).
    ///
    /// Returns 0 if no failed reconciliation has occurred yet.
    pub fn last_reconcile_err_ms(&self) -> u64 {
        self.metrics
            .last_reconcile_err_ms
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the total number of reconciliation cycles completed.
    pub fn cycles_completed(&self) -> u64 {
        self.metrics
            .cycles_completed
            .load(std::sync::atomic::Ordering::Relaxed)
    }
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
    let metrics = Arc::new(SharedReconcilerMetrics::default());
    let metrics_clone = Arc::clone(&metrics);

    tokio::spawn(async move {
        run_settlement_reconciler(config, storage, l1_client, cancel_rx, metrics_clone).await;
    });

    SettlementReconcilerHandle {
        _cancel: Arc::new(cancel_tx),
        metrics,
    }
}

/// Main reconciler loop.
async fn run_settlement_reconciler<C>(
    config: SettlementReconcilerConfig,
    storage: Arc<Storage>,
    l1_client: Option<C>,
    mut cancel_rx: watch::Receiver<bool>,
    metrics: Arc<SharedReconcilerMetrics>,
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
    match run_reconcile_cycle(&config, &storage, &l1_client).await {
        Ok(_) => metrics.record_cycle_ok(),
        Err(e) => {
            warn!(error = %e, "initial reconciliation failed");
            metrics.record_cycle_err();
        }
    }

    let mut interval = tokio::time::interval(Duration::from_millis(config.interval_ms));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                match run_reconcile_cycle(&config, &storage, &l1_client).await {
                    Ok(_) => metrics.record_cycle_ok(),
                    Err(e) => {
                        warn!(error = %e, "reconciliation cycle failed");
                        metrics.record_cycle_err();
                    }
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
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(
        skip(config, storage, l1_client),
        level = "debug",
        name = "reconcile_iteration"
    )
)]
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
        // Fee fields populated by get_in_flight_summary_with_fees
        in_flight_fee_total_scaled: None,
        last_finalised_batch_fee_total_scaled: None,
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
    /// In-flight batch fee total (scaled).
    pub in_flight_fee_total_scaled: Option<u64>,
    /// Last finalised batch fee total (scaled).
    pub last_finalised_batch_fee_total_scaled: Option<u64>,
}

/// Update M2M batch fee state when settlement state changes.
///
/// This couples batch fee totals to the settlement lifecycle.
pub fn update_batch_fee_settlement_state(
    m2m: &M2mStorage,
    batch_hash: &Hash32,
    settlement_state: &str,
) -> Result<(), crate::BatcherError> {
    if let Err(e) = m2m.update_batch_fee_state(&batch_hash.0, settlement_state) {
        warn!(
            batch_hash = %batch_hash.to_hex(),
            state = settlement_state,
            error = %e,
            "failed to update batch fee settlement state"
        );
    } else {
        debug!(
            batch_hash = %batch_hash.to_hex(),
            state = settlement_state,
            "updated batch fee settlement state"
        );
    }
    Ok(())
}

/// Get in-flight summary with fee totals.
pub fn get_in_flight_summary_with_fees(
    storage: &Storage,
    m2m: Option<&M2mStorage>,
    limit: usize,
) -> InFlightSummary {
    let mut summary = get_in_flight_summary(storage, limit);

    if let Some(m2m_storage) = m2m {
        // Get in-flight fee totals
        if let Ok((total_fees, _batch_count)) = m2m_storage.get_in_flight_fee_totals() {
            summary.in_flight_fee_total_scaled = Some(total_fees);
        }

        // Try to get last finalised batch fee total
        // We need to look up the last finalised batch from storage
        // For now, we'll leave this as None - can be enhanced with proper indexing
    }

    summary
}

// ============== Multi-Hub Reconciler ==============

/// Configuration for multi-hub settlement reconciler.
#[derive(Debug, Clone)]
pub struct MultiHubReconcilerConfig {
    /// Interval between reconciliation cycles (ms).
    pub interval_ms: u64,
    /// Maximum batches to reconcile per cycle per hub.
    pub batch_limit: usize,
    /// Timeout for considering a submitted batch as stale (ms).
    pub stale_threshold_ms: u64,
    /// Maximum retries before marking as failed.
    pub max_retries: u32,
    /// Number of confirmations required for finality.
    pub finality_confirmations: u64,
    /// Chain ID.
    pub chain_id: u64,
}

impl Default for MultiHubReconcilerConfig {
    fn default() -> Self {
        Self {
            interval_ms: 10_000, // 10 seconds
            batch_limit: 100,
            stale_threshold_ms: 300_000, // 5 minutes
            max_retries: 3,
            finality_confirmations: 6, // 6 blocks for finality
            chain_id: 1,
        }
    }
}

impl MultiHubReconcilerConfig {
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
            chain_id,
        }
    }

    /// Convert to single-hub config for a specific hub.
    pub fn to_single_hub_config(&self, hub: L2HubId) -> SettlementReconcilerConfig {
        SettlementReconcilerConfig {
            interval_ms: self.interval_ms,
            batch_limit: self.batch_limit,
            stale_threshold_ms: self.stale_threshold_ms,
            max_retries: self.max_retries,
            finality_confirmations: self.finality_confirmations,
            hub: hub.as_str().to_string(),
            chain_id: self.chain_id,
        }
    }
}

/// Per-hub settlement summary for observability.
#[derive(Debug, Clone)]
pub struct HubSettlementSummary {
    /// Hub identifier.
    pub hub: L2HubId,
    /// Number of batches awaiting inclusion.
    pub submitted_count: u32,
    /// Number of batches awaiting finality.
    pub included_count: u32,
    /// In-flight batch count total.
    pub in_flight_count: u32,
    /// Last submitted batch hash.
    pub last_submitted_hash: Option<Hash32>,
    /// Last included batch hash.
    pub last_included_hash: Option<Hash32>,
    /// Last finalised batch hash.
    pub last_finalised_hash: Option<Hash32>,
    /// Last finalised timestamp (ms).
    pub last_finalised_at_ms: Option<u64>,
    /// Total fees finalised (M2M hub only, scaled).
    pub total_fees_finalised_scaled: u64,
}

impl Default for HubSettlementSummary {
    fn default() -> Self {
        Self::new(L2HubId::Fin)
    }
}

impl HubSettlementSummary {
    /// Create a new hub settlement summary.
    pub fn new(hub: L2HubId) -> Self {
        Self {
            hub,
            submitted_count: 0,
            included_count: 0,
            in_flight_count: 0,
            last_submitted_hash: None,
            last_included_hash: None,
            last_finalised_hash: None,
            last_finalised_at_ms: None,
            total_fees_finalised_scaled: 0,
        }
    }
}

/// Multi-hub settlement summary.
#[derive(Debug, Clone, Default)]
pub struct MultiHubSettlementSummary {
    /// Per-hub summaries (BTreeMap for deterministic ordering).
    pub per_hub: BTreeMap<L2HubId, HubSettlementSummary>,
    /// Global submitted count.
    pub total_submitted: u32,
    /// Global included count.
    pub total_included: u32,
    /// Global in-flight count.
    pub total_in_flight: u32,
    /// Global finalised count (since startup).
    pub total_finalised: u64,
}

impl MultiHubSettlementSummary {
    /// Create a new multi-hub settlement summary.
    pub fn new() -> Self {
        let mut per_hub = BTreeMap::new();
        for hub in ALL_HUBS {
            per_hub.insert(hub, HubSettlementSummary::new(hub));
        }
        Self {
            per_hub,
            ..Default::default()
        }
    }

    /// Get summary for a specific hub.
    pub fn hub(&self, hub: L2HubId) -> Option<&HubSettlementSummary> {
        self.per_hub.get(&hub)
    }

    /// Update summary for a specific hub.
    pub fn update_hub(&mut self, summary: HubSettlementSummary) {
        self.per_hub.insert(summary.hub, summary);
        self.recompute_totals();
    }

    /// Recompute global totals from per-hub data.
    fn recompute_totals(&mut self) {
        self.total_submitted = 0;
        self.total_included = 0;
        self.total_in_flight = 0;

        for summary in self.per_hub.values() {
            self.total_submitted = self.total_submitted.saturating_add(summary.submitted_count);
            self.total_included = self.total_included.saturating_add(summary.included_count);
            self.total_in_flight = self.total_in_flight.saturating_add(summary.in_flight_count);
        }
    }
}

/// Result of a single multi-hub reconciliation cycle.
#[derive(Debug, Clone, Default)]
pub struct MultiHubReconcileCycleResult {
    /// Per-hub results (BTreeMap for deterministic ordering).
    pub per_hub: BTreeMap<L2HubId, ReconcileCycleResult>,
    /// Global totals.
    pub total_included: u32,
    pub total_finalised: u32,
    pub total_failed: u32,
    pub total_in_flight: u32,
}

impl MultiHubReconcileCycleResult {
    /// Create a new result.
    pub fn new() -> Self {
        let mut per_hub = BTreeMap::new();
        for hub in ALL_HUBS {
            per_hub.insert(hub, ReconcileCycleResult::default());
        }
        Self {
            per_hub,
            ..Default::default()
        }
    }

    /// Update result for a specific hub.
    pub fn set_hub_result(&mut self, hub: L2HubId, result: ReconcileCycleResult) {
        self.per_hub.insert(hub, result);
        self.recompute_totals();
    }

    /// Recompute global totals.
    fn recompute_totals(&mut self) {
        self.total_included = 0;
        self.total_finalised = 0;
        self.total_failed = 0;
        self.total_in_flight = 0;

        for result in self.per_hub.values() {
            self.total_included = self.total_included.saturating_add(result.included);
            self.total_finalised = self.total_finalised.saturating_add(result.finalised);
            self.total_failed = self.total_failed.saturating_add(result.failed);
            self.total_in_flight = self.total_in_flight.saturating_add(result.in_flight);
        }
    }
}

/// Handle for controlling the multi-hub reconciler background task.
#[derive(Clone)]
pub struct MultiHubReconcilerHandle {
    /// Channel to signal shutdown.
    _cancel: Arc<watch::Sender<bool>>,
    /// Shared metrics (updated by the reconciler task).
    metrics: Arc<SharedReconcilerMetrics>,
}

impl MultiHubReconcilerHandle {
    /// Get the last reconciliation timestamp (ms since epoch).
    ///
    /// Returns 0 if no reconciliation has completed yet.
    pub fn last_reconcile_ms(&self) -> u64 {
        self.metrics
            .last_reconcile_ms
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the last successful reconciliation timestamp (ms since epoch).
    ///
    /// Returns 0 if no successful reconciliation has completed yet.
    pub fn last_reconcile_ok_ms(&self) -> u64 {
        self.metrics
            .last_reconcile_ok_ms
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the last failed reconciliation timestamp (ms since epoch).
    ///
    /// Returns 0 if no failed reconciliation has occurred yet.
    pub fn last_reconcile_err_ms(&self) -> u64 {
        self.metrics
            .last_reconcile_err_ms
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the total number of reconciliation cycles completed.
    pub fn cycles_completed(&self) -> u64 {
        self.metrics
            .cycles_completed
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Spawn the multi-hub settlement reconciler background task.
///
/// This reconciler handles settlement for all hubs in deterministic order:
/// Fin, Data, M2m, World, Bridge
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
pub fn spawn_multi_hub_reconciler<C>(
    config: MultiHubReconcilerConfig,
    storage: Arc<Storage>,
    l1_client: Option<C>,
) -> MultiHubReconcilerHandle
where
    C: crate::async_l1_client::AsyncL1Client + Send + Sync + 'static,
{
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let metrics = Arc::new(SharedReconcilerMetrics::default());
    let metrics_clone = Arc::clone(&metrics);

    tokio::spawn(async move {
        run_multi_hub_reconciler(config, storage, l1_client, cancel_rx, metrics_clone).await;
    });

    MultiHubReconcilerHandle {
        _cancel: Arc::new(cancel_tx),
        metrics,
    }
}

/// Main multi-hub reconciler loop.
async fn run_multi_hub_reconciler<C>(
    config: MultiHubReconcilerConfig,
    storage: Arc<Storage>,
    l1_client: Option<C>,
    mut cancel_rx: watch::Receiver<bool>,
    metrics: Arc<SharedReconcilerMetrics>,
) where
    C: crate::async_l1_client::AsyncL1Client + Send + Sync,
{
    info!(
        interval_ms = config.interval_ms,
        batch_limit = config.batch_limit,
        finality_confirmations = config.finality_confirmations,
        "starting multi-hub settlement reconciler"
    );

    // Run once immediately on startup (crash recovery)
    match run_multi_hub_reconcile_cycle(&config, &storage, &l1_client).await {
        Ok(_) => metrics.record_cycle_ok(),
        Err(e) => {
            warn!(error = %e, "initial multi-hub reconciliation failed");
            metrics.record_cycle_err();
        }
    }

    let mut interval = tokio::time::interval(Duration::from_millis(config.interval_ms));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                match run_multi_hub_reconcile_cycle(&config, &storage, &l1_client).await {
                    Ok(_) => metrics.record_cycle_ok(),
                    Err(e) => {
                        warn!(error = %e, "multi-hub reconciliation cycle failed");
                        metrics.record_cycle_err();
                    }
                }
            }
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    info!("multi-hub settlement reconciler shutting down");
                    break;
                }
            }
        }
    }
}

/// Execute a single multi-hub reconciliation cycle.
async fn run_multi_hub_reconcile_cycle<C>(
    config: &MultiHubReconcilerConfig,
    storage: &Storage,
    l1_client: &Option<C>,
) -> Result<MultiHubReconcileCycleResult, crate::BatcherError>
where
    C: crate::async_l1_client::AsyncL1Client + Send + Sync,
{
    let mut result = MultiHubReconcileCycleResult::new();

    // Process each hub in deterministic order
    for hub in ALL_HUBS {
        let hub_config = config.to_single_hub_config(hub);
        let hub_result = run_reconcile_cycle(&hub_config, storage, l1_client).await?;

        // Update in-flight count for this hub after reconciliation
        let hub_str = hub.as_str();
        let chain_id = config.chain_id;

        // Decrease in-flight count for finalised batches
        for _ in 0..hub_result.finalised {
            if let Err(e) = storage.dec_hub_in_flight(hub_str, chain_id) {
                debug!(hub = hub_str, error = %e, "failed to decrement in-flight count");
            }
        }

        // Also decrease for failed batches
        for _ in 0..hub_result.failed {
            if let Err(e) = storage.dec_hub_in_flight(hub_str, chain_id) {
                debug!(hub = hub_str, error = %e, "failed to decrement in-flight count for failed batch");
            }
        }

        if hub_result.included > 0 || hub_result.finalised > 0 || hub_result.failed > 0 {
            debug!(
                hub = hub_str,
                included = hub_result.included,
                finalised = hub_result.finalised,
                failed = hub_result.failed,
                in_flight = hub_result.in_flight,
                "hub reconciliation complete"
            );
        }

        result.set_hub_result(hub, hub_result);
    }

    if result.total_included > 0 || result.total_finalised > 0 || result.total_failed > 0 {
        info!(
            total_included = result.total_included,
            total_finalised = result.total_finalised,
            total_failed = result.total_failed,
            total_in_flight = result.total_in_flight,
            "multi-hub reconciliation cycle complete"
        );
    }

    Ok(result)
}

/// Get multi-hub settlement summary.
pub fn get_multi_hub_settlement_summary(
    storage: &Storage,
    chain_id: u64,
) -> MultiHubSettlementSummary {
    let mut summary = MultiHubSettlementSummary::new();

    for hub in ALL_HUBS {
        let hub_str = hub.as_str();
        let mut hub_summary = HubSettlementSummary::new(hub);

        // Get in-flight count
        hub_summary.in_flight_count = storage
            .get_hub_in_flight_count(hub_str, chain_id)
            .unwrap_or(0);

        // Get last finalised batch
        if let Ok(Some((hash, at_ms))) = storage.get_last_finalised_batch(hub_str, chain_id) {
            hub_summary.last_finalised_hash = Some(hash);
            hub_summary.last_finalised_at_ms = Some(at_ms);
        }

        // Get total fees for this hub (if applicable)
        if hub.uses_m2m_fees() {
            hub_summary.total_fees_finalised_scaled =
                storage.get_hub_total_fees(hub_str, chain_id).unwrap_or(0);
        }

        summary.update_hub(hub_summary);
    }

    summary
}

/// Get per-hub in-flight summary.
pub fn get_per_hub_in_flight_summary(
    storage: &Storage,
    chain_id: u64,
    limit: usize,
) -> BTreeMap<L2HubId, InFlightSummary> {
    let mut result = BTreeMap::new();

    // Get global in-flight summary (for now, we don't have per-hub batch lists)
    let global_summary = get_in_flight_summary(storage, limit);

    // Distribute to each hub with basic info
    for hub in ALL_HUBS {
        let hub_str = hub.as_str();
        let _in_flight_count = storage
            .get_hub_in_flight_count(hub_str, chain_id)
            .unwrap_or(0);

        // For now, we create a summary per hub with the in-flight count
        // A more sophisticated implementation would track batch-hub associations
        let summary = InFlightSummary {
            submitted_count: 0, // Would need per-hub batch tracking
            included_count: 0,  // Would need per-hub batch tracking
            oldest_submitted_ms: None,
            oldest_included_ms: None,
            in_flight_fee_total_scaled: None,
            last_finalised_batch_fee_total_scaled: None,
        };

        result.insert(hub, summary);
    }

    // Add the global counts to the first hub (Fin) for backward compatibility
    if let Some(fin_summary) = result.get_mut(&L2HubId::Fin) {
        *fin_summary = global_summary;
    }

    result
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

    #[test]
    fn shared_metrics_record_cycle_ok() {
        let metrics = SharedReconcilerMetrics::default();
        assert_eq!(
            metrics
                .last_reconcile_ms
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            metrics
                .cycles_completed
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        metrics.record_cycle_ok();

        assert!(
            metrics
                .last_reconcile_ms
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        );
        assert!(
            metrics
                .last_reconcile_ok_ms
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        );
        assert_eq!(
            metrics
                .last_reconcile_err_ms
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            metrics
                .cycles_completed
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn shared_metrics_record_cycle_err() {
        let metrics = SharedReconcilerMetrics::default();

        metrics.record_cycle_err();

        assert!(
            metrics
                .last_reconcile_ms
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        );
        assert_eq!(
            metrics
                .last_reconcile_ok_ms
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert!(
            metrics
                .last_reconcile_err_ms
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        );
        assert_eq!(
            metrics
                .cycles_completed
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
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

    // ========== Restart Safety Tests ==========

    /// Test: Restart with Submitted state progresses to Included/Finalised without re-submitting.
    ///
    /// This test simulates a crash recovery scenario where:
    /// 1. A batch was submitted before crash
    /// 2. On restart, the reconciler picks it up from storage
    /// 3. The reconciler queries L1 and advances the state
    /// 4. No duplicate submission occurs
    #[tokio::test]
    async fn restart_safety_no_resubmit() {
        let storage = test_storage();
        let config = SettlementReconcilerConfig::default();
        let l1_client: Option<TestL1Client> = None;

        // Simulate state from previous session - batch was submitted before crash
        let hash = Hash32([0xDD; 32]);
        let old_time = now_ms().saturating_sub(5000); // Submitted 5 seconds ago
        let submitted =
            SettlementState::submitted("l1tx_old".to_string(), old_time, "key_old".to_string());
        storage
            .set_settlement_state_unchecked(&hash, &submitted)
            .unwrap();

        // Verify initial state
        let initial_state = storage.get_settlement_state(&hash).unwrap().unwrap();
        assert!(initial_state.is_submitted());
        assert_eq!(initial_state.l1_tx_id(), Some("l1tx_old"));

        // Run reconciliation (simulates startup recovery)
        // In best-effort mode (no L1 client), it will advance the state
        let result = run_reconcile_cycle(&config, &storage, &l1_client)
            .await
            .unwrap();

        // Should have progressed the batch (included + finalised in best-effort mode)
        assert!(result.included >= 1 || result.finalised >= 1);

        // Verify state advanced to Finalised
        let final_state = storage.get_settlement_state(&hash).unwrap().unwrap();
        assert!(
            final_state.is_finalised(),
            "expected Finalised, got {}",
            final_state
        );

        // Verify the original L1 tx ID is preserved (no re-submission)
        assert_eq!(final_state.l1_tx_id(), Some("l1tx_old"));
    }

    /// Test: Multiple batches in different states are all handled correctly on restart.
    #[tokio::test]
    async fn restart_safety_multiple_batches() {
        let storage = test_storage();
        let config = SettlementReconcilerConfig::default();
        let l1_client: Option<TestL1Client> = None;

        let now = now_ms();

        // Batch 1: Submitted state
        let hash1 = Hash32([0xE1; 32]);
        storage
            .set_settlement_state_unchecked(
                &hash1,
                &SettlementState::submitted("tx1".to_string(), now - 3000, "key1".to_string()),
            )
            .unwrap();

        // Batch 2: Included state
        let hash2 = Hash32([0xE2; 32]);
        storage
            .set_settlement_state_unchecked(
                &hash2,
                &SettlementState::included("tx2".to_string(), 100, now - 1000, now - 2000),
            )
            .unwrap();

        // Batch 3: Already Finalised (should not be touched)
        let hash3 = Hash32([0xE3; 32]);
        storage
            .set_settlement_state_unchecked(
                &hash3,
                &SettlementState::finalised("tx3".to_string(), 50, now - 5000, now - 4000),
            )
            .unwrap();

        // Run reconciliation
        let result = run_reconcile_cycle(&config, &storage, &l1_client)
            .await
            .unwrap();

        // In best-effort mode: batch1 goes submitted->included->finalised, batch2 goes included->finalised
        assert_eq!(result.included, 1); // batch1
        assert_eq!(result.finalised, 2); // batch1 + batch2

        // Verify all in-flight batches reached Finalised
        assert!(storage
            .get_settlement_state(&hash1)
            .unwrap()
            .unwrap()
            .is_finalised());
        assert!(storage
            .get_settlement_state(&hash2)
            .unwrap()
            .unwrap()
            .is_finalised());
        assert!(storage
            .get_settlement_state(&hash3)
            .unwrap()
            .unwrap()
            .is_finalised());
    }

    /// Test: L1 client errors do not crash the reconciler; state remains unchanged.
    #[tokio::test]
    async fn reconciler_handles_l1_errors_gracefully() {
        let storage = test_storage();
        let config = SettlementReconcilerConfig::default();

        // Use a mock client that returns inclusion status
        let mock = MockL1Client::new("testnet");
        let adapter = BlockingL1ClientAdapter::new(mock);
        let l1_client = Some(adapter);

        let now = now_ms();

        // Add a submitted batch
        let hash = Hash32([0xF1; 32]);
        storage
            .set_settlement_state_unchecked(
                &hash,
                &SettlementState::submitted(
                    "tx_pending".to_string(),
                    now - 1000,
                    // Use a key that won't be found in mock (simulates not-yet-included)
                    "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                ),
            )
            .unwrap();

        // Run reconciliation - the mock won't have this batch, so it stays Submitted
        let result = run_reconcile_cycle(&config, &storage, &l1_client)
            .await
            .unwrap();

        // Should not crash, batch stays in-flight
        assert_eq!(result.included, 0);
        assert_eq!(result.failed, 0);
        assert_eq!(result.in_flight, 1);

        // State should remain Submitted
        let state = storage.get_settlement_state(&hash).unwrap().unwrap();
        assert!(state.is_submitted());
    }

    /// Test: Scenario A - Full lifecycle Submitted → Included → Finalised
    ///
    /// This test verifies the full reconciliation flow using best-effort mode
    /// (no L1 client), which advances states immediately. This tests the
    /// state machine transitions work correctly in a single cycle.
    #[tokio::test]
    async fn scenario_full_lifecycle_submitted_to_finalised() {
        let storage = test_storage();
        let config = SettlementReconcilerConfig::default();
        let l1_client: Option<TestL1Client> = None;

        // Add a batch in Submitted state
        let hash = Hash32([0xF2; 32]);
        let now = now_ms();
        storage
            .set_settlement_state_unchecked(
                &hash,
                &SettlementState::submitted(
                    "l1tx_test".to_string(),
                    now - 1000,
                    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string(),
                ),
            )
            .unwrap();

        // Run reconciliation - in best-effort mode (no L1 client):
        // 1. Submitted -> Included in phase 1
        // 2. Included -> Finalised in phase 2 (same cycle)
        let result = run_reconcile_cycle(&config, &storage, &l1_client)
            .await
            .unwrap();

        // Should have included AND finalised in one cycle (best-effort mode)
        assert_eq!(result.included, 1);
        assert_eq!(result.finalised, 1);

        // Verify final state is Finalised
        let state = storage.get_settlement_state(&hash).unwrap().unwrap();
        assert!(
            state.is_finalised(),
            "expected Finalised, got {}",
            state.name()
        );

        // Verify original L1 tx ID is preserved
        assert_eq!(state.l1_tx_id(), Some("l1tx_test"));
    }

    /// Test: Created batches are NOT processed by reconciler (poster owns them)
    #[tokio::test]
    async fn reconciler_ignores_created_batches() {
        let storage = test_storage();
        let config = SettlementReconcilerConfig::default();
        let l1_client: Option<TestL1Client> = None;

        // Add a batch in Created state (not yet submitted)
        let hash = Hash32([0xF3; 32]);
        storage
            .set_settlement_state_unchecked(&hash, &SettlementState::created(now_ms() - 1000))
            .unwrap();

        // Run reconciliation
        let result = run_reconcile_cycle(&config, &storage, &l1_client)
            .await
            .unwrap();

        // Created batches are not in the reconciler's scope
        assert_eq!(result.included, 0);
        assert_eq!(result.finalised, 0);
        assert_eq!(result.in_flight, 0);

        // State should remain Created (poster will handle it)
        let state = storage.get_settlement_state(&hash).unwrap().unwrap();
        assert!(state.is_created());
    }

    // ========== Multi-Hub Reconciler Tests ==========

    #[test]
    fn multi_hub_config_defaults() {
        let config = MultiHubReconcilerConfig::default();
        assert_eq!(config.interval_ms, 10_000);
        assert_eq!(config.batch_limit, 100);
        assert_eq!(config.finality_confirmations, 6);
        assert_eq!(config.chain_id, 1);
    }

    #[test]
    fn multi_hub_config_to_single_hub() {
        let config = MultiHubReconcilerConfig {
            interval_ms: 5_000,
            batch_limit: 50,
            stale_threshold_ms: 100_000,
            max_retries: 5,
            finality_confirmations: 12,
            chain_id: 42,
        };

        let single = config.to_single_hub_config(L2HubId::M2m);
        assert_eq!(single.interval_ms, 5_000);
        assert_eq!(single.batch_limit, 50);
        assert_eq!(single.hub, "m2m");
        assert_eq!(single.chain_id, 42);
    }

    #[test]
    fn hub_settlement_summary_creation() {
        let summary = HubSettlementSummary::new(L2HubId::Data);
        assert_eq!(summary.hub, L2HubId::Data);
        assert_eq!(summary.submitted_count, 0);
        assert_eq!(summary.in_flight_count, 0);
        assert!(summary.last_finalised_hash.is_none());
    }

    #[test]
    fn multi_hub_settlement_summary_creation() {
        let summary = MultiHubSettlementSummary::new();

        // Should have all 5 hubs
        assert_eq!(summary.per_hub.len(), 5);
        assert!(summary.per_hub.contains_key(&L2HubId::Fin));
        assert!(summary.per_hub.contains_key(&L2HubId::Data));
        assert!(summary.per_hub.contains_key(&L2HubId::M2m));
        assert!(summary.per_hub.contains_key(&L2HubId::World));
        assert!(summary.per_hub.contains_key(&L2HubId::Bridge));

        assert_eq!(summary.total_submitted, 0);
        assert_eq!(summary.total_in_flight, 0);
    }

    #[test]
    fn multi_hub_settlement_summary_update() {
        let mut summary = MultiHubSettlementSummary::new();

        let mut fin_summary = HubSettlementSummary::new(L2HubId::Fin);
        fin_summary.submitted_count = 5;
        fin_summary.in_flight_count = 10;
        summary.update_hub(fin_summary);

        let mut m2m_summary = HubSettlementSummary::new(L2HubId::M2m);
        m2m_summary.submitted_count = 3;
        m2m_summary.in_flight_count = 7;
        summary.update_hub(m2m_summary);

        assert_eq!(summary.total_submitted, 8);
        assert_eq!(summary.total_in_flight, 17);
    }

    #[test]
    fn multi_hub_reconcile_cycle_result_creation() {
        let result = MultiHubReconcileCycleResult::new();
        assert_eq!(result.per_hub.len(), 5);
        assert_eq!(result.total_included, 0);
        assert_eq!(result.total_finalised, 0);
    }

    #[test]
    fn multi_hub_reconcile_cycle_result_update() {
        let mut result = MultiHubReconcileCycleResult::new();

        let fin_result = ReconcileCycleResult {
            included: 2,
            finalised: 1,
            failed: 0,
            in_flight: 3,
        };
        result.set_hub_result(L2HubId::Fin, fin_result);

        let data_result = ReconcileCycleResult {
            included: 1,
            finalised: 2,
            failed: 1,
            in_flight: 2,
        };
        result.set_hub_result(L2HubId::Data, data_result);

        assert_eq!(result.total_included, 3);
        assert_eq!(result.total_finalised, 3);
        assert_eq!(result.total_failed, 1);
        assert_eq!(result.total_in_flight, 5);
    }

    #[tokio::test]
    async fn multi_hub_reconcile_cycle_empty() {
        let storage = test_storage();
        let config = MultiHubReconcilerConfig::default();
        let l1_client: Option<TestL1Client> = None;

        let result = run_multi_hub_reconcile_cycle(&config, &storage, &l1_client)
            .await
            .unwrap();

        assert_eq!(result.total_included, 0);
        assert_eq!(result.total_finalised, 0);
        assert_eq!(result.total_failed, 0);
        assert_eq!(result.total_in_flight, 0);
    }

    #[tokio::test]
    async fn multi_hub_reconcile_cycle_with_batch() {
        let storage = test_storage();
        let config = MultiHubReconcilerConfig::default();
        let l1_client: Option<TestL1Client> = None;

        // Add a submitted batch
        let hash = Hash32([0xAA; 32]);
        let submitted = SettlementState::submitted("l1tx".to_string(), now_ms(), "key".to_string());
        storage
            .set_settlement_state_unchecked(&hash, &submitted)
            .unwrap();

        // Run multi-hub reconciliation
        let result = run_multi_hub_reconcile_cycle(&config, &storage, &l1_client)
            .await
            .unwrap();

        // In best-effort mode, batch should be included and finalised
        assert!(result.total_included >= 1 || result.total_finalised >= 1);
    }

    #[test]
    fn get_multi_hub_settlement_summary_empty() {
        let storage = test_storage();
        let summary = get_multi_hub_settlement_summary(&storage, 1);

        assert_eq!(summary.per_hub.len(), 5);
        assert_eq!(summary.total_in_flight, 0);

        // Each hub should have an entry
        for hub in ALL_HUBS {
            let hub_summary = summary.hub(hub).unwrap();
            assert_eq!(hub_summary.hub, hub);
            assert_eq!(hub_summary.in_flight_count, 0);
        }
    }

    #[test]
    fn get_per_hub_in_flight_summary_empty() {
        let storage = test_storage();
        let summaries = get_per_hub_in_flight_summary(&storage, 1, 10);

        assert_eq!(summaries.len(), 5);
        for hub in ALL_HUBS {
            assert!(summaries.contains_key(&hub));
        }
    }
}
