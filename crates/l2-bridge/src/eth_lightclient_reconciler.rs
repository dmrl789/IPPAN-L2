//! Ethereum PoS Light Client Reconciler.
//!
//! This module provides a background loop that:
//! 1. Processes pending light client updates
//! 2. Advances the finalized tip
//! 3. Re-verifies pending receipt proofs once finalization catches up
//!
//! ## Light Client Update Processing
//!
//! The reconciler maintains a queue of pending updates (fetched from external sources)
//! and applies them in order when verification succeeds.
//!
//! ## Proof Re-verification
//!
//! When the finalized tip advances, pending receipt proofs that were waiting for
//! finalization are re-checked and moved to verified status.
//!
//! ## Leader-Only Operation
//!
//! Like other reconcilers, this should only run on the leader node.

use crate::eth_lightclient_api::{LightClientApi, LightClientApiError, UpdateRequest};
use crate::eth_merkle::verify_eth_receipt_merkle_proof;
use l2_core::{
    eth_lightclient::{ExecutionPayloadHeaderV1, LightClientUpdateV1},
    ExternalProofState, VerificationMode,
};
use l2_storage::ExternalProofStorage;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::interval;
use tracing::{debug, info, warn};

/// Configuration for the light client reconciler.
#[derive(Debug, Clone)]
pub struct LightClientReconcilerConfig {
    /// Interval between reconciliation cycles (ms).
    pub poll_interval_ms: u64,

    /// Maximum updates to apply per cycle.
    pub max_updates_per_cycle: usize,

    /// Maximum proofs to re-verify per cycle.
    pub max_proofs_per_cycle: usize,

    /// Whether the reconciler is enabled.
    pub enabled: bool,

    /// Minimum confirmations required for finalized proofs.
    pub min_confirmations: u64,

    // === DoS Protection Caps ===
    /// Maximum pending updates that can be queued.
    /// New updates are rejected once this limit is reached.
    pub max_pending_updates: usize,

    /// Maximum pending execution headers that can be queued.
    /// New headers are rejected once this limit is reached.
    pub max_pending_exec_headers: usize,

    /// Maximum execution headers to retain in storage.
    /// Oldest headers (by block number) are evicted once this limit is reached.
    pub max_retained_exec_headers: usize,
}

impl Default for LightClientReconcilerConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 10_000, // 10 seconds
            max_updates_per_cycle: 10,
            max_proofs_per_cycle: 50,
            enabled: true,
            min_confirmations: 1, // Finalized is already final
            // DoS protection defaults
            max_pending_updates: 1000,
            max_pending_exec_headers: 1000,
            max_retained_exec_headers: 100_000, // ~100k headers
        }
    }
}

impl LightClientReconcilerConfig {
    /// Create from environment variables.
    pub fn from_env() -> Self {
        let poll_interval_ms = std::env::var("LC_RECONCILER_POLL_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000);

        let max_updates_per_cycle = std::env::var("LC_RECONCILER_MAX_UPDATES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        let max_proofs_per_cycle = std::env::var("LC_RECONCILER_MAX_PROOFS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(50);

        let enabled = std::env::var("LC_RECONCILER_ENABLED")
            .ok()
            .map(|s| s.to_lowercase() != "false" && s != "0")
            .unwrap_or(true);

        let min_confirmations = std::env::var("LC_MIN_CONFIRMATIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        // DoS protection caps
        let max_pending_updates = std::env::var("LC_MAX_PENDING_UPDATES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);

        let max_pending_exec_headers = std::env::var("LC_MAX_PENDING_EXEC_HEADERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);

        let max_retained_exec_headers = std::env::var("LC_MAX_RETAINED_EXEC_HEADERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100_000);

        Self {
            poll_interval_ms,
            max_updates_per_cycle,
            max_proofs_per_cycle,
            enabled,
            min_confirmations,
            max_pending_updates,
            max_pending_exec_headers,
            max_retained_exec_headers,
        }
    }
}

/// Metrics for the light client reconciler.
#[derive(Debug, Default)]
pub struct LightClientReconcilerMetrics {
    /// Total updates applied successfully.
    pub updates_applied: AtomicU64,
    /// Total updates rejected.
    pub updates_rejected: AtomicU64,
    /// Total proofs re-verified successfully.
    pub proofs_reverified: AtomicU64,
    /// Total cycles completed.
    pub cycles_completed: AtomicU64,
    /// Last cycle timestamp (ms since epoch).
    pub last_cycle_ms: AtomicU64,
    /// Current finalized slot.
    pub finalized_slot: AtomicU64,
    /// Current finalized execution block number.
    pub finalized_block_number: AtomicU64,
}

impl LightClientReconcilerMetrics {
    /// Create a new metrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful update application.
    pub fn record_update_applied(&self) {
        self.updates_applied.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rejected update.
    pub fn record_update_rejected(&self) {
        self.updates_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a re-verified proof.
    pub fn record_proof_reverified(&self) {
        self.proofs_reverified.fetch_add(1, Ordering::Relaxed);
    }

    /// Record cycle completion.
    pub fn record_cycle(&self, finalized_slot: u64, finalized_block_number: u64) {
        self.cycles_completed.fetch_add(1, Ordering::Relaxed);
        self.last_cycle_ms
            .store(current_time_ms(), Ordering::Relaxed);
        self.finalized_slot.store(finalized_slot, Ordering::Relaxed);
        self.finalized_block_number
            .store(finalized_block_number, Ordering::Relaxed);
    }

    /// Get a snapshot of the metrics.
    pub fn snapshot(&self) -> LightClientReconcilerMetricsSnapshot {
        LightClientReconcilerMetricsSnapshot {
            updates_applied: self.updates_applied.load(Ordering::Relaxed),
            updates_rejected: self.updates_rejected.load(Ordering::Relaxed),
            proofs_reverified: self.proofs_reverified.load(Ordering::Relaxed),
            cycles_completed: self.cycles_completed.load(Ordering::Relaxed),
            last_cycle_ms: self.last_cycle_ms.load(Ordering::Relaxed),
            finalized_slot: self.finalized_slot.load(Ordering::Relaxed),
            finalized_block_number: self.finalized_block_number.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of reconciler metrics.
#[derive(Debug, Clone)]
pub struct LightClientReconcilerMetricsSnapshot {
    pub updates_applied: u64,
    pub updates_rejected: u64,
    pub proofs_reverified: u64,
    pub cycles_completed: u64,
    pub last_cycle_ms: u64,
    pub finalized_slot: u64,
    pub finalized_block_number: u64,
}

/// Result of a reconciliation cycle.
#[derive(Debug, Clone)]
pub struct LightClientReconcileCycleResult {
    /// Number of updates applied this cycle.
    pub updates_applied: usize,
    /// Number of updates rejected this cycle.
    pub updates_rejected: usize,
    /// Number of execution headers stored this cycle.
    pub exec_headers_stored: usize,
    /// Number of proofs re-verified this cycle.
    pub proofs_reverified: usize,
    /// Current finalized slot.
    pub finalized_slot: u64,
    /// Current finalized execution block number.
    pub finalized_block_number: Option<u64>,
}

/// Entry containing an update and its optional execution header.
#[derive(Debug, Clone)]
pub struct PendingUpdateEntry {
    /// The light client update.
    pub update: LightClientUpdateV1,
    /// Optional execution header to store alongside this update.
    pub execution_header: Option<ExecutionPayloadHeaderV1>,
}

/// Handle to the light client reconciler.
pub struct LightClientReconcilerHandle {
    /// Pending updates queue (with optional execution headers).
    pending_updates: Arc<Mutex<VecDeque<PendingUpdateEntry>>>,
    /// Pending execution headers (keyed by block hash hex).
    /// These can be submitted independently of updates for blocks
    /// that were finalized by earlier updates.
    pending_exec_headers: Arc<Mutex<HashMap<String, ExecutionPayloadHeaderV1>>>,
    /// Shutdown signal.
    shutdown: Arc<AtomicBool>,
    /// Metrics.
    pub metrics: Arc<LightClientReconcilerMetrics>,
    /// Configuration (for enforcing caps).
    config: LightClientReconcilerConfig,
}

/// Error when enqueueing updates or headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueError {
    /// Queue is at capacity.
    QueueFull,
}

impl std::fmt::Display for EnqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueFull => write!(f, "queue is at capacity"),
        }
    }
}

impl std::error::Error for EnqueueError {}

impl LightClientReconcilerHandle {
    /// Queue an update for processing (legacy method without execution header).
    ///
    /// Returns `Err(EnqueueError::QueueFull)` if the queue is at capacity.
    pub async fn queue_update(&self, update: LightClientUpdateV1) -> Result<(), EnqueueError> {
        self.queue_update_with_header(update, None).await
    }

    /// Queue an update with an optional execution header.
    ///
    /// When the update is processed, the execution header (if provided) will be
    /// stored alongside the beacon state update, enabling proof verification
    /// for that block.
    ///
    /// Returns `Err(EnqueueError::QueueFull)` if the queue is at capacity.
    pub async fn queue_update_with_header(
        &self,
        update: LightClientUpdateV1,
        execution_header: Option<ExecutionPayloadHeaderV1>,
    ) -> Result<(), EnqueueError> {
        let mut queue = self.pending_updates.lock().await;

        // Enforce cap
        if queue.len() >= self.config.max_pending_updates {
            warn!(
                queue_len = queue.len(),
                max = self.config.max_pending_updates,
                "rejecting update: queue at capacity"
            );
            return Err(EnqueueError::QueueFull);
        }

        let has_exec_header = execution_header.is_some();
        queue.push_back(PendingUpdateEntry {
            update,
            execution_header,
        });
        debug!(
            queue_len = queue.len(),
            has_exec_header = has_exec_header,
            "queued light client update"
        );
        Ok(())
    }

    /// Submit an execution header for a finalized block.
    ///
    /// Use this to provide execution headers for blocks that were finalized
    /// by earlier beacon updates but whose execution headers were not available
    /// at the time.
    ///
    /// Returns `Ok(true)` if the header was accepted (new).
    /// Returns `Ok(false)` if already queued.
    /// Returns `Err(EnqueueError::QueueFull)` if the queue is at capacity.
    pub async fn submit_execution_header(
        &self,
        header: ExecutionPayloadHeaderV1,
    ) -> Result<bool, EnqueueError> {
        let key = hex::encode(header.block_hash);
        let mut pending = self.pending_exec_headers.lock().await;

        // Check if already queued
        if pending.contains_key(&key) {
            debug!(
                block_hash = %key,
                block_number = header.block_number,
                "execution header already pending"
            );
            return Ok(false);
        }

        // Enforce cap
        if pending.len() >= self.config.max_pending_exec_headers {
            warn!(
                pending_len = pending.len(),
                max = self.config.max_pending_exec_headers,
                "rejecting execution header: queue at capacity"
            );
            return Err(EnqueueError::QueueFull);
        }

        pending.insert(key.clone(), header.clone());
        debug!(
            block_hash = %key,
            block_number = header.block_number,
            "queued standalone execution header"
        );
        Ok(true)
    }

    /// Get the pending updates count.
    pub async fn pending_count(&self) -> usize {
        self.pending_updates.lock().await.len()
    }

    /// Get the pending execution headers count.
    pub async fn pending_exec_headers_count(&self) -> usize {
        self.pending_exec_headers.lock().await.len()
    }

    /// Signal shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> LightClientReconcilerMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get the last reconcile cycle timestamp (ms since epoch).
    ///
    /// Returns 0 if no cycle has completed yet.
    pub fn last_reconcile_ms(&self) -> u64 {
        self.metrics.last_cycle_ms.load(Ordering::Relaxed)
    }

    /// Get the configuration (read-only).
    pub fn config(&self) -> &LightClientReconcilerConfig {
        &self.config
    }
}

/// Spawn the light client reconciler background task.
pub fn spawn_lightclient_reconciler(
    lc_api: Arc<LightClientApi>,
    proof_storage: Arc<ExternalProofStorage>,
    config: LightClientReconcilerConfig,
) -> LightClientReconcilerHandle {
    let pending_updates = Arc::new(Mutex::new(VecDeque::new()));
    let pending_exec_headers = Arc::new(Mutex::new(HashMap::new()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(LightClientReconcilerMetrics::new());

    let handle = LightClientReconcilerHandle {
        pending_updates: Arc::clone(&pending_updates),
        pending_exec_headers: Arc::clone(&pending_exec_headers),
        shutdown: Arc::clone(&shutdown),
        metrics: Arc::clone(&metrics),
        config: config.clone(),
    };

    if config.enabled {
        tokio::spawn(run_reconciler_loop(
            lc_api,
            proof_storage,
            pending_updates,
            pending_exec_headers,
            shutdown,
            metrics,
            config,
        ));
    } else {
        info!("light client reconciler disabled");
    }

    handle
}

async fn run_reconciler_loop(
    lc_api: Arc<LightClientApi>,
    proof_storage: Arc<ExternalProofStorage>,
    pending_updates: Arc<Mutex<VecDeque<PendingUpdateEntry>>>,
    pending_exec_headers: Arc<Mutex<HashMap<String, ExecutionPayloadHeaderV1>>>,
    shutdown: Arc<AtomicBool>,
    metrics: Arc<LightClientReconcilerMetrics>,
    config: LightClientReconcilerConfig,
) {
    let mut ticker = interval(Duration::from_millis(config.poll_interval_ms));

    info!(
        poll_interval_ms = config.poll_interval_ms,
        "starting light client reconciler"
    );

    loop {
        ticker.tick().await;

        if shutdown.load(Ordering::SeqCst) {
            info!("light client reconciler shutting down");
            break;
        }

        match run_reconcile_cycle(
            &lc_api,
            &proof_storage,
            &pending_updates,
            &pending_exec_headers,
            &metrics,
            &config,
        )
        .await
        {
            Ok(result) => {
                if result.updates_applied > 0
                    || result.proofs_reverified > 0
                    || result.exec_headers_stored > 0
                {
                    info!(
                        updates_applied = result.updates_applied,
                        exec_headers_stored = result.exec_headers_stored,
                        proofs_reverified = result.proofs_reverified,
                        finalized_slot = result.finalized_slot,
                        "reconcile cycle completed"
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, "reconcile cycle failed");
            }
        }
    }
}

async fn run_reconcile_cycle(
    lc_api: &Arc<LightClientApi>,
    proof_storage: &Arc<ExternalProofStorage>,
    pending_updates: &Arc<Mutex<VecDeque<PendingUpdateEntry>>>,
    pending_exec_headers: &Arc<Mutex<HashMap<String, ExecutionPayloadHeaderV1>>>,
    metrics: &Arc<LightClientReconcilerMetrics>,
    config: &LightClientReconcilerConfig,
) -> Result<LightClientReconcileCycleResult, LightClientApiError> {
    let mut updates_applied = 0;
    let mut updates_rejected = 0;
    let mut exec_headers_stored = 0;
    let mut proofs_reverified = 0;

    // Phase 1: Apply pending updates (with their execution headers)
    {
        let mut queue = pending_updates.lock().await;
        for _ in 0..config.max_updates_per_cycle {
            if let Some(entry) = queue.pop_front() {
                let has_exec_header = entry.execution_header.is_some();
                let request = UpdateRequest {
                    update: entry.update,
                    execution_header: entry.execution_header,
                };

                match lc_api.submit_update(request) {
                    Ok(response) => {
                        if response.accepted {
                            metrics.record_update_applied();
                            updates_applied += 1;
                            if has_exec_header {
                                exec_headers_stored += 1;
                            }
                            debug!(
                                update_id = %hex::encode(response.update_id),
                                finalized_slot = response.finalized_slot,
                                has_exec_header = has_exec_header,
                                "applied update"
                            );
                        } else {
                            metrics.record_update_rejected();
                            updates_rejected += 1;
                            warn!(
                                error = ?response.error,
                                "update rejected"
                            );
                        }
                    }
                    Err(e) => {
                        metrics.record_update_rejected();
                        updates_rejected += 1;
                        warn!(error = %e, "failed to apply update");
                    }
                }
            } else {
                break;
            }
        }
    }

    // Phase 2: Process standalone execution headers
    // These are headers submitted independently for blocks that were
    // finalized by previous beacon updates.
    {
        let mut pending = pending_exec_headers.lock().await;
        // Take up to max_updates_per_cycle headers
        let keys_to_process: Vec<String> = pending
            .keys()
            .take(config.max_updates_per_cycle)
            .cloned()
            .collect();

        for key in keys_to_process {
            if let Some(header) = pending.remove(&key) {
                // Store the execution header directly
                match lc_api
                    .storage()
                    .store_execution_header_if_finalized(&header)
                {
                    Ok(true) => {
                        exec_headers_stored += 1;
                        debug!(
                            block_hash = %key,
                            block_number = header.block_number,
                            "stored standalone execution header"
                        );
                    }
                    Ok(false) => {
                        // Block not finalized yet - re-queue for later
                        pending.insert(key.clone(), header);
                        debug!(
                            block_hash = %key,
                            "execution header block not yet finalized, re-queued"
                        );
                    }
                    Err(e) => {
                        warn!(
                            block_hash = %key,
                            error = %e,
                            "failed to store execution header"
                        );
                    }
                }
            }
        }
    }

    // Phase 3: Get current finalized state
    let status = lc_api.get_status()?;
    let (finalized_slot, finalized_block_number) = if let Some(ref s) = status.status {
        (s.finalized_slot, s.finalized_execution_number)
    } else {
        (0, None)
    };

    // Phase 4: Re-verify pending proofs that might now be finalized
    if status.bootstrapped {
        let pending_proofs = proof_storage
            .list_unverified_proofs(config.max_proofs_per_cycle)
            .unwrap_or_default();

        let now_ms = current_time_ms();

        for entry in pending_proofs {
            // Only process Merkle proofs
            if !matches!(
                entry.verification_mode,
                VerificationMode::EthMerkleReceiptProof
            ) {
                continue;
            }

            // Extract the Merkle proof from the enum
            let merkle_proof = match &entry.proof {
                l2_core::ExternalEventProofV1::EthReceiptMerkleProofV1(p) => p,
                _ => continue,
            };

            // Check if proof's block is now finalized
            if lc_api
                .storage()
                .is_execution_header_finalized(&merkle_proof.block_hash)
                .unwrap_or(false)
            {
                // Verify the Merkle proof
                match verify_eth_receipt_merkle_proof(merkle_proof) {
                    Ok(_verified) => {
                        // Update proof state to verified
                        if let Err(e) = proof_storage
                            .set_proof_state(&entry.proof_id, ExternalProofState::verified(now_ms))
                        {
                            warn!(
                                proof_id = %entry.proof_id.to_hex(),
                                error = %e,
                                "failed to update proof state"
                            );
                        } else {
                            metrics.record_proof_reverified();
                            proofs_reverified += 1;
                            debug!(
                                proof_id = %entry.proof_id.to_hex(),
                                "re-verified proof after finalization"
                            );
                        }
                    }
                    Err(e) => {
                        // Mark as rejected if Merkle proof fails
                        if let Err(e2) = proof_storage.set_proof_state(
                            &entry.proof_id,
                            ExternalProofState::rejected(e.to_string(), now_ms),
                        ) {
                            warn!(
                                proof_id = %entry.proof_id.to_hex(),
                                error = %e2,
                                "failed to update proof state"
                            );
                        } else {
                            warn!(
                                proof_id = %entry.proof_id.to_hex(),
                                error = %e,
                                "merkle proof verification failed"
                            );
                        }
                    }
                }
            }
        }
    }

    // Record cycle
    metrics.record_cycle(finalized_slot, finalized_block_number.unwrap_or(0));

    Ok(LightClientReconcileCycleResult {
        updates_applied,
        updates_rejected,
        exec_headers_stored,
        proofs_reverified,
        finalized_slot,
        finalized_block_number,
    })
}

/// Get current time in milliseconds.
fn current_time_ms() -> u64 {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(ms).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let config = LightClientReconcilerConfig::default();
        assert_eq!(config.poll_interval_ms, 10_000);
        assert!(config.enabled);
        // Check DoS protection caps
        assert_eq!(config.max_pending_updates, 1000);
        assert_eq!(config.max_pending_exec_headers, 1000);
        assert_eq!(config.max_retained_exec_headers, 100_000);
    }

    #[test]
    fn config_from_env_defaults() {
        // Just verify from_env() doesn't panic with no env vars set
        let config = LightClientReconcilerConfig::from_env();
        assert!(config.enabled);
        assert!(config.max_pending_updates > 0);
    }

    #[test]
    fn metrics_increment() {
        let metrics = LightClientReconcilerMetrics::new();
        assert_eq!(metrics.updates_applied.load(Ordering::Relaxed), 0);

        metrics.record_update_applied();
        assert_eq!(metrics.updates_applied.load(Ordering::Relaxed), 1);

        metrics.record_proof_reverified();
        assert_eq!(metrics.proofs_reverified.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn metrics_snapshot() {
        let metrics = LightClientReconcilerMetrics::new();
        metrics.record_update_applied();
        metrics.record_update_applied();
        metrics.record_proof_reverified();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.updates_applied, 2);
        assert_eq!(snapshot.proofs_reverified, 1);
    }

    #[test]
    fn pending_update_entry_with_header() {
        use l2_core::eth_lightclient::{
            BeaconBlockHeaderV1, ExecutionPayloadHeaderV1, LightClientUpdateV1, SyncAggregateV1,
        };

        let update = LightClientUpdateV1 {
            attested_header: BeaconBlockHeaderV1 {
                slot: 8_001_000,
                proposer_index: 12345,
                parent_root: [0x11; 32],
                state_root: [0x22; 32],
                body_root: [0x33; 32],
            },
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: BeaconBlockHeaderV1 {
                slot: 8_000_900,
                proposer_index: 12345,
                parent_root: [0x11; 32],
                state_root: [0x22; 32],
                body_root: [0x33; 32],
            },
            finality_branch: vec![[0xDD; 32]; 6],
            sync_aggregate: SyncAggregateV1 {
                sync_committee_bits: vec![0xFF; 64],
                sync_committee_signature: [0xEE; 96],
            },
            signature_slot: 8_001_001,
        };

        let exec_header = ExecutionPayloadHeaderV1 {
            parent_hash: [0x11; 32],
            fee_recipient: [0x22; 20],
            state_root: [0x33; 32],
            receipts_root: [0x44; 32],
            logs_bloom: [0x00; 256],
            prev_randao: [0x55; 32],
            block_number: 18_000_000,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            timestamp: 1_700_000_000,
            extra_data: vec![],
            base_fee_per_gas: 10_000_000_000,
            block_hash: [0x66; 32],
            transactions_root: [0x77; 32],
            withdrawals_root: [0x88; 32],
            blob_gas_used: 0,
            excess_blob_gas: 0,
        };

        let entry = PendingUpdateEntry {
            update: update.clone(),
            execution_header: Some(exec_header.clone()),
        };

        assert!(entry.execution_header.is_some());
        assert_eq!(entry.update.finalized_header.slot, 8_000_900);
        assert_eq!(
            entry.execution_header.as_ref().unwrap().block_number,
            18_000_000
        );
    }

    #[test]
    fn enqueue_error_display() {
        let err = EnqueueError::QueueFull;
        assert_eq!(err.to_string(), "queue is at capacity");
    }

    #[test]
    fn cycle_result_with_exec_headers() {
        let result = LightClientReconcileCycleResult {
            updates_applied: 2,
            updates_rejected: 0,
            exec_headers_stored: 3,
            proofs_reverified: 1,
            finalized_slot: 8_000_000,
            finalized_block_number: Some(18_000_000),
        };

        assert_eq!(result.updates_applied, 2);
        assert_eq!(result.exec_headers_stored, 3);
        assert_eq!(result.proofs_reverified, 1);
    }
}
