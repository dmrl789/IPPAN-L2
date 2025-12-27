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
use l2_core::{eth_lightclient::LightClientUpdateV1, ExternalProofState, VerificationMode};
use l2_storage::ExternalProofStorage;
use std::collections::VecDeque;
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
}

impl Default for LightClientReconcilerConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 10_000, // 10 seconds
            max_updates_per_cycle: 10,
            max_proofs_per_cycle: 50,
            enabled: true,
            min_confirmations: 1, // Finalized is already final
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

        Self {
            poll_interval_ms,
            max_updates_per_cycle,
            max_proofs_per_cycle,
            enabled,
            min_confirmations,
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
    /// Number of proofs re-verified this cycle.
    pub proofs_reverified: usize,
    /// Current finalized slot.
    pub finalized_slot: u64,
    /// Current finalized execution block number.
    pub finalized_block_number: Option<u64>,
}

/// Handle to the light client reconciler.
pub struct LightClientReconcilerHandle {
    /// Pending updates queue.
    pending_updates: Arc<Mutex<VecDeque<LightClientUpdateV1>>>,
    /// Shutdown signal.
    shutdown: Arc<AtomicBool>,
    /// Metrics.
    pub metrics: Arc<LightClientReconcilerMetrics>,
}

impl LightClientReconcilerHandle {
    /// Queue an update for processing.
    pub async fn queue_update(&self, update: LightClientUpdateV1) {
        let mut queue = self.pending_updates.lock().await;
        queue.push_back(update);
        debug!(queue_len = queue.len(), "queued light client update");
    }

    /// Get the pending updates count.
    pub async fn pending_count(&self) -> usize {
        self.pending_updates.lock().await.len()
    }

    /// Signal shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> LightClientReconcilerMetricsSnapshot {
        self.metrics.snapshot()
    }
}

/// Spawn the light client reconciler background task.
pub fn spawn_lightclient_reconciler(
    lc_api: Arc<LightClientApi>,
    proof_storage: Arc<ExternalProofStorage>,
    config: LightClientReconcilerConfig,
) -> LightClientReconcilerHandle {
    let pending_updates = Arc::new(Mutex::new(VecDeque::new()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(LightClientReconcilerMetrics::new());

    let handle = LightClientReconcilerHandle {
        pending_updates: Arc::clone(&pending_updates),
        shutdown: Arc::clone(&shutdown),
        metrics: Arc::clone(&metrics),
    };

    if config.enabled {
        tokio::spawn(run_reconciler_loop(
            lc_api,
            proof_storage,
            pending_updates,
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
    pending_updates: Arc<Mutex<VecDeque<LightClientUpdateV1>>>,
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

        match run_reconcile_cycle(&lc_api, &proof_storage, &pending_updates, &metrics, &config)
            .await
        {
            Ok(result) => {
                if result.updates_applied > 0 || result.proofs_reverified > 0 {
                    info!(
                        updates_applied = result.updates_applied,
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
    pending_updates: &Arc<Mutex<VecDeque<LightClientUpdateV1>>>,
    metrics: &Arc<LightClientReconcilerMetrics>,
    config: &LightClientReconcilerConfig,
) -> Result<LightClientReconcileCycleResult, LightClientApiError> {
    let mut updates_applied = 0;
    let mut updates_rejected = 0;
    let mut proofs_reverified = 0;

    // Phase 1: Apply pending updates
    {
        let mut queue = pending_updates.lock().await;
        for _ in 0..config.max_updates_per_cycle {
            if let Some(update) = queue.pop_front() {
                let request = UpdateRequest {
                    update,
                    execution_header: None, // TODO: fetch execution header
                };

                match lc_api.submit_update(request) {
                    Ok(response) => {
                        if response.accepted {
                            metrics.record_update_applied();
                            updates_applied += 1;
                            debug!(
                                update_id = %hex::encode(response.update_id),
                                finalized_slot = response.finalized_slot,
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

    // Phase 2: Get current finalized state
    let status = lc_api.get_status()?;
    let (finalized_slot, finalized_block_number) = if let Some(ref s) = status.status {
        (s.finalized_slot, s.finalized_execution_number)
    } else {
        (0, None)
    };

    // Phase 3: Re-verify pending proofs that might now be finalized
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
}
