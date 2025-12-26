//! External Proof Verification Reconciler.
//!
//! This module provides a background loop that:
//! 1. Scans for unverified external proofs
//! 2. Runs the configured verifier
//! 3. Updates proof state to Verified/Rejected
//! 4. Updates metrics counters
//!
//! ## Leader-Only Operation
//!
//! The reconciler should only run on the leader node to avoid duplicate
//! verification work. Use HA leader election to coordinate.
//!
//! ## Header-Aware Mode (eth-headers feature)
//!
//! When the `eth-headers` feature is enabled, the reconciler can optionally
//! verify Merkle proofs against the header store. This provides:
//! - Deterministic confirmation counting from verified headers
//! - Block hash validation against known headers
//! - Receipt root verification from stored headers
//!
//! If a block is not yet in the header store, the proof remains pending
//! and will be retried when headers become available.

use crate::eth_adapter::{ExternalVerifier, ExternalVerifyError};
use crate::eth_merkle::verify_eth_receipt_merkle_proof;
use l2_core::{ExternalEventProofV1, ExternalProofId, ExternalProofState, VerificationMode};
use l2_storage::{ExternalProofStorage, VerifiedSummary};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

#[cfg(feature = "eth-headers")]
use crate::eth_headers_verify::HeaderVerifier;
#[cfg(feature = "eth-headers")]
use l2_storage::eth_headers::EthHeaderStorage;

/// Configuration for the external proof reconciler.
#[derive(Debug, Clone)]
pub struct ExternalProofReconcilerConfig {
    /// Interval between reconciliation cycles (ms).
    pub poll_interval_ms: u64,

    /// Maximum proofs to process per cycle.
    pub max_proofs_per_cycle: usize,

    /// Whether the reconciler is enabled.
    pub enabled: bool,

    /// Minimum confirmations required for mainnet Merkle proofs.
    pub min_confirmations_mainnet: u32,

    /// Minimum confirmations required for testnet Merkle proofs.
    pub min_confirmations_testnet: u32,

    /// Whether to require header verification for Merkle proofs.
    ///
    /// When enabled (with `eth-headers` feature), proofs are only verified if:
    /// - The block exists in the header store
    /// - The block is on a verified chain
    /// - The block has sufficient confirmations from header depth
    ///
    /// If the block is not yet known, the proof remains pending.
    pub require_header_verification: bool,
}

impl Default for ExternalProofReconcilerConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 5_000, // 5 seconds
            max_proofs_per_cycle: 100,
            enabled: true,
            min_confirmations_mainnet: 12,
            min_confirmations_testnet: 6,
            require_header_verification: false, // Default to legacy behavior
        }
    }
}

impl ExternalProofReconcilerConfig {
    /// Create from environment variables.
    pub fn from_env() -> Self {
        let poll_interval_ms = std::env::var("EXTERNAL_PROOF_POLL_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5_000);

        let max_proofs_per_cycle = std::env::var("EXTERNAL_PROOF_MAX_PER_CYCLE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        let enabled = std::env::var("EXTERNAL_PROOF_RECONCILER_ENABLED")
            .ok()
            .map(|s| s.to_lowercase() != "false" && s != "0")
            .unwrap_or(true);

        let min_confirmations_mainnet = std::env::var("MERKLE_PROOF_MIN_CONFIRMATIONS_MAINNET")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(12);

        let min_confirmations_testnet = std::env::var("MERKLE_PROOF_MIN_CONFIRMATIONS_TESTNET")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(6);

        let require_header_verification = std::env::var("REQUIRE_HEADER_VERIFICATION")
            .ok()
            .map(|s| s.to_lowercase() == "true" || s == "1")
            .unwrap_or(false);

        Self {
            poll_interval_ms,
            max_proofs_per_cycle,
            enabled,
            min_confirmations_mainnet,
            min_confirmations_testnet,
            require_header_verification,
        }
    }
}

/// Metrics for the external proof reconciler.
#[derive(Debug, Default)]
pub struct ExternalProofReconcilerMetrics {
    /// Total proofs verified successfully.
    pub proofs_verified: AtomicU64,
    /// Total proofs rejected.
    pub proofs_rejected: AtomicU64,
    /// Total verification errors (retryable).
    pub verification_errors: AtomicU64,
    /// Current unverified queue depth.
    pub unverified_queue_depth: AtomicU64,
    /// Total reconciliation cycles completed.
    pub cycles_completed: AtomicU64,
    /// Last cycle timestamp (ms since epoch).
    pub last_cycle_ms: AtomicU64,
}

impl ExternalProofReconcilerMetrics {
    /// Create a new metrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful verification.
    pub fn record_verified(&self) {
        self.proofs_verified.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rejection.
    pub fn record_rejected(&self) {
        self.proofs_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a verification error.
    pub fn record_error(&self) {
        self.verification_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Update the unverified queue depth.
    pub fn update_queue_depth(&self, depth: u64) {
        self.unverified_queue_depth.store(depth, Ordering::Relaxed);
    }

    /// Record a completed cycle.
    pub fn record_cycle(&self, timestamp_ms: u64) {
        self.cycles_completed.fetch_add(1, Ordering::Relaxed);
        self.last_cycle_ms.store(timestamp_ms, Ordering::Relaxed);
    }

    /// Get a snapshot of the metrics.
    pub fn snapshot(&self) -> ExternalProofReconcilerMetricsSnapshot {
        ExternalProofReconcilerMetricsSnapshot {
            proofs_verified: self.proofs_verified.load(Ordering::Relaxed),
            proofs_rejected: self.proofs_rejected.load(Ordering::Relaxed),
            verification_errors: self.verification_errors.load(Ordering::Relaxed),
            unverified_queue_depth: self.unverified_queue_depth.load(Ordering::Relaxed),
            cycles_completed: self.cycles_completed.load(Ordering::Relaxed),
            last_cycle_ms: self.last_cycle_ms.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of reconciler metrics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExternalProofReconcilerMetricsSnapshot {
    pub proofs_verified: u64,
    pub proofs_rejected: u64,
    pub verification_errors: u64,
    pub unverified_queue_depth: u64,
    pub cycles_completed: u64,
    pub last_cycle_ms: u64,
}

/// Result of a single reconciliation cycle.
#[derive(Debug, Clone)]
pub struct ExternalProofReconcileCycleResult {
    /// Number of proofs verified in this cycle.
    pub verified: u32,
    /// Number of proofs rejected in this cycle.
    pub rejected: u32,
    /// Number of verification errors in this cycle.
    pub errors: u32,
    /// Number of proofs still unverified.
    pub remaining_unverified: u64,
}

/// Handle to the external proof reconciler.
pub struct ExternalProofReconcilerHandle {
    /// Shared metrics.
    metrics: Arc<ExternalProofReconcilerMetrics>,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
}

impl ExternalProofReconcilerHandle {
    /// Get a snapshot of the reconciler metrics.
    pub fn metrics_snapshot(&self) -> ExternalProofReconcilerMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Signal the reconciler to shut down.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Check if shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }
}

impl Clone for ExternalProofReconcilerHandle {
    fn clone(&self) -> Self {
        Self {
            metrics: Arc::clone(&self.metrics),
            shutdown: Arc::clone(&self.shutdown),
        }
    }
}

/// Spawn the external proof reconciler background loop.
///
/// Returns a handle that can be used to get metrics and request shutdown.
///
/// Note: For header-aware verification, use `spawn_external_proof_reconciler_with_headers`.
pub fn spawn_external_proof_reconciler(
    config: ExternalProofReconcilerConfig,
    storage: Arc<ExternalProofStorage>,
    verifier: Arc<dyn ExternalVerifier>,
    is_leader: Arc<AtomicBool>,
) -> ExternalProofReconcilerHandle {
    let metrics = Arc::new(ExternalProofReconcilerMetrics::new());
    let shutdown = Arc::new(AtomicBool::new(false));

    let handle = ExternalProofReconcilerHandle {
        metrics: Arc::clone(&metrics),
        shutdown: Arc::clone(&shutdown),
    };

    if config.enabled {
        #[cfg(feature = "eth-headers")]
        tokio::spawn(reconciler_loop(
            config, storage, verifier, is_leader, metrics, shutdown, None,
        ));
        #[cfg(not(feature = "eth-headers"))]
        tokio::spawn(reconciler_loop(
            config, storage, verifier, is_leader, metrics, shutdown,
        ));
    } else {
        info!("external proof reconciler disabled by config");
    }

    handle
}

/// Spawn the external proof reconciler with header-aware verification.
///
/// When `header_ctx` is provided and `config.require_header_verification` is true,
/// Merkle proofs will be verified against the header store with deterministic
/// confirmation counting.
#[cfg(feature = "eth-headers")]
pub fn spawn_external_proof_reconciler_with_headers(
    config: ExternalProofReconcilerConfig,
    storage: Arc<ExternalProofStorage>,
    verifier: Arc<dyn ExternalVerifier>,
    is_leader: Arc<AtomicBool>,
    header_ctx: Option<Arc<HeaderVerificationContext>>,
) -> ExternalProofReconcilerHandle {
    let metrics = Arc::new(ExternalProofReconcilerMetrics::new());
    let shutdown = Arc::new(AtomicBool::new(false));

    let handle = ExternalProofReconcilerHandle {
        metrics: Arc::clone(&metrics),
        shutdown: Arc::clone(&shutdown),
    };

    if config.enabled {
        if header_ctx.is_some() {
            info!(
                require_header_verification = config.require_header_verification,
                "spawning header-aware proof reconciler"
            );
        }
        tokio::spawn(reconciler_loop(
            config, storage, verifier, is_leader, metrics, shutdown, header_ctx,
        ));
    } else {
        info!("external proof reconciler disabled by config");
    }

    handle
}

/// Main reconciler loop.
async fn reconciler_loop(
    config: ExternalProofReconcilerConfig,
    storage: Arc<ExternalProofStorage>,
    verifier: Arc<dyn ExternalVerifier>,
    is_leader: Arc<AtomicBool>,
    metrics: Arc<ExternalProofReconcilerMetrics>,
    shutdown: Arc<AtomicBool>,
    #[cfg(feature = "eth-headers")] header_ctx: Option<Arc<HeaderVerificationContext>>,
) {
    let mut ticker = interval(Duration::from_millis(config.poll_interval_ms));

    info!(
        poll_interval_ms = config.poll_interval_ms,
        max_per_cycle = config.max_proofs_per_cycle,
        require_header_verification = config.require_header_verification,
        "external proof reconciler started"
    );

    loop {
        ticker.tick().await;

        // Check for shutdown
        if shutdown.load(Ordering::SeqCst) {
            info!("external proof reconciler shutting down");
            break;
        }

        // Only run on leader
        if !is_leader.load(Ordering::SeqCst) {
            debug!("skipping reconciliation (not leader)");
            continue;
        }

        // Run one reconciliation cycle
        #[cfg(feature = "eth-headers")]
        let result = run_reconcile_cycle(
            &config,
            &storage,
            verifier.as_ref(),
            &metrics,
            header_ctx.as_ref().map(|c| c.as_ref()),
        )
        .await;

        #[cfg(not(feature = "eth-headers"))]
        let result = run_reconcile_cycle(&config, &storage, verifier.as_ref(), &metrics).await;

        // Update metrics
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let now_ms = u64::try_from(now_ms).unwrap_or(u64::MAX);
        metrics.record_cycle(now_ms);

        if result.verified > 0 || result.rejected > 0 || result.errors > 0 {
            info!(
                verified = result.verified,
                rejected = result.rejected,
                errors = result.errors,
                remaining = result.remaining_unverified,
                "external proof reconcile cycle completed"
            );
        } else {
            debug!(
                remaining = result.remaining_unverified,
                "external proof reconcile cycle completed (no changes)"
            );
        }
    }
}

/// Run a single reconciliation cycle.
pub async fn run_reconcile_cycle(
    config: &ExternalProofReconcilerConfig,
    storage: &ExternalProofStorage,
    verifier: &dyn ExternalVerifier,
    metrics: &ExternalProofReconcilerMetrics,
    #[cfg(feature = "eth-headers")] header_ctx: Option<&HeaderVerificationContext>,
) -> ExternalProofReconcileCycleResult {
    let mut verified = 0u32;
    let mut rejected = 0u32;
    let mut errors = 0u32;

    // Get unverified proofs
    let unverified = match storage.list_unverified_proofs(config.max_proofs_per_cycle) {
        Ok(proofs) => proofs,
        Err(e) => {
            error!(error = %e, "failed to list unverified proofs");
            return ExternalProofReconcileCycleResult {
                verified: 0,
                rejected: 0,
                errors: 1,
                remaining_unverified: 0,
            };
        }
    };

    // Update queue depth metric
    let total_unverified = match storage.count_proofs() {
        Ok(counts) => counts.unverified,
        Err(_) => u64::try_from(unverified.len()).unwrap_or(u64::MAX),
    };
    metrics.update_queue_depth(total_unverified);

    // Process each unverified proof
    for entry in &unverified {
        #[cfg(feature = "eth-headers")]
        let result =
            verify_and_update(config, storage, verifier, &entry.proof_id, &entry.proof, header_ctx).await;
        #[cfg(not(feature = "eth-headers"))]
        let result =
            verify_and_update(config, storage, verifier, &entry.proof_id, &entry.proof).await;

        match result {
            VerifyUpdateResult::Verified => {
                verified += 1;
                metrics.record_verified();
            }
            VerifyUpdateResult::Rejected => {
                rejected += 1;
                metrics.record_rejected();
            }
            VerifyUpdateResult::Error => {
                errors += 1;
                metrics.record_error();
            }
        }
    }

    // Calculate remaining
    let remaining_unverified = total_unverified.saturating_sub(u64::from(verified + rejected));

    ExternalProofReconcileCycleResult {
        verified,
        rejected,
        errors,
        remaining_unverified,
    }
}

/// Result of verifying and updating a single proof.
enum VerifyUpdateResult {
    Verified,
    Rejected,
    Error,
}

/// Internal result of proof verification.
struct VerificationSuccess {
    mode: VerificationMode,
    block_number: u64,
    log_index: u32,
    data_hash: [u8; 32],
}

/// Verify a proof and update its state.
///
/// Handles both attestation and Merkle proof verification modes.
async fn verify_and_update(
    config: &ExternalProofReconcilerConfig,
    storage: &ExternalProofStorage,
    verifier: &dyn ExternalVerifier,
    proof_id: &ExternalProofId,
    proof: &ExternalEventProofV1,
    #[cfg(feature = "eth-headers")] header_ctx: Option<&HeaderVerificationContext>,
) -> VerifyUpdateResult {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let now_ms = u64::try_from(now_ms).unwrap_or(u64::MAX);

    // Verify based on mode
    #[cfg(feature = "eth-headers")]
    let verification_result = verify_by_mode(config, verifier, proof, header_ctx);
    #[cfg(not(feature = "eth-headers"))]
    let verification_result = verify_by_mode(config, verifier, proof);

    match verification_result {
        Ok(success) => {
            // Create verified summary
            let summary = VerifiedSummary {
                mode: success.mode,
                block_number: success.block_number,
                log_index: success.log_index,
                event_data_hash: success.data_hash,
                verified_at_ms: now_ms,
            };

            // Update state to Verified with summary
            if let Err(e) = storage.set_proof_verified_with_summary(proof_id, now_ms, summary) {
                warn!(
                    proof_id = %proof_id,
                    error = %e,
                    "failed to update proof state to verified"
                );
                return VerifyUpdateResult::Error;
            }

            debug!(
                proof_id = %proof_id,
                mode = %success.mode.name(),
                block_number = success.block_number,
                "proof verified"
            );
            VerifyUpdateResult::Verified
        }
        Err(VerifyModeError::Permanent(reason)) => {
            // Permanent rejection - update state
            let new_state = ExternalProofState::rejected(reason.clone(), now_ms);
            if let Err(update_err) = storage.set_proof_state(proof_id, new_state) {
                warn!(
                    proof_id = %proof_id,
                    error = %update_err,
                    "failed to update proof state to rejected"
                );
                return VerifyUpdateResult::Error;
            }
            warn!(
                proof_id = %proof_id,
                reason = %reason,
                "proof rejected"
            );
            VerifyUpdateResult::Rejected
        }
        Err(VerifyModeError::Transient(reason)) => {
            // Transient error - log but don't update state (retry later)
            warn!(
                proof_id = %proof_id,
                error = %reason,
                "proof verification error (will retry)"
            );
            VerifyUpdateResult::Error
        }
    }
}

/// Error from mode-aware verification.
enum VerifyModeError {
    /// Permanent failure - proof should be rejected.
    Permanent(String),
    /// Transient failure - should retry later.
    Transient(String),
}

/// Verify a proof based on its verification mode.
fn verify_by_mode(
    config: &ExternalProofReconcilerConfig,
    verifier: &dyn ExternalVerifier,
    proof: &ExternalEventProofV1,
    #[cfg(feature = "eth-headers")] header_ctx: Option<&HeaderVerificationContext>,
) -> Result<VerificationSuccess, VerifyModeError> {
    match proof.verification_mode() {
        VerificationMode::Attestation => {
            // Use the attestation verifier
            verify_attestation(verifier, proof)
        }
        VerificationMode::EthMerkleReceiptProof => {
            // Use the Merkle proof verifier
            #[cfg(feature = "eth-headers")]
            {
                verify_merkle_proof(config, proof, header_ctx)
            }
            #[cfg(not(feature = "eth-headers"))]
            {
                verify_merkle_proof_legacy_only(config, proof)
            }
        }
    }
}

/// Legacy Merkle proof verification (non-feature-gated version).
#[cfg(not(feature = "eth-headers"))]
fn verify_merkle_proof_legacy_only(
    config: &ExternalProofReconcilerConfig,
    proof: &ExternalEventProofV1,
) -> Result<VerificationSuccess, VerifyModeError> {
    let merkle_proof = match proof {
        ExternalEventProofV1::EthReceiptMerkleProofV1(p) => p,
        _ => {
            return Err(VerifyModeError::Permanent(
                "expected EthReceiptMerkleProofV1 for Merkle verification mode".to_string(),
            ));
        }
    };

    let min_confirmations = if merkle_proof.chain.is_mainnet() {
        config.min_confirmations_mainnet
    } else {
        config.min_confirmations_testnet
    };

    if let Some(confirmations) = merkle_proof.confirmations {
        if confirmations < min_confirmations {
            return Err(VerifyModeError::Transient(format!(
                "insufficient confirmations: {} < {} required",
                confirmations, min_confirmations
            )));
        }
    }

    match verify_eth_receipt_merkle_proof(merkle_proof) {
        Ok(verified) => Ok(VerificationSuccess {
            mode: VerificationMode::EthMerkleReceiptProof,
            block_number: verified.block_number,
            log_index: verified.log_index,
            data_hash: verified.data_hash,
        }),
        Err(e) => Err(VerifyModeError::Permanent(format!(
            "merkle proof verification failed: {}",
            e
        ))),
    }
}

/// Verify an attestation proof using the ExternalVerifier.
fn verify_attestation(
    verifier: &dyn ExternalVerifier,
    proof: &ExternalEventProofV1,
) -> Result<VerificationSuccess, VerifyModeError> {
    match verifier.verify(proof, None) {
        Ok(verified_event) => Ok(VerificationSuccess {
            mode: VerificationMode::Attestation,
            block_number: verified_event.block_number,
            log_index: verified_event.log_index,
            data_hash: verified_event.data_hash,
        }),
        Err(e) => {
            // Determine if this is a permanent rejection or transient error
            let is_permanent = matches!(
                &e,
                ExternalVerifyError::AttestorNotAllowed { .. }
                    | ExternalVerifyError::SignatureVerification(_)
                    | ExternalVerifyError::BasicValidation(_)
                    | ExternalVerifyError::UnsupportedProofType(_)
            );

            if is_permanent {
                Err(VerifyModeError::Permanent(e.to_string()))
            } else {
                Err(VerifyModeError::Transient(e.to_string()))
            }
        }
    }
}

/// Optional context for header-aware Merkle proof verification.
#[cfg(feature = "eth-headers")]
pub struct HeaderVerificationContext {
    /// Header storage.
    pub storage: Arc<EthHeaderStorage>,
    /// Header verifier.
    pub verifier: Arc<HeaderVerifier>,
}

#[cfg(feature = "eth-headers")]
impl HeaderVerificationContext {
    /// Create a new context.
    pub fn new(storage: Arc<EthHeaderStorage>, verifier: Arc<HeaderVerifier>) -> Self {
        Self { storage, verifier }
    }
}

/// Verify a Merkle proof using the eth_merkle verifier.
fn verify_merkle_proof(
    config: &ExternalProofReconcilerConfig,
    proof: &ExternalEventProofV1,
    #[cfg(feature = "eth-headers")] header_ctx: Option<&HeaderVerificationContext>,
) -> Result<VerificationSuccess, VerifyModeError> {
    // Extract the Merkle proof variant
    let merkle_proof = match proof {
        ExternalEventProofV1::EthReceiptMerkleProofV1(p) => p,
        _ => {
            return Err(VerifyModeError::Permanent(
                "expected EthReceiptMerkleProofV1 for Merkle verification mode".to_string(),
            ));
        }
    };

    // Header-aware verification when enabled
    #[cfg(feature = "eth-headers")]
    if config.require_header_verification {
        if let Some(ctx) = header_ctx {
            return verify_merkle_proof_with_header_store(merkle_proof, ctx);
        } else {
            return Err(VerifyModeError::Transient(
                "header verification required but no header context available".to_string(),
            ));
        }
    }

    // Legacy verification (without header store)
    verify_merkle_proof_legacy(config, merkle_proof)
}

/// Legacy Merkle proof verification (without header store).
fn verify_merkle_proof_legacy(
    config: &ExternalProofReconcilerConfig,
    merkle_proof: &l2_core::EthReceiptMerkleProofV1,
) -> Result<VerificationSuccess, VerifyModeError> {
    // Check confirmation policy
    let min_confirmations = if merkle_proof.chain.is_mainnet() {
        config.min_confirmations_mainnet
    } else {
        config.min_confirmations_testnet
    };

    // Use confirmations from the proof if provided
    if let Some(confirmations) = merkle_proof.confirmations {
        if confirmations < min_confirmations {
            return Err(VerifyModeError::Transient(format!(
                "insufficient confirmations: {} < {} required",
                confirmations, min_confirmations
            )));
        }
    }
    // Note: If confirmations is None, we proceed without confirmation check.
    // This allows proofs to be verified cryptographically without RPC-based confirmation tracking.
    // Policy can be enforced at a higher level (e.g., API or intent binding).

    // Verify the cryptographic proof
    match verify_eth_receipt_merkle_proof(merkle_proof) {
        Ok(verified) => Ok(VerificationSuccess {
            mode: VerificationMode::EthMerkleReceiptProof,
            block_number: verified.block_number,
            log_index: verified.log_index,
            data_hash: verified.data_hash,
        }),
        Err(e) => {
            // All Merkle proof errors are permanent (cryptographic verification failed)
            Err(VerifyModeError::Permanent(format!(
                "merkle proof verification failed: {}",
                e
            )))
        }
    }
}

/// Header-aware Merkle proof verification.
#[cfg(feature = "eth-headers")]
fn verify_merkle_proof_with_header_store(
    merkle_proof: &l2_core::EthReceiptMerkleProofV1,
    ctx: &HeaderVerificationContext,
) -> Result<VerificationSuccess, VerifyModeError> {
    use crate::eth_merkle::{can_verify_proof, verify_merkle_proof_with_headers, ProofReadiness};

    // First check if the proof can be verified (block is known with sufficient confirmations)
    match can_verify_proof(merkle_proof, &ctx.storage, &ctx.verifier) {
        ProofReadiness::Ready { confirmations } => {
            debug!(
                block_hash = %hex::encode(merkle_proof.block_hash),
                confirmations = confirmations,
                "block ready for header-aware verification"
            );
        }
        ProofReadiness::BlockNotFound => {
            return Err(VerifyModeError::Transient(
                "block not found in header store (waiting for headers)".to_string(),
            ));
        }
        ProofReadiness::BlockNotVerified => {
            return Err(VerifyModeError::Transient(
                "block exists but not on verified chain (waiting for verification)".to_string(),
            ));
        }
        ProofReadiness::BlockNotOnBestChain => {
            return Err(VerifyModeError::Transient(
                "block not on best chain (possible reorg)".to_string(),
            ));
        }
        ProofReadiness::InsufficientConfirmations { got, need } => {
            return Err(VerifyModeError::Transient(format!(
                "insufficient confirmations from header store: {} < {} required",
                got, need
            )));
        }
        ProofReadiness::StorageError => {
            return Err(VerifyModeError::Transient(
                "header storage error".to_string(),
            ));
        }
    }

    // Verify the proof with header-awareness
    match verify_merkle_proof_with_headers(merkle_proof, &ctx.storage, &ctx.verifier) {
        Ok(verified) => {
            info!(
                block_hash = %hex::encode(merkle_proof.block_hash),
                block_number = verified.event.block_number,
                confirmations = verified.confirmations,
                "merkle proof verified with header store"
            );
            Ok(VerificationSuccess {
                mode: VerificationMode::EthMerkleReceiptProof,
                block_number: verified.event.block_number,
                log_index: verified.event.log_index,
                data_hash: verified.event.data_hash,
            })
        }
        Err(e) => {
            // Determine if error is permanent or transient
            let is_transient = matches!(
                &e,
                crate::eth_merkle::HeaderAwareMerkleError::Header(_)
            );

            if is_transient {
                Err(VerifyModeError::Transient(format!(
                    "header-aware verification error: {}",
                    e
                )))
            } else {
                Err(VerifyModeError::Permanent(format!(
                    "merkle proof verification failed: {}",
                    e
                )))
            }
        }
    }
}

/// Storage-backed external proof checker for the IntentRouter.
///
/// This implements `ExternalProofChecker` by querying the proof storage.
pub struct StorageExternalProofChecker {
    storage: Arc<ExternalProofStorage>,
}

impl StorageExternalProofChecker {
    /// Create a new checker with the given storage.
    pub fn new(storage: Arc<ExternalProofStorage>) -> Self {
        Self { storage }
    }
}

impl crate::intents::ExternalProofChecker for StorageExternalProofChecker {
    fn all_proofs_verified(
        &self,
        intent_id: &l2_core::IntentId,
    ) -> Result<bool, crate::intents::IntentRouterError> {
        self.storage
            .all_proofs_verified_for_intent(intent_id)
            .map_err(|e| crate::intents::IntentRouterError::ExternalProofStorage(e.to_string()))
    }

    fn requires_proof(&self, intent: &l2_core::Intent) -> bool {
        intent.kind.requires_external_proof()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth_adapter::MockVerifier;
    use crate::intents::ExternalProofChecker;
    use l2_core::{EthReceiptAttestationV1, ExternalChainId};
    use std::sync::atomic::AtomicBool;
    use tempfile::tempdir;

    fn test_db() -> sled::Db {
        let dir = tempdir().expect("tmpdir");
        sled::open(dir.path()).expect("open")
    }

    fn test_attestation(suffix: u8) -> ExternalEventProofV1 {
        ExternalEventProofV1::EthReceiptAttestationV1(EthReceiptAttestationV1 {
            chain: ExternalChainId::EthereumMainnet,
            tx_hash: [suffix; 32],
            log_index: 0,
            contract: [0xBB; 20],
            topic0: [0xCC; 32],
            data_hash: [0xDD; 32],
            block_number: 18_000_000,
            block_hash: [0xEE; 32],
            confirmations: 12,
            attestor_pubkey: [0x11; 32],
            signature: [0x22; 64],
        })
    }

    // ========== Config Tests ==========

    #[test]
    fn config_default() {
        let config = ExternalProofReconcilerConfig::default();
        assert_eq!(config.poll_interval_ms, 5_000);
        assert_eq!(config.max_proofs_per_cycle, 100);
        assert!(config.enabled);
        assert_eq!(config.min_confirmations_mainnet, 12);
        assert_eq!(config.min_confirmations_testnet, 6);
    }

    // ========== Metrics Tests ==========

    #[test]
    fn metrics_recording() {
        let metrics = ExternalProofReconcilerMetrics::new();

        metrics.record_verified();
        metrics.record_verified();
        metrics.record_rejected();
        metrics.record_error();
        metrics.update_queue_depth(10);
        metrics.record_cycle(1_700_000_000_000);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.proofs_verified, 2);
        assert_eq!(snapshot.proofs_rejected, 1);
        assert_eq!(snapshot.verification_errors, 1);
        assert_eq!(snapshot.unverified_queue_depth, 10);
        assert_eq!(snapshot.cycles_completed, 1);
        assert_eq!(snapshot.last_cycle_ms, 1_700_000_000_000);
    }

    // ========== Reconciler Cycle Tests ==========

    #[tokio::test]
    async fn reconcile_cycle_verifies_proofs() {
        let db = test_db();
        let storage = Arc::new(ExternalProofStorage::new(&db).unwrap());

        // Add some proofs
        let proof1 = test_attestation(0xAA);
        let proof2 = test_attestation(0xBB);

        storage
            .put_proof_if_absent(&proof1, 1_700_000_000_000)
            .unwrap();
        storage
            .put_proof_if_absent(&proof2, 1_700_000_000_000)
            .unwrap();

        // Create accepting verifier
        let verifier = MockVerifier::accepting();
        let metrics = Arc::new(ExternalProofReconcilerMetrics::new());

        let config = ExternalProofReconcilerConfig::default();

        #[cfg(feature = "eth-headers")]
        let result = run_reconcile_cycle(&config, &storage, &verifier, &metrics, None).await;
        #[cfg(not(feature = "eth-headers"))]
        let result = run_reconcile_cycle(&config, &storage, &verifier, &metrics).await;

        assert_eq!(result.verified, 2);
        assert_eq!(result.rejected, 0);
        assert_eq!(result.errors, 0);
        assert_eq!(result.remaining_unverified, 0);

        // Check proofs are now verified
        let proof1_id = proof1.proof_id().unwrap();
        let proof2_id = proof2.proof_id().unwrap();

        assert!(storage
            .get_proof_state(&proof1_id)
            .unwrap()
            .unwrap()
            .is_verified());
        assert!(storage
            .get_proof_state(&proof2_id)
            .unwrap()
            .unwrap()
            .is_verified());
    }

    #[tokio::test]
    async fn reconcile_cycle_rejects_proofs() {
        let db = test_db();
        let storage = Arc::new(ExternalProofStorage::new(&db).unwrap());

        // Add a proof
        let proof = test_attestation(0xAA);
        storage
            .put_proof_if_absent(&proof, 1_700_000_000_000)
            .unwrap();

        // Create rejecting verifier
        let verifier = MockVerifier::rejecting();
        let metrics = Arc::new(ExternalProofReconcilerMetrics::new());

        let config = ExternalProofReconcilerConfig::default();

        #[cfg(feature = "eth-headers")]
        let result = run_reconcile_cycle(&config, &storage, &verifier, &metrics, None).await;
        #[cfg(not(feature = "eth-headers"))]
        let result = run_reconcile_cycle(&config, &storage, &verifier, &metrics).await;

        assert_eq!(result.verified, 0);
        assert_eq!(result.rejected, 1);
        assert_eq!(result.errors, 0);

        // Check proof is rejected
        let proof_id = proof.proof_id().unwrap();
        assert!(storage
            .get_proof_state(&proof_id)
            .unwrap()
            .unwrap()
            .is_rejected());
    }

    #[tokio::test]
    async fn reconcile_respects_max_per_cycle() {
        let db = test_db();
        let storage = Arc::new(ExternalProofStorage::new(&db).unwrap());

        // Add 10 proofs
        for i in 0u8..10 {
            let proof = test_attestation(i);
            storage
                .put_proof_if_absent(&proof, 1_700_000_000_000)
                .unwrap();
        }

        let verifier = MockVerifier::accepting();
        let metrics = Arc::new(ExternalProofReconcilerMetrics::new());

        let config = ExternalProofReconcilerConfig {
            max_proofs_per_cycle: 3,
            ..Default::default()
        };

        #[cfg(feature = "eth-headers")]
        let result = run_reconcile_cycle(&config, &storage, &verifier, &metrics, None).await;
        #[cfg(not(feature = "eth-headers"))]
        let result = run_reconcile_cycle(&config, &storage, &verifier, &metrics).await;

        // Should only process 3 proofs
        assert_eq!(result.verified, 3);
        assert_eq!(result.remaining_unverified, 7);
    }

    // ========== Handle Tests ==========

    #[test]
    fn handle_shutdown() {
        let config = ExternalProofReconcilerConfig {
            enabled: false, // Don't actually spawn
            ..Default::default()
        };
        let db = test_db();
        let storage = Arc::new(ExternalProofStorage::new(&db).unwrap());
        let verifier: Arc<dyn ExternalVerifier> = Arc::new(MockVerifier::accepting());
        let is_leader = Arc::new(AtomicBool::new(true));

        let handle = spawn_external_proof_reconciler(config, storage, verifier, is_leader);

        assert!(!handle.is_shutdown());
        handle.shutdown();
        assert!(handle.is_shutdown());
    }

    // ========== Storage Checker Tests ==========

    #[test]
    fn storage_checker_requires_proof() {
        let db = test_db();
        let storage = Arc::new(ExternalProofStorage::new(&db).unwrap());
        let checker = StorageExternalProofChecker::new(storage);

        // Test with external lock intent
        let external_intent = l2_core::Intent {
            kind: l2_core::IntentKind::ExternalLockAndMint,
            created_ms: 1_700_000_000_000,
            expires_ms: 1_700_000_600_000,
            from_hub: l2_core::L2HubId::Bridge,
            to_hub: l2_core::L2HubId::Fin,
            initiator: "alice".to_string(),
            payload: vec![],
        };
        assert!(checker.requires_proof(&external_intent));

        // Test with regular intent
        let regular_intent = l2_core::Intent {
            kind: l2_core::IntentKind::CrossHubTransfer,
            created_ms: 1_700_000_000_000,
            expires_ms: 1_700_000_600_000,
            from_hub: l2_core::L2HubId::Fin,
            to_hub: l2_core::L2HubId::World,
            initiator: "alice".to_string(),
            payload: vec![],
        };
        assert!(!checker.requires_proof(&regular_intent));
    }
}
