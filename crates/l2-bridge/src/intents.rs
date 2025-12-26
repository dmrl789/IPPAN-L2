//! BRIDGE Intent Router for Cross-Hub Atomic Operations.
//!
//! This module implements the BRIDGE hub's role as the intent coordinator
//! for deterministic two-phase commit (2PC) across IPPAN hubs.
//!
//! ## Protocol Overview
//!
//! 1. **Create**: Intent is created and stored
//! 2. **Prepare**: Both hubs apply locks/reserves (deterministic receipts)
//! 3. **Commit**: Both hubs finalize the operation
//! 4. **Abort**: Roll back if prepare fails or intent expires
//!
//! ## Determinism
//!
//! All operations are deterministic and crash-safe. The intent router:
//! - Never makes probabilistic decisions
//! - Uses explicit integer timeouts (no implicit timeouts)
//! - Produces deterministic receipts for replay

use async_trait::async_trait;
use l2_core::{
    canonical_hash_bytes, CommitReceipt, Hash32, Intent, IntentHubTx, IntentId, IntentPhase,
    PrepareReceipt, L2HubId,
};
use l2_storage::{IntentState, IntentStateCounts, IntentStateEntry, IntentStorage};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Default intent expiry duration in milliseconds (10 minutes).
pub const DEFAULT_INTENT_EXPIRES_MS: u64 = 600_000;

/// Intent router policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentPolicy {
    /// Require prepare finality before allowing commit.
    /// When true, commit is blocked until the prepare batch is finalised on L1.
    pub require_prep_finality: bool,

    /// Default intent expiry duration in milliseconds.
    pub default_expires_ms: u64,

    /// Maximum intent expiry duration in milliseconds.
    pub max_expires_ms: u64,

    /// Minimum intent expiry duration in milliseconds.
    pub min_expires_ms: u64,
}

impl Default for IntentPolicy {
    fn default() -> Self {
        Self {
            require_prep_finality: true,
            default_expires_ms: DEFAULT_INTENT_EXPIRES_MS,
            max_expires_ms: 3_600_000, // 1 hour
            min_expires_ms: 60_000,    // 1 minute
        }
    }
}

impl IntentPolicy {
    /// Create policy from environment variables.
    pub fn from_env() -> Self {
        let require_prep_finality = std::env::var("INTENT_REQUIRE_PREP_FINALITY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(true);

        let default_expires_ms = std::env::var("INTENT_DEFAULT_EXPIRES_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_INTENT_EXPIRES_MS);

        let max_expires_ms = std::env::var("INTENT_MAX_EXPIRES_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3_600_000);

        let min_expires_ms = std::env::var("INTENT_MIN_EXPIRES_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60_000);

        Self {
            require_prep_finality,
            default_expires_ms,
            max_expires_ms,
            min_expires_ms,
        }
    }

    /// Validate and clamp expiry duration.
    pub fn validate_expiry(&self, requested_ms: Option<u64>) -> u64 {
        let expiry = requested_ms.unwrap_or(self.default_expires_ms);
        expiry.clamp(self.min_expires_ms, self.max_expires_ms)
    }
}

/// Errors from the intent router.
#[derive(Debug, Error)]
pub enum IntentRouterError {
    #[error("storage error: {0}")]
    Storage(#[from] l2_storage::IntentStorageError),

    #[error("canonical error: {0}")]
    Canonical(#[from] l2_core::CanonicalError),

    #[error("intent validation error: {0}")]
    Validation(#[from] l2_core::IntentValidationError),

    #[error("intent not found: {0}")]
    NotFound(String),

    #[error("intent expired at {expires_ms}, current time is {current_ms}")]
    Expired { expires_ms: u64, current_ms: u64 },

    #[error("intent already {state}")]
    AlreadyInState { state: String },

    #[error("intent not in expected state: expected {expected}, found {found}")]
    WrongState { expected: String, found: String },

    #[error("policy violation: {0}")]
    PolicyViolation(String),

    #[error("prepare not finalised on L1")]
    PrepareNotFinalised,

    #[error("hub execution error: {hub}: {message}")]
    HubExecution { hub: String, message: String },
}

/// Result of creating an intent.
#[derive(Debug, Clone)]
pub struct CreateIntentResult {
    /// The computed intent ID.
    pub intent_id: IntentId,
    /// The initial state.
    pub state: IntentState,
}

/// Result of preparing an intent.
#[derive(Debug, Clone)]
pub struct PrepareIntentResult {
    /// The intent ID.
    pub intent_id: IntentId,
    /// Receipts from the prepare phase.
    pub receipts: Vec<PrepareReceipt>,
    /// Hash of all receipts (for settlement).
    pub receipts_hash: Hash32,
    /// Hub transaction to emit.
    pub hub_tx: IntentHubTx,
}

/// Result of committing an intent.
#[derive(Debug, Clone)]
pub struct CommitIntentResult {
    /// The intent ID.
    pub intent_id: IntentId,
    /// Receipts from the commit phase.
    pub receipts: Vec<CommitReceipt>,
    /// Hash of all receipts (for settlement).
    pub receipts_hash: Hash32,
    /// Hub transaction to emit.
    pub hub_tx: IntentHubTx,
}

/// Result of aborting an intent.
#[derive(Debug, Clone)]
pub struct AbortIntentResult {
    /// The intent ID.
    pub intent_id: IntentId,
    /// Reason for abort.
    pub reason: String,
    /// Hash of the reason (for settlement).
    pub reason_hash: Hash32,
    /// Hub transaction to emit.
    pub hub_tx: IntentHubTx,
}

/// Status of intent preparation finality (for policy checks).
pub struct PrepareFinality {
    /// Whether the prepare has been settled on L1.
    pub is_finalised: bool,
    /// L1 block where prepare was included (if known).
    pub l1_block: Option<u64>,
}

/// Trait for hub execution hooks.
///
/// Each hub implements this trait to provide its specific prepare/commit/abort logic.
/// The implementations must be deterministic and produce consistent receipts.
#[async_trait]
pub trait HubIntentExecutor: Send + Sync {
    /// Execute prepare phase for this hub.
    ///
    /// Returns a deterministic receipt or error.
    async fn prepare(
        &self,
        intent_id: &IntentId,
        intent: &Intent,
    ) -> Result<PrepareReceipt, IntentRouterError>;

    /// Execute commit phase for this hub.
    ///
    /// Returns a deterministic receipt or error.
    async fn commit(
        &self,
        intent_id: &IntentId,
        intent: &Intent,
    ) -> Result<CommitReceipt, IntentRouterError>;

    /// Execute abort/rollback for this hub.
    ///
    /// Returns Ok(()) if rollback succeeded (or was no-op).
    async fn abort(&self, intent_id: &IntentId, reason: &str) -> Result<(), IntentRouterError>;
}

/// Mock hub executor for testing.
pub struct MockHubExecutor {
    /// Hub this executor represents.
    pub hub: L2HubId,
}

impl MockHubExecutor {
    pub fn new(hub: L2HubId) -> Self {
        Self { hub }
    }
}

#[async_trait]
impl HubIntentExecutor for MockHubExecutor {
    async fn prepare(
        &self,
        intent_id: &IntentId,
        _intent: &Intent,
    ) -> Result<PrepareReceipt, IntentRouterError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let now_ms = u64::try_from(now_ms).unwrap_or(u64::MAX);

        // Deterministic lock hash based on intent_id and hub
        let lock_data = format!("{}:{}", intent_id.to_hex(), self.hub.as_str());
        let lock_hash = Hash32(canonical_hash_bytes(lock_data.as_bytes()));

        Ok(PrepareReceipt {
            intent_id: *intent_id,
            hub: self.hub,
            prepared_ms: now_ms,
            lock_hash,
            details: Some(format!("mock prepare on {}", self.hub)),
        })
    }

    async fn commit(
        &self,
        intent_id: &IntentId,
        _intent: &Intent,
    ) -> Result<CommitReceipt, IntentRouterError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let now_ms = u64::try_from(now_ms).unwrap_or(u64::MAX);

        // Deterministic finalize hash based on intent_id and hub
        let finalize_data = format!("commit:{}:{}", intent_id.to_hex(), self.hub.as_str());
        let finalize_hash = Hash32(canonical_hash_bytes(finalize_data.as_bytes()));

        Ok(CommitReceipt {
            intent_id: *intent_id,
            hub: self.hub,
            committed_ms: now_ms,
            finalize_hash,
            details: Some(format!("mock commit on {}", self.hub)),
        })
    }

    async fn abort(&self, intent_id: &IntentId, reason: &str) -> Result<(), IntentRouterError> {
        debug!(
            intent_id = %intent_id,
            hub = %self.hub,
            reason = reason,
            "mock abort"
        );
        Ok(())
    }
}

/// Trait for checking prepare finality.
pub trait FinalityChecker: Send + Sync {
    /// Check if the prepare phase for an intent has been finalised on L1.
    fn check_prepare_finality(&self, intent_id: &IntentId) -> PrepareFinality;
}

/// Mock finality checker that always returns finalised.
pub struct MockFinalityChecker {
    /// Whether to report as finalised.
    pub is_finalised: bool,
}

impl Default for MockFinalityChecker {
    fn default() -> Self {
        Self { is_finalised: true }
    }
}

impl FinalityChecker for MockFinalityChecker {
    fn check_prepare_finality(&self, _intent_id: &IntentId) -> PrepareFinality {
        PrepareFinality {
            is_finalised: self.is_finalised,
            l1_block: if self.is_finalised { Some(100) } else { None },
        }
    }
}

/// The BRIDGE Intent Router.
///
/// Coordinates cross-hub atomic operations using a deterministic 2PC protocol.
pub struct IntentRouter {
    /// Persistent storage for intent state.
    storage: IntentStorage,

    /// Policy configuration.
    policy: IntentPolicy,

    /// Hub executors by hub ID.
    executors: std::collections::HashMap<L2HubId, Arc<dyn HubIntentExecutor>>,

    /// Finality checker for prepare phase.
    finality_checker: Arc<dyn FinalityChecker>,
}

impl IntentRouter {
    /// Create a new intent router.
    pub fn new(
        storage: IntentStorage,
        policy: IntentPolicy,
        finality_checker: Arc<dyn FinalityChecker>,
    ) -> Self {
        Self {
            storage,
            policy,
            executors: std::collections::HashMap::new(),
            finality_checker,
        }
    }

    /// Register a hub executor.
    pub fn register_executor(&mut self, hub: L2HubId, executor: Arc<dyn HubIntentExecutor>) {
        self.executors.insert(hub, executor);
    }

    /// Get the policy configuration.
    pub fn policy(&self) -> &IntentPolicy {
        &self.policy
    }

    /// Create a new intent.
    ///
    /// Validates the intent structure and stores it in Created state.
    pub fn create_intent(
        &self,
        intent: Intent,
        current_ms: u64,
    ) -> Result<CreateIntentResult, IntentRouterError> {
        // Validate intent structure
        intent.validate()?;

        // Compute intent ID
        let intent_id = intent.compute_id()?;

        // Validate expiry
        let expires_ms = self.policy.validate_expiry(Some(intent.expires_ms));
        if expires_ms != intent.expires_ms {
            warn!(
                intent_id = %intent_id,
                requested_expires_ms = intent.expires_ms,
                clamped_expires_ms = expires_ms,
                "intent expiry was clamped by policy"
            );
        }

        // Check not already expired
        if current_ms >= intent.expires_ms {
            return Err(IntentRouterError::Expired {
                expires_ms: intent.expires_ms,
                current_ms,
            });
        }

        // Create initial state
        let state = IntentState::created(
            intent.created_ms,
            intent.expires_ms,
            intent.from_hub,
            intent.to_hub,
        );

        // Store the intent
        self.storage.create(&intent_id, &state)?;

        info!(
            intent_id = %intent_id,
            kind = %intent.kind,
            from_hub = %intent.from_hub,
            to_hub = %intent.to_hub,
            "created intent"
        );

        Ok(CreateIntentResult { intent_id, state })
    }

    /// Prepare an intent.
    ///
    /// Executes the prepare phase on both hubs, acquiring locks/reserves.
    pub async fn prepare_intent(
        &self,
        intent_id: &IntentId,
        intent: &Intent,
        current_ms: u64,
    ) -> Result<PrepareIntentResult, IntentRouterError> {
        // Get current state
        let state = self.get_state(intent_id)?;

        // Verify in Created state
        if !state.is_created() {
            return Err(IntentRouterError::WrongState {
                expected: "created".to_string(),
                found: state.name().to_string(),
            });
        }

        // Check not expired
        if let Some(expires_ms) = state.expires_ms() {
            if current_ms >= expires_ms {
                return Err(IntentRouterError::Expired {
                    expires_ms,
                    current_ms,
                });
            }
        }

        // Get executors for both hubs
        let from_executor = self.get_executor(intent.from_hub)?;
        let to_executor = self.get_executor(intent.to_hub)?;

        // Execute prepare on from_hub
        let from_receipt = from_executor.prepare(intent_id, intent).await?;

        // Execute prepare on to_hub
        let to_receipt = match to_executor.prepare(intent_id, intent).await {
            Ok(receipt) => receipt,
            Err(e) => {
                // Rollback from_hub on failure
                warn!(
                    intent_id = %intent_id,
                    error = %e,
                    "to_hub prepare failed, rolling back from_hub"
                );
                let _ = from_executor.abort(intent_id, &e.to_string()).await;
                return Err(e);
            }
        };

        // Compute receipts hash
        let receipts = vec![from_receipt.clone(), to_receipt.clone()];
        let receipt_hashes: Vec<Hash32> = receipts
            .iter()
            .map(|r| r.hash())
            .collect::<Result<_, _>>()?;
        let receipts_hash = hash_receipt_hashes(&receipt_hashes);

        // Update state to Prepared
        let new_state = IntentState::prepared(current_ms, receipt_hashes);
        self.storage.update(intent_id, &new_state)?;

        // Create hub transaction
        let hub_tx = IntentHubTx::IntentPrepared {
            intent_id: *intent_id,
            receipts_hash,
            prepared_ms: current_ms,
        };

        info!(
            intent_id = %intent_id,
            receipts_hash = %receipts_hash.to_hex(),
            "prepared intent"
        );

        Ok(PrepareIntentResult {
            intent_id: *intent_id,
            receipts,
            receipts_hash,
            hub_tx,
        })
    }

    /// Commit an intent.
    ///
    /// Executes the commit phase on both hubs, finalizing the operation.
    pub async fn commit_intent(
        &self,
        intent_id: &IntentId,
        intent: &Intent,
        current_ms: u64,
    ) -> Result<CommitIntentResult, IntentRouterError> {
        // Get current state
        let state = self.get_state(intent_id)?;

        // Verify in Prepared state
        if !state.is_prepared() {
            if state.is_committed() {
                return Err(IntentRouterError::AlreadyInState {
                    state: "committed".to_string(),
                });
            }
            return Err(IntentRouterError::WrongState {
                expected: "prepared".to_string(),
                found: state.name().to_string(),
            });
        }

        // Check policy: require prep finality
        if self.policy.require_prep_finality {
            let finality = self.finality_checker.check_prepare_finality(intent_id);
            if !finality.is_finalised {
                return Err(IntentRouterError::PrepareNotFinalised);
            }
        }

        // Get executors for both hubs
        let from_executor = self.get_executor(intent.from_hub)?;
        let to_executor = self.get_executor(intent.to_hub)?;

        // Execute commit on from_hub
        let from_receipt = from_executor.commit(intent_id, intent).await?;

        // Execute commit on to_hub
        let to_receipt = to_executor.commit(intent_id, intent).await?;

        // Compute receipts hash
        let receipts = vec![from_receipt.clone(), to_receipt.clone()];
        let receipt_hashes: Vec<Hash32> = receipts
            .iter()
            .map(|r| r.hash())
            .collect::<Result<_, _>>()?;
        let receipts_hash = hash_receipt_hashes(&receipt_hashes);

        // Update state to Committed
        let new_state = IntentState::committed(current_ms, receipt_hashes);
        self.storage.update(intent_id, &new_state)?;

        // Create hub transaction
        let hub_tx = IntentHubTx::IntentCommitted {
            intent_id: *intent_id,
            receipts_hash,
            committed_ms: current_ms,
        };

        info!(
            intent_id = %intent_id,
            receipts_hash = %receipts_hash.to_hex(),
            "committed intent"
        );

        Ok(CommitIntentResult {
            intent_id: *intent_id,
            receipts,
            receipts_hash,
            hub_tx,
        })
    }

    /// Abort an intent.
    ///
    /// Rolls back any prepared locks and marks the intent as aborted.
    pub async fn abort_intent(
        &self,
        intent_id: &IntentId,
        reason: String,
        intent: Option<&Intent>,
        current_ms: u64,
    ) -> Result<AbortIntentResult, IntentRouterError> {
        // Get current state
        let state = self.get_state(intent_id)?;

        // Cannot abort terminal states
        if state.is_terminal() {
            return Err(IntentRouterError::AlreadyInState {
                state: state.name().to_string(),
            });
        }

        // If prepared, need to rollback on both hubs
        if state.is_prepared() {
            if let Some(intent) = intent {
                let from_executor = self.get_executor(intent.from_hub)?;
                let to_executor = self.get_executor(intent.to_hub)?;

                // Best-effort rollback (log errors but continue)
                if let Err(e) = from_executor.abort(intent_id, &reason).await {
                    warn!(
                        intent_id = %intent_id,
                        hub = %intent.from_hub,
                        error = %e,
                        "from_hub abort failed"
                    );
                }
                if let Err(e) = to_executor.abort(intent_id, &reason).await {
                    warn!(
                        intent_id = %intent_id,
                        hub = %intent.to_hub,
                        error = %e,
                        "to_hub abort failed"
                    );
                }
            }
        }

        // Compute reason hash
        let reason_hash = Hash32(canonical_hash_bytes(reason.as_bytes()));

        // Update state to Aborted
        let new_state = IntentState::aborted(current_ms, reason.clone());
        self.storage.update(intent_id, &new_state)?;

        // Create hub transaction
        let hub_tx = IntentHubTx::IntentAborted {
            intent_id: *intent_id,
            reason_hash,
            aborted_ms: current_ms,
        };

        info!(
            intent_id = %intent_id,
            reason = reason,
            "aborted intent"
        );

        Ok(AbortIntentResult {
            intent_id: *intent_id,
            reason,
            reason_hash,
            hub_tx,
        })
    }

    /// Get the current state of an intent.
    pub fn get_state(&self, intent_id: &IntentId) -> Result<IntentState, IntentRouterError> {
        self.storage
            .get(intent_id)?
            .ok_or_else(|| IntentRouterError::NotFound(intent_id.to_hex()))
    }

    /// Get the status of an intent (public-facing).
    pub fn get_status(&self, intent_id: &IntentId) -> Result<IntentStatus, IntentRouterError> {
        let state = self.get_state(intent_id)?;
        Ok(IntentStatus::from_state(&state, intent_id))
    }

    /// List intents by state.
    pub fn list_by_state(
        &self,
        state_filter: Option<&str>,
        limit: usize,
    ) -> Result<Vec<IntentStateEntry>, IntentRouterError> {
        let entries = match state_filter {
            Some("created") => self.storage.list_created(limit)?,
            Some("prepared") => self.storage.list_prepared(limit)?,
            Some("committed") => self.storage.list_committed(limit)?,
            Some("aborted") => self.storage.list_aborted(limit)?,
            Some("pending") => self.storage.list_pending(limit)?,
            _ => self.storage.list_pending(limit)?,
        };
        Ok(entries)
    }

    /// List pending intents for a specific hub.
    pub fn list_pending_for_hub(
        &self,
        hub: L2HubId,
        limit: usize,
    ) -> Result<Vec<IntentStateEntry>, IntentRouterError> {
        Ok(self.storage.list_pending_for_hub(hub, limit)?)
    }

    /// Get counts of intents by state.
    pub fn count_states(&self) -> Result<IntentStateCounts, IntentRouterError> {
        Ok(self.storage.count_states()?)
    }

    /// Process expired intents (abort them).
    pub async fn process_expired(&self, current_ms: u64, limit: usize) -> Vec<AbortIntentResult> {
        let mut results = Vec::new();

        match self.storage.list_expired(current_ms, limit) {
            Ok(expired) => {
                for entry in expired {
                    let result = self
                        .abort_intent(
                            &entry.intent_id,
                            "expired".to_string(),
                            None,
                            current_ms,
                        )
                        .await;
                    if let Ok(r) = result {
                        results.push(r);
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to list expired intents");
            }
        }

        results
    }

    // ========== Internal helpers ==========

    fn get_executor(
        &self,
        hub: L2HubId,
    ) -> Result<&Arc<dyn HubIntentExecutor>, IntentRouterError> {
        self.executors
            .get(&hub)
            .ok_or_else(|| IntentRouterError::HubExecution {
                hub: hub.to_string(),
                message: "no executor registered".to_string(),
            })
    }
}

/// Compute a combined hash of multiple receipt hashes.
fn hash_receipt_hashes(hashes: &[Hash32]) -> Hash32 {
    let mut combined = Vec::new();
    for h in hashes {
        combined.extend_from_slice(&h.0);
    }
    Hash32(canonical_hash_bytes(&combined))
}

/// Public-facing intent status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentStatus {
    /// The intent ID.
    pub intent_id: String,
    /// Current phase.
    pub phase: IntentPhase,
    /// Whether the intent is terminal.
    pub is_terminal: bool,
    /// Human-readable state name.
    pub state_name: String,
    /// Additional details.
    pub details: Option<String>,
}

impl IntentStatus {
    fn from_state(state: &IntentState, intent_id: &IntentId) -> Self {
        let phase = match state {
            IntentState::Created { .. } => IntentPhase::Prepared, // Not yet prepared
            IntentState::Prepared { .. } => IntentPhase::Prepared,
            IntentState::Committed { .. } => IntentPhase::Committed,
            IntentState::Aborted { .. } => IntentPhase::Aborted,
        };

        let details = match state {
            IntentState::Created { expires_ms, .. } => {
                Some(format!("expires at {}", expires_ms))
            }
            IntentState::Prepared { prepared_ms, prep_receipts } => {
                Some(format!("prepared at {} with {} receipts", prepared_ms, prep_receipts.len()))
            }
            IntentState::Committed { committed_ms, commit_receipts } => {
                Some(format!("committed at {} with {} receipts", committed_ms, commit_receipts.len()))
            }
            IntentState::Aborted { aborted_ms, reason } => {
                Some(format!("aborted at {}: {}", aborted_ms, reason))
            }
        };

        Self {
            intent_id: intent_id.to_hex(),
            phase,
            is_terminal: state.is_terminal(),
            state_name: state.name().to_string(),
            details,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_core::IntentKind;
    use tempfile::tempdir;

    fn test_db() -> sled::Db {
        let dir = tempdir().expect("tmpdir");
        sled::open(dir.path()).expect("open")
    }

    fn test_intent() -> Intent {
        Intent {
            kind: IntentKind::CrossHubTransfer,
            created_ms: 1_700_000_000_000,
            expires_ms: 1_700_000_600_000,
            from_hub: L2HubId::Fin,
            to_hub: L2HubId::World,
            initiator: "alice".to_string(),
            payload: vec![1, 2, 3, 4],
        }
    }

    fn setup_router() -> (IntentRouter, Intent) {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();
        let policy = IntentPolicy::default();
        let finality_checker = Arc::new(MockFinalityChecker::default());

        let mut router = IntentRouter::new(storage, policy, finality_checker);

        // Register mock executors
        router.register_executor(L2HubId::Fin, Arc::new(MockHubExecutor::new(L2HubId::Fin)));
        router.register_executor(L2HubId::World, Arc::new(MockHubExecutor::new(L2HubId::World)));
        router.register_executor(L2HubId::Data, Arc::new(MockHubExecutor::new(L2HubId::Data)));
        router.register_executor(L2HubId::M2m, Arc::new(MockHubExecutor::new(L2HubId::M2m)));
        router.register_executor(L2HubId::Bridge, Arc::new(MockHubExecutor::new(L2HubId::Bridge)));

        let intent = test_intent();
        (router, intent)
    }

    #[test]
    fn create_intent_success() {
        let (router, intent) = setup_router();
        let current_ms = 1_700_000_000_000;

        let result = router.create_intent(intent.clone(), current_ms).unwrap();
        assert_eq!(result.intent_id, intent.compute_id().unwrap());
        assert!(result.state.is_created());
    }

    #[test]
    fn create_intent_already_expired() {
        let (router, intent) = setup_router();
        let current_ms = 1_700_000_700_000; // After expiry

        let result = router.create_intent(intent, current_ms);
        assert!(matches!(result, Err(IntentRouterError::Expired { .. })));
    }

    #[tokio::test]
    async fn prepare_intent_success() {
        let (router, intent) = setup_router();
        let current_ms = 1_700_000_100_000;

        let create_result = router.create_intent(intent.clone(), current_ms).unwrap();

        let prepare_result = router
            .prepare_intent(&create_result.intent_id, &intent, current_ms)
            .await
            .unwrap();

        assert_eq!(prepare_result.receipts.len(), 2);
        assert!(!prepare_result.receipts_hash.0.iter().all(|&b| b == 0));

        // Verify state updated
        let state = router.get_state(&create_result.intent_id).unwrap();
        assert!(state.is_prepared());
    }

    #[tokio::test]
    async fn prepare_requires_created_state() {
        let (router, intent) = setup_router();
        let current_ms = 1_700_000_100_000;

        let create_result = router.create_intent(intent.clone(), current_ms).unwrap();

        // Prepare first time
        router
            .prepare_intent(&create_result.intent_id, &intent, current_ms)
            .await
            .unwrap();

        // Try to prepare again - should fail
        let result = router
            .prepare_intent(&create_result.intent_id, &intent, current_ms)
            .await;

        assert!(matches!(result, Err(IntentRouterError::WrongState { .. })));
    }

    #[tokio::test]
    async fn commit_intent_success() {
        let (router, intent) = setup_router();
        let current_ms = 1_700_000_100_000;

        let create_result = router.create_intent(intent.clone(), current_ms).unwrap();
        router
            .prepare_intent(&create_result.intent_id, &intent, current_ms)
            .await
            .unwrap();

        let commit_result = router
            .commit_intent(&create_result.intent_id, &intent, current_ms)
            .await
            .unwrap();

        assert_eq!(commit_result.receipts.len(), 2);

        // Verify state updated
        let state = router.get_state(&create_result.intent_id).unwrap();
        assert!(state.is_committed());
        assert!(state.is_terminal());
    }

    #[tokio::test]
    async fn commit_requires_prepared_state() {
        let (router, intent) = setup_router();
        let current_ms = 1_700_000_100_000;

        let create_result = router.create_intent(intent.clone(), current_ms).unwrap();

        // Try to commit without prepare - should fail
        let result = router
            .commit_intent(&create_result.intent_id, &intent, current_ms)
            .await;

        assert!(matches!(result, Err(IntentRouterError::WrongState { .. })));
    }

    #[tokio::test]
    async fn commit_requires_finality_when_policy_enabled() {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();
        let policy = IntentPolicy {
            require_prep_finality: true,
            ..Default::default()
        };

        // Use mock that says NOT finalised
        let finality_checker = Arc::new(MockFinalityChecker { is_finalised: false });

        let mut router = IntentRouter::new(storage, policy, finality_checker);
        router.register_executor(L2HubId::Fin, Arc::new(MockHubExecutor::new(L2HubId::Fin)));
        router.register_executor(L2HubId::World, Arc::new(MockHubExecutor::new(L2HubId::World)));

        let intent = test_intent();
        let current_ms = 1_700_000_100_000;

        let create_result = router.create_intent(intent.clone(), current_ms).unwrap();
        router
            .prepare_intent(&create_result.intent_id, &intent, current_ms)
            .await
            .unwrap();

        // Try to commit - should fail due to finality requirement
        let result = router
            .commit_intent(&create_result.intent_id, &intent, current_ms)
            .await;

        assert!(matches!(result, Err(IntentRouterError::PrepareNotFinalised)));
    }

    #[tokio::test]
    async fn abort_from_created() {
        let (router, intent) = setup_router();
        let current_ms = 1_700_000_100_000;

        let create_result = router.create_intent(intent.clone(), current_ms).unwrap();

        let abort_result = router
            .abort_intent(
                &create_result.intent_id,
                "cancelled".to_string(),
                Some(&intent),
                current_ms,
            )
            .await
            .unwrap();

        assert_eq!(abort_result.reason, "cancelled");

        // Verify state updated
        let state = router.get_state(&create_result.intent_id).unwrap();
        assert!(state.is_aborted());
        assert!(state.is_terminal());
    }

    #[tokio::test]
    async fn abort_from_prepared() {
        let (router, intent) = setup_router();
        let current_ms = 1_700_000_100_000;

        let create_result = router.create_intent(intent.clone(), current_ms).unwrap();
        router
            .prepare_intent(&create_result.intent_id, &intent, current_ms)
            .await
            .unwrap();

        let abort_result = router
            .abort_intent(
                &create_result.intent_id,
                "timeout".to_string(),
                Some(&intent),
                current_ms,
            )
            .await
            .unwrap();

        assert_eq!(abort_result.reason, "timeout");

        let state = router.get_state(&create_result.intent_id).unwrap();
        assert!(state.is_aborted());
    }

    #[tokio::test]
    async fn cannot_abort_committed() {
        let (router, intent) = setup_router();
        let current_ms = 1_700_000_100_000;

        let create_result = router.create_intent(intent.clone(), current_ms).unwrap();
        router
            .prepare_intent(&create_result.intent_id, &intent, current_ms)
            .await
            .unwrap();
        router
            .commit_intent(&create_result.intent_id, &intent, current_ms)
            .await
            .unwrap();

        // Try to abort - should fail
        let result = router
            .abort_intent(
                &create_result.intent_id,
                "late cancel".to_string(),
                Some(&intent),
                current_ms,
            )
            .await;

        assert!(matches!(result, Err(IntentRouterError::AlreadyInState { .. })));
    }

    #[test]
    fn get_status() {
        let (router, intent) = setup_router();
        let current_ms = 1_700_000_100_000;

        let create_result = router.create_intent(intent.clone(), current_ms).unwrap();

        let status = router.get_status(&create_result.intent_id).unwrap();
        assert_eq!(status.state_name, "created");
        assert!(!status.is_terminal);
    }

    #[test]
    fn count_states() {
        let (router, _) = setup_router();
        let current_ms = 1_700_000_100_000;

        // Create several intents
        for i in 0u8..5 {
            let intent = Intent {
                kind: IntentKind::CrossHubTransfer,
                created_ms: 1_700_000_000_000,
                expires_ms: 1_700_000_600_000,
                from_hub: L2HubId::Fin,
                to_hub: L2HubId::World,
                initiator: format!("user_{}", i),
                payload: vec![i],
            };
            router.create_intent(intent, current_ms).unwrap();
        }

        let counts = router.count_states().unwrap();
        assert_eq!(counts.created, 5);
        assert_eq!(counts.pending(), 5);
        assert_eq!(counts.total(), 5);
    }

    #[test]
    fn policy_from_env() {
        // Just test that it doesn't panic and returns defaults
        let policy = IntentPolicy::from_env();
        assert!(policy.default_expires_ms > 0);
    }

    #[test]
    fn policy_validate_expiry() {
        let policy = IntentPolicy {
            min_expires_ms: 60_000,
            max_expires_ms: 3_600_000,
            default_expires_ms: 600_000,
            ..Default::default()
        };

        // Default
        assert_eq!(policy.validate_expiry(None), 600_000);

        // Within range
        assert_eq!(policy.validate_expiry(Some(120_000)), 120_000);

        // Below min
        assert_eq!(policy.validate_expiry(Some(10_000)), 60_000);

        // Above max
        assert_eq!(policy.validate_expiry(Some(10_000_000)), 3_600_000);
    }

    #[tokio::test]
    async fn process_expired_intents() {
        let (router, _) = setup_router();
        let created_ms = 1_700_000_000_000;

        // Create intent that expires soon
        let intent = Intent {
            kind: IntentKind::CrossHubTransfer,
            created_ms,
            expires_ms: 1_700_000_100_000, // Expires at +100s
            from_hub: L2HubId::Fin,
            to_hub: L2HubId::World,
            initiator: "alice".to_string(),
            payload: vec![1, 2, 3],
        };

        router.create_intent(intent, created_ms).unwrap();

        // Process at a time before expiry - should not abort
        let results = router.process_expired(1_700_000_050_000, 10).await;
        assert_eq!(results.len(), 0);

        // Process at a time after expiry - should abort
        let results = router.process_expired(1_700_000_200_000, 10).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].reason, "expired");
    }
}
