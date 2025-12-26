//! BRIDGE Intent API handlers.
//!
//! This module provides HTTP API handlers for the cross-hub intent protocol.
//!
//! ## Endpoints
//!
//! - `POST /bridge/intent` - Create a new intent
//! - `POST /bridge/intent/:id/prepare` - Prepare an intent (acquire locks)
//! - `POST /bridge/intent/:id/commit` - Commit an intent (finalize)
//! - `POST /bridge/intent/:id/abort` - Abort an intent (rollback)
//! - `GET /bridge/intent/:id` - Get intent status
//! - `GET /bridge/intents` - List intents (with filters)

use l2_core::{Intent, IntentId, IntentKind, L2HubId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

use crate::intent_reconciler::IntentBatchTracker;
use crate::intents::{IntentPolicy, IntentRouter, IntentRouterError};

/// Intent API service.
pub struct IntentApi {
    router: Arc<IntentRouter>,
    batch_tracker: Arc<tokio::sync::Mutex<IntentBatchTracker>>,
    /// Cache of intent payloads for prepare/commit (intent_id -> Intent).
    /// In production, this should be persisted or fetched from storage.
    intent_cache: Arc<tokio::sync::Mutex<std::collections::HashMap<String, Intent>>>,
}

impl IntentApi {
    /// Create a new IntentApi.
    pub fn new(
        router: Arc<IntentRouter>,
        batch_tracker: Arc<tokio::sync::Mutex<IntentBatchTracker>>,
    ) -> Self {
        Self {
            router,
            batch_tracker,
            intent_cache: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Get the intent policy.
    pub fn policy(&self) -> &IntentPolicy {
        self.router.policy()
    }

    // ========== API Handlers ==========

    /// Create a new intent.
    ///
    /// POST /bridge/intent
    pub async fn create_intent(
        &self,
        request: CreateIntentRequest,
    ) -> Result<CreateIntentResponse, IntentApiError> {
        let current_ms = now_ms();

        // Parse the request into an Intent
        let intent = request.to_intent(current_ms)?;

        // Create via router
        let result = self.router.create_intent(intent.clone(), current_ms)?;

        // Cache the intent for future prepare/commit
        {
            let mut cache = self.intent_cache.lock().await;
            cache.insert(result.intent_id.to_hex(), intent);
        }

        Ok(CreateIntentResponse {
            intent_id: result.intent_id.to_hex(),
            state: result.state.name().to_string(),
            created_ms: current_ms,
        })
    }

    /// Prepare an intent (acquire locks).
    ///
    /// POST /bridge/intent/:id/prepare
    pub async fn prepare_intent(
        &self,
        intent_id_hex: &str,
    ) -> Result<PrepareIntentResponse, IntentApiError> {
        let intent_id = IntentId::from_hex(intent_id_hex)
            .map_err(|e| IntentApiError::InvalidRequest(format!("invalid intent_id: {}", e)))?;

        let current_ms = now_ms();

        // Get cached intent
        let intent = {
            let cache = self.intent_cache.lock().await;
            cache.get(intent_id_hex).cloned()
        }
        .ok_or_else(|| {
            IntentApiError::NotFound(format!("intent {} not found in cache", intent_id_hex))
        })?;

        // Prepare via router
        let result = self
            .router
            .prepare_intent(&intent_id, &intent, current_ms)
            .await?;

        // Record the batch association (in real impl, this would be the batch hash)
        // For now, we use a placeholder since we're not actually batching
        {
            let mut tracker = self.batch_tracker.lock().await;
            let placeholder_batch = l2_core::Hash32([0x00; 32]);
            tracker.record_prepare_batch(&intent_id, placeholder_batch);
        }

        Ok(PrepareIntentResponse {
            intent_id: result.intent_id.to_hex(),
            receipts_hash: result.receipts_hash.to_hex(),
            prepared_ms: result.hub_tx.timestamp_ms(),
            receipt_count: result.receipts.len(),
        })
    }

    /// Commit an intent (finalize).
    ///
    /// POST /bridge/intent/:id/commit
    pub async fn commit_intent(
        &self,
        intent_id_hex: &str,
    ) -> Result<CommitIntentResponse, IntentApiError> {
        let intent_id = IntentId::from_hex(intent_id_hex)
            .map_err(|e| IntentApiError::InvalidRequest(format!("invalid intent_id: {}", e)))?;

        let current_ms = now_ms();

        // Check if expired
        let state = self.router.get_state(&intent_id)?;
        if let Some(expires_ms) = state.expires_ms() {
            if current_ms >= expires_ms {
                return Err(IntentApiError::Expired {
                    intent_id: intent_id_hex.to_string(),
                    expires_ms,
                    current_ms,
                });
            }
        }

        // Check if prepared (required for commit)
        if !state.is_prepared() {
            return Err(IntentApiError::WrongState {
                expected: "prepared".to_string(),
                found: state.name().to_string(),
            });
        }

        // Get cached intent
        let intent = {
            let cache = self.intent_cache.lock().await;
            cache.get(intent_id_hex).cloned()
        }
        .ok_or_else(|| {
            IntentApiError::NotFound(format!("intent {} not found in cache", intent_id_hex))
        })?;

        // Commit via router
        let result = self
            .router
            .commit_intent(&intent_id, &intent, current_ms)
            .await?;

        // Clean up cache
        {
            let mut cache = self.intent_cache.lock().await;
            cache.remove(intent_id_hex);
        }

        // Clean up tracker
        {
            let mut tracker = self.batch_tracker.lock().await;
            tracker.remove(&intent_id);
        }

        Ok(CommitIntentResponse {
            intent_id: result.intent_id.to_hex(),
            receipts_hash: result.receipts_hash.to_hex(),
            committed_ms: result.hub_tx.timestamp_ms(),
            receipt_count: result.receipts.len(),
        })
    }

    /// Abort an intent (rollback).
    ///
    /// POST /bridge/intent/:id/abort
    pub async fn abort_intent(
        &self,
        intent_id_hex: &str,
        request: AbortIntentRequest,
    ) -> Result<AbortIntentResponse, IntentApiError> {
        let intent_id = IntentId::from_hex(intent_id_hex)
            .map_err(|e| IntentApiError::InvalidRequest(format!("invalid intent_id: {}", e)))?;

        let current_ms = now_ms();

        // Get cached intent (optional for abort)
        let intent = {
            let cache = self.intent_cache.lock().await;
            cache.get(intent_id_hex).cloned()
        };

        // Abort via router
        let result = self
            .router
            .abort_intent(
                &intent_id,
                request.reason.clone(),
                intent.as_ref(),
                current_ms,
            )
            .await?;

        // Clean up cache
        {
            let mut cache = self.intent_cache.lock().await;
            cache.remove(intent_id_hex);
        }

        // Clean up tracker
        {
            let mut tracker = self.batch_tracker.lock().await;
            tracker.remove(&intent_id);
        }

        Ok(AbortIntentResponse {
            intent_id: result.intent_id.to_hex(),
            reason: result.reason,
            reason_hash: result.reason_hash.to_hex(),
            aborted_ms: result.hub_tx.timestamp_ms(),
        })
    }

    /// Get intent status.
    ///
    /// GET /bridge/intent/:id
    pub fn get_intent(&self, intent_id_hex: &str) -> Result<IntentStatusResponse, IntentApiError> {
        let intent_id = IntentId::from_hex(intent_id_hex)
            .map_err(|e| IntentApiError::InvalidRequest(format!("invalid intent_id: {}", e)))?;

        let status = self.router.get_status(&intent_id)?;

        Ok(IntentStatusResponse {
            intent_id: status.intent_id,
            phase: status.phase.as_str().to_string(),
            is_terminal: status.is_terminal,
            state_name: status.state_name,
            details: status.details,
        })
    }

    /// List intents with optional filters.
    ///
    /// GET /bridge/intents?hub=FIN&state=prepared
    pub fn list_intents(
        &self,
        query: ListIntentsQuery,
    ) -> Result<ListIntentsResponse, IntentApiError> {
        let limit = query.limit.unwrap_or(100).min(1000);

        let entries = if let Some(hub_str) = &query.hub {
            let hub = L2HubId::parse(hub_str).ok_or_else(|| {
                IntentApiError::InvalidRequest(format!("invalid hub: {}", hub_str))
            })?;
            self.router.list_pending_for_hub(hub, limit)?
        } else {
            self.router.list_by_state(query.state.as_deref(), limit)?
        };

        let intents: Vec<IntentListItem> = entries
            .into_iter()
            .map(|e| IntentListItem {
                intent_id: e.intent_id.to_hex(),
                state: e.state.name().to_string(),
                is_terminal: e.state.is_terminal(),
            })
            .collect();

        let total = intents.len();
        Ok(ListIntentsResponse { intents, total })
    }

    /// Get intent counts by state for /status endpoint.
    pub fn get_counts(&self) -> Result<IntentCountsResponse, IntentApiError> {
        let counts = self.router.count_states()?;
        Ok(IntentCountsResponse {
            created: counts.created,
            prepared: counts.prepared,
            committed: counts.committed,
            aborted: counts.aborted,
            total: counts.total(),
            pending: counts.pending(),
        })
    }
}

// ========== Request/Response Types ==========

/// Request to create a new intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIntentRequest {
    /// Kind of intent operation.
    pub kind: String,
    /// Source hub.
    pub from_hub: String,
    /// Destination hub.
    pub to_hub: String,
    /// Initiator account.
    pub initiator: String,
    /// Hub-specific payload (base64 encoded).
    pub payload: String,
    /// Optional expiry duration (ms from now). Uses default if not specified.
    #[serde(default)]
    pub expires_in_ms: Option<u64>,
}

impl CreateIntentRequest {
    fn to_intent(&self, current_ms: u64) -> Result<Intent, IntentApiError> {
        let kind = IntentKind::parse(&self.kind).ok_or_else(|| {
            IntentApiError::InvalidRequest(format!("invalid intent kind: {}", self.kind))
        })?;

        let from_hub = L2HubId::parse(&self.from_hub).ok_or_else(|| {
            IntentApiError::InvalidRequest(format!("invalid from_hub: {}", self.from_hub))
        })?;

        let to_hub = L2HubId::parse(&self.to_hub).ok_or_else(|| {
            IntentApiError::InvalidRequest(format!("invalid to_hub: {}", self.to_hub))
        })?;

        let payload = base64_decode(&self.payload)?;

        let expires_ms = current_ms
            + self
                .expires_in_ms
                .unwrap_or(crate::DEFAULT_INTENT_EXPIRES_MS);

        Ok(Intent {
            kind,
            created_ms: current_ms,
            expires_ms,
            from_hub,
            to_hub,
            initiator: self.initiator.clone(),
            payload,
        })
    }
}

/// Response from creating an intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIntentResponse {
    pub intent_id: String,
    pub state: String,
    pub created_ms: u64,
}

/// Response from preparing an intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareIntentResponse {
    pub intent_id: String,
    pub receipts_hash: String,
    pub prepared_ms: u64,
    pub receipt_count: usize,
}

/// Response from committing an intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitIntentResponse {
    pub intent_id: String,
    pub receipts_hash: String,
    pub committed_ms: u64,
    pub receipt_count: usize,
}

/// Request to abort an intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbortIntentRequest {
    /// Reason for aborting.
    pub reason: String,
}

/// Response from aborting an intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbortIntentResponse {
    pub intent_id: String,
    pub reason: String,
    pub reason_hash: String,
    pub aborted_ms: u64,
}

/// Response with intent status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentStatusResponse {
    pub intent_id: String,
    pub phase: String,
    pub is_terminal: bool,
    pub state_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Query parameters for listing intents.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListIntentsQuery {
    /// Filter by hub (either from_hub or to_hub).
    #[serde(default)]
    pub hub: Option<String>,
    /// Filter by state (created, prepared, committed, aborted, pending).
    #[serde(default)]
    pub state: Option<String>,
    /// Maximum number of intents to return.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Single intent in list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentListItem {
    pub intent_id: String,
    pub state: String,
    pub is_terminal: bool,
}

/// Response with list of intents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListIntentsResponse {
    pub intents: Vec<IntentListItem>,
    pub total: usize,
}

/// Response with intent counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentCountsResponse {
    pub created: u64,
    pub prepared: u64,
    pub committed: u64,
    pub aborted: u64,
    pub total: u64,
    pub pending: u64,
}

// ========== Error Types ==========

/// API error type.
#[derive(Debug, Error)]
pub enum IntentApiError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("intent {intent_id} expired at {expires_ms}, current time is {current_ms}")]
    Expired {
        intent_id: String,
        expires_ms: u64,
        current_ms: u64,
    },

    #[error("wrong state: expected {expected}, found {found}")]
    WrongState { expected: String, found: String },

    #[error("router error: {0}")]
    Router(#[from] IntentRouterError),

    #[error("internal error: {0}")]
    Internal(String),
}

impl IntentApiError {
    /// Get HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            IntentApiError::InvalidRequest(_) => 400,
            IntentApiError::NotFound(_) => 404,
            IntentApiError::Expired { .. } => 409,
            IntentApiError::WrongState { .. } => 409,
            IntentApiError::Router(IntentRouterError::NotFound(_)) => 404,
            IntentApiError::Router(IntentRouterError::Expired { .. }) => 409,
            IntentApiError::Router(IntentRouterError::AlreadyInState { .. }) => 409,
            IntentApiError::Router(IntentRouterError::WrongState { .. }) => 409,
            IntentApiError::Router(IntentRouterError::PrepareNotFinalised) => 409,
            IntentApiError::Router(IntentRouterError::PolicyViolation(_)) => 403,
            IntentApiError::Router(_) => 500,
            IntentApiError::Internal(_) => 500,
        }
    }

    /// Get error code for this error.
    pub fn error_code(&self) -> &'static str {
        match self {
            IntentApiError::InvalidRequest(_) => "invalid_request",
            IntentApiError::NotFound(_) => "not_found",
            IntentApiError::Expired { .. } => "expired",
            IntentApiError::WrongState { .. } => "wrong_state",
            IntentApiError::Router(IntentRouterError::NotFound(_)) => "not_found",
            IntentApiError::Router(IntentRouterError::Expired { .. }) => "expired",
            IntentApiError::Router(IntentRouterError::AlreadyInState { .. }) => "already_in_state",
            IntentApiError::Router(IntentRouterError::WrongState { .. }) => "wrong_state",
            IntentApiError::Router(IntentRouterError::PrepareNotFinalised) => {
                "prepare_not_finalised"
            }
            IntentApiError::Router(IntentRouterError::PolicyViolation(_)) => "policy_violation",
            IntentApiError::Router(_) => "router_error",
            IntentApiError::Internal(_) => "internal_error",
        }
    }
}

// ========== Helpers ==========

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, IntentApiError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| IntentApiError::InvalidRequest(format!("invalid base64 payload: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intents::{MockFinalityChecker, MockHubExecutor};
    use base64::Engine as _;
    use l2_storage::IntentStorage;
    use tempfile::tempdir;

    fn test_db() -> sled::Db {
        let dir = tempdir().expect("tmpdir");
        sled::open(dir.path()).expect("open")
    }

    fn setup_api() -> IntentApi {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();
        let policy = IntentPolicy::default();
        let finality_checker = Arc::new(MockFinalityChecker::default());

        let mut router = IntentRouter::new(storage, policy, finality_checker);
        router.register_executor(L2HubId::Fin, Arc::new(MockHubExecutor::new(L2HubId::Fin)));
        router.register_executor(
            L2HubId::World,
            Arc::new(MockHubExecutor::new(L2HubId::World)),
        );
        router.register_executor(L2HubId::Data, Arc::new(MockHubExecutor::new(L2HubId::Data)));
        router.register_executor(L2HubId::M2m, Arc::new(MockHubExecutor::new(L2HubId::M2m)));
        router.register_executor(
            L2HubId::Bridge,
            Arc::new(MockHubExecutor::new(L2HubId::Bridge)),
        );

        let batch_tracker = Arc::new(tokio::sync::Mutex::new(IntentBatchTracker::new()));

        IntentApi::new(Arc::new(router), batch_tracker)
    }

    #[tokio::test]
    async fn create_intent_api() {
        let api = setup_api();

        let request = CreateIntentRequest {
            kind: "cross_hub_transfer".to_string(),
            from_hub: "fin".to_string(),
            to_hub: "world".to_string(),
            initiator: "alice".to_string(),
            payload: base64::engine::general_purpose::STANDARD.encode(b"test payload"),
            expires_in_ms: Some(600_000),
        };

        let response = api.create_intent(request).await.unwrap();

        assert!(!response.intent_id.is_empty());
        assert_eq!(response.state, "created");
    }

    #[tokio::test]
    async fn full_intent_lifecycle() {
        let api = setup_api();

        // Create
        let create_request = CreateIntentRequest {
            kind: "cross_hub_transfer".to_string(),
            from_hub: "fin".to_string(),
            to_hub: "world".to_string(),
            initiator: "alice".to_string(),
            payload: base64::engine::general_purpose::STANDARD.encode(b"test"),
            expires_in_ms: Some(600_000),
        };
        let create_response = api.create_intent(create_request).await.unwrap();
        let intent_id = &create_response.intent_id;

        // Prepare
        let prepare_response = api.prepare_intent(intent_id).await.unwrap();
        assert_eq!(prepare_response.intent_id, *intent_id);
        assert_eq!(prepare_response.receipt_count, 2);

        // Get status - should be prepared
        let status = api.get_intent(intent_id).unwrap();
        assert_eq!(status.state_name, "prepared");

        // Commit
        let commit_response = api.commit_intent(intent_id).await.unwrap();
        assert_eq!(commit_response.intent_id, *intent_id);

        // Get status - should be committed
        let status = api.get_intent(intent_id).unwrap();
        assert_eq!(status.state_name, "committed");
        assert!(status.is_terminal);
    }

    #[tokio::test]
    async fn abort_intent_api() {
        let api = setup_api();

        // Create
        let create_request = CreateIntentRequest {
            kind: "cross_hub_transfer".to_string(),
            from_hub: "fin".to_string(),
            to_hub: "world".to_string(),
            initiator: "alice".to_string(),
            payload: base64::engine::general_purpose::STANDARD.encode(b"test"),
            expires_in_ms: Some(600_000),
        };
        let create_response = api.create_intent(create_request).await.unwrap();
        let intent_id = &create_response.intent_id;

        // Abort
        let abort_request = AbortIntentRequest {
            reason: "user cancelled".to_string(),
        };
        let abort_response = api.abort_intent(intent_id, abort_request).await.unwrap();
        assert_eq!(abort_response.intent_id, *intent_id);
        assert_eq!(abort_response.reason, "user cancelled");

        // Get status - should be aborted
        let status = api.get_intent(intent_id).unwrap();
        assert_eq!(status.state_name, "aborted");
        assert!(status.is_terminal);
    }

    #[tokio::test]
    async fn list_intents_api() {
        let api = setup_api();

        // Create several intents
        for i in 0u8..3 {
            let request = CreateIntentRequest {
                kind: "cross_hub_transfer".to_string(),
                from_hub: "fin".to_string(),
                to_hub: "world".to_string(),
                initiator: format!("user_{}", i),
                payload: base64::engine::general_purpose::STANDARD.encode([i]),
                expires_in_ms: Some(600_000),
            };
            api.create_intent(request).await.unwrap();
        }

        // List all
        let query = ListIntentsQuery::default();
        let response = api.list_intents(query).unwrap();
        assert_eq!(response.total, 3);

        // List by hub
        let query = ListIntentsQuery {
            hub: Some("fin".to_string()),
            ..Default::default()
        };
        let response = api.list_intents(query).unwrap();
        assert_eq!(response.total, 3); // All have fin as from_hub
    }

    #[test]
    fn get_counts_api() {
        let api = setup_api();
        let counts = api.get_counts().unwrap();

        assert_eq!(counts.created, 0);
        assert_eq!(counts.prepared, 0);
        assert_eq!(counts.committed, 0);
        assert_eq!(counts.aborted, 0);
        assert_eq!(counts.total, 0);
        assert_eq!(counts.pending, 0);
    }

    #[test]
    fn intent_api_error_codes() {
        let err = IntentApiError::InvalidRequest("test".to_string());
        assert_eq!(err.status_code(), 400);
        assert_eq!(err.error_code(), "invalid_request");

        let err = IntentApiError::NotFound("test".to_string());
        assert_eq!(err.status_code(), 404);
        assert_eq!(err.error_code(), "not_found");

        let err = IntentApiError::Expired {
            intent_id: "test".to_string(),
            expires_ms: 1000,
            current_ms: 2000,
        };
        assert_eq!(err.status_code(), 409);
        assert_eq!(err.error_code(), "expired");
    }
}
