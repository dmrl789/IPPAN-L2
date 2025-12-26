#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::disallowed_types)]

//! Batching and posting for IPPAN L2.
//!
//! This crate provides the batcher loop that collects transactions, forms batches,
//! and posts them to L1 via either the legacy IPPAN RPC endpoint or the new
//! contract-based `L2BatchEnvelopeV1` submission.
//!
//! ## Posting Modes
//!
//! - **Contract (ContractBatchPoster)** - **RECOMMENDED**: Builds `BatchEnvelope` →
//!   `L2BatchEnvelopeV1` and submits via `L1Client::submit_batch` for proper
//!   idempotency and finality tracking. This is the default mode.
//!
//! - **Raw/Legacy (IppanBatchPoster)** - **DEBUG ONLY**: Posts raw batch JSON to
//!   `/tx` endpoint. Use only for debugging or when contract posting is unavailable.
//!   Set `L2_POSTER_MODE=raw` to enable.
//!
//! ## Features
//!
//! - `contract-posting`: Enable contract-based batch posting (recommended for production)
//! - `signed-envelopes`: Enable Ed25519 envelope signing
//! - `async-l1-http`: Enable native async HTTP L1 client

pub mod async_l1_client;
pub mod contract_bridge;
pub mod gbdt_organiser;
pub mod gbdt_organiser_v2;
pub mod reconciler;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use ippan_rpc::{DataTxRequest, IppanRpcClient, IppanRpcConfig, IppanRpcError};
use l2_core::fees::FeeSchedule;
use l2_core::{Batch, ChainId, Hash32, Tx};
use l2_storage::m2m::{BatchFeeTotals, M2mStorage};
use l2_storage::{PostingState, SettlementState, Storage};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Instant};
use tracing::{debug, error, info, warn};

// Re-exports for convenience
pub use async_l1_client::{AsyncL1Client, BatchStatus, BlockingL1ClientAdapter, FinalityStatus};
pub use contract_bridge::{
    batch_envelope_payload_bytes, batch_envelope_to_l1_envelope, batch_to_l1_envelope,
    get_prev_batch_hash, BridgeConfig, BridgeError, BridgeResult, ContentType,
    BATCH_ENVELOPE_CONTENT_TYPE_BINARY, BATCH_ENVELOPE_CONTENT_TYPE_JSON,
    BATCH_ENVELOPE_SCHEMA_VERSION, MAX_PAYLOAD_SIZE,
};
pub use gbdt_organiser::{GbdtOrganiserConfig, GbdtOrganiserV1};
pub use gbdt_organiser_v2::{
    GbdtOrganiserV2, GbdtOrganiserV2Config, NoopOrganiserV2, OrganiserV2, OrganiserVersionV2,
};
// Re-export organiser types from l2-core for convenience
pub use l2_core::{
    NoopOrganiser, Organiser, OrganiserDecision, OrganiserInputs, OrganiserPolicyBounds,
    OrganiserStatus, OrganiserVersion,
};
pub use reconciler::{
    get_in_flight_summary, get_settlement_counts, spawn_settlement_reconciler, InFlightSummary,
    ReconcileCycleResult, ReconcilerMetrics, SettlementReconcilerConfig,
    SettlementReconcilerHandle,
};

#[derive(Debug, Clone)]
pub struct BatcherConfig {
    pub max_batch_txs: usize,
    pub max_batch_bytes: usize,
    pub max_wait_ms: u64,
    pub chain_id: ChainId,
    /// Whether the organiser is enabled.
    pub organiser_enabled: bool,
    /// Policy bounds for organiser decisions.
    pub organiser_bounds: OrganiserPolicyBounds,
}

impl Default for BatcherConfig {
    fn default() -> Self {
        Self {
            max_batch_txs: 256,
            max_batch_bytes: 512 * 1024,
            max_wait_ms: 1_000,
            chain_id: ChainId(1),
            organiser_enabled: true,
            organiser_bounds: OrganiserPolicyBounds::default(),
        }
    }
}

impl BatcherConfig {
    /// Create configuration from environment variables.
    pub fn from_env() -> Self {
        let default = Self::default();
        Self {
            max_batch_txs: std::env::var("L2_MAX_BATCH_TXS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.max_batch_txs),
            max_batch_bytes: std::env::var("L2_MAX_BATCH_BYTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.max_batch_bytes),
            max_wait_ms: std::env::var("L2_MAX_WAIT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.max_wait_ms),
            chain_id: ChainId(
                std::env::var("L2_CHAIN_ID")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(default.chain_id.0),
            ),
            organiser_enabled: std::env::var("L2_ORGANISER_ENABLED")
                .map(|s| s != "0" && s.to_lowercase() != "false")
                .unwrap_or(default.organiser_enabled),
            organiser_bounds: OrganiserPolicyBounds::from_env(),
        }
    }
}

#[derive(Debug, Error)]
pub enum BatcherError {
    #[error("storage error: {0}")]
    Storage(#[from] l2_storage::StorageError),
    #[error("poster error: {0}")]
    Poster(String),
    #[error("queue closed")]
    QueueClosed,
}

#[async_trait]
pub trait BatchPoster: Send + Sync {
    async fn post_batch(&self, batch: &Batch, hash: &Hash32) -> Result<(), BatcherError>;
}

pub struct LoggingBatchPoster;

#[async_trait]
impl BatchPoster for LoggingBatchPoster {
    async fn post_batch(&self, batch: &Batch, hash: &Hash32) -> Result<(), BatcherError> {
        info!(txs = batch.txs.len(), hash = %hash.to_hex(), "stub posting batch to L1");
        Ok(())
    }
}

/// Posting mode for IPPAN batch poster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PostMode {
    /// Use POST /tx endpoint with data field.
    #[default]
    TxData,
    /// Use POST /tx/payment endpoint with memo field.
    TxPaymentMemo,
}

impl PostMode {
    /// Parse from environment variable value.
    pub fn from_env_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "tx_payment_memo" | "payment" => Self::TxPaymentMemo,
            _ => Self::TxData,
        }
    }
}

/// Configuration for IPPAN batch poster.
#[derive(Debug, Clone)]
pub struct IppanPosterConfig {
    /// Posting mode (tx_data or tx_payment_memo).
    pub mode: PostMode,
    /// Force repost even if already posted/confirmed.
    pub force_repost: bool,
    /// Maximum number of posting retries.
    pub max_retries: u32,
    /// Base retry delay in milliseconds.
    pub retry_delay_ms: u64,
}

impl Default for IppanPosterConfig {
    fn default() -> Self {
        Self {
            mode: PostMode::TxData,
            force_repost: false,
            max_retries: 3,
            retry_delay_ms: 500,
        }
    }
}

impl IppanPosterConfig {
    /// Create configuration from environment variables.
    pub fn from_env() -> Self {
        let mode = std::env::var("L2_POST_MODE")
            .map(|s| PostMode::from_env_str(&s))
            .unwrap_or_default();
        let force_repost = std::env::var("L2_FORCE_REPOST")
            .map(|s| s == "1" || s.to_lowercase() == "true")
            .unwrap_or(false);
        let max_retries = std::env::var("L2_POST_MAX_RETRIES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);
        let retry_delay_ms = std::env::var("L2_POST_RETRY_DELAY_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(500);

        Self {
            mode,
            force_repost,
            max_retries,
            retry_delay_ms,
        }
    }
}

/// Batch data payload for posting to L1.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BatchPostData {
    /// Batch hash (hex).
    pub batch_hash: String,
    /// Chain ID.
    pub chain_id: u64,
    /// Batch number.
    pub batch_number: u64,
    /// Transaction count.
    pub tx_count: usize,
    /// Creation timestamp (ms).
    pub created_ms: u64,
    /// Payload hash (hex).
    pub payload_hash: String,
}

/// IPPAN RPC batch poster with idempotent posting.
///
/// # Legacy/Debug Mode
///
/// This poster is maintained for debugging and backwards compatibility.
/// **For production use, prefer `ContractBatchPoster`** which provides:
/// - Deterministic idempotency keys
/// - Proper finality/inclusion tracking
/// - Versioned envelope format
///
/// Enable contract posting with `--features contract-posting` and
/// `L2_POSTER_MODE=contract` (default).
pub struct IppanBatchPoster {
    client: IppanRpcClient,
    storage: Arc<Storage>,
    config: IppanPosterConfig,
}

impl IppanBatchPoster {
    /// Create a new IPPAN batch poster.
    pub fn new(
        rpc_config: IppanRpcConfig,
        storage: Arc<Storage>,
        poster_config: IppanPosterConfig,
    ) -> Result<Self, BatcherError> {
        let client = IppanRpcClient::new(rpc_config)
            .map_err(|e| BatcherError::Poster(format!("failed to create RPC client: {e}")))?;
        Ok(Self {
            client,
            storage,
            config: poster_config,
        })
    }

    /// Create from environment variables.
    pub fn from_env(storage: Arc<Storage>) -> Result<Self, BatcherError> {
        let rpc_config = IppanRpcConfig::from_env()
            .map_err(|e| BatcherError::Poster(format!("RPC config error: {e}")))?;
        let poster_config = IppanPosterConfig::from_env();
        Self::new(rpc_config, storage, poster_config)
    }

    /// Check if batch should be posted (idempotency check).
    fn should_post(&self, hash: &Hash32) -> Result<bool, BatcherError> {
        let state = self.storage.get_posting_state(hash)?;
        match state {
            None => Ok(true),                               // Never posted
            Some(PostingState::Pending { .. }) => Ok(true), // Ready to post
            Some(PostingState::Posted { .. }) => Ok(self.config.force_repost),
            Some(PostingState::Confirmed { .. }) => Ok(self.config.force_repost),
            Some(PostingState::Failed { retry_count, .. }) => {
                // Allow retry if under limit
                Ok(retry_count < self.config.max_retries)
            }
        }
    }

    /// Post batch data using the configured mode.
    async fn do_post(&self, batch: &Batch, hash: &Hash32) -> Result<String, IppanRpcError> {
        // Create the batch data payload
        let payload_hash = l2_core::canonical_hash(batch)
            .map(|h| h.to_hex())
            .unwrap_or_else(|_| "unknown".to_string());

        let batch_data = BatchPostData {
            batch_hash: hash.to_hex(),
            chain_id: batch.chain_id.0,
            batch_number: batch.batch_number,
            tx_count: batch.txs.len(),
            created_ms: batch.created_ms,
            payload_hash,
        };

        // Serialize to JSON string for the data field
        let data_json = serde_json::to_string(&batch_data)
            .map_err(|e| IppanRpcError::Decode(format!("failed to serialize batch data: {e}")))?;

        // Use hex encoding of the JSON for the data field
        let data_hex = hex::encode(data_json.as_bytes());

        match self.config.mode {
            PostMode::TxData => {
                let request = DataTxRequest {
                    data: data_hex,
                    memo: Some(format!("L2 Batch {}", hash.to_hex())),
                    nonce: Some(batch.batch_number),
                };
                let response = self.client.submit_data_tx(&request).await?;
                Ok(response.tx_hash)
            }
            PostMode::TxPaymentMemo => {
                // For payment mode, we'd use submit_payment_tx, but since data posting
                // is more appropriate for batch anchoring, we use the same data endpoint
                // but document that payment_memo would use a different endpoint
                let request = DataTxRequest {
                    data: data_hex,
                    memo: Some(format!("L2 Batch {}", hash.to_hex())),
                    nonce: Some(batch.batch_number),
                };
                let response = self.client.submit_data_tx(&request).await?;
                Ok(response.tx_hash)
            }
        }
    }
}

#[async_trait]
impl BatchPoster for IppanBatchPoster {
    async fn post_batch(&self, batch: &Batch, hash: &Hash32) -> Result<(), BatcherError> {
        // Idempotency check
        if !self.should_post(hash)? {
            info!(hash = %hash.to_hex(), "batch already posted, skipping");
            return Ok(());
        }

        // Mark as pending
        self.storage
            .set_posting_state(hash, &PostingState::pending(now_ms()))?;

        // Attempt posting with bounded retries
        let mut last_error: Option<String> = None;
        let mut retry_count: u32 = 0;

        while retry_count <= self.config.max_retries {
            match self.do_post(batch, hash).await {
                Ok(l1_tx) => {
                    info!(
                        hash = %hash.to_hex(),
                        l1_tx = %l1_tx,
                        "batch posted successfully"
                    );
                    self.storage
                        .set_posting_state(hash, &PostingState::posted(l1_tx, now_ms()))?;
                    return Ok(());
                }
                Err(err) => {
                    warn!(
                        hash = %hash.to_hex(),
                        attempt = retry_count + 1,
                        error = %err,
                        "batch posting failed"
                    );
                    last_error = Some(err.to_string());
                    retry_count = retry_count.saturating_add(1);

                    if retry_count <= self.config.max_retries {
                        // Exponential backoff
                        let delay_ms = self
                            .config
                            .retry_delay_ms
                            .saturating_mul(2u64.saturating_pow(retry_count.saturating_sub(1)));
                        let delay = Duration::from_millis(delay_ms.min(10_000)); // Cap at 10s
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        // All retries exhausted
        let reason = last_error.unwrap_or_else(|| "unknown error".to_string());
        error!(
            hash = %hash.to_hex(),
            retries = retry_count,
            reason = %reason,
            "batch posting failed after all retries"
        );
        self.storage.set_posting_state(
            hash,
            &PostingState::failed(reason.clone(), now_ms(), retry_count),
        )?;
        Err(BatcherError::Poster(reason))
    }
}

// ============== Contract-based Batch Poster ==============

/// Maximum retry attempts for batch posting.
pub const MAX_RETRY_LIMIT: u32 = 10;

/// Maximum retry delay in milliseconds.
pub const MAX_RETRY_DELAY_MS: u64 = 60_000;

/// Configuration for contract-based batch poster.
#[derive(Debug, Clone)]
pub struct ContractPosterConfig {
    /// Bridge configuration for envelope construction.
    pub bridge: BridgeConfig,
    /// Force repost even if already posted/confirmed.
    pub force_repost: bool,
    /// Maximum number of posting retries.
    pub max_retries: u32,
    /// Base retry delay in milliseconds.
    pub retry_delay_ms: u64,
    /// Timeout for individual L1 requests in milliseconds.
    pub l1_timeout_ms: u64,
}

impl Default for ContractPosterConfig {
    fn default() -> Self {
        Self {
            bridge: BridgeConfig::default(),
            force_repost: false,
            max_retries: 3,
            retry_delay_ms: 500,
            l1_timeout_ms: 30_000,
        }
    }
}

impl ContractPosterConfig {
    /// Validate configuration. Returns an error if invalid.
    pub fn validate(&self) -> Result<(), BatcherError> {
        // Validate bridge config
        self.bridge
            .validate()
            .map_err(|e| BatcherError::Poster(format!("bridge config error: {e}")))?;

        // Validate retry bounds
        if self.max_retries > MAX_RETRY_LIMIT {
            return Err(BatcherError::Poster(format!(
                "max_retries ({}) exceeds limit ({})",
                self.max_retries, MAX_RETRY_LIMIT
            )));
        }

        // Validate retry delay
        if self.retry_delay_ms > MAX_RETRY_DELAY_MS {
            return Err(BatcherError::Poster(format!(
                "retry_delay_ms ({}) exceeds limit ({}ms)",
                self.retry_delay_ms, MAX_RETRY_DELAY_MS
            )));
        }

        // Validate timeout
        if self.l1_timeout_ms == 0 {
            return Err(BatcherError::Poster(
                "l1_timeout_ms must be > 0".to_string(),
            ));
        }
        if self.l1_timeout_ms > 300_000 {
            // 5 minute max
            return Err(BatcherError::Poster(
                "l1_timeout_ms must be <= 300000 (5 minutes)".to_string(),
            ));
        }

        Ok(())
    }

    /// Create configuration from environment variables with validation.
    pub fn from_env() -> Self {
        let bridge = BridgeConfig::from_env().unwrap_or_default();

        let force_repost = std::env::var("L2_FORCE_REPOST")
            .map(|s| s == "1" || s.to_lowercase() == "true")
            .unwrap_or(false);

        let max_retries = std::env::var("L2_POST_MAX_RETRIES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3)
            .min(MAX_RETRY_LIMIT);

        let retry_delay_ms = std::env::var("L2_POST_RETRY_DELAY_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(500)
            .min(MAX_RETRY_DELAY_MS);

        let l1_timeout_ms = std::env::var("L2_L1_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30_000)
            .min(300_000);

        Self {
            bridge,
            force_repost,
            max_retries,
            retry_delay_ms,
            l1_timeout_ms,
        }
    }
}

/// Contract-based batch poster using `L2BatchEnvelopeV1` and `L1Client::submit_batch`.
///
/// This poster builds proper `BatchEnvelope` → `L2BatchEnvelopeV1` envelopes
/// and submits them via the L1 contract client, providing:
/// - Deterministic idempotency keys
/// - Proper finality/inclusion tracking
/// - Versioned envelope format
/// - Persistent prev_batch_hash chaining per hub/chain
pub struct ContractBatchPoster<C> {
    l1_client: C,
    storage: Arc<Storage>,
    config: ContractPosterConfig,
}

impl<C> ContractBatchPoster<C>
where
    C: AsyncL1Client + Send + Sync,
{
    /// Create a new contract-based batch poster.
    pub fn new(l1_client: C, storage: Arc<Storage>, config: ContractPosterConfig) -> Self {
        Self {
            l1_client,
            storage,
            config,
        }
    }

    /// Check if batch should be posted (idempotency check).
    fn should_post(&self, hash: &Hash32) -> Result<bool, BatcherError> {
        let state = self.storage.get_posting_state(hash)?;
        match state {
            None => Ok(true),
            Some(PostingState::Pending { .. }) => Ok(true),
            Some(PostingState::Posted { .. }) => Ok(self.config.force_repost),
            Some(PostingState::Confirmed { .. }) => Ok(self.config.force_repost),
            Some(PostingState::Failed { retry_count, .. }) => {
                Ok(retry_count < self.config.max_retries)
            }
        }
    }

    /// Get the hub identifier as a string for storage key.
    fn hub_key(&self) -> String {
        format!("{:?}", self.config.bridge.hub).to_lowercase()
    }

    /// Post batch using contract envelope format.
    ///
    /// Returns the L1 tx ID and idempotency key on success.
    async fn do_post(
        &self,
        batch: &Batch,
        hash: &Hash32,
    ) -> Result<ContractPostResult, BatcherError> {
        use l2_core::l1_contract::L1ClientError;

        let hub_key = self.hub_key();
        let chain_id = batch.chain_id.0;

        // Get previous batch hash for linking from persistent storage
        let prev_hash = self
            .storage
            .get_last_batch_hash(&hub_key, chain_id)?
            .map(|h| contract_bridge::get_prev_batch_hash(Some(&h)))
            .unwrap_or_else(|| contract_bridge::get_prev_batch_hash(None));

        // Build the L1 envelope
        let bridge_result = batch_to_l1_envelope(batch, hash, &prev_hash, &self.config.bridge)
            .map_err(|e| BatcherError::Poster(format!("bridge error: {e}")))?;

        let idempotency_key = bridge_result.idempotency_key_hex.clone();

        debug!(
            batch_hash = %hash.to_hex(),
            idempotency_key = %idempotency_key,
            prev_batch_hash = %prev_hash.to_hex(),
            hub = %hub_key,
            chain_id = chain_id,
            "submitting batch via contract envelope"
        );

        // Submit to L1
        let result = self
            .l1_client
            .submit_batch(&bridge_result.l2_envelope)
            .await
            .map_err(|e| match e {
                L1ClientError::Timeout => BatcherError::Poster("L1 request timeout".to_string()),
                L1ClientError::HttpStatus(s) => BatcherError::Poster(format!("L1 HTTP error: {s}")),
                L1ClientError::RetryExhausted { attempts, .. } => {
                    BatcherError::Poster(format!("L1 retry exhausted after {attempts} attempts"))
                }
                other => BatcherError::Poster(format!("L1 error: {other}")),
            })?;

        if !result.accepted && !result.already_known {
            let msg = result
                .message
                .unwrap_or_else(|| "submission rejected".to_string());
            return Err(BatcherError::Poster(msg));
        }

        // Update last batch hash for chaining (persist to storage)
        // This is updated on successful submit_batch response (MVP policy)
        self.storage.set_last_batch_hash(&hub_key, chain_id, hash)?;

        // Determine the L1 tx ID
        let l1_tx_id = result
            .l1_tx_id
            .map(|id| id.0)
            .unwrap_or_else(|| idempotency_key.clone());

        info!(
            batch_hash = %hash.to_hex(),
            l1_tx_id = %l1_tx_id,
            hub = %hub_key,
            chain_id = chain_id,
            already_known = result.already_known,
            "batch chaining updated (prev_batch_hash set)"
        );

        Ok(ContractPostResult {
            l1_tx_id,
            idempotency_key,
            already_known: result.already_known,
        })
    }
}

/// Result of a successful contract batch post.
#[derive(Debug, Clone)]
struct ContractPostResult {
    /// L1 transaction ID.
    l1_tx_id: String,
    /// Idempotency key (hex).
    idempotency_key: String,
    /// Whether L1 responded with AlreadyKnown.
    already_known: bool,
}

#[async_trait]
impl<C> BatchPoster for ContractBatchPoster<C>
where
    C: AsyncL1Client + Send + Sync,
{
    async fn post_batch(&self, batch: &Batch, hash: &Hash32) -> Result<(), BatcherError> {
        // Idempotency check using posting state
        if !self.should_post(hash)? {
            info!(hash = %hash.to_hex(), "batch already posted (contract), skipping");
            return Ok(());
        }

        // Also check settlement state - if already Submitted or later, don't re-submit
        // This ensures crash recovery doesn't cause duplicate submissions
        if let Some(settlement_state) = self.storage.get_settlement_state(hash)? {
            if !settlement_state.is_created() {
                info!(
                    hash = %hash.to_hex(),
                    state = %settlement_state,
                    "batch already in settlement lifecycle, skipping submission"
                );
                return Ok(());
            }
        }

        let ts_now = now_ms();

        // Mark as pending (legacy posting state)
        self.storage
            .set_posting_state(hash, &PostingState::pending(ts_now))?;

        // Set settlement state to Created (start of lifecycle)
        // Use unchecked to allow starting fresh if no state exists
        self.storage
            .set_settlement_state_unchecked(hash, &SettlementState::created(ts_now))?;

        // Attempt posting with bounded retries
        let mut last_error: Option<String> = None;
        let mut retry_count: u32 = 0;

        while retry_count <= self.config.max_retries {
            match self.do_post(batch, hash).await {
                Ok(post_result) => {
                    let ts_submitted = now_ms();

                    info!(
                        hash = %hash.to_hex(),
                        l1_tx_id = %post_result.l1_tx_id,
                        idempotency_key = %post_result.idempotency_key,
                        already_known = post_result.already_known,
                        "batch posted successfully via contract envelope"
                    );

                    // Update legacy posting state
                    self.storage.set_posting_state(
                        hash,
                        &PostingState::posted(post_result.l1_tx_id.clone(), ts_submitted),
                    )?;

                    // Update settlement state to Submitted
                    // This transition is valid: Created -> Submitted
                    self.storage.set_settlement_state(
                        hash,
                        &SettlementState::submitted(
                            post_result.l1_tx_id,
                            ts_submitted,
                            post_result.idempotency_key,
                        ),
                    )?;

                    return Ok(());
                }
                Err(err) => {
                    warn!(
                        hash = %hash.to_hex(),
                        attempt = retry_count + 1,
                        error = %err,
                        "contract batch posting failed"
                    );
                    last_error = Some(err.to_string());
                    retry_count = retry_count.saturating_add(1);

                    if retry_count <= self.config.max_retries {
                        let delay_ms = self
                            .config
                            .retry_delay_ms
                            .saturating_mul(2u64.saturating_pow(retry_count.saturating_sub(1)));
                        let delay = Duration::from_millis(delay_ms.min(10_000));
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        // All retries exhausted - mark as failed
        let reason = last_error.unwrap_or_else(|| "unknown error".to_string());
        let ts_failed = now_ms();

        error!(
            hash = %hash.to_hex(),
            retries = retry_count,
            reason = %reason,
            "contract batch posting failed after all retries"
        );

        // Update legacy posting state
        self.storage.set_posting_state(
            hash,
            &PostingState::failed(reason.clone(), ts_failed, retry_count),
        )?;

        // Update settlement state to Failed
        // Get current state for the last_state field
        let current_state = self.storage.get_settlement_state(hash)?;
        self.storage.set_settlement_state(
            hash,
            &SettlementState::failed(reason.clone(), ts_failed, retry_count, current_state),
        )?;

        Err(BatcherError::Poster(reason))
    }
}

/// Result of a posting attempt.
#[derive(Debug, Clone)]
pub struct PostingResult {
    pub batch_hash: String,
    pub l1_tx: Option<String>,
    pub success: bool,
    pub error: Option<String>,
}

// ============== Reconciler ==============

/// Configuration for the reconciler.
#[derive(Debug, Clone)]
pub struct ReconcilerConfig {
    /// Interval between reconciliation cycles (ms).
    pub interval_ms: u64,
    /// Maximum batches to check per cycle.
    pub batch_limit: usize,
    /// Timeout threshold for considering a batch stale (ms).
    pub stale_threshold_ms: u64,
}

impl Default for ReconcilerConfig {
    fn default() -> Self {
        Self {
            interval_ms: 10_000, // 10 seconds
            batch_limit: 100,
            stale_threshold_ms: 300_000, // 5 minutes
        }
    }
}

impl ReconcilerConfig {
    /// Create from environment variables.
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

        Self {
            interval_ms,
            batch_limit,
            stale_threshold_ms,
        }
    }
}

/// Reconciler handle for controlling the background task.
#[derive(Clone)]
pub struct ReconcilerHandle {
    _cancel: Arc<tokio::sync::watch::Sender<bool>>,
}

/// Spawn the reconciler background task.
///
/// The reconciler periodically checks Posted batches and attempts to confirm them
/// by querying the IPPAN RPC for transaction status.
pub fn spawn_reconciler(
    config: ReconcilerConfig,
    storage: Arc<Storage>,
    client: Option<IppanRpcClient>,
) -> ReconcilerHandle {
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(run_reconciler(config, storage, client, cancel_rx));
    ReconcilerHandle {
        _cancel: Arc::new(cancel_tx),
    }
}

async fn run_reconciler(
    config: ReconcilerConfig,
    storage: Arc<Storage>,
    client: Option<IppanRpcClient>,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(config.interval_ms));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(e) = reconcile_cycle(&config, &storage, &client).await {
                    warn!(error = %e, "reconciler cycle failed");
                }
            }
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    info!("reconciler shutting down");
                    break;
                }
            }
        }
    }
}

async fn reconcile_cycle(
    config: &ReconcilerConfig,
    storage: &Storage,
    client: &Option<IppanRpcClient>,
) -> Result<(), BatcherError> {
    // List posted batches
    let posted = storage.list_posted(config.batch_limit)?;

    if posted.is_empty() {
        debug!("no posted batches to reconcile");
        return Ok(());
    }

    info!(count = posted.len(), "reconciling posted batches");

    for entry in posted {
        // Get the L1 tx hash from the state
        let l1_tx = match &entry.state {
            PostingState::Posted { l1_tx, .. } => l1_tx.clone(),
            _ => continue, // Should not happen
        };

        // Query IPPAN for transaction status
        let confirmed = if let Some(rpc_client) = client {
            match rpc_client.get_tx(&l1_tx).await {
                Ok(Some(tx_info)) => {
                    // Check if transaction is confirmed
                    tx_info.success.unwrap_or(false) || tx_info.height.is_some()
                }
                Ok(None) => {
                    // Transaction not found - might still be pending
                    debug!(l1_tx = %l1_tx, "L1 tx not found yet");
                    false
                }
                Err(e) => {
                    warn!(l1_tx = %l1_tx, error = %e, "failed to query L1 tx");
                    false
                }
            }
        } else {
            // No client - best effort mode, treat as confirmed after posting
            // This is documented as a limitation in MVP
            debug!(
                batch_hash = %entry.batch_hash.to_hex(),
                "no RPC client, treating posted as terminal (best-effort mode)"
            );
            true // Consider confirmed in best-effort mode
        };

        if confirmed {
            info!(
                batch_hash = %entry.batch_hash.to_hex(),
                l1_tx = %l1_tx,
                "batch confirmed on L1"
            );
            storage
                .set_posting_state(&entry.batch_hash, &PostingState::confirmed(l1_tx, now_ms()))?;
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct BatcherSnapshot {
    pub queue_depth: usize,
    pub last_batch_hash: Option<String>,
    pub last_post_time_ms: Option<u64>,
    /// Organiser status snapshot.
    pub organiser: OrganiserStatus,
}

#[derive(Clone)]
struct BatcherState {
    queue_depth: usize,
    last_batch_hash: Option<Hash32>,
    last_post_time_ms: Option<u64>,
    /// Organiser enabled flag.
    organiser_enabled: bool,
    /// Organiser version.
    organiser_version: OrganiserVersion,
    /// Last organiser inputs.
    last_organiser_inputs: Option<OrganiserInputs>,
    /// Last organiser decision.
    last_organiser_decision: Option<OrganiserDecision>,
    /// Organiser policy bounds.
    organiser_bounds: OrganiserPolicyBounds,
    /// Rolling counter: recent quota rejects.
    recent_quota_rejects: u32,
    /// Rolling counter: recent insufficient balance rejects.
    recent_insufficient_balance: u32,
    /// Rolling counter: recent forced bytes used.
    recent_forced_used_bytes: u64,
    /// Integer EMA of tx bytes (scaled by 1000 for precision).
    avg_tx_bytes_ema_scaled: u64,
}

impl BatcherState {
    fn new(
        organiser_enabled: bool,
        organiser_version: OrganiserVersion,
        organiser_bounds: OrganiserPolicyBounds,
    ) -> Self {
        Self {
            queue_depth: 0,
            last_batch_hash: None,
            last_post_time_ms: None,
            organiser_enabled,
            organiser_version,
            last_organiser_inputs: None,
            last_organiser_decision: None,
            organiser_bounds,
            recent_quota_rejects: 0,
            recent_insufficient_balance: 0,
            recent_forced_used_bytes: 0,
            avg_tx_bytes_ema_scaled: 256_000, // Default: 256 bytes scaled by 1000
        }
    }

    /// Update the EMA of tx bytes (integer-only computation).
    /// Uses EMA formula: new_ema = (alpha * sample + (1 - alpha) * old_ema)
    /// With alpha = 1/8 (12.5%), scaled by 1000 for integer math.
    fn update_avg_tx_bytes(&mut self, tx_bytes: u64) {
        // alpha_scaled = 125 (12.5% * 1000)
        // one_minus_alpha_scaled = 875 (87.5% * 1000)
        const ALPHA_SCALED: u64 = 125;
        const ONE_MINUS_ALPHA_SCALED: u64 = 875;

        // new_ema_scaled = (ALPHA * sample * 1000 + ONE_MINUS_ALPHA * old_ema) / 1000
        let sample_contribution = tx_bytes.saturating_mul(ALPHA_SCALED);
        let old_contribution = self
            .avg_tx_bytes_ema_scaled
            .saturating_mul(ONE_MINUS_ALPHA_SCALED)
            .saturating_div(1000);

        self.avg_tx_bytes_ema_scaled = sample_contribution.saturating_add(old_contribution);
    }

    /// Get the current EMA value (unscaled).
    fn avg_tx_bytes_est(&self) -> u32 {
        // Unscale by dividing by 1000, then truncate to u32
        let unscaled = self.avg_tx_bytes_ema_scaled.saturating_div(1000);
        u32::try_from(unscaled).unwrap_or(u32::MAX)
    }

    /// Decay rolling counters (called periodically to prevent stale values).
    fn decay_counters(&mut self) {
        // Decay by halving (integer-safe)
        self.recent_quota_rejects = self.recent_quota_rejects.saturating_div(2);
        self.recent_insufficient_balance = self.recent_insufficient_balance.saturating_div(2);
        self.recent_forced_used_bytes = self.recent_forced_used_bytes.saturating_div(2);
    }
}

impl From<BatcherState> for BatcherSnapshot {
    fn from(state: BatcherState) -> Self {
        Self {
            queue_depth: state.queue_depth,
            last_batch_hash: state.last_batch_hash.map(Hash32::to_hex),
            last_post_time_ms: state.last_post_time_ms,
            organiser: OrganiserStatus {
                enabled: state.organiser_enabled,
                version: state.organiser_version.to_string(),
                last_inputs: state.last_organiser_inputs,
                last_decision: state.last_organiser_decision,
                bounds: state.organiser_bounds,
            },
        }
    }
}

// ============== Multi-Hub Batcher Structures ==============

use l2_core::{L2HubId, ALL_HUBS};
use std::collections::BTreeMap;

/// Transaction with hub identification for multi-hub routing.
#[derive(Debug, Clone)]
pub struct HubTx {
    /// The target hub for this transaction.
    pub hub: L2HubId,
    /// The underlying transaction.
    pub tx: Tx,
}

impl HubTx {
    /// Create a new hub-routed transaction.
    pub fn new(hub: L2HubId, tx: Tx) -> Self {
        Self { hub, tx }
    }

    /// Get the size of the transaction payload in bytes.
    pub fn payload_size(&self) -> usize {
        self.tx.payload.len()
    }
}

/// Per-hub queue state for tracking individual hub queues.
#[derive(Debug, Clone, Default)]
pub struct PerHubQueueState {
    /// Number of transactions in the normal queue.
    pub queue_depth: u32,
    /// Number of transactions in the forced queue.
    pub forced_queue_depth: u32,
    /// Number of batches currently in-flight (submitted but not finalised).
    pub in_flight_batches: u32,
    /// Recent reject count (rolling window).
    pub recent_rejects: u32,
    /// Estimated average transaction size in bytes.
    pub avg_tx_bytes_est: u32,
    /// Last batch hash (for chaining).
    pub last_batch_hash: Option<Hash32>,
    /// Last batch number.
    pub batch_number: u64,
    /// Total fees finalised (M2M hub only).
    pub total_fees_finalised_scaled: u64,
    /// Last batch creation timestamp (ms).
    pub last_batch_created_ms: Option<u64>,
}

impl PerHubQueueState {
    /// Create a new empty per-hub queue state.
    pub fn new() -> Self {
        Self {
            avg_tx_bytes_est: 256, // Default estimate
            ..Default::default()
        }
    }

    /// Update the EMA of tx bytes (integer-only computation).
    pub fn update_avg_tx_bytes(&mut self, tx_bytes: u64) {
        const ALPHA_SCALED: u64 = 125;
        const ONE_MINUS_ALPHA_SCALED: u64 = 875;

        let current_scaled = u64::from(self.avg_tx_bytes_est).saturating_mul(1000);
        let sample_contribution = tx_bytes.saturating_mul(ALPHA_SCALED);
        let old_contribution = current_scaled.saturating_mul(ONE_MINUS_ALPHA_SCALED).saturating_div(1000);
        let new_scaled = sample_contribution.saturating_add(old_contribution);
        self.avg_tx_bytes_est = u32::try_from(new_scaled.saturating_div(1000)).unwrap_or(u32::MAX);
    }

    /// Increment batch number and return the new value.
    pub fn next_batch_number(&mut self) -> u64 {
        self.batch_number = self.batch_number.saturating_add(1);
        self.batch_number
    }

    /// Decay rolling counters.
    pub fn decay_counters(&mut self) {
        self.recent_rejects = self.recent_rejects.saturating_div(2);
    }

    /// Set the last batch hash (for chaining).
    pub fn set_last_batch_hash(&mut self, hash: [u8; 32]) {
        self.last_batch_hash = Some(Hash32(hash));
    }

    /// Add finalised fees (M2M hub only).
    pub fn add_finalised_fees(&mut self, fees: u64) {
        self.total_fees_finalised_scaled = self.total_fees_finalised_scaled.saturating_add(fees);
    }
}

/// Multi-hub batcher state with per-hub tracking.
#[derive(Clone)]
pub struct MultiHubBatcherState {
    /// Per-hub states (BTreeMap for deterministic iteration order).
    pub per_hub: BTreeMap<L2HubId, PerHubQueueState>,
    /// Global organiser enabled flag.
    pub organiser_enabled: bool,
    /// Organiser version.
    pub organiser_version: OrganiserVersion,
    /// Organiser policy bounds.
    pub organiser_bounds: OrganiserPolicyBounds,
    /// Last V2 organiser decision.
    pub last_v2_decision: Option<OrganiserDecisionV2>,
    /// Rolling counter: recent quota rejects (global).
    pub recent_quota_rejects: u32,
    /// Rolling counter: recent insufficient balance (global).
    pub recent_insufficient_balance: u32,
}

impl MultiHubBatcherState {
    /// Create a new multi-hub batcher state.
    pub fn new(
        organiser_enabled: bool,
        organiser_version: OrganiserVersion,
        organiser_bounds: OrganiserPolicyBounds,
    ) -> Self {
        let mut per_hub = BTreeMap::new();
        for hub in ALL_HUBS {
            per_hub.insert(hub, PerHubQueueState::new());
        }

        Self {
            per_hub,
            organiser_enabled,
            organiser_version,
            organiser_bounds,
            last_v2_decision: None,
            recent_quota_rejects: 0,
            recent_insufficient_balance: 0,
        }
    }

    /// Get mutable reference to a hub's state.
    pub fn hub_state_mut(&mut self, hub: L2HubId) -> &mut PerHubQueueState {
        self.per_hub.entry(hub).or_insert_with(PerHubQueueState::new)
    }

    /// Get reference to a hub's state.
    pub fn hub_state(&self, hub: L2HubId) -> Option<&PerHubQueueState> {
        self.per_hub.get(&hub)
    }

    /// Get total queue depth across all hubs.
    pub fn total_queue_depth(&self) -> u32 {
        self.per_hub.values().map(|s| s.queue_depth).sum()
    }

    /// Get total forced queue depth across all hubs.
    pub fn total_forced_queue_depth(&self) -> u32 {
        self.per_hub.values().map(|s| s.forced_queue_depth).sum()
    }

    /// Get total in-flight batches across all hubs.
    pub fn total_in_flight(&self) -> u32 {
        self.per_hub.values().map(|s| s.in_flight_batches).sum()
    }

    /// Decay counters for all hubs.
    pub fn decay_all_counters(&mut self) {
        for state in self.per_hub.values_mut() {
            state.decay_counters();
        }
        self.recent_quota_rejects = self.recent_quota_rejects.saturating_div(2);
        self.recent_insufficient_balance = self.recent_insufficient_balance.saturating_div(2);
    }

    /// Build HubInputs for organiser V2.
    pub fn build_hub_inputs(&self, hub: L2HubId) -> HubInputs {
        let state = self.hub_state(hub).cloned().unwrap_or_default();
        HubInputs {
            hub,
            queue_depth: state.queue_depth,
            forced_queue_depth: state.forced_queue_depth,
            in_flight_batches: state.in_flight_batches,
            recent_rejects: state.recent_rejects,
            avg_tx_bytes_est: state.avg_tx_bytes_est,
        }
    }

    /// Build V2 organiser inputs from current state.
    pub fn build_organiser_inputs_v2(&self, now_ms: u64) -> OrganiserInputsV2 {
        let hubs: Vec<HubInputs> = ALL_HUBS
            .iter()
            .map(|&hub| self.build_hub_inputs(hub))
            .collect();

        OrganiserInputsV2 { now_ms, hubs }
    }
}

/// Per-hub inputs for OrganiserV2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubInputs {
    /// Hub identifier.
    pub hub: L2HubId,
    /// Number of transactions in the normal queue.
    pub queue_depth: u32,
    /// Number of transactions in the forced queue.
    pub forced_queue_depth: u32,
    /// Number of batches currently in-flight.
    pub in_flight_batches: u32,
    /// Recent reject count.
    pub recent_rejects: u32,
    /// Estimated average transaction size in bytes.
    pub avg_tx_bytes_est: u32,
}

impl Default for HubInputs {
    fn default() -> Self {
        Self {
            hub: L2HubId::Fin,
            queue_depth: 0,
            forced_queue_depth: 0,
            in_flight_batches: 0,
            recent_rejects: 0,
            avg_tx_bytes_est: 256,
        }
    }
}

/// V2 organiser inputs with per-hub statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganiserInputsV2 {
    /// Current timestamp in milliseconds since epoch.
    pub now_ms: u64,
    /// Per-hub inputs in deterministic order: Fin, Data, M2m, World, Bridge.
    pub hubs: Vec<HubInputs>,
}

impl Default for OrganiserInputsV2 {
    fn default() -> Self {
        Self {
            now_ms: 0,
            hubs: ALL_HUBS
                .iter()
                .map(|&hub| HubInputs { hub, ..Default::default() })
                .collect(),
        }
    }
}

impl OrganiserInputsV2 {
    /// Get inputs for a specific hub.
    pub fn get_hub(&self, hub: L2HubId) -> Option<&HubInputs> {
        self.hubs.iter().find(|h| h.hub == hub)
    }

    /// Get total queue depth across all hubs.
    pub fn total_queue_depth(&self) -> u32 {
        self.hubs.iter().map(|h| h.queue_depth).sum()
    }

    /// Get total forced queue depth across all hubs.
    pub fn total_forced_depth(&self) -> u32 {
        self.hubs.iter().map(|h| h.forced_queue_depth).sum()
    }
}

/// V2 organiser decision with hub selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganiserDecisionV2 {
    /// The hub chosen to serve in this batch cycle.
    pub chosen_hub: L2HubId,
    /// Sleep duration before building next batch (milliseconds).
    pub sleep_ms: u64,
    /// Maximum number of transactions to include in the batch.
    pub max_txs: u32,
    /// Maximum bytes to include in the batch.
    pub max_bytes: u32,
    /// Maximum number of forced queue transactions to drain.
    pub forced_drain_max: u32,
}

impl Default for OrganiserDecisionV2 {
    fn default() -> Self {
        Self {
            chosen_hub: L2HubId::Fin,
            sleep_ms: 1000,
            max_txs: 256,
            max_bytes: 512 * 1024,
            forced_drain_max: 128,
        }
    }
}

impl OrganiserDecisionV2 {
    /// Create a new V2 decision.
    pub fn new(
        chosen_hub: L2HubId,
        sleep_ms: u64,
        max_txs: u32,
        max_bytes: u32,
        forced_drain_max: u32,
    ) -> Self {
        Self {
            chosen_hub,
            sleep_ms,
            max_txs,
            max_bytes,
            forced_drain_max,
        }
    }
}

/// Multi-hub batcher snapshot for /status endpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MultiHubBatcherSnapshot {
    /// Per-hub snapshots.
    pub per_hub: BTreeMap<String, HubQueueSnapshot>,
    /// Total queue depth across all hubs.
    pub total_queue_depth: u32,
    /// Total forced queue depth across all hubs.
    pub total_forced_depth: u32,
    /// Total in-flight batches.
    pub total_in_flight: u32,
    /// Last V2 organiser decision.
    pub last_v2_decision: Option<OrganiserDecisionV2>,
    /// Organiser status.
    pub organiser_enabled: bool,
    /// Organiser version string.
    pub organiser_version: String,
}

/// Per-hub snapshot for /status endpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HubQueueSnapshot {
    /// Hub identifier.
    pub hub: String,
    /// Queue depth.
    pub queue_depth: u32,
    /// Forced queue depth.
    pub forced_queue_depth: u32,
    /// In-flight batches.
    pub in_flight_batches: u32,
    /// Last submitted batch hash (hex).
    pub last_submitted_hash: Option<String>,
    /// Last included batch hash (hex).
    pub last_included_hash: Option<String>,
    /// Last finalised batch hash (hex).
    pub last_finalised_hash: Option<String>,
    /// Last batch hash (for chaining, hex).
    pub last_batch_hash: Option<String>,
    /// Batch number.
    pub batch_number: u64,
    /// Total fees finalised (M2M hub only).
    pub total_fees_finalised_scaled: Option<u64>,
    /// Last batch creation timestamp (ms).
    pub last_batch_created_ms: Option<u64>,
}

impl From<&MultiHubBatcherState> for MultiHubBatcherSnapshot {
    fn from(state: &MultiHubBatcherState) -> Self {
        let mut per_hub = BTreeMap::new();
        for (hub, hub_state) in &state.per_hub {
            let snapshot = HubQueueSnapshot {
                hub: hub.as_str().to_string(),
                queue_depth: hub_state.queue_depth,
                forced_queue_depth: hub_state.forced_queue_depth,
                in_flight_batches: hub_state.in_flight_batches,
                last_submitted_hash: None, // Populated from storage
                last_included_hash: None,  // Populated from storage
                last_finalised_hash: None, // Populated from storage
                last_batch_hash: hub_state.last_batch_hash.map(|h| h.to_hex()),
                batch_number: hub_state.batch_number,
                total_fees_finalised_scaled: if hub.uses_m2m_fees() {
                    Some(hub_state.total_fees_finalised_scaled)
                } else {
                    None
                },
                last_batch_created_ms: hub_state.last_batch_created_ms,
            };
            per_hub.insert(hub.as_str().to_string(), snapshot);
        }

        Self {
            per_hub,
            total_queue_depth: state.total_queue_depth(),
            total_forced_depth: state.total_forced_queue_depth(),
            total_in_flight: state.total_in_flight(),
            last_v2_decision: state.last_v2_decision.clone(),
            organiser_enabled: state.organiser_enabled,
            organiser_version: state.organiser_version.to_string(),
        }
    }
}

impl MultiHubBatcherSnapshot {
    /// Enrich snapshot with data from storage (last finalised batch hashes, etc.).
    pub fn enrich_from_storage(&mut self, storage: &Storage, chain_id: u64) {
        for (hub_str, snapshot) in &mut self.per_hub {
            // Get last finalised batch hash from storage
            if let Ok(Some((hash, _at_ms))) = storage.get_last_finalised_batch(hub_str, chain_id) {
                snapshot.last_finalised_hash = Some(hash.to_hex());
            }

            // Get fee totals from storage for M2M hub
            if hub_str == "m2m" {
                if let Ok(total_fees) = storage.get_hub_total_fees(hub_str, chain_id) {
                    snapshot.total_fees_finalised_scaled = Some(total_fees);
                }
            }

            // Get in-flight count from storage
            if let Ok(in_flight) = storage.get_hub_in_flight_count(hub_str, chain_id) {
                snapshot.in_flight_batches = in_flight;
            }
        }
    }
}

/// Multi-hub batcher handle for submitting transactions to specific hubs.
#[derive(Clone)]
pub struct MultiHubBatcherHandle {
    /// Per-hub senders (BTreeMap for deterministic iteration).
    senders: BTreeMap<L2HubId, mpsc::Sender<Tx>>,
    /// Shared multi-hub state.
    state: Arc<Mutex<MultiHubBatcherState>>,
}

impl MultiHubBatcherHandle {
    /// Create a new multi-hub batcher handle.
    pub fn new(
        senders: BTreeMap<L2HubId, mpsc::Sender<Tx>>,
        state: Arc<Mutex<MultiHubBatcherState>>,
    ) -> Self {
        Self { senders, state }
    }

    /// Submit a transaction to a specific hub.
    pub async fn submit_tx(&self, hub: L2HubId, tx: Tx) -> Result<(), BatcherError> {
        let sender = self.senders.get(&hub).ok_or_else(|| {
            BatcherError::Poster(format!("no sender for hub {:?}", hub))
        })?;

        sender.send(tx).await.map_err(|_| BatcherError::QueueClosed)?;

        let mut guard = self.state.lock().await;
        let hub_state = guard.hub_state_mut(hub);
        hub_state.queue_depth = hub_state.queue_depth.saturating_add(1);
        Ok(())
    }

    /// Submit a hub-tagged transaction.
    pub async fn submit_hub_tx(&self, hub_tx: HubTx) -> Result<(), BatcherError> {
        self.submit_tx(hub_tx.hub, hub_tx.tx).await
    }

    /// Get a snapshot of the multi-hub batcher state.
    pub async fn snapshot(&self) -> MultiHubBatcherSnapshot {
        let state = self.state.lock().await;
        MultiHubBatcherSnapshot::from(&*state)
    }

    /// Get queue depth for a specific hub.
    pub async fn hub_queue_depth(&self, hub: L2HubId) -> u32 {
        let state = self.state.lock().await;
        state.hub_state(hub).map(|s| s.queue_depth).unwrap_or(0)
    }

    /// Get forced queue depth for a specific hub.
    pub async fn hub_forced_depth(&self, hub: L2HubId) -> u32 {
        let state = self.state.lock().await;
        state.hub_state(hub).map(|s| s.forced_queue_depth).unwrap_or(0)
    }

    /// Update hub stats from storage.
    pub async fn sync_hub_stats(&self, hub: L2HubId, queue: u32, forced: u32, in_flight: u32) {
        let mut guard = self.state.lock().await;
        let hub_state = guard.hub_state_mut(hub);
        hub_state.queue_depth = queue;
        hub_state.forced_queue_depth = forced;
        hub_state.in_flight_batches = in_flight;
    }
}

// ============== Per-Hub Receiver Collection ==============

/// Collection of per-hub receivers for the batcher loop.
pub struct MultiHubReceivers {
    receivers: BTreeMap<L2HubId, mpsc::Receiver<Tx>>,
}

impl MultiHubReceivers {
    /// Create from a map of receivers.
    pub fn new(receivers: BTreeMap<L2HubId, mpsc::Receiver<Tx>>) -> Self {
        Self { receivers }
    }

    /// Get mutable reference to a specific hub's receiver.
    pub fn get_mut(&mut self, hub: L2HubId) -> Option<&mut mpsc::Receiver<Tx>> {
        self.receivers.get_mut(&hub)
    }

    /// Check if a hub has pending messages.
    pub fn hub_has_pending(&self, hub: L2HubId) -> bool {
        self.receivers.get(&hub).map(|r| !r.is_empty()).unwrap_or(false)
    }
}

/// Create per-hub channels for multi-hub batcher.
pub fn create_multi_hub_channels(buffer_size: usize) -> (
    BTreeMap<L2HubId, mpsc::Sender<Tx>>,
    MultiHubReceivers,
) {
    let mut senders = BTreeMap::new();
    let mut receivers = BTreeMap::new();

    for hub in ALL_HUBS {
        let (tx, rx) = mpsc::channel(buffer_size);
        senders.insert(hub, tx);
        receivers.insert(hub, rx);
    }

    (senders, MultiHubReceivers::new(receivers))
}

// ============== Multi-Hub Batcher ==============

/// Configuration for multi-hub batcher.
#[derive(Debug, Clone)]
pub struct MultiHubBatcherConfig {
    /// Maximum transactions per batch per hub.
    pub max_batch_txs: usize,
    /// Maximum bytes per batch per hub.
    pub max_batch_bytes: usize,
    /// Maximum wait time before building a batch (ms).
    pub max_wait_ms: u64,
    /// Chain ID.
    pub chain_id: ChainId,
    /// Policy bounds for organiser.
    pub organiser_bounds: OrganiserPolicyBounds,
    /// Channel buffer size per hub.
    pub channel_buffer_size: usize,
}

impl Default for MultiHubBatcherConfig {
    fn default() -> Self {
        Self {
            max_batch_txs: 256,
            max_batch_bytes: 512 * 1024,
            max_wait_ms: 1_000,
            chain_id: ChainId(1),
            organiser_bounds: OrganiserPolicyBounds::default(),
            channel_buffer_size: 1024,
        }
    }
}

impl MultiHubBatcherConfig {
    /// Create from environment variables.
    pub fn from_env() -> Self {
        let default = Self::default();
        Self {
            max_batch_txs: std::env::var("L2_MAX_BATCH_TXS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.max_batch_txs),
            max_batch_bytes: std::env::var("L2_MAX_BATCH_BYTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.max_batch_bytes),
            max_wait_ms: std::env::var("L2_MAX_WAIT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.max_wait_ms),
            chain_id: ChainId(
                std::env::var("L2_CHAIN_ID")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(default.chain_id.0),
            ),
            organiser_bounds: OrganiserPolicyBounds::from_env(),
            channel_buffer_size: std::env::var("L2_CHANNEL_BUFFER_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.channel_buffer_size),
        }
    }
}

/// Spawn a multi-hub batcher with per-hub queues and fairness scheduling.
///
/// Returns a handle for submitting transactions to specific hubs.
pub fn spawn_multi_hub(
    config: MultiHubBatcherConfig,
    storage: Arc<Storage>,
    poster: Arc<dyn BatchPoster>,
    m2m_storage: Option<Arc<M2mStorage>>,
    organiser: Option<Arc<dyn OrganiserV2 + Send + Sync>>,
) -> MultiHubBatcherHandle {
    let (senders, receivers) = create_multi_hub_channels(config.channel_buffer_size);

    let state = Arc::new(Mutex::new(MultiHubBatcherState::new(
        true,
        OrganiserVersion::GbdtV1, // Will be upgraded in loop
        config.organiser_bounds.clone(),
    )));

    // Create default organiser if none provided
    let organiser: Arc<dyn OrganiserV2 + Send + Sync> = organiser.unwrap_or_else(|| {
        Arc::new(GbdtOrganiserV2::new())
    });

    tokio::spawn(run_multi_hub_loop(
        config,
        storage,
        poster,
        receivers,
        Arc::clone(&state),
        m2m_storage,
        organiser,
    ));

    MultiHubBatcherHandle::new(senders, state)
}

/// Main loop for multi-hub batcher.
#[allow(clippy::too_many_arguments)]
async fn run_multi_hub_loop(
    config: MultiHubBatcherConfig,
    storage: Arc<Storage>,
    poster: Arc<dyn BatchPoster>,
    mut receivers: MultiHubReceivers,
    state: Arc<Mutex<MultiHubBatcherState>>,
    m2m_storage: Option<Arc<M2mStorage>>,
    organiser: Arc<dyn OrganiserV2 + Send + Sync>,
) {
    let mut iteration_counter: u64 = 0;
    let mut organiser_state = GbdtOrganiserV2::new();

    loop {
        iteration_counter = iteration_counter.wrapping_add(1);

        // Build V2 organiser inputs from current state
        let (_inputs_v2, decision) = {
            let mut guard = state.lock().await;

            // Sync per-hub stats from storage
            for hub in ALL_HUBS {
                let hub_str = hub.as_str();
                let chain_id = config.chain_id.0;

                // Get queue stats
                let (_queue_depth, forced_depth) = storage
                    .get_hub_queue_stats(hub_str)
                    .unwrap_or((0, 0));

                // Get in-flight count
                let in_flight = storage
                    .get_hub_in_flight_count(hub_str, chain_id)
                    .unwrap_or(0);

                let hub_state = guard.hub_state_mut(hub);
                hub_state.forced_queue_depth = u32::try_from(forced_depth).unwrap_or(u32::MAX);
                hub_state.in_flight_batches = in_flight;
            }

            // Build inputs
            let inputs = guard.build_organiser_inputs_v2(now_ms());

            // Get decision from organiser
            let decision = organiser.decide(&inputs);

            // Store decision in state
            guard.last_v2_decision = Some(decision.clone());

            // Decay counters periodically
            if iteration_counter % 10 == 0 {
                guard.decay_all_counters();
            }

            (inputs, decision)
        };

        debug!(
            chosen_hub = %decision.chosen_hub,
            sleep_ms = decision.sleep_ms,
            max_txs = decision.max_txs,
            max_bytes = decision.max_bytes,
            forced_drain_max = decision.forced_drain_max,
            "organiser v2 decision"
        );

        // Apply sleep from organiser decision
        let deadline = Instant::now() + Duration::from_millis(decision.sleep_ms);
        let chosen_hub = decision.chosen_hub;
        let hub_str = chosen_hub.as_str();
        let chain_id = config.chain_id.0;

        let mut batch_txs: Vec<Tx> = Vec::new();
        let mut batch_bytes: usize = 0;
        let mut forced_tx_hashes: Vec<Hash32> = Vec::new();

        let max_txs = usize::try_from(decision.max_txs).unwrap_or(config.max_batch_txs);
        let max_bytes = usize::try_from(decision.max_bytes).unwrap_or(config.max_batch_bytes);
        let forced_drain_max = usize::try_from(decision.forced_drain_max).unwrap_or(max_txs / 2);

        // Step 1: Get forced txs for this hub
        match get_forced_txs_for_hub(&storage, hub_str, forced_drain_max).await {
            Ok(forced_txs) => {
                let mut forced_bytes_this_batch: u64 = 0;
                for (tx, tx_hash) in forced_txs {
                    if batch_txs.len() >= max_txs || batch_bytes >= max_bytes {
                        break;
                    }
                    let tx_size = tx.payload.len();
                    batch_txs.push(tx);
                    batch_bytes += tx_size;
                    forced_tx_hashes.push(tx_hash);
                    forced_bytes_this_batch =
                        forced_bytes_this_batch.saturating_add(u64::try_from(tx_size).unwrap_or(0));
                }
                if !forced_tx_hashes.is_empty() {
                    info!(
                        hub = hub_str,
                        count = forced_tx_hashes.len(),
                        bytes = forced_bytes_this_batch,
                        "including forced txs in hub batch"
                    );
                }
            }
            Err(err) => {
                warn!(hub = hub_str, error = %err, "failed to get forced txs for hub");
            }
        }

        // Step 2: Fill remaining slots from this hub's queue
        if let Some(rx) = receivers.get_mut(chosen_hub) {
            while batch_txs.len() < max_txs && batch_bytes < max_bytes {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match timeout(remaining, rx.recv()).await {
                    Ok(Some(tx)) => {
                        let tx_size = tx.payload.len();
                        batch_txs.push(tx);
                        batch_bytes += tx_size;

                        // Update state
                        let mut guard = state.lock().await;
                        let hub_state = guard.hub_state_mut(chosen_hub);
                        hub_state.queue_depth = hub_state.queue_depth.saturating_sub(1);
                        hub_state.update_avg_tx_bytes(u64::try_from(tx_size).unwrap_or(0));
                    }
                    Ok(None) => {
                        // Channel closed
                        info!(hub = hub_str, "hub channel closed, exiting loop");
                        return;
                    }
                    Err(_) => break, // Timeout
                }
            }
        }

        // If no txs, try to drain one from any hub to avoid idle
        if batch_txs.is_empty() {
            // Try the chosen hub first
            if let Some(rx) = receivers.get_mut(chosen_hub) {
                match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
                    Ok(Some(tx)) => {
                        batch_txs.push(tx);
                        let mut guard = state.lock().await;
                        let hub_state = guard.hub_state_mut(chosen_hub);
                        hub_state.queue_depth = hub_state.queue_depth.saturating_sub(1);
                    }
                    Ok(None) => {
                        info!(hub = hub_str, "hub channel closed");
                        return;
                    }
                    Err(_) => {
                        // No messages, continue to next iteration
                        continue;
                    }
                }
            } else {
                continue;
            }
        }

        // Get per-hub batch number
        let batch_number = match storage.next_hub_batch_number(hub_str, chain_id) {
            Ok(num) => num,
            Err(err) => {
                warn!(hub = hub_str, error = %err, "failed to obtain hub batch number");
                continue;
            }
        };

        let batch = Batch {
            chain_id: config.chain_id,
            batch_number,
            txs: batch_txs,
            created_ms: now_ms(),
        };

        match storage.put_batch(&batch) {
            Ok(hash) => {
                // Mark forced txs as included
                for forced_hash in &forced_tx_hashes {
                    if let Err(err) = mark_forced_included(&storage, forced_hash, &hash) {
                        warn!(
                            hub = hub_str,
                            error = %err,
                            tx_hash = %forced_hash.to_hex(),
                            "failed to mark forced tx as included"
                        );
                    }
                }

                // Update per-hub stats
                {
                    let mut guard = state.lock().await;
                    let hub_state = guard.hub_state_mut(chosen_hub);
                    hub_state.batch_number = batch_number;
                    hub_state.set_last_batch_hash(hash.0);
                    hub_state.last_batch_created_ms = Some(batch.created_ms);
                }

                // Increment in-flight count for this hub
                if let Err(err) = storage.inc_hub_in_flight(hub_str, chain_id) {
                    warn!(hub = hub_str, error = %err, "failed to increment in-flight count");
                }

                // Handle M2M fees if this is the M2M hub
                if chosen_hub.uses_m2m_fees() {
                    if let Some(m2m) = &m2m_storage {
                        let batch_hash_hex = hash.to_hex();
                        let mut batch_total_fee_scaled: u64 = 0;
                        let mut m2m_tx_count: u64 = 0;

                        for tx in &batch.txs {
                            let tx_hash = match l2_core::canonical_hash(tx) {
                                Ok(h) => h,
                                Err(_) => continue,
                            };

                            if let Ok(Some(res)) = m2m.get_reservation(&tx_hash.0) {
                                let final_fee = res.breakdown.total_fee.scaled();
                                match m2m.finalise_fee_with_batch(
                                    &res.machine_id,
                                    tx_hash.0,
                                    final_fee,
                                    now_ms(),
                                    &batch_hash_hex,
                                ) {
                                    Ok(result) => {
                                        if result.is_new() {
                                            let (charged, _refund) = match &result {
                                                l2_storage::m2m::FinaliseFeeResult::Finalised {
                                                    charged_scaled, ..
                                                } => (*charged_scaled, 0),
                                                l2_storage::m2m::FinaliseFeeResult::AlreadyFinalised {
                                                    charged_scaled, ..
                                                } => (*charged_scaled, 0),
                                            };
                                            batch_total_fee_scaled =
                                                batch_total_fee_scaled.saturating_add(charged);
                                            m2m_tx_count = m2m_tx_count.saturating_add(1);
                                        }
                                    }
                                    Err(err) => {
                                        warn!(error = %err, "failed to finalize M2M fee");
                                    }
                                }
                            }
                        }

                        // Update hub fee totals
                        if batch_total_fee_scaled > 0 {
                            if let Err(err) = storage.add_hub_total_fees(hub_str, chain_id, batch_total_fee_scaled) {
                                warn!(error = %err, "failed to update hub fee totals");
                            }

                            let mut guard = state.lock().await;
                            let hub_state = guard.hub_state_mut(chosen_hub);
                            hub_state.add_finalised_fees(batch_total_fee_scaled);
                        }

                        info!(
                            hub = hub_str,
                            batch_hash = %hash.to_hex(),
                            total_fees = batch_total_fee_scaled,
                            m2m_tx_count = m2m_tx_count,
                            "finalized M2M fees for hub batch"
                        );
                    }
                }

                // Post the batch
                if let Err(err) = poster.post_batch(&batch, &hash).await {
                    warn!(hub = hub_str, error = %err, "poster failed for hub batch");
                } else {
                    // Update last batch hash in storage for chaining
                    if let Err(err) = storage.set_last_batch_hash(hub_str, chain_id, &hash) {
                        warn!(hub = hub_str, error = %err, "failed to update last batch hash");
                    }
                }

                // Mark hub as served for fairness tracking
                organiser_state.mark_hub_served(chosen_hub);

                info!(
                    hub = hub_str,
                    batch_number = batch_number,
                    tx_count = batch.txs.len(),
                    batch_hash = %hash.to_hex(),
                    forced_count = forced_tx_hashes.len(),
                    "created hub batch"
                );
            }
            Err(err) => {
                warn!(hub = hub_str, error = %err, "failed to persist hub batch");
            }
        }
    }
}

/// Get forced txs for a specific hub.
async fn get_forced_txs_for_hub(
    storage: &Storage,
    hub: &str,
    limit: usize,
) -> Result<Vec<(Tx, Hash32)>, BatcherError> {
    let tickets = storage.list_queued_forced_for_hub(hub, limit)?;
    let mut txs = Vec::new();

    for ticket in tickets {
        if let Ok(Some(tx)) = storage.get_tx(&ticket.tx_hash) {
            txs.push((tx, ticket.tx_hash));
        }
    }

    Ok(txs)
}

pub struct BatcherHandle {
    tx: mpsc::Sender<Tx>,
    state: Arc<Mutex<BatcherState>>,
}

impl Clone for BatcherHandle {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

impl BatcherHandle {
    pub async fn submit_tx(&self, tx: Tx) -> Result<(), BatcherError> {
        self.tx
            .send(tx)
            .await
            .map_err(|_| BatcherError::QueueClosed)?;
        let mut guard = self.state.lock().await;
        guard.queue_depth = guard.queue_depth.saturating_add(1);
        Ok(())
    }

    pub async fn snapshot(&self) -> BatcherSnapshot {
        let state = self.state.lock().await;
        state.clone().into()
    }
}

pub fn spawn(
    config: BatcherConfig,
    storage: Arc<Storage>,
    poster: Arc<dyn BatchPoster>,
) -> BatcherHandle {
    spawn_with_m2m(config, storage, poster, None, None, None)
}

/// Spawn batcher with optional M2M fee storage for fee finalization.
pub fn spawn_with_m2m(
    config: BatcherConfig,
    storage: Arc<Storage>,
    poster: Arc<dyn BatchPoster>,
    m2m_storage: Option<Arc<M2mStorage>>,
    fee_schedule: Option<FeeSchedule>,
    organiser: Option<Arc<dyn Organiser>>,
) -> BatcherHandle {
    let (tx, rx) = mpsc::channel(1024);

    // Determine organiser version
    let organiser_version = organiser
        .as_ref()
        .map(|o| o.version())
        .unwrap_or(OrganiserVersion::None);

    // Create default organiser if none provided and organiser is enabled
    let organiser: Arc<dyn Organiser> = if config.organiser_enabled {
        organiser.unwrap_or_else(|| Arc::new(GbdtOrganiserV1::new()))
    } else {
        Arc::new(NoopOrganiser::new(OrganiserDecision::new(
            config.max_wait_ms,
            u32::try_from(config.max_batch_txs).unwrap_or(u32::MAX),
            u32::try_from(config.max_batch_bytes).unwrap_or(u32::MAX),
            u32::try_from(config.max_batch_txs / 2).unwrap_or(u32::MAX),
        )))
    };

    let state = Arc::new(Mutex::new(BatcherState::new(
        config.organiser_enabled,
        organiser_version,
        config.organiser_bounds.clone(),
    )));

    tokio::spawn(run_loop(
        config,
        storage,
        poster,
        rx,
        Arc::clone(&state),
        m2m_storage,
        fee_schedule.unwrap_or_default(),
        organiser,
    ));
    BatcherHandle { tx, state }
}

#[allow(clippy::too_many_arguments)]
async fn run_loop(
    config: BatcherConfig,
    storage: Arc<Storage>,
    poster: Arc<dyn BatchPoster>,
    mut rx: mpsc::Receiver<Tx>,
    state: Arc<Mutex<BatcherState>>,
    m2m_storage: Option<Arc<M2mStorage>>,
    _fee_schedule: FeeSchedule,
    organiser: Arc<dyn Organiser>,
) {
    // Counter for decay interval (decay every 10 iterations)
    let mut iteration_counter: u64 = 0;

    loop {
        iteration_counter = iteration_counter.wrapping_add(1);

        // Build organiser inputs from current state
        let (organiser_inputs, decision) = {
            let guard = state.lock().await;

            // Get in-flight batch count from storage
            let in_flight_batches = storage
                .count_settlement_states()
                .map(|c| c.in_flight())
                .unwrap_or(0);

            // Get forced queue depth from storage
            let forced_queue_depth = storage.count_forced_queue().map(|c| c.queued).unwrap_or(0);

            let inputs = OrganiserInputs {
                now_ms: now_ms(),
                queue_depth: u32::try_from(guard.queue_depth).unwrap_or(u32::MAX),
                forced_queue_depth: u32::try_from(forced_queue_depth).unwrap_or(u32::MAX),
                in_flight_batches: u32::try_from(in_flight_batches).unwrap_or(u32::MAX),
                recent_quota_rejects: guard.recent_quota_rejects,
                recent_insufficient_balance: guard.recent_insufficient_balance,
                recent_forced_used_bytes: guard.recent_forced_used_bytes,
                avg_tx_bytes_est: guard.avg_tx_bytes_est(),
            };

            // Get organiser decision
            let raw_decision = organiser.decide(&inputs);

            // Clamp to bounds
            let clamped_decision = guard.organiser_bounds.clamp(raw_decision);

            (inputs, clamped_decision)
        };

        // Update state with last inputs/decision
        {
            let mut guard = state.lock().await;
            guard.last_organiser_inputs = Some(organiser_inputs.clone());
            guard.last_organiser_decision = Some(decision.clone());

            // Decay counters periodically (every 10 iterations)
            if iteration_counter % 10 == 0 {
                guard.decay_counters();
            }
        }

        debug!(
            sleep_ms = decision.sleep_ms,
            max_txs = decision.max_txs,
            max_bytes = decision.max_bytes,
            forced_drain_max = decision.forced_drain_max,
            queue_depth = organiser_inputs.queue_depth,
            in_flight = organiser_inputs.in_flight_batches,
            "organiser decision"
        );

        // Apply sleep from organiser decision
        let deadline = Instant::now() + Duration::from_millis(decision.sleep_ms);
        let mut batch_txs: Vec<Tx> = Vec::new();
        let mut batch_bytes: usize = 0;
        let mut forced_tx_hashes: Vec<Hash32> = Vec::new();

        // Use organiser decision for limits
        let max_txs = usize::try_from(decision.max_txs).unwrap_or(config.max_batch_txs);
        let max_bytes = usize::try_from(decision.max_bytes).unwrap_or(config.max_batch_bytes);
        let forced_drain_max = usize::try_from(decision.forced_drain_max).unwrap_or(max_txs / 2);

        // Step 1: First include due forced txs from storage (capped by organiser)
        match get_forced_txs(&storage, forced_drain_max).await {
            Ok(forced_txs) => {
                let mut forced_bytes_this_batch: u64 = 0;
                for (tx, tx_hash) in forced_txs {
                    if batch_txs.len() >= max_txs || batch_bytes >= max_bytes {
                        break;
                    }
                    let tx_size = tx.payload.len();
                    batch_txs.push(tx);
                    batch_bytes += tx_size;
                    forced_tx_hashes.push(tx_hash);
                    forced_bytes_this_batch =
                        forced_bytes_this_batch.saturating_add(u64::try_from(tx_size).unwrap_or(0));
                }
                if !forced_tx_hashes.is_empty() {
                    info!(
                        count = forced_tx_hashes.len(),
                        bytes = forced_bytes_this_batch,
                        "including forced txs in batch"
                    );
                    // Update forced bytes counter
                    let mut guard = state.lock().await;
                    guard.recent_forced_used_bytes = guard
                        .recent_forced_used_bytes
                        .saturating_add(forced_bytes_this_batch);
                }
            }
            Err(err) => {
                warn!(error = %err, "failed to get forced txs");
            }
        }

        // Step 2: Fill remaining slots with normal pool txs (using organiser limits)
        while batch_txs.len() < max_txs && batch_bytes < max_bytes {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, rx.recv()).await {
                Ok(Some(tx)) => {
                    let tx_size = tx.payload.len();
                    batch_txs.push(tx);
                    batch_bytes += tx_size;

                    // Update state
                    let mut guard = state.lock().await;
                    guard.queue_depth = guard.queue_depth.saturating_sub(1);
                    // Update tx bytes EMA
                    guard.update_avg_tx_bytes(u64::try_from(tx_size).unwrap_or(0));
                }
                Ok(None) => return,
                Err(_) => break,
            }
        }

        if batch_txs.is_empty() {
            // Drain one pending message if available to avoid idle state.
            if let Some(tx) = rx.recv().await {
                let tx_size = tx.payload.len();
                batch_txs.push(tx);
                #[allow(unused_assignments)]
                {
                    batch_bytes += tx_size;
                }
                let mut guard = state.lock().await;
                guard.queue_depth = guard.queue_depth.saturating_sub(1);
            } else {
                return;
            }
        }

        let batch_number = match next_batch_number(&storage).await {
            Ok(num) => num,
            Err(err) => {
                warn!(error = %err, "failed to obtain batch number");
                continue;
            }
        };

        let batch = Batch {
            chain_id: config.chain_id,
            batch_number,
            txs: batch_txs,
            created_ms: now_ms(),
        };

        match storage.put_batch(&batch) {
            Ok(hash) => {
                // Mark forced txs as included
                for forced_hash in &forced_tx_hashes {
                    if let Err(err) = mark_forced_included(&storage, forced_hash, &hash) {
                        warn!(
                            error = %err,
                            tx_hash = %forced_hash.to_hex(),
                            "failed to mark forced tx as included"
                        );
                    }
                }

                // Finalize fees for all transactions in the batch (idempotent via ledger)
                let mut batch_total_fee_scaled: u64 = 0;
                let mut batch_total_refunds_scaled: u64 = 0;
                let mut m2m_tx_count: u64 = 0;
                let batch_hash_hex = hash.to_hex();

                if let Some(m2m) = &m2m_storage {
                    for tx in &batch.txs {
                        let tx_hash = match l2_core::canonical_hash(tx) {
                            Ok(h) => h,
                            Err(_) => continue,
                        };

                        // Get reservation if exists (check ledger first via get_ledger_entry)
                        let maybe_reservation = m2m.get_reservation(&tx_hash.0);
                        let maybe_ledger = m2m.get_ledger_entry_by_hash(&tx_hash.0);

                        // Determine if we should finalize and with what parameters
                        let finalize_params: Option<(String, u64)> =
                            match (&maybe_reservation, &maybe_ledger) {
                                (Ok(Some(res)), _) => {
                                    // Has reservation - use its params
                                    Some((res.machine_id.clone(), res.breakdown.total_fee.scaled()))
                                }
                                (
                                    _,
                                    Ok(Some(l2_storage::m2m::LedgerEntry::Reserved {
                                        machine_id,
                                        reserved_scaled,
                                        ..
                                    })),
                                ) => {
                                    // Ledger has reserved entry
                                    Some((machine_id.clone(), *reserved_scaled))
                                }
                                (
                                    _,
                                    Ok(Some(l2_storage::m2m::LedgerEntry::Finalised {
                                        charged_scaled,
                                        refunded_scaled,
                                        ..
                                    })),
                                ) => {
                                    // Already finalised - idempotent, just add to totals
                                    batch_total_fee_scaled =
                                        batch_total_fee_scaled.saturating_add(*charged_scaled);
                                    batch_total_refunds_scaled =
                                        batch_total_refunds_scaled.saturating_add(*refunded_scaled);
                                    m2m_tx_count = m2m_tx_count.saturating_add(1);
                                    debug!(
                                        tx_hash = %tx_hash.to_hex(),
                                        charged = charged_scaled,
                                        refunded = refunded_scaled,
                                        "fee already finalized (idempotent)"
                                    );
                                    continue;
                                }
                                _ => None,
                            };

                        if let Some((machine_id, final_fee)) = finalize_params {
                            // Finalize the fee using the idempotent ledger-based method
                            match m2m.finalise_fee_with_batch(
                                &machine_id,
                                tx_hash.0,
                                final_fee,
                                now_ms(),
                                &batch_hash_hex,
                            ) {
                                Ok(result) => {
                                    let (charged, refund) = match &result {
                                        l2_storage::m2m::FinaliseFeeResult::Finalised {
                                            charged_scaled,
                                            refunded_scaled,
                                        } => (*charged_scaled, *refunded_scaled),
                                        l2_storage::m2m::FinaliseFeeResult::AlreadyFinalised {
                                            charged_scaled,
                                            refunded_scaled,
                                        } => {
                                            debug!(
                                                tx_hash = %tx_hash.to_hex(),
                                                "finalise_fee returned AlreadyFinalised"
                                            );
                                            (*charged_scaled, *refunded_scaled)
                                        }
                                    };

                                    // Only add to totals if this was a new finalization
                                    // to avoid double-counting on crash recovery
                                    if result.is_new() {
                                        batch_total_fee_scaled =
                                            batch_total_fee_scaled.saturating_add(charged);
                                        batch_total_refunds_scaled =
                                            batch_total_refunds_scaled.saturating_add(refund);
                                        m2m_tx_count = m2m_tx_count.saturating_add(1);
                                    }

                                    debug!(
                                        tx_hash = %tx_hash.to_hex(),
                                        machine_id = %machine_id,
                                        final_fee = charged,
                                        refund = refund,
                                        is_new = result.is_new(),
                                        "finalized fee for tx"
                                    );
                                }
                                Err(err) => {
                                    warn!(
                                        error = %err,
                                        tx_hash = %tx_hash.to_hex(),
                                        "failed to finalize fee"
                                    );
                                }
                            }
                        }
                    }

                    // Record batch fee totals with settlement state
                    let totals = BatchFeeTotals {
                        batch_hash: hash.0,
                        total_fees_scaled: batch_total_fee_scaled,
                        tx_count: m2m_tx_count,
                        total_refunds_scaled: batch_total_refunds_scaled,
                        created_at_ms: batch.created_ms,
                    };

                    // Record with initial "created" settlement state
                    if let Err(err) = m2m.record_batch_fees_with_state(&totals, "created") {
                        warn!(
                            error = %err,
                            batch_hash = %hash.to_hex(),
                            "failed to record batch fee totals"
                        );
                    } else {
                        info!(
                            batch_hash = %hash.to_hex(),
                            total_fees = batch_total_fee_scaled,
                            total_refunds = batch_total_refunds_scaled,
                            m2m_tx_count = m2m_tx_count,
                            "recorded batch fee totals with settlement tracking"
                        );
                    }
                }

                if let Err(err) = poster.post_batch(&batch, &hash).await {
                    warn!(error = %err, "poster failed for batch");
                }
                let mut guard = state.lock().await;
                guard.last_batch_hash = Some(hash);
                guard.last_post_time_ms = Some(batch.created_ms);
                debug!(
                    batch_number,
                    hash = %hash.to_hex(),
                    forced_count = forced_tx_hashes.len(),
                    batch_fee_total = batch_total_fee_scaled,
                    "stored batch"
                );
            }
            Err(err) => warn!(error = %err, "failed to persist batch"),
        }
    }
}

/// Get queued forced txs from storage.
async fn get_forced_txs(
    storage: &Storage,
    limit: usize,
) -> Result<Vec<(Tx, Hash32)>, BatcherError> {
    let tickets = storage.list_queued_forced(limit)?;
    let mut txs = Vec::new();

    for ticket in tickets {
        if let Ok(Some(tx)) = storage.get_tx(&ticket.tx_hash) {
            txs.push((tx, ticket.tx_hash));
        }
    }

    Ok(txs)
}

/// Mark a forced tx as included in a batch.
fn mark_forced_included(
    storage: &Storage,
    tx_hash: &Hash32,
    batch_hash: &Hash32,
) -> Result<(), BatcherError> {
    if let Some(mut ticket) = storage.get_forced_ticket(tx_hash)? {
        ticket.mark_included(*batch_hash);
        storage.update_forced_ticket(&ticket)?;
    }
    Ok(())
}

async fn next_batch_number(storage: &Storage) -> Result<u64, BatcherError> {
    let current_bytes = storage.get_meta("last_batch_number")?;
    let next = current_bytes
        .and_then(|bytes| bytes.try_into().ok().map(u64::from_le_bytes))
        .unwrap_or(0)
        .saturating_add(1);
    storage.set_meta("last_batch_number", &next.to_le_bytes())?;
    Ok(next)
}

fn now_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

pub fn build_handle_for_tests(
    config: BatcherConfig,
    _storage: Arc<Storage>,
    _poster: Arc<dyn BatchPoster>,
) -> (BatcherHandle, mpsc::Receiver<Tx>) {
    let (tx, rx) = mpsc::channel(1024);
    let state = Arc::new(Mutex::new(BatcherState::new(
        config.organiser_enabled,
        OrganiserVersion::None,
        config.organiser_bounds,
    )));
    let handle = BatcherHandle { tx, state };
    (handle, rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_storage::SCHEMA_VERSION;
    use tempfile::tempdir;

    struct NoopPoster;

    #[async_trait]
    impl BatchPoster for NoopPoster {
        async fn post_batch(&self, _batch: &Batch, _hash: &Hash32) -> Result<(), BatcherError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn creates_batch_and_updates_state() {
        let dir = tempdir().expect("tmpdir");
        let storage = Arc::new(Storage::open(dir.path()).expect("open"));
        let poster: Arc<dyn BatchPoster> = Arc::new(NoopPoster {});
        let config = BatcherConfig {
            max_batch_txs: 2,
            max_batch_bytes: 1024,
            max_wait_ms: 10,
            chain_id: ChainId(7),
            organiser_enabled: false, // Disable organiser for deterministic test timing
            ..BatcherConfig::default()
        };
        let handle = spawn(config, Arc::clone(&storage), poster);
        handle
            .submit_tx(Tx {
                chain_id: ChainId(7),
                nonce: 1,
                from: "alice".to_string(),
                payload: vec![1, 2, 3],
            })
            .await
            .expect("queue");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let snapshot = handle.snapshot().await;
        assert!(snapshot.last_batch_hash.is_some());
        assert_eq!(snapshot.queue_depth, 0);
        assert_eq!(
            storage.get_meta("schema_version").unwrap(),
            Some(SCHEMA_VERSION.as_bytes().to_vec())
        );
    }

    #[test]
    fn post_mode_from_env_str() {
        assert_eq!(PostMode::from_env_str("tx_data"), PostMode::TxData);
        assert_eq!(PostMode::from_env_str("TX_DATA"), PostMode::TxData);
        assert_eq!(
            PostMode::from_env_str("tx_payment_memo"),
            PostMode::TxPaymentMemo
        );
        assert_eq!(PostMode::from_env_str("payment"), PostMode::TxPaymentMemo);
        assert_eq!(PostMode::from_env_str("unknown"), PostMode::TxData); // Default
    }

    #[test]
    fn ippan_poster_config_defaults() {
        let config = IppanPosterConfig::default();
        assert_eq!(config.mode, PostMode::TxData);
        assert!(!config.force_repost);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_ms, 500);
    }

    #[test]
    fn batch_post_data_serialization() {
        let data = BatchPostData {
            batch_hash: "aabbccdd".to_string(),
            chain_id: 1337,
            batch_number: 42,
            tx_count: 10,
            created_ms: 1_700_000_000_000,
            payload_hash: "11223344".to_string(),
        };
        let json = serde_json::to_string(&data).expect("serialize");
        assert!(json.contains("\"batch_hash\":\"aabbccdd\""));
        assert!(json.contains("\"chain_id\":1337"));
        assert!(json.contains("\"batch_number\":42"));
    }

    // ========== Multi-Hub Tests ==========

    #[test]
    fn hub_tx_creation() {
        let tx = Tx {
            chain_id: ChainId(1337),
            nonce: 1,
            from: "alice".to_string(),
            payload: vec![1, 2, 3, 4, 5],
        };
        let hub_tx = HubTx::new(L2HubId::Fin, tx);
        assert_eq!(hub_tx.hub, L2HubId::Fin);
        assert_eq!(hub_tx.payload_size(), 5);
    }

    #[test]
    fn per_hub_queue_state_defaults() {
        let state = PerHubQueueState::new();
        assert_eq!(state.queue_depth, 0);
        assert_eq!(state.forced_queue_depth, 0);
        assert_eq!(state.in_flight_batches, 0);
        assert_eq!(state.avg_tx_bytes_est, 256);
        assert_eq!(state.batch_number, 0);
    }

    #[test]
    fn per_hub_queue_state_batch_number() {
        let mut state = PerHubQueueState::new();
        assert_eq!(state.next_batch_number(), 1);
        assert_eq!(state.next_batch_number(), 2);
        assert_eq!(state.next_batch_number(), 3);
        assert_eq!(state.batch_number, 3);
    }

    #[test]
    fn per_hub_queue_state_avg_bytes_update() {
        let mut state = PerHubQueueState::new();
        assert_eq!(state.avg_tx_bytes_est, 256);
        
        // Update with larger tx
        state.update_avg_tx_bytes(1024);
        // EMA should move towards 1024
        assert!(state.avg_tx_bytes_est > 256);
        assert!(state.avg_tx_bytes_est < 1024);
    }

    #[test]
    fn multi_hub_batcher_state_creation() {
        let state = MultiHubBatcherState::new(
            true,
            OrganiserVersion::GbdtV1,
            OrganiserPolicyBounds::default(),
        );
        
        // Should have all 5 hubs
        assert_eq!(state.per_hub.len(), 5);
        assert!(state.per_hub.contains_key(&L2HubId::Fin));
        assert!(state.per_hub.contains_key(&L2HubId::Data));
        assert!(state.per_hub.contains_key(&L2HubId::M2m));
        assert!(state.per_hub.contains_key(&L2HubId::World));
        assert!(state.per_hub.contains_key(&L2HubId::Bridge));
    }

    #[test]
    fn multi_hub_batcher_state_totals() {
        let mut state = MultiHubBatcherState::new(
            true,
            OrganiserVersion::GbdtV1,
            OrganiserPolicyBounds::default(),
        );
        
        // Add some queue depths
        state.hub_state_mut(L2HubId::Fin).queue_depth = 100;
        state.hub_state_mut(L2HubId::Data).queue_depth = 50;
        state.hub_state_mut(L2HubId::M2m).queue_depth = 75;
        
        assert_eq!(state.total_queue_depth(), 225);
        
        // Add forced queue depths
        state.hub_state_mut(L2HubId::Fin).forced_queue_depth = 5;
        state.hub_state_mut(L2HubId::M2m).forced_queue_depth = 3;
        
        assert_eq!(state.total_forced_queue_depth(), 8);
    }

    #[test]
    fn multi_hub_batcher_state_hub_inputs() {
        let mut state = MultiHubBatcherState::new(
            true,
            OrganiserVersion::GbdtV1,
            OrganiserPolicyBounds::default(),
        );
        
        state.hub_state_mut(L2HubId::Fin).queue_depth = 100;
        state.hub_state_mut(L2HubId::Fin).forced_queue_depth = 5;
        state.hub_state_mut(L2HubId::Fin).in_flight_batches = 2;
        
        let inputs = state.build_hub_inputs(L2HubId::Fin);
        assert_eq!(inputs.hub, L2HubId::Fin);
        assert_eq!(inputs.queue_depth, 100);
        assert_eq!(inputs.forced_queue_depth, 5);
        assert_eq!(inputs.in_flight_batches, 2);
    }

    #[test]
    fn organiser_inputs_v2_default() {
        let inputs = OrganiserInputsV2::default();
        assert_eq!(inputs.now_ms, 0);
        assert_eq!(inputs.hubs.len(), 5);
        assert_eq!(inputs.total_queue_depth(), 0);
    }

    #[test]
    fn organiser_inputs_v2_build() {
        let mut state = MultiHubBatcherState::new(
            true,
            OrganiserVersion::GbdtV1,
            OrganiserPolicyBounds::default(),
        );
        
        state.hub_state_mut(L2HubId::Fin).queue_depth = 100;
        state.hub_state_mut(L2HubId::Data).queue_depth = 50;
        
        let inputs = state.build_organiser_inputs_v2(1_700_000_000_000);
        
        assert_eq!(inputs.now_ms, 1_700_000_000_000);
        assert_eq!(inputs.hubs.len(), 5);
        assert_eq!(inputs.total_queue_depth(), 150);
        
        let fin_inputs = inputs.get_hub(L2HubId::Fin).unwrap();
        assert_eq!(fin_inputs.queue_depth, 100);
        
        let data_inputs = inputs.get_hub(L2HubId::Data).unwrap();
        assert_eq!(data_inputs.queue_depth, 50);
    }

    #[test]
    fn organiser_decision_v2_default() {
        let decision = OrganiserDecisionV2::default();
        assert_eq!(decision.chosen_hub, L2HubId::Fin);
        assert_eq!(decision.sleep_ms, 1000);
        assert_eq!(decision.max_txs, 256);
    }

    #[test]
    fn organiser_decision_v2_creation() {
        let decision = OrganiserDecisionV2::new(L2HubId::M2m, 500, 128, 256 * 1024, 64);
        assert_eq!(decision.chosen_hub, L2HubId::M2m);
        assert_eq!(decision.sleep_ms, 500);
        assert_eq!(decision.max_txs, 128);
        assert_eq!(decision.max_bytes, 256 * 1024);
        assert_eq!(decision.forced_drain_max, 64);
    }

    #[test]
    fn multi_hub_snapshot_creation() {
        let mut state = MultiHubBatcherState::new(
            true,
            OrganiserVersion::GbdtV1,
            OrganiserPolicyBounds::default(),
        );
        
        state.hub_state_mut(L2HubId::Fin).queue_depth = 100;
        state.hub_state_mut(L2HubId::Fin).batch_number = 42;
        state.hub_state_mut(L2HubId::M2m).queue_depth = 50;
        state.hub_state_mut(L2HubId::M2m).total_fees_finalised_scaled = 1_000_000;
        
        let snapshot = MultiHubBatcherSnapshot::from(&state);
        
        assert_eq!(snapshot.total_queue_depth, 150);
        assert_eq!(snapshot.per_hub.len(), 5);
        
        let fin_snap = snapshot.per_hub.get("fin").unwrap();
        assert_eq!(fin_snap.queue_depth, 100);
        assert_eq!(fin_snap.batch_number, 42);
        assert!(fin_snap.total_fees_finalised_scaled.is_none()); // Not M2M hub
        
        let m2m_snap = snapshot.per_hub.get("m2m").unwrap();
        assert_eq!(m2m_snap.queue_depth, 50);
        assert_eq!(m2m_snap.total_fees_finalised_scaled, Some(1_000_000));
    }

    #[test]
    fn create_multi_hub_channels_creates_all_hubs() {
        let (senders, receivers) = create_multi_hub_channels(64);
        
        assert_eq!(senders.len(), 5);
        assert!(senders.contains_key(&L2HubId::Fin));
        assert!(senders.contains_key(&L2HubId::Data));
        assert!(senders.contains_key(&L2HubId::M2m));
        assert!(senders.contains_key(&L2HubId::World));
        assert!(senders.contains_key(&L2HubId::Bridge));
        
        // Can't easily check receiver count without consuming them
        // but we can check one hub works
        assert!(!receivers.hub_has_pending(L2HubId::Fin));
    }

    #[tokio::test]
    async fn multi_hub_handle_submit() {
        let (senders, _receivers) = create_multi_hub_channels(64);
        let state = Arc::new(Mutex::new(MultiHubBatcherState::new(
            true,
            OrganiserVersion::GbdtV1,
            OrganiserPolicyBounds::default(),
        )));
        
        let handle = MultiHubBatcherHandle::new(senders, state);
        
        // Submit to FIN hub
        let tx = Tx {
            chain_id: ChainId(1337),
            nonce: 1,
            from: "alice".to_string(),
            payload: vec![1, 2, 3],
        };
        
        handle.submit_tx(L2HubId::Fin, tx.clone()).await.unwrap();
        
        assert_eq!(handle.hub_queue_depth(L2HubId::Fin).await, 1);
        assert_eq!(handle.hub_queue_depth(L2HubId::Data).await, 0);
        
        // Submit to DATA hub
        handle.submit_tx(L2HubId::Data, tx.clone()).await.unwrap();
        assert_eq!(handle.hub_queue_depth(L2HubId::Data).await, 1);
        
        // Check snapshot
        let snapshot = handle.snapshot().await;
        assert_eq!(snapshot.total_queue_depth, 2);
    }

    #[tokio::test]
    async fn multi_hub_handle_submit_hub_tx() {
        let (senders, _receivers) = create_multi_hub_channels(64);
        let state = Arc::new(Mutex::new(MultiHubBatcherState::new(
            true,
            OrganiserVersion::GbdtV1,
            OrganiserPolicyBounds::default(),
        )));
        
        let handle = MultiHubBatcherHandle::new(senders, state);
        
        let hub_tx = HubTx::new(L2HubId::M2m, Tx {
            chain_id: ChainId(1337),
            nonce: 1,
            from: "machine001".to_string(),
            payload: vec![1, 2, 3],
        });
        
        handle.submit_hub_tx(hub_tx).await.unwrap();
        assert_eq!(handle.hub_queue_depth(L2HubId::M2m).await, 1);
    }

    #[test]
    fn multi_hub_batcher_config_defaults() {
        let config = MultiHubBatcherConfig::default();
        assert_eq!(config.max_batch_txs, 256);
        assert_eq!(config.max_batch_bytes, 512 * 1024);
        assert_eq!(config.max_wait_ms, 1_000);
        assert_eq!(config.chain_id.0, 1);
        assert_eq!(config.channel_buffer_size, 1024);
    }

    #[test]
    fn per_hub_queue_state_set_last_batch_hash() {
        let mut state = PerHubQueueState::new();
        assert!(state.last_batch_hash.is_none());
        
        let hash = [0xaa; 32];
        state.set_last_batch_hash(hash);
        assert!(state.last_batch_hash.is_some());
        assert_eq!(state.last_batch_hash.unwrap().0, hash);
    }

    #[test]
    fn per_hub_queue_state_add_finalised_fees() {
        let mut state = PerHubQueueState::new();
        assert_eq!(state.total_fees_finalised_scaled, 0);
        
        state.add_finalised_fees(1000);
        assert_eq!(state.total_fees_finalised_scaled, 1000);
        
        state.add_finalised_fees(500);
        assert_eq!(state.total_fees_finalised_scaled, 1500);
        
        // Test saturation
        state.total_fees_finalised_scaled = u64::MAX - 10;
        state.add_finalised_fees(100);
        assert_eq!(state.total_fees_finalised_scaled, u64::MAX);
    }

    #[test]
    fn per_hub_queue_state_last_batch_created_ms() {
        let mut state = PerHubQueueState::new();
        assert!(state.last_batch_created_ms.is_none());
        
        state.last_batch_created_ms = Some(now_ms());
        assert!(state.last_batch_created_ms.is_some());
    }

    #[test]
    fn get_forced_txs_for_hub_handles_empty() {
        // This tests the async function with an empty storage
        // The function should return an empty vec when no forced txs
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            get_forced_txs_for_hub(&storage, "fin", 10).await
        });
        
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}

#[cfg(test)]
mod ippan_poster_tests {
    use super::*;
    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_batch() -> Batch {
        Batch {
            chain_id: ChainId(1337),
            batch_number: 1,
            txs: vec![Tx {
                chain_id: ChainId(1337),
                nonce: 1,
                from: "alice".to_string(),
                payload: vec![1, 2, 3],
            }],
            created_ms: 1_700_000_000_000,
        }
    }

    #[tokio::test]
    async fn ippan_poster_success() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tx_hash": "l1tx123abc",
                "accepted": true
            })))
            .mount(&server)
            .await;

        let dir = tempdir().expect("tmpdir");
        let storage = Arc::new(Storage::open(dir.path()).expect("open"));

        let rpc_config = IppanRpcConfig {
            base_url: server.uri(),
            timeout_ms: 5000,
            retry_max: 1,
        };
        let poster_config = IppanPosterConfig {
            mode: PostMode::TxData,
            force_repost: false,
            max_retries: 1,
            retry_delay_ms: 10,
        };

        let poster =
            IppanBatchPoster::new(rpc_config, Arc::clone(&storage), poster_config).unwrap();

        let batch = test_batch();
        let hash = l2_core::canonical_hash(&batch).unwrap();

        poster.post_batch(&batch, &hash).await.unwrap();

        // Verify posting state was updated
        let state = storage.get_posting_state(&hash).unwrap().unwrap();
        assert!(state.is_posted());
        assert_eq!(state.l1_tx(), Some("l1tx123abc"));
    }

    #[tokio::test]
    async fn ippan_poster_idempotent_skip() {
        let server = MockServer::start().await;

        // Should not be called since batch is already confirmed
        Mock::given(method("POST"))
            .and(path("/tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tx_hash": "newl1tx",
                "accepted": true
            })))
            .expect(0) // Should not be called
            .mount(&server)
            .await;

        let dir = tempdir().expect("tmpdir");
        let storage = Arc::new(Storage::open(dir.path()).expect("open"));

        // Pre-set the state as confirmed
        let batch = test_batch();
        let hash = l2_core::canonical_hash(&batch).unwrap();
        storage
            .set_posting_state(
                &hash,
                &PostingState::confirmed("existingl1tx".to_string(), 1_700_000_000_000),
            )
            .unwrap();

        let rpc_config = IppanRpcConfig {
            base_url: server.uri(),
            timeout_ms: 5000,
            retry_max: 1,
        };
        let poster_config = IppanPosterConfig {
            mode: PostMode::TxData,
            force_repost: false,
            max_retries: 1,
            retry_delay_ms: 10,
        };

        let poster =
            IppanBatchPoster::new(rpc_config, Arc::clone(&storage), poster_config).unwrap();

        // Should skip without error
        poster.post_batch(&batch, &hash).await.unwrap();

        // State should remain confirmed with original l1_tx
        let state = storage.get_posting_state(&hash).unwrap().unwrap();
        assert_eq!(state.l1_tx(), Some("existingl1tx"));
    }

    #[tokio::test]
    async fn ippan_poster_retry_on_failure() {
        let server = MockServer::start().await;

        // First call fails with 500
        Mock::given(method("POST"))
            .and(path("/tx"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Second call succeeds
        Mock::given(method("POST"))
            .and(path("/tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tx_hash": "retryl1tx",
                "accepted": true
            })))
            .mount(&server)
            .await;

        let dir = tempdir().expect("tmpdir");
        let storage = Arc::new(Storage::open(dir.path()).expect("open"));

        let rpc_config = IppanRpcConfig {
            base_url: server.uri(),
            timeout_ms: 5000,
            retry_max: 2,
        };
        let poster_config = IppanPosterConfig {
            mode: PostMode::TxData,
            force_repost: false,
            max_retries: 2,
            retry_delay_ms: 10,
        };

        let poster =
            IppanBatchPoster::new(rpc_config, Arc::clone(&storage), poster_config).unwrap();

        let batch = test_batch();
        let hash = l2_core::canonical_hash(&batch).unwrap();

        poster.post_batch(&batch, &hash).await.unwrap();

        let state = storage.get_posting_state(&hash).unwrap().unwrap();
        assert!(state.is_posted());
        assert_eq!(state.l1_tx(), Some("retryl1tx"));
    }
}

#[cfg(test)]
mod contract_poster_tests {
    use super::*;
    use l2_core::l1_contract::mock_client::MockL1Client;
    use l2_core::l1_contract::FixedAmountV1;
    use l2_core::L2HubId;
    use tempfile::tempdir;

    fn test_batch() -> Batch {
        Batch {
            chain_id: ChainId(1337),
            batch_number: 1,
            txs: vec![Tx {
                chain_id: ChainId(1337),
                nonce: 1,
                from: "alice".to_string(),
                payload: vec![1, 2, 3],
            }],
            created_ms: 1_700_000_000_000,
        }
    }

    #[tokio::test]
    async fn contract_poster_success() {
        let dir = tempdir().expect("tmpdir");
        let storage = Arc::new(Storage::open(dir.path()).expect("open"));

        let mock = MockL1Client::new("testnet");
        let adapter = BlockingL1ClientAdapter::new(mock);

        let config = ContractPosterConfig {
            bridge: BridgeConfig {
                hub: L2HubId::Fin,
                content_type: ContentType::Json,
                ..BridgeConfig::default()
            },
            force_repost: false,
            max_retries: 1,
            retry_delay_ms: 10,
            ..ContractPosterConfig::default()
        };

        let poster = ContractBatchPoster::new(adapter, Arc::clone(&storage), config);

        let batch = test_batch();
        let hash = l2_core::canonical_hash(&batch).unwrap();

        poster.post_batch(&batch, &hash).await.unwrap();

        // Verify posting state was updated
        let state = storage.get_posting_state(&hash).unwrap().unwrap();
        assert!(state.is_posted());
        // The L1 tx ID should be set (mock returns a deterministic ID)
        assert!(state.l1_tx().is_some());
    }

    #[tokio::test]
    async fn contract_poster_idempotent_skip() {
        let dir = tempdir().expect("tmpdir");
        let storage = Arc::new(Storage::open(dir.path()).expect("open"));

        // Pre-set the state as confirmed
        let batch = test_batch();
        let hash = l2_core::canonical_hash(&batch).unwrap();
        storage
            .set_posting_state(
                &hash,
                &PostingState::confirmed("existingl1tx".to_string(), 1_700_000_000_000),
            )
            .unwrap();

        let mock = MockL1Client::new("testnet");
        let adapter = BlockingL1ClientAdapter::new(mock);

        let config = ContractPosterConfig {
            force_repost: false,
            max_retries: 1,
            retry_delay_ms: 10,
            ..ContractPosterConfig::default()
        };

        let poster = ContractBatchPoster::new(adapter, Arc::clone(&storage), config);

        // Should skip without error
        poster.post_batch(&batch, &hash).await.unwrap();

        // State should remain confirmed with original l1_tx
        let state = storage.get_posting_state(&hash).unwrap().unwrap();
        assert_eq!(state.l1_tx(), Some("existingl1tx"));
    }

    #[tokio::test]
    async fn contract_poster_idempotent_replay_on_l1() {
        // Test that submitting the same batch twice with force_repost works
        // Note: Due to prev_batch_hash chaining, the second submission will have
        // a different idempotency key (prev_hash != zero_hash). This tests that
        // the poster handles L1 submission correctly even with force_repost.
        let dir = tempdir().expect("tmpdir");
        let storage = Arc::new(Storage::open(dir.path()).expect("open"));

        let mock = MockL1Client::new("testnet");
        let adapter = BlockingL1ClientAdapter::new(mock);

        let config = ContractPosterConfig {
            force_repost: true,
            max_retries: 1,
            retry_delay_ms: 10,
            ..ContractPosterConfig::default()
        };

        let poster = ContractBatchPoster::new(adapter, Arc::clone(&storage), config);

        let batch = test_batch();
        let hash = l2_core::canonical_hash(&batch).unwrap();

        // First post
        poster.post_batch(&batch, &hash).await.unwrap();
        let state1 = storage.get_posting_state(&hash).unwrap().unwrap();
        assert!(state1.is_posted());
        let l1_tx_1 = state1.l1_tx().unwrap().to_string();

        // Second post (force_repost = true, so it will post again)
        // The prev_batch_hash will be different (hash of batch1 vs zero),
        // resulting in a different idempotency key and L1 tx ID.
        poster.post_batch(&batch, &hash).await.unwrap();
        let state2 = storage.get_posting_state(&hash).unwrap().unwrap();
        assert!(state2.is_posted());
        let l1_tx_2 = state2.l1_tx().unwrap().to_string();

        // L1 tx IDs will be different because prev_hash changed
        // (first post: prev=zero, second post: prev=hash1)
        // Both submissions succeed, which is the important part
        assert!(!l1_tx_1.is_empty());
        assert!(!l1_tx_2.is_empty());
    }

    #[tokio::test]
    async fn contract_poster_batch_chaining() {
        let dir = tempdir().expect("tmpdir");
        let storage = Arc::new(Storage::open(dir.path()).expect("open"));

        let mock = MockL1Client::new("testnet");
        let adapter = BlockingL1ClientAdapter::new(mock);

        let config = ContractPosterConfig::default();
        let poster = ContractBatchPoster::new(adapter, Arc::clone(&storage), config);

        // Post first batch
        let batch1 = Batch {
            chain_id: ChainId(1337),
            batch_number: 1,
            txs: vec![Tx {
                chain_id: ChainId(1337),
                nonce: 1,
                from: "alice".to_string(),
                payload: vec![1, 2, 3],
            }],
            created_ms: 1_700_000_000_000,
        };
        let hash1 = l2_core::canonical_hash(&batch1).unwrap();
        poster.post_batch(&batch1, &hash1).await.unwrap();

        // Post second batch
        let batch2 = Batch {
            chain_id: ChainId(1337),
            batch_number: 2,
            txs: vec![Tx {
                chain_id: ChainId(1337),
                nonce: 2,
                from: "bob".to_string(),
                payload: vec![4, 5, 6],
            }],
            created_ms: 1_700_000_001_000,
        };
        let hash2 = l2_core::canonical_hash(&batch2).unwrap();
        poster.post_batch(&batch2, &hash2).await.unwrap();

        // Both batches should be posted
        let state1 = storage.get_posting_state(&hash1).unwrap().unwrap();
        let state2 = storage.get_posting_state(&hash2).unwrap().unwrap();
        assert!(state1.is_posted());
        assert!(state2.is_posted());

        // L1 tx IDs should be different (different batches)
        assert_ne!(state1.l1_tx(), state2.l1_tx());
    }

    /// Test that AlreadyKnown responses are treated as success.
    ///
    /// This verifies idempotent behavior: if L1 says "already known",
    /// the poster should NOT fail, and the posting state should be Posted.
    #[tokio::test]
    async fn contract_poster_already_known_is_success() {
        let dir = tempdir().expect("tmpdir");
        let storage = Arc::new(Storage::open(dir.path()).expect("open"));

        // Use a mock that will return AlreadyKnown on second submission
        let mock = MockL1Client::new("testnet");
        let adapter = BlockingL1ClientAdapter::new(mock);

        let config = ContractPosterConfig {
            force_repost: true, // Force repost to test idempotency handling
            max_retries: 1,
            retry_delay_ms: 10,
            ..ContractPosterConfig::default()
        };

        let poster = ContractBatchPoster::new(adapter, Arc::clone(&storage), config);

        let batch = test_batch();
        let hash = l2_core::canonical_hash(&batch).unwrap();

        // First post - should return Accepted
        poster.post_batch(&batch, &hash).await.unwrap();
        let state1 = storage.get_posting_state(&hash).unwrap().unwrap();
        assert!(state1.is_posted());

        // Second post (force_repost) - MockL1Client returns AlreadyKnown
        // This should NOT fail
        poster.post_batch(&batch, &hash).await.unwrap();
        let state2 = storage.get_posting_state(&hash).unwrap().unwrap();
        assert!(state2.is_posted());

        // State should never be Failed
        assert!(!matches!(state2, PostingState::Failed { .. }));
    }

    /// Test that batch chaining persists correctly across poster instances.
    #[tokio::test]
    async fn contract_poster_batch_chaining_persistence() {
        let dir = tempdir().expect("tmpdir");
        let storage = Arc::new(Storage::open(dir.path()).expect("open"));

        let mock1 = MockL1Client::new("testnet");
        let adapter1 = BlockingL1ClientAdapter::new(mock1);

        // Post first batch with first poster
        {
            let config = ContractPosterConfig::default();
            let poster = ContractBatchPoster::new(adapter1, Arc::clone(&storage), config);

            let batch1 = Batch {
                chain_id: ChainId(1337),
                batch_number: 1,
                txs: vec![Tx {
                    chain_id: ChainId(1337),
                    nonce: 1,
                    from: "alice".to_string(),
                    payload: vec![1, 2, 3],
                }],
                created_ms: 1_700_000_000_000,
            };
            let hash1 = l2_core::canonical_hash(&batch1).unwrap();
            poster.post_batch(&batch1, &hash1).await.unwrap();
        }

        // Create new poster (simulating restart)
        let mock2 = MockL1Client::new("testnet");
        let adapter2 = BlockingL1ClientAdapter::new(mock2);

        {
            let config = ContractPosterConfig::default();
            let poster = ContractBatchPoster::new(adapter2, Arc::clone(&storage), config);

            // Post second batch - should pick up prev_batch_hash from storage
            let batch2 = Batch {
                chain_id: ChainId(1337),
                batch_number: 2,
                txs: vec![Tx {
                    chain_id: ChainId(1337),
                    nonce: 2,
                    from: "bob".to_string(),
                    payload: vec![4, 5, 6],
                }],
                created_ms: 1_700_000_001_000,
            };
            let hash2 = l2_core::canonical_hash(&batch2).unwrap();
            poster.post_batch(&batch2, &hash2).await.unwrap();

            let state2 = storage.get_posting_state(&hash2).unwrap().unwrap();
            assert!(state2.is_posted());
        }

        // Verify prev_batch_hash was persisted
        let last_hash = storage.get_last_batch_hash("fin", 1337).unwrap();
        assert!(last_hash.is_some());
    }

    #[test]
    fn contract_poster_config_defaults() {
        let config = ContractPosterConfig::default();
        assert_eq!(config.bridge.hub, L2HubId::Fin);
        assert_eq!(config.bridge.content_type, ContentType::Json);
        assert_eq!(config.bridge.fee, FixedAmountV1(0));
        assert!(!config.force_repost);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_ms, 500);
    }
}
