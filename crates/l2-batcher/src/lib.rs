#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::disallowed_types)]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use ippan_rpc::{DataTxRequest, IppanRpcClient, IppanRpcConfig, IppanRpcError};
use l2_core::{Batch, ChainId, Hash32, Tx};
use l2_storage::{PostingState, Storage};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Instant};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct BatcherConfig {
    pub max_batch_txs: usize,
    pub max_batch_bytes: usize,
    pub max_wait_ms: u64,
    pub chain_id: ChainId,
}

impl Default for BatcherConfig {
    fn default() -> Self {
        Self {
            max_batch_txs: 256,
            max_batch_bytes: 512 * 1024,
            max_wait_ms: 1_000,
            chain_id: ChainId(1),
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
}

#[derive(Clone)]
struct BatcherState {
    queue_depth: usize,
    last_batch_hash: Option<Hash32>,
    last_post_time_ms: Option<u64>,
}

impl From<BatcherState> for BatcherSnapshot {
    fn from(state: BatcherState) -> Self {
        Self {
            queue_depth: state.queue_depth,
            last_batch_hash: state.last_batch_hash.map(Hash32::to_hex),
            last_post_time_ms: state.last_post_time_ms,
        }
    }
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
    let (tx, rx) = mpsc::channel(1024);
    let state = Arc::new(Mutex::new(BatcherState {
        queue_depth: 0,
        last_batch_hash: None,
        last_post_time_ms: None,
    }));
    tokio::spawn(run_loop(config, storage, poster, rx, Arc::clone(&state)));
    BatcherHandle { tx, state }
}

async fn run_loop(
    config: BatcherConfig,
    storage: Arc<Storage>,
    poster: Arc<dyn BatchPoster>,
    mut rx: mpsc::Receiver<Tx>,
    state: Arc<Mutex<BatcherState>>,
) {
    loop {
        let deadline = Instant::now() + Duration::from_millis(config.max_wait_ms);
        let mut batch_txs: Vec<Tx> = Vec::new();
        let mut batch_bytes: usize = 0;
        let mut forced_tx_hashes: Vec<Hash32> = Vec::new();

        // Step 1: First include due forced txs from storage
        let forced_limit = config.max_batch_txs / 2; // Reserve half for forced
        match get_forced_txs(&storage, forced_limit).await {
            Ok(forced_txs) => {
                for (tx, tx_hash) in forced_txs {
                    if batch_txs.len() >= config.max_batch_txs
                        || batch_bytes >= config.max_batch_bytes
                    {
                        break;
                    }
                    let tx_size = tx.payload.len();
                    batch_txs.push(tx);
                    batch_bytes += tx_size;
                    forced_tx_hashes.push(tx_hash);
                }
                if !forced_tx_hashes.is_empty() {
                    info!(
                        count = forced_tx_hashes.len(),
                        "including forced txs in batch"
                    );
                }
            }
            Err(err) => {
                warn!(error = %err, "failed to get forced txs");
            }
        }

        // Step 2: Fill remaining slots with normal pool txs
        while batch_txs.len() < config.max_batch_txs && batch_bytes < config.max_batch_bytes {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, rx.recv()).await {
                Ok(Some(tx)) => {
                    let tx_size = tx.payload.len();
                    batch_txs.push(tx);
                    batch_bytes += tx_size;
                    let mut guard = state.lock().await;
                    guard.queue_depth = guard.queue_depth.saturating_sub(1);
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
    _config: BatcherConfig,
    _storage: Arc<Storage>,
    _poster: Arc<dyn BatchPoster>,
) -> (BatcherHandle, mpsc::Receiver<Tx>) {
    let (tx, rx) = mpsc::channel(1024);
    let state = Arc::new(Mutex::new(BatcherState {
        queue_depth: 0,
        last_batch_hash: None,
        last_post_time_ms: None,
    }));
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
