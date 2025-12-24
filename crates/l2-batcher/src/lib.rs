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
use l2_core::{Batch, ChainId, Hash32, Tx};
use l2_storage::Storage;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Instant};
use tracing::{debug, info, warn};

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

#[derive(Debug, Clone, Default)]
pub struct BatcherSnapshot {
    pub queue_depth: usize,
    pub last_batch_hash: Option<String>,
    pub last_post_time_ms: Option<u64>,
}

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

        while batch_txs.len() < config.max_batch_txs && batch_bytes < config.max_batch_bytes {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, rx.recv()).await {
                Ok(Some(tx)) => {
                    batch_bytes += tx.payload.len();
                    batch_txs.push(tx);
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
                batch_bytes += tx.payload.len();
                batch_txs.push(tx);
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
                if let Err(err) = poster.post_batch(&batch, &hash).await {
                    warn!(error = %err, "poster failed for batch");
                }
                let mut guard = state.lock().await;
                guard.last_batch_hash = Some(hash);
                guard.last_post_time_ms = Some(batch.created_ms);
                debug!(batch_number, hash = %hash.to_hex(), "stored batch");
            }
            Err(err) => warn!(error = %err, "failed to persist batch"),
        }
    }
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

pub fn build_handle_for_tests(
    config: BatcherConfig,
    storage: Arc<Storage>,
    poster: Arc<dyn BatchPoster>,
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
}
