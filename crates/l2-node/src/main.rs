#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::disallowed_types)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use l2_batcher::{
    spawn as spawn_batcher, BatcherConfig, BatcherHandle, BatcherSnapshot, BatchPoster,
    IppanBatchPoster, IppanPosterConfig, LoggingBatchPoster,
};
use l2_bridge::{
    spawn as spawn_bridge, BridgeConfig, BridgeHandle, BridgeSnapshot, LoggingWatcher,
};
use l2_core::{canonical_hash, ChainId, Hash32, Tx};
use l2_storage::{PostingStateCounts, Storage};
use ippan_rpc::IppanRpcConfig;
use prometheus::{Encoder, IntCounter, IntGauge, Opts, Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

// ============== Configuration ==============

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "IPPAN L2 node")]
pub struct Settings {
    #[arg(long, env = "L2_DB_PATH", default_value = "./data/l2")]
    pub db_path: String,
    #[arg(long, env = "L2_LISTEN_ADDR", default_value = "0.0.0.0:3000")]
    pub listen_addr: String,
    #[arg(long, env = "IPPAN_RPC_URL", default_value = "")]
    pub ippan_rpc_url: String,
    #[arg(long, env = "BATCHER_ENABLED", default_value_t = true)]
    pub batcher_enabled: bool,
    #[arg(long, env = "BRIDGE_ENABLED", default_value_t = true)]
    pub bridge_enabled: bool,
    #[arg(long, env = "L2_LEADER_MODE", default_value = "single")]
    pub leader_mode: String,
    #[arg(long, env = "L2_LEADER", default_value_t = true)]
    pub is_leader: bool,
    #[arg(long, env = "LEADER_ID", default_value = "sequencer-0")]
    pub leader_id: String,
    #[arg(long, env = "LEADER_TERM", default_value_t = 1)]
    pub leader_term: u64,
    #[arg(long, env = "L2_ADMISSION_CAP", default_value_t = 1024)]
    pub admission_cap: usize,
    #[arg(long, env = "L2_CHAIN_ID", default_value_t = 1)]
    pub chain_id: u64,
    #[arg(long, env = "L2_MAX_TX_SIZE", default_value_t = 65536)]
    pub max_tx_size: usize,
}

#[derive(Debug, Error)]
enum NodeError {
    #[error("storage error: {0}")]
    Storage(#[from] l2_storage::StorageError),
    #[error("batcher error: {0}")]
    Batcher(#[from] l2_batcher::BatcherError),
    #[error("server error: {0}")]
    Server(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ============== Metrics ==============

#[derive(Clone)]
struct Metrics {
    registry: Registry,
    uptime_ms: IntGauge,
    queue_depth: IntGauge,
    queue_capacity: IntGauge,
    tx_submitted: IntCounter,
    tx_rejected: IntCounter,
    batches_pending: IntGauge,
    batches_posted: IntGauge,
    batches_confirmed: IntGauge,
    batches_failed: IntGauge,
}

impl Metrics {
    fn new() -> Self {
        let registry = Registry::new();
        
        let uptime_ms = IntGauge::with_opts(Opts::new(
            "l2_uptime_ms",
            "Uptime of the L2 node in milliseconds",
        ))
        .expect("uptime gauge");
        
        let queue_depth = IntGauge::with_opts(Opts::new(
            "l2_batcher_queue_depth",
            "Current batcher queue depth",
        ))
        .expect("queue gauge");
        
        let queue_capacity = IntGauge::with_opts(Opts::new(
            "l2_admission_queue_capacity",
            "Maximum admission queue capacity",
        ))
        .expect("capacity gauge");
        
        let tx_submitted = IntCounter::with_opts(Opts::new(
            "l2_tx_submitted_total",
            "Total transactions submitted",
        ))
        .expect("tx submitted counter");
        
        let tx_rejected = IntCounter::with_opts(Opts::new(
            "l2_tx_rejected_total",
            "Total transactions rejected",
        ))
        .expect("tx rejected counter");
        
        let batches_pending = IntGauge::with_opts(Opts::new(
            "l2_batches_pending",
            "Number of batches pending posting",
        ))
        .expect("batches pending gauge");
        
        let batches_posted = IntGauge::with_opts(Opts::new(
            "l2_batches_posted",
            "Number of batches posted to L1",
        ))
        .expect("batches posted gauge");
        
        let batches_confirmed = IntGauge::with_opts(Opts::new(
            "l2_batches_confirmed",
            "Number of batches confirmed on L1",
        ))
        .expect("batches confirmed gauge");
        
        let batches_failed = IntGauge::with_opts(Opts::new(
            "l2_post_failures_total",
            "Number of batch posting failures",
        ))
        .expect("batches failed gauge");

        // Register all metrics
        for metric in [
            Box::new(uptime_ms.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(queue_depth.clone()),
            Box::new(queue_capacity.clone()),
            Box::new(tx_submitted.clone()),
            Box::new(tx_rejected.clone()),
            Box::new(batches_pending.clone()),
            Box::new(batches_posted.clone()),
            Box::new(batches_confirmed.clone()),
            Box::new(batches_failed.clone()),
        ] {
            registry.register(metric).expect("register metric");
        }

        Self {
            registry,
            uptime_ms,
            queue_depth,
            queue_capacity,
            tx_submitted,
            tx_rejected,
            batches_pending,
            batches_posted,
            batches_confirmed,
            batches_failed,
        }
    }
    
    fn update_posting_counts(&self, counts: &PostingStateCounts) {
        self.batches_pending.set(i64::try_from(counts.pending).unwrap_or(i64::MAX));
        self.batches_posted.set(i64::try_from(counts.posted).unwrap_or(i64::MAX));
        self.batches_confirmed.set(i64::try_from(counts.confirmed).unwrap_or(i64::MAX));
        self.batches_failed.set(i64::try_from(counts.failed).unwrap_or(i64::MAX));
    }
}

// ============== Application State ==============

#[derive(Clone)]
struct AppState {
    storage: Arc<Storage>,
    start_instant: Instant,
    settings: Settings,
    batcher: Option<BatcherHandle>,
    bridge: Option<BridgeHandle>,
    metrics: Metrics,
    queue_depth: Arc<AtomicUsize>,
}

impl AppState {
    fn queue_depth(&self) -> usize {
        self.queue_depth.load(Ordering::Relaxed)
    }
    
    fn try_enqueue(&self) -> bool {
        let current = self.queue_depth.load(Ordering::Relaxed);
        if current >= self.settings.admission_cap {
            return false;
        }
        // Try to increment atomically
        self.queue_depth
            .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
    }
    
    fn dequeue(&self) {
        self.queue_depth.fetch_sub(1, Ordering::Relaxed);
    }
}

// ============== Request/Response Types ==============

#[derive(Debug, Deserialize)]
struct SubmitTxRequest {
    /// Chain ID (must match node configuration).
    chain_id: u64,
    /// Sender address/identifier.
    from: String,
    /// Transaction nonce.
    nonce: u64,
    /// Transaction payload (hex encoded).
    payload: String,
}

#[derive(Debug, Serialize)]
struct SubmitTxResponse {
    tx_hash: String,
    accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct TxQueryResponse {
    tx_hash: String,
    chain_id: u64,
    from: String,
    nonce: u64,
    payload_size: usize,
}

#[derive(Debug, Serialize)]
struct BatchQueryResponse {
    batch_hash: String,
    chain_id: u64,
    batch_number: u64,
    tx_count: usize,
    created_ms: u64,
}

// ============== Status Response Types ==============

#[derive(Serialize)]
struct StatusResponse {
    service: ServiceInfo,
    uptime_ms: u64,
    leader: LeaderInfo,
    queue: QueueInfo,
    batcher: BatcherInfo,
    bridge: BridgeInfo,
    posting: PostingInfo,
}

#[derive(Serialize)]
struct ServiceInfo {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct LeaderInfo {
    mode: String,
    is_leader: bool,
    leader_pubkey: String,
    term_id: u64,
    last_heartbeat_ms: u64,
}

#[derive(Serialize)]
struct QueueInfo {
    depth: usize,
    capacity: usize,
}

#[derive(Serialize)]
struct BatcherInfo {
    enabled: bool,
    last_batch_hash: Option<String>,
    last_post_time: Option<u64>,
}

#[derive(Serialize)]
struct BridgeInfo {
    enabled: bool,
    last_event_time: Option<u64>,
}

#[derive(Serialize)]
struct PostingInfo {
    pending: u64,
    posted: u64,
    confirmed: u64,
    failed: u64,
}

// ============== Main Entry Point ==============

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        error!(error = %err, "node terminated with error");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), NodeError> {
    let settings = Settings::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    info!(?settings, "starting l2-node");
    let storage = Arc::new(Storage::open(&settings.db_path)?);

    let metrics = Metrics::new();
    let queue_depth = Arc::new(AtomicUsize::new(0));
    
    // Set queue capacity metric
    metrics.queue_capacity.set(i64::try_from(settings.admission_cap).unwrap_or(i64::MAX));
    
    let mut batcher_handle = None;
    let mut bridge_handle = None;

    if settings.batcher_enabled && settings.is_leader {
        let config = BatcherConfig {
            max_batch_txs: 256,
            max_batch_bytes: 512 * 1024,
            max_wait_ms: 1_000,
            chain_id: ChainId(settings.chain_id),
        };
        
        // Create poster based on IPPAN_RPC_URL
        let poster: Arc<dyn BatchPoster> = if !settings.ippan_rpc_url.is_empty() {
            info!(url = %settings.ippan_rpc_url, "using IPPAN RPC poster");
            let rpc_config = IppanRpcConfig {
                base_url: settings.ippan_rpc_url.clone(),
                timeout_ms: IppanRpcConfig::DEFAULT_TIMEOUT_MS,
                retry_max: IppanRpcConfig::DEFAULT_RETRY_MAX,
            };
            let poster_config = IppanPosterConfig::from_env();
            match IppanBatchPoster::new(rpc_config, Arc::clone(&storage), poster_config) {
                Ok(poster) => Arc::new(poster),
                Err(err) => {
                    warn!(error = %err, "failed to create IPPAN poster, using logging poster");
                    Arc::new(LoggingBatchPoster {})
                }
            }
        } else {
            info!("using logging batch poster (IPPAN_RPC_URL not set)");
            Arc::new(LoggingBatchPoster {})
        };
        
        let handle = spawn_batcher(config, Arc::clone(&storage), poster);
        batcher_handle = Some(handle);
    }

    if settings.bridge_enabled {
        let config = BridgeConfig::default();
        let handle = spawn_bridge(config, Arc::clone(&storage), Arc::new(LoggingWatcher {}));
        bridge_handle = Some(handle);
    }

    let state = AppState {
        storage,
        start_instant: Instant::now(),
        settings: settings.clone(),
        batcher: batcher_handle,
        bridge: bridge_handle,
        metrics,
        queue_depth,
    };

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/status", get(status))
        .route("/metrics", get(metrics_handler))
        // Transaction endpoints
        .route("/tx", post(submit_tx))
        .route("/tx/{hash}", get(get_tx))
        // Batch endpoints
        .route("/batch/{hash}", get(get_batch))
        .with_state(state.clone());

    let addr: SocketAddr = settings
        .listen_addr
        .parse()
        .expect("invalid listen addr");
    info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| NodeError::Server(e.to_string()))?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

// ============== Health/Status Endpoints ==============

async fn health() -> impl IntoResponse {
    "ok"
}

async fn ready(state: axum::extract::State<AppState>) -> impl IntoResponse {
    match state.storage.get_meta("schema_version") {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn status(state: axum::extract::State<AppState>) -> impl IntoResponse {
    let uptime_millis = state.start_instant.elapsed().as_millis();
    let uptime_ms = u64::try_from(uptime_millis).unwrap_or(u64::MAX);
    
    let batcher_snapshot: BatcherSnapshot = if let Some(handle) = &state.batcher {
        handle.snapshot().await
    } else {
        BatcherSnapshot::default()
    };
    
    let bridge_snapshot: BridgeSnapshot = if let Some(handle) = &state.bridge {
        handle.snapshot().await
    } else {
        BridgeSnapshot::default()
    };
    
    // Get posting state counts
    let posting_counts = state.storage.count_posting_states().unwrap_or_default();

    let response = StatusResponse {
        service: ServiceInfo {
            name: "ippan-l2-node",
            version: env!("CARGO_PKG_VERSION"),
        },
        uptime_ms,
        leader: LeaderInfo {
            mode: state.settings.leader_mode.clone(),
            is_leader: state.settings.is_leader,
            leader_pubkey: state.settings.leader_id.clone(), // TODO: actual pubkey
            term_id: state.settings.leader_term,
            last_heartbeat_ms: uptime_ms, // For single-leader, heartbeat is now
        },
        queue: QueueInfo {
            depth: state.queue_depth(),
            capacity: state.settings.admission_cap,
        },
        batcher: BatcherInfo {
            enabled: state.batcher.is_some(),
            last_batch_hash: batcher_snapshot.last_batch_hash,
            last_post_time: batcher_snapshot.last_post_time_ms,
        },
        bridge: BridgeInfo {
            enabled: state.bridge.is_some(),
            last_event_time: bridge_snapshot.last_event_time_ms,
        },
        posting: PostingInfo {
            pending: posting_counts.pending,
            posted: posting_counts.posted,
            confirmed: posting_counts.confirmed,
            failed: posting_counts.failed,
        },
    };

    Json(response)
}

async fn metrics_handler(state: axum::extract::State<AppState>) -> impl IntoResponse {
    let uptime_millis = state.start_instant.elapsed().as_millis();
    let uptime_ms = i64::try_from(uptime_millis).unwrap_or(i64::MAX);
    let queue_depth = if let Some(handle) = &state.batcher {
        let depth = handle.snapshot().await.queue_depth;
        i64::try_from(depth).unwrap_or(i64::MAX)
    } else {
        0
    };
    
    state.metrics.uptime_ms.set(uptime_ms);
    state.metrics.queue_depth.set(queue_depth);
    
    // Update posting counts
    if let Ok(counts) = state.storage.count_posting_states() {
        state.metrics.update_posting_counts(&counts);
    }

    let encoder = TextEncoder::new();
    let metric_families = state.metrics.registry.gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .expect("encode metrics");
    (StatusCode::OK, buffer)
}

// ============== Transaction Endpoints ==============

async fn submit_tx(
    state: axum::extract::State<AppState>,
    Json(req): Json<SubmitTxRequest>,
) -> impl IntoResponse {
    // Check if leader (only leader accepts writes)
    if !state.settings.is_leader {
        return (
            StatusCode::FORBIDDEN,
            Json(SubmitTxResponse {
                tx_hash: String::new(),
                accepted: false,
                error: Some("not leader - reads only".to_string()),
            }),
        );
    }
    
    // Check if batcher is enabled
    let batcher = match &state.batcher {
        Some(b) => b,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(SubmitTxResponse {
                    tx_hash: String::new(),
                    accepted: false,
                    error: Some("batcher not enabled".to_string()),
                }),
            );
        }
    };
    
    // Validate chain_id
    if req.chain_id != state.settings.chain_id {
        state.metrics.tx_rejected.inc();
        return (
            StatusCode::BAD_REQUEST,
            Json(SubmitTxResponse {
                tx_hash: String::new(),
                accepted: false,
                error: Some(format!(
                    "chain_id mismatch: expected {}, got {}",
                    state.settings.chain_id, req.chain_id
                )),
            }),
        );
    }
    
    // Decode payload
    let payload = match hex::decode(&req.payload) {
        Ok(p) => p,
        Err(e) => {
            state.metrics.tx_rejected.inc();
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitTxResponse {
                    tx_hash: String::new(),
                    accepted: false,
                    error: Some(format!("invalid payload hex: {e}")),
                }),
            );
        }
    };
    
    // Check payload size
    if payload.len() > state.settings.max_tx_size {
        state.metrics.tx_rejected.inc();
        return (
            StatusCode::BAD_REQUEST,
            Json(SubmitTxResponse {
                tx_hash: String::new(),
                accepted: false,
                error: Some(format!(
                    "payload too large: {} > {}",
                    payload.len(),
                    state.settings.max_tx_size
                )),
            }),
        );
    }
    
    // Check admission queue capacity (429 backpressure)
    if !state.try_enqueue() {
        state.metrics.tx_rejected.inc();
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(SubmitTxResponse {
                tx_hash: String::new(),
                accepted: false,
                error: Some("queue full".to_string()),
            }),
        );
    }
    
    // Create transaction
    let tx = Tx {
        chain_id: ChainId(req.chain_id),
        nonce: req.nonce,
        from: req.from,
        payload,
    };
    
    // Compute hash
    let tx_hash = match canonical_hash(&tx) {
        Ok(h) => h,
        Err(e) => {
            state.dequeue();
            state.metrics.tx_rejected.inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SubmitTxResponse {
                    tx_hash: String::new(),
                    accepted: false,
                    error: Some(format!("hash error: {e}")),
                }),
            );
        }
    };
    
    // Store transaction
    if let Err(e) = state.storage.put_tx(&tx) {
        state.dequeue();
        state.metrics.tx_rejected.inc();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SubmitTxResponse {
                tx_hash: String::new(),
                accepted: false,
                error: Some(format!("storage error: {e}")),
            }),
        );
    }
    
    // Submit to batcher
    if let Err(e) = batcher.submit_tx(tx).await {
        state.dequeue();
        state.metrics.tx_rejected.inc();
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SubmitTxResponse {
                tx_hash: tx_hash.to_hex(),
                accepted: false,
                error: Some(format!("batcher error: {e}")),
            }),
        );
    }
    
    // Success - queue depth will be decremented by batcher
    state.metrics.tx_submitted.inc();
    
    (
        StatusCode::OK,
        Json(SubmitTxResponse {
            tx_hash: tx_hash.to_hex(),
            accepted: true,
            error: None,
        }),
    )
}

async fn get_tx(
    state: axum::extract::State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    // Parse hash
    let tx_hash = match Hash32::from_hex(&hash) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("invalid hash: {e}")
                })),
            );
        }
    };
    
    // Look up transaction
    match state.storage.get_tx(&tx_hash) {
        Ok(Some(tx)) => {
            let response = TxQueryResponse {
                tx_hash: tx_hash.to_hex(),
                chain_id: tx.chain_id.0,
                from: tx.from,
                nonce: tx.nonce,
                payload_size: tx.payload.len(),
            };
            (StatusCode::OK, Json(serde_json::to_value(response).unwrap()))
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "transaction not found"
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("storage error: {e}")
            })),
        ),
    }
}

// ============== Batch Endpoints ==============

async fn get_batch(
    state: axum::extract::State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    // Parse hash
    let batch_hash = match Hash32::from_hex(&hash) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("invalid hash: {e}")
                })),
            );
        }
    };
    
    // Look up batch
    match state.storage.get_batch(&batch_hash) {
        Ok(Some(batch)) => {
            let response = BatchQueryResponse {
                batch_hash: batch_hash.to_hex(),
                chain_id: batch.chain_id.0,
                batch_number: batch.batch_number,
                tx_count: batch.txs.len(),
                created_ms: batch.created_ms,
            };
            (StatusCode::OK, Json(serde_json::to_value(response).unwrap()))
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "batch not found"
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("storage error: {e}")
            })),
        ),
    }
}
