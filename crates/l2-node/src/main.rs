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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use ippan_rpc::IppanRpcConfig;
use l2_batcher::{
    spawn as spawn_batcher, spawn_reconciler, BatchPoster, BatcherConfig, BatcherHandle,
    BatcherSnapshot, IppanBatchPoster, IppanPosterConfig, LoggingBatchPoster, ReconcilerConfig,
    ReconcilerHandle,
};
use l2_bridge::{
    spawn as spawn_bridge, BridgeConfig, BridgeHandle, BridgeSnapshot, DepositClaimRequest,
    DepositClaimResponse, DepositEvent, DepositStatus, LoggingWatcher, WithdrawRequest,
    WithdrawStatus,
};
use l2_core::forced_inclusion::{
    ForceIncludeRequest, ForceIncludeResponse, ForceIncludeStatus, ForcedInclusionConfig,
    InclusionTicket,
};
use l2_core::{canonical_hash, ChainId, Hash32, Tx};
use l2_leader::{LeaderConfig, LeaderSet, LeaderState, PubKey};
use l2_storage::{PostingStateCounts, Storage};
use prometheus::{Encoder, IntCounter, IntGauge, Opts, Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
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
    /// Leader mode: "single" (legacy) or "rotating"
    #[arg(long, env = "L2_LEADER_MODE", default_value = "single")]
    pub leader_mode: String,
    /// For "single" mode: whether this node is the leader
    #[arg(long, env = "L2_LEADER", default_value_t = true)]
    pub is_leader: bool,
    #[arg(long, env = "LEADER_ID", default_value = "sequencer-0")]
    pub leader_id: String,
    #[arg(long, env = "LEADER_TERM", default_value_t = 0)]
    pub leader_term: u64,
    #[arg(long, env = "L2_SEQUENCER_KEY_PATH", default_value = "")]
    pub sequencer_key_path: String,
    #[arg(long, env = "L2_ADMISSION_CAP", default_value_t = 1024)]
    pub admission_cap: usize,
    #[arg(long, env = "L2_CHAIN_ID", default_value_t = 1)]
    pub chain_id: u64,
    #[arg(long, env = "L2_MAX_TX_SIZE", default_value_t = 65536)]
    pub max_tx_size: usize,
    // Leader rotation config (used when leader_mode = "rotating")
    /// Comma-separated hex-encoded ed25519 pubkeys for leader set
    #[arg(long, env = "L2_LEADER_SET", default_value = "")]
    pub leader_set: String,
    /// Epoch duration in milliseconds
    #[arg(long, env = "L2_EPOCH_MS", default_value_t = 10_000)]
    pub epoch_ms: u64,
    /// Genesis timestamp in milliseconds (all nodes must agree)
    #[arg(long, env = "L2_GENESIS_MS", default_value_t = 0)]
    pub genesis_ms: u64,
    /// This node's public key (hex)
    #[arg(long, env = "L2_NODE_PUBKEY", default_value = "")]
    pub node_pubkey: String,
    // Forwarding config
    /// Forward txs to leader when not leader (0 or 1)
    #[arg(long, env = "L2_FORWARD_TO_LEADER", default_value_t = false)]
    pub forward_to_leader: bool,
    /// Fallback behavior when forwarding fails: "accept" or "reject"
    #[arg(long, env = "L2_FORWARD_FALLBACK", default_value = "accept")]
    pub forward_fallback: String,
    /// Leader endpoints mapping: "pubkey1=http://host1:port,pubkey2=http://host2:port"
    #[arg(long, env = "L2_LEADER_ENDPOINTS", default_value = "")]
    pub leader_endpoints: String,
}

impl Settings {
    /// Parse leader config from settings.
    fn to_leader_config(&self) -> Result<LeaderConfig, NodeError> {
        let leader_set = LeaderSet::from_csv(&self.leader_set)
            .map_err(|e| NodeError::Config(format!("invalid leader set: {e}")))?;

        let node_pubkey = if self.node_pubkey.is_empty() {
            PubKey::new([0u8; 32])
        } else {
            PubKey::from_hex(&self.node_pubkey)
                .map_err(|e| NodeError::Config(format!("invalid node pubkey: {e}")))?
        };

        Ok(LeaderConfig {
            leader_set,
            epoch_ms: self.epoch_ms,
            genesis_ms: self.genesis_ms,
            node_pubkey,
        })
    }

    /// Parse leader endpoints mapping.
    fn parse_leader_endpoints(&self) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        if self.leader_endpoints.is_empty() {
            return map;
        }
        for pair in self.leader_endpoints.split(',') {
            if let Some((pubkey, url)) = pair.split_once('=') {
                map.insert(pubkey.trim().to_string(), url.trim().to_string());
            }
        }
        map
    }
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
    #[error("config error: {0}")]
    Config(String),
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
    tx_forwarded: IntCounter,
    batches_pending: IntGauge,
    batches_posted: IntGauge,
    batches_confirmed: IntGauge,
    batches_failed: IntGauge,
    leader_is_leader: IntGauge,
    leader_epoch_idx: IntGauge,
    // Forced inclusion metrics
    forced_queue_depth: IntGauge,
    #[allow(dead_code)] // Will be used when forced inclusion is fully wired
    forced_included_total: IntCounter,
    // Bridge metrics
    #[allow(dead_code)] // Will be used when bridge verification is complete
    bridge_deposits_total: IntCounter,
    #[allow(dead_code)] // Will be used when bridge posting is complete
    bridge_withdrawals_total: IntCounter,
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

        let tx_forwarded = IntCounter::with_opts(Opts::new(
            "l2_tx_forwarded_total",
            "Total transactions forwarded to leader",
        ))
        .expect("tx forwarded counter");

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

        let leader_is_leader = IntGauge::with_opts(Opts::new(
            "l2_leader_is_leader",
            "1 if this node is currently the leader, 0 otherwise",
        ))
        .expect("leader is_leader gauge");

        let leader_epoch_idx = IntGauge::with_opts(Opts::new(
            "l2_epoch_idx",
            "Current epoch index",
        ))
        .expect("epoch idx gauge");

        let forced_queue_depth = IntGauge::with_opts(Opts::new(
            "l2_forced_queue_depth",
            "Number of forced inclusion tickets queued",
        ))
        .expect("forced queue depth gauge");

        let forced_included_total = IntCounter::with_opts(Opts::new(
            "l2_forced_included_total",
            "Total forced inclusion tickets included",
        ))
        .expect("forced included counter");

        let bridge_deposits_total = IntCounter::with_opts(Opts::new(
            "l2_bridge_deposits_total",
            "Total bridge deposits processed",
        ))
        .expect("bridge deposits counter");

        let bridge_withdrawals_total = IntCounter::with_opts(Opts::new(
            "l2_bridge_withdrawals_total",
            "Total bridge withdrawals requested",
        ))
        .expect("bridge withdrawals counter");

        // Register all metrics
        for metric in [
            Box::new(uptime_ms.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(queue_depth.clone()),
            Box::new(queue_capacity.clone()),
            Box::new(tx_submitted.clone()),
            Box::new(tx_rejected.clone()),
            Box::new(tx_forwarded.clone()),
            Box::new(batches_pending.clone()),
            Box::new(batches_posted.clone()),
            Box::new(batches_confirmed.clone()),
            Box::new(batches_failed.clone()),
            Box::new(leader_is_leader.clone()),
            Box::new(leader_epoch_idx.clone()),
            Box::new(forced_queue_depth.clone()),
            Box::new(forced_included_total.clone()),
            Box::new(bridge_deposits_total.clone()),
            Box::new(bridge_withdrawals_total.clone()),
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
            tx_forwarded,
            batches_pending,
            batches_posted,
            batches_confirmed,
            batches_failed,
            leader_is_leader,
            leader_epoch_idx,
            forced_queue_depth,
            forced_included_total,
            bridge_deposits_total,
            bridge_withdrawals_total,
        }
    }

    fn update_posting_counts(&self, counts: &PostingStateCounts) {
        self.batches_pending
            .set(i64::try_from(counts.pending).unwrap_or(i64::MAX));
        self.batches_posted
            .set(i64::try_from(counts.posted).unwrap_or(i64::MAX));
        self.batches_confirmed
            .set(i64::try_from(counts.confirmed).unwrap_or(i64::MAX));
        self.batches_failed
            .set(i64::try_from(counts.failed).unwrap_or(i64::MAX));
    }

    fn update_leader_state(&self, state: &LeaderState) {
        self.leader_is_leader.set(if state.is_leader { 1 } else { 0 });
        self.leader_epoch_idx
            .set(i64::try_from(state.epoch_idx).unwrap_or(i64::MAX));
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
    #[allow(dead_code)] // Held to keep background task alive
    reconciler: Option<ReconcilerHandle>,
    metrics: Metrics,
    queue_depth: Arc<AtomicUsize>,
    // Leader rotation state
    leader_config: Option<LeaderConfig>,
    leader_state: Arc<RwLock<LeaderState>>,
    leader_endpoints: std::collections::HashMap<String, String>,
    http_client: reqwest::Client,
    // Forced inclusion config
    forced_config: ForcedInclusionConfig,
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

    /// Check if this node is currently the leader.
    async fn is_current_leader(&self) -> bool {
        match &self.settings.leader_mode.as_str() {
            &"rotating" => {
                let state = self.leader_state.read().await;
                state.is_leader
            }
            _ => self.settings.is_leader, // "single" mode
        }
    }

    /// Get current leader state snapshot.
    async fn get_leader_state(&self) -> LeaderState {
        self.leader_state.read().await.clone()
    }

    /// Update leader state to current time.
    async fn update_leader_state(&self) {
        if let Some(config) = &self.leader_config {
            let now_ms = now_ms();
            let mut state = self.leader_state.write().await;
            state.update(config, now_ms);
        }
    }

    /// Get the URL for the current leader (for forwarding).
    async fn get_leader_url(&self) -> Option<String> {
        let state = self.leader_state.read().await;
        if let Some(leader_pk) = &state.elected_leader {
            let pk_hex = leader_pk.to_hex();
            self.leader_endpoints.get(&pk_hex).cloned()
        } else {
            None
        }
    }
}

// ============== Request/Response Types ==============

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
struct SubmitTxResponse {
    tx_hash: String,
    accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    forwarded: Option<bool>,
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
    bridge: BridgeStatusInfo,
    posting: PostingInfo,
    forced_inclusion: ForcedInclusionInfo,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    elected_leader_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epoch_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epoch_idx: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epoch_start_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epoch_end_ms: Option<u64>,
    // Legacy fields for single mode
    #[serde(skip_serializing_if = "Option::is_none")]
    leader_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    term_id: Option<u64>,
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
struct BridgeStatusInfo {
    enabled: bool,
    last_event_time: Option<u64>,
    deposits_total: u64,
    withdrawals_total: u64,
}

#[derive(Serialize)]
struct PostingInfo {
    pending: u64,
    posted: u64,
    confirmed: u64,
    failed: u64,
}

#[derive(Serialize)]
struct ForcedInclusionInfo {
    enabled: bool,
    queue_depth: u64,
    max_epochs: u64,
    max_per_account_per_epoch: u64,
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
    metrics
        .queue_capacity
        .set(i64::try_from(settings.admission_cap).unwrap_or(i64::MAX));

    // Parse leader config for rotating mode
    let leader_config = if settings.leader_mode == "rotating" {
        let config = settings.to_leader_config()?;
        info!(
            leader_count = config.leader_set.len(),
            epoch_ms = config.epoch_ms,
            genesis_ms = config.genesis_ms,
            node_pubkey = %config.node_pubkey,
            "rotating leader mode enabled"
        );
        Some(config)
    } else {
        None
    };

    // Initialize leader state
    let initial_state = if let Some(config) = &leader_config {
        LeaderState::from_config(config, now_ms())
    } else {
        LeaderState {
            epoch_idx: 0,
            elected_leader: None,
            is_leader: settings.is_leader,
            epoch_start_ms: 0,
            epoch_end_ms: u64::MAX,
        }
    };
    let leader_state = Arc::new(RwLock::new(initial_state));

    // Parse leader endpoints for forwarding
    let leader_endpoints = settings.parse_leader_endpoints();
    if !leader_endpoints.is_empty() {
        info!(
            endpoints = ?leader_endpoints.keys().collect::<Vec<_>>(),
            "leader endpoints configured for forwarding"
        );
    }

    // HTTP client for forwarding
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| NodeError::Config(format!("failed to build http client: {e}")))?;

    let mut batcher_handle = None;
    let mut bridge_handle = None;
    let mut reconciler_handle = None;

    // Create RPC client for use by poster and reconciler
    let rpc_client = if !settings.ippan_rpc_url.is_empty() {
        let rpc_config = IppanRpcConfig {
            base_url: settings.ippan_rpc_url.clone(),
            timeout_ms: IppanRpcConfig::DEFAULT_TIMEOUT_MS,
            retry_max: IppanRpcConfig::DEFAULT_RETRY_MAX,
        };
        ippan_rpc::IppanRpcClient::new(rpc_config).ok()
    } else {
        None
    };

    // Determine if we should start batcher (leader-only in single mode, always in rotating mode)
    let should_start_batcher = settings.batcher_enabled
        && (settings.leader_mode == "rotating" || settings.is_leader);

    if should_start_batcher {
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

        // Spawn reconciler (leader-only in production)
        let reconciler_config = ReconcilerConfig::from_env();
        info!(
            interval_ms = reconciler_config.interval_ms,
            batch_limit = reconciler_config.batch_limit,
            "starting reconciler"
        );
        reconciler_handle = Some(spawn_reconciler(
            reconciler_config,
            Arc::clone(&storage),
            rpc_client.clone(),
        ));
    }

    if settings.bridge_enabled {
        let config = BridgeConfig::default();
        let handle = spawn_bridge(config, Arc::clone(&storage), Arc::new(LoggingWatcher {}));
        bridge_handle = Some(handle);
    }

    // Load forced inclusion config
    let forced_config = ForcedInclusionConfig::from_env();
    info!(
        max_epochs = forced_config.max_epochs,
        max_per_account = forced_config.max_per_account_per_epoch,
        l1_commitments = forced_config.post_l1_commitments,
        "forced inclusion config"
    );

    let state = AppState {
        storage,
        start_instant: Instant::now(),
        settings: settings.clone(),
        batcher: batcher_handle,
        bridge: bridge_handle,
        reconciler: reconciler_handle,
        metrics: metrics.clone(),
        queue_depth,
        leader_config,
        leader_state: Arc::clone(&leader_state),
        leader_endpoints,
        http_client,
        forced_config,
    };

    // Spawn background task for leader state updates (rotating mode)
    if settings.leader_mode == "rotating" {
        let update_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                update_state.update_leader_state().await;
                let ls = update_state.get_leader_state().await;
                update_state.metrics.update_leader_state(&ls);
            }
        });
    }

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/status", get(status))
        .route("/metrics", get(metrics_handler))
        // Transaction endpoints
        .route("/tx", post(submit_tx))
        .route("/tx/{hash}", get(get_tx))
        // Forced inclusion endpoints
        .route("/tx/force", post(force_include_tx))
        .route("/tx/force/{hash}", get(get_force_status))
        // Bridge endpoints
        .route("/bridge/deposit/claim", post(claim_deposit))
        .route("/bridge/deposit/{id}", get(get_deposit))
        .route("/bridge/withdraw", post(request_withdraw))
        .route("/bridge/withdraw/{id}", get(get_withdraw))
        // Batch endpoints
        .route("/batch/{hash}", get(get_batch))
        .with_state(state.clone());

    let addr: SocketAddr = settings.listen_addr.parse().expect("invalid listen addr");
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

    // Build leader info based on mode
    let leader_info = if state.settings.leader_mode == "rotating" {
        let leader_state = state.get_leader_state().await;
        LeaderInfo {
            mode: "rotating".to_string(),
            is_leader: leader_state.is_leader,
            elected_leader_pubkey: leader_state.elected_leader.map(|pk| pk.to_hex()),
            epoch_ms: state.leader_config.as_ref().map(|c| c.epoch_ms),
            epoch_idx: Some(leader_state.epoch_idx),
            epoch_start_ms: Some(leader_state.epoch_start_ms),
            epoch_end_ms: Some(leader_state.epoch_end_ms),
            leader_pubkey: None,
            term_id: None,
            last_heartbeat_ms: uptime_ms,
        }
    } else {
        LeaderInfo {
            mode: state.settings.leader_mode.clone(),
            is_leader: state.settings.is_leader,
            elected_leader_pubkey: None,
            epoch_ms: None,
            epoch_idx: None,
            epoch_start_ms: None,
            epoch_end_ms: None,
            leader_pubkey: Some(state.settings.leader_id.clone()),
            term_id: Some(state.settings.leader_term),
            last_heartbeat_ms: uptime_ms,
        }
    };

    // Get bridge counts
    let deposits_total = state.storage.count_deposits().unwrap_or(0);
    let withdrawals_total = state.storage.count_withdrawals().unwrap_or(0);

    // Get forced queue counts
    let forced_counts = state.storage.count_forced_queue().unwrap_or_default();

    let response = StatusResponse {
        service: ServiceInfo {
            name: "ippan-l2-node",
            version: env!("CARGO_PKG_VERSION"),
        },
        uptime_ms,
        leader: leader_info,
        queue: QueueInfo {
            depth: state.queue_depth(),
            capacity: state.settings.admission_cap,
        },
        batcher: BatcherInfo {
            enabled: state.batcher.is_some(),
            last_batch_hash: batcher_snapshot.last_batch_hash,
            last_post_time: batcher_snapshot.last_post_time_ms,
        },
        bridge: BridgeStatusInfo {
            enabled: state.bridge.is_some(),
            last_event_time: bridge_snapshot.last_event_time_ms,
            deposits_total,
            withdrawals_total,
        },
        posting: PostingInfo {
            pending: posting_counts.pending,
            posted: posting_counts.posted,
            confirmed: posting_counts.confirmed,
            failed: posting_counts.failed,
        },
        forced_inclusion: ForcedInclusionInfo {
            enabled: true,
            queue_depth: forced_counts.queued,
            max_epochs: state.forced_config.max_epochs,
            max_per_account_per_epoch: state.forced_config.max_per_account_per_epoch,
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

    // Update leader state metrics
    let leader_state = state.get_leader_state().await;
    state.metrics.update_leader_state(&leader_state);

    // Update forced queue metrics
    if let Ok(forced_counts) = state.storage.count_forced_queue() {
        state
            .metrics
            .forced_queue_depth
            .set(i64::try_from(forced_counts.queued).unwrap_or(i64::MAX));
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
    let is_leader = state.is_current_leader().await;

    // If not leader, handle forwarding or rejection
    if !is_leader {
        if state.settings.forward_to_leader {
            return forward_tx_to_leader(&state, &req).await;
        }
        return (
            StatusCode::FORBIDDEN,
            Json(SubmitTxResponse {
                tx_hash: String::new(),
                accepted: false,
                error: Some("not leader - reads only".to_string()),
                forwarded: None,
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
                    forwarded: None,
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
                forwarded: None,
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
                    forwarded: None,
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
                forwarded: None,
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
                forwarded: None,
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
                    forwarded: None,
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
                forwarded: None,
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
                forwarded: None,
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
            forwarded: None,
        }),
    )
}

/// Forward a transaction to the current leader.
async fn forward_tx_to_leader(
    state: &AppState,
    req: &SubmitTxRequest,
) -> (StatusCode, Json<SubmitTxResponse>) {
    let leader_url = match state.get_leader_url().await {
        Some(url) => url,
        None => {
            debug!("no leader URL configured for forwarding");
            // Fallback behavior
            if state.settings.forward_fallback == "accept" {
                // Accept locally (will be stored but not batched until we become leader)
                return accept_tx_locally(state, req).await;
            }
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(SubmitTxResponse {
                    tx_hash: String::new(),
                    accepted: false,
                    error: Some("no leader URL for forwarding".to_string()),
                    forwarded: None,
                }),
            );
        }
    };

    let forward_url = format!("{}/tx", leader_url.trim_end_matches('/'));
    debug!(url = %forward_url, "forwarding tx to leader");

    // Create signed forward headers (simplified for MVP - just include node pubkey)
    let node_pubkey = state.leader_config.as_ref().map(|c| c.node_pubkey.to_hex()).unwrap_or_default();
    let timestamp = now_ms();

    let result = state
        .http_client
        .post(&forward_url)
        .header("x-l2-forwarder-pubkey", &node_pubkey)
        .header("x-l2-forwarder-ts", timestamp.to_string())
        .json(req)
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.json::<SubmitTxResponse>().await {
                    Ok(mut forward_resp) => {
                        state.metrics.tx_forwarded.inc();
                        forward_resp.forwarded = Some(true);
                        (StatusCode::OK, Json(forward_resp))
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to parse forwarded response");
                        handle_forward_failure(state, req).await
                    }
                }
            } else {
                warn!(status = %status, "leader returned error on forward");
                handle_forward_failure(state, req).await
            }
        }
        Err(e) => {
            warn!(error = %e, url = %forward_url, "failed to forward tx to leader");
            handle_forward_failure(state, req).await
        }
    }
}

/// Handle forwarding failure based on fallback config.
async fn handle_forward_failure(
    state: &AppState,
    req: &SubmitTxRequest,
) -> (StatusCode, Json<SubmitTxResponse>) {
    if state.settings.forward_fallback == "accept" {
        accept_tx_locally(state, req).await
    } else {
        state.metrics.tx_rejected.inc();
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SubmitTxResponse {
                tx_hash: String::new(),
                accepted: false,
                error: Some("forwarding failed and fallback is reject".to_string()),
                forwarded: Some(false),
            }),
        )
    }
}

/// Accept a transaction locally (store in pool but don't batch).
async fn accept_tx_locally(
    state: &AppState,
    req: &SubmitTxRequest,
) -> (StatusCode, Json<SubmitTxResponse>) {
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
                forwarded: None,
            }),
        );
    }

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
                    forwarded: None,
                }),
            );
        }
    };

    let tx = Tx {
        chain_id: ChainId(req.chain_id),
        nonce: req.nonce,
        from: req.from.clone(),
        payload,
    };

    let tx_hash = match canonical_hash(&tx) {
        Ok(h) => h,
        Err(e) => {
            state.metrics.tx_rejected.inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SubmitTxResponse {
                    tx_hash: String::new(),
                    accepted: false,
                    error: Some(format!("hash error: {e}")),
                    forwarded: None,
                }),
            );
        }
    };

    if let Err(e) = state.storage.put_tx(&tx) {
        state.metrics.tx_rejected.inc();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SubmitTxResponse {
                tx_hash: String::new(),
                accepted: false,
                error: Some(format!("storage error: {e}")),
                forwarded: None,
            }),
        );
    }

    state.metrics.tx_submitted.inc();
    info!(tx_hash = %tx_hash.to_hex(), "accepted tx locally (not leader)");

    (
        StatusCode::OK,
        Json(SubmitTxResponse {
            tx_hash: tx_hash.to_hex(),
            accepted: true,
            error: None,
            forwarded: Some(false),
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
            (
                StatusCode::OK,
                Json(serde_json::to_value(response).unwrap()),
            )
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

// ============== Forced Inclusion Endpoints ==============

async fn force_include_tx(
    state: axum::extract::State<AppState>,
    Json(req): Json<ForceIncludeRequest>,
) -> impl IntoResponse {
    // Validate chain_id
    if req.chain_id != state.settings.chain_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(ForceIncludeResponse {
                accepted: false,
                tx_hash: String::new(),
                ticket: None,
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
            return (
                StatusCode::BAD_REQUEST,
                Json(ForceIncludeResponse {
                    accepted: false,
                    tx_hash: String::new(),
                    ticket: None,
                    error: Some(format!("invalid payload hex: {e}")),
                }),
            );
        }
    };

    // Check payload size
    if payload.len() > state.settings.max_tx_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(ForceIncludeResponse {
                accepted: false,
                tx_hash: String::new(),
                ticket: None,
                error: Some(format!(
                    "payload too large: {} > {}",
                    payload.len(),
                    state.settings.max_tx_size
                )),
            }),
        );
    }

    // Create transaction
    let tx = Tx {
        chain_id: ChainId(req.chain_id),
        nonce: req.nonce,
        from: req.from.clone(),
        payload,
    };

    // Compute hash
    let tx_hash = match canonical_hash(&tx) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ForceIncludeResponse {
                    accepted: false,
                    tx_hash: String::new(),
                    ticket: None,
                    error: Some(format!("hash error: {e}")),
                }),
            );
        }
    };

    // Check if tx already has a forced ticket
    if let Ok(Some(existing)) = state.storage.get_forced_ticket(&tx_hash) {
        return (
            StatusCode::CONFLICT,
            Json(ForceIncludeResponse {
                accepted: false,
                tx_hash: tx_hash.to_hex(),
                ticket: Some(existing),
                error: Some("tx already has a forced inclusion ticket".to_string()),
            }),
        );
    }

    // Get current epoch
    let current_ms = now_ms();
    let current_epoch = state
        .leader_config
        .as_ref()
        .map(|c| c.epoch_at(current_ms))
        .unwrap_or(0);
    let epoch_ms = state
        .leader_config
        .as_ref()
        .map(|c| c.epoch_ms)
        .unwrap_or(10_000);

    // Check rate limit per account per epoch
    let account_count = state
        .storage
        .count_forced_for_account_epoch(&req.from, current_epoch)
        .unwrap_or(0);
    if account_count >= state.forced_config.max_per_account_per_epoch {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ForceIncludeResponse {
                accepted: false,
                tx_hash: tx_hash.to_hex(),
                ticket: None,
                error: Some(format!(
                    "exceeded forced tx limit for account this epoch: {} >= {}",
                    account_count, state.forced_config.max_per_account_per_epoch
                )),
            }),
        );
    }

    // Store transaction
    if let Err(e) = state.storage.put_tx(&tx) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ForceIncludeResponse {
                accepted: false,
                tx_hash: tx_hash.to_hex(),
                ticket: None,
                error: Some(format!("storage error: {e}")),
            }),
        );
    }

    // Create inclusion ticket
    let ticket = InclusionTicket::new(
        tx_hash,
        req.from,
        current_ms,
        epoch_ms,
        state.forced_config.max_epochs,
        current_epoch,
    );

    // Store ticket
    if let Err(e) = state.storage.put_forced_ticket(&ticket) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ForceIncludeResponse {
                accepted: false,
                tx_hash: tx_hash.to_hex(),
                ticket: None,
                error: Some(format!("failed to store ticket: {e}")),
            }),
        );
    }

    info!(
        tx_hash = %tx_hash.to_hex(),
        requester = %ticket.requester,
        expires_at = ticket.expires_at_ms,
        "created forced inclusion ticket"
    );

    (
        StatusCode::OK,
        Json(ForceIncludeResponse {
            accepted: true,
            tx_hash: tx_hash.to_hex(),
            ticket: Some(ticket),
            error: None,
        }),
    )
}

async fn get_force_status(
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

    // Look up ticket
    match state.storage.get_forced_ticket(&tx_hash) {
        Ok(Some(ticket)) => {
            let response = ForceIncludeStatus {
                tx_hash: tx_hash.to_hex(),
                status: ticket.status,
                ticket,
            };
            (
                StatusCode::OK,
                Json(serde_json::to_value(response).unwrap()),
            )
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "forced inclusion ticket not found"
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
            (
                StatusCode::OK,
                Json(serde_json::to_value(response).unwrap()),
            )
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

// ============== Bridge Endpoints ==============

async fn claim_deposit(
    state: axum::extract::State<AppState>,
    Json(req): Json<DepositClaimRequest>,
) -> impl IntoResponse {
    // Validate L1 tx hash format
    if req.l1_tx_hash.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(DepositClaimResponse {
                accepted: false,
                deposit: None,
                error: Some("l1_tx_hash is required".to_string()),
            }),
        );
    }

    // Check if deposit already claimed
    let deposit_id = req.l1_tx_hash.clone();
    if let Ok(true) = state.storage.deposit_exists(&deposit_id) {
        // Deposit already exists - return existing
        if let Ok(Some(data)) = state.storage.get_deposit(&deposit_id) {
            if let Ok(existing) = l2_core::canonical_decode::<DepositEvent>(&data) {
                return (
                    StatusCode::CONFLICT,
                    Json(DepositClaimResponse {
                        accepted: false,
                        deposit: Some(existing),
                        error: Some("deposit already claimed".to_string()),
                    }),
                );
            }
        }
    }

    // For MVP, we create a pending deposit that needs manual verification
    // In production, we would verify via the L1 watcher
    let deposit = DepositEvent {
        l1_tx_hash: req.l1_tx_hash.clone(),
        from_l1: String::new(), // Would be extracted from L1 tx
        to_l2: String::new(),   // Would be parsed from memo
        asset: "IPN".to_string(),
        amount: 0, // Would be extracted from L1 tx
        memo: None,
        seen_at_ms: now_ms(),
        status: DepositStatus::Pending,
        chain_id: ChainId(state.settings.chain_id),
        nonce: 0,
    };

    // Store deposit
    let encoded = match l2_core::canonical_encode(&deposit) {
        Ok(data) => data,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(DepositClaimResponse {
                    accepted: false,
                    deposit: None,
                    error: Some(format!("encoding error: {e}")),
                }),
            );
        }
    };

    if let Err(e) = state.storage.put_deposit(&deposit_id, &encoded) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(DepositClaimResponse {
                accepted: false,
                deposit: None,
                error: Some(format!("storage error: {e}")),
            }),
        );
    }

    info!(
        l1_tx_hash = %req.l1_tx_hash,
        "created pending deposit claim"
    );

    (
        StatusCode::OK,
        Json(DepositClaimResponse {
            accepted: true,
            deposit: Some(deposit),
            error: None,
        }),
    )
}

async fn get_deposit(
    state: axum::extract::State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.storage.get_deposit(&id) {
        Ok(Some(data)) => match l2_core::canonical_decode::<DepositEvent>(&data) {
            Ok(deposit) => (
                StatusCode::OK,
                Json(serde_json::to_value(deposit).unwrap()),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("decode error: {e}")
                })),
            ),
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "deposit not found"
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

/// Request to withdraw from L2 to L1.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WithdrawApiRequest {
    /// Sender address on L2.
    from_l2: String,
    /// Recipient address on L1.
    to_l1: String,
    /// Asset identifier.
    asset: String,
    /// Amount in smallest units.
    amount: u128,
    /// Nonce for replay protection.
    nonce: u64,
    /// Signature from L2 account (hex, optional for MVP).
    #[serde(default)]
    sig: Option<String>,
}

/// Response to a withdraw request.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WithdrawApiResponse {
    /// Whether the request was accepted.
    accepted: bool,
    /// Withdrawal ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    withdraw_id: Option<String>,
    /// The full withdrawal request.
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<WithdrawRequest>,
    /// Error message (if rejected).
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn request_withdraw(
    state: axum::extract::State<AppState>,
    Json(req): Json<WithdrawApiRequest>,
) -> impl IntoResponse {
    // Validate required fields
    if req.from_l2.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(WithdrawApiResponse {
                accepted: false,
                withdraw_id: None,
                request: None,
                error: Some("from_l2 is required".to_string()),
            }),
        );
    }
    if req.to_l1.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(WithdrawApiResponse {
                accepted: false,
                withdraw_id: None,
                request: None,
                error: Some("to_l1 is required".to_string()),
            }),
        );
    }
    if req.amount == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(WithdrawApiResponse {
                accepted: false,
                withdraw_id: None,
                request: None,
                error: Some("amount must be > 0".to_string()),
            }),
        );
    }

    // Generate withdrawal ID
    let withdraw_id = WithdrawRequest::generate_id(&req.from_l2, req.nonce);

    // Check if withdrawal already exists
    if let Ok(true) = state.storage.withdrawal_exists(&withdraw_id) {
        // Return existing
        if let Ok(Some(data)) = state.storage.get_withdrawal(&withdraw_id) {
            if let Ok(existing) = l2_core::canonical_decode::<WithdrawRequest>(&data) {
                return (
                    StatusCode::CONFLICT,
                    Json(WithdrawApiResponse {
                        accepted: false,
                        withdraw_id: Some(withdraw_id),
                        request: Some(existing),
                        error: Some("withdrawal already exists".to_string()),
                    }),
                );
            }
        }
    }

    // Create withdrawal request
    let withdraw = WithdrawRequest {
        id: withdraw_id.clone(),
        from_l2: req.from_l2,
        to_l1: req.to_l1,
        asset: req.asset,
        amount: req.amount,
        nonce: req.nonce,
        sig: req.sig,
        created_at_ms: now_ms(),
        status: WithdrawStatus::Pending,
        l1_tx: None,
        chain_id: ChainId(state.settings.chain_id),
    };

    // Store withdrawal
    let encoded = match l2_core::canonical_encode(&withdraw) {
        Ok(data) => data,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WithdrawApiResponse {
                    accepted: false,
                    withdraw_id: None,
                    request: None,
                    error: Some(format!("encoding error: {e}")),
                }),
            );
        }
    };

    if let Err(e) = state.storage.put_withdrawal(&withdraw_id, &encoded) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(WithdrawApiResponse {
                accepted: false,
                withdraw_id: None,
                request: None,
                error: Some(format!("storage error: {e}")),
            }),
        );
    }

    info!(
        withdraw_id = %withdraw_id,
        from_l2 = %withdraw.from_l2,
        to_l1 = %withdraw.to_l1,
        amount = %withdraw.amount,
        "created withdrawal request"
    );

    (
        StatusCode::OK,
        Json(WithdrawApiResponse {
            accepted: true,
            withdraw_id: Some(withdraw_id),
            request: Some(withdraw),
            error: None,
        }),
    )
}

async fn get_withdraw(
    state: axum::extract::State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.storage.get_withdrawal(&id) {
        Ok(Some(data)) => match l2_core::canonical_decode::<WithdrawRequest>(&data) {
            Ok(withdraw) => (
                StatusCode::OK,
                Json(serde_json::to_value(withdraw).unwrap()),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("decode error: {e}")
                })),
            ),
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "withdrawal not found"
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

// ============== Utility Functions ==============

fn now_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}
