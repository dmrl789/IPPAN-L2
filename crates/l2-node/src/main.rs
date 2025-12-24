#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::disallowed_types)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use l2_batcher::{
    spawn as spawn_batcher, BatcherConfig, BatcherHandle, BatcherSnapshot, LoggingBatchPoster,
};
use l2_bridge::{
    spawn as spawn_bridge, BridgeConfig, BridgeHandle, BridgeSnapshot, LoggingWatcher,
};
use l2_core::ChainId;
use l2_storage::Storage;
use prometheus::{Encoder, IntGauge, Opts, Registry, TextEncoder};
use serde::Serialize;
use thiserror::Error;
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

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
    #[arg(long, env = "LEADER_ID", default_value = "sequencer-0")]
    pub leader_id: String,
    #[arg(long, env = "LEADER_TERM", default_value_t = 1)]
    pub leader_term: u64,
}

#[derive(Debug, Error)]
enum NodeError {
    #[error("storage error: {0}")]
    Storage(#[from] l2_storage::StorageError),
    #[error("server error: {0}")]
    Server(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone)]
struct Metrics {
    registry: Registry,
    uptime_ms: IntGauge,
    queue_depth: IntGauge,
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
        registry
            .register(Box::new(uptime_ms.clone()))
            .expect("register uptime");
        registry
            .register(Box::new(queue_depth.clone()))
            .expect("register queue depth");
        Self {
            registry,
            uptime_ms,
            queue_depth,
        }
    }
}

#[derive(Clone)]
struct AppState {
    storage: Arc<Storage>,
    start_instant: Instant,
    settings: Settings,
    batcher: Option<BatcherHandle>,
    bridge: Option<BridgeHandle>,
    metrics: Metrics,
    queue_capacity: usize,
}

#[derive(Serialize)]
struct StatusResponse {
    service: ServiceInfo,
    uptime_ms: u64,
    leader: LeaderInfo,
    queue: QueueInfo,
    batcher: BatcherInfo,
    bridge: BridgeInfo,
}

#[derive(Serialize)]
struct ServiceInfo {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct LeaderInfo {
    mode: &'static str,
    id: String,
    term: u64,
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
    let mut batcher_handle = None;
    let mut bridge_handle = None;
    let queue_capacity = 1024usize;

    if settings.batcher_enabled {
        let config = BatcherConfig {
            max_batch_txs: 256,
            max_batch_bytes: 512 * 1024,
            max_wait_ms: 1_000,
            chain_id: ChainId(1),
        };
        let handle = spawn_batcher(
            config,
            Arc::clone(&storage),
            Arc::new(LoggingBatchPoster {}),
        );
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
        settings,
        batcher: batcher_handle,
        bridge: bridge_handle,
        metrics,
        queue_capacity,
    };

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/status", get(status))
        .route("/metrics", get(metrics_handler))
        .with_state(state.clone());

    let addr: SocketAddr = state
        .settings
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

async fn health() -> impl IntoResponse {
    "ok"
}

async fn ready(state: axum::extract::State<AppState>) -> impl IntoResponse {
    match state.storage.get_meta("schema_version") {
        Ok(_) => axum::http::StatusCode::OK,
        Err(_) => axum::http::StatusCode::SERVICE_UNAVAILABLE,
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

    let response = StatusResponse {
        service: ServiceInfo {
            name: "ippan-l2-node",
            version: env!("CARGO_PKG_VERSION"),
        },
        uptime_ms,
        leader: LeaderInfo {
            mode: "single",
            id: state.settings.leader_id.clone(),
            term: state.settings.leader_term,
        },
        queue: QueueInfo {
            depth: batcher_snapshot.queue_depth,
            capacity: state.queue_capacity,
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

    let encoder = TextEncoder::new();
    let metric_families = state.metrics.registry.gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .expect("encode metrics");
    (axum::http::StatusCode::OK, buffer)
}
