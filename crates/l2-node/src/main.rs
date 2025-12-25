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
    get_in_flight_summary, get_settlement_counts, spawn_settlement_reconciler,
    spawn_with_m2m as spawn_batcher, BatchPoster, BatcherConfig, BatcherHandle, BatcherSnapshot,
    IppanBatchPoster, IppanPosterConfig, LoggingBatchPoster, SettlementReconcilerConfig,
    SettlementReconcilerHandle,
};
#[cfg(feature = "contract-posting")]
use l2_batcher::{BlockingL1ClientAdapter, ContractBatchPoster, ContractPosterConfig};
use l2_bridge::{
    spawn as spawn_bridge, BridgeConfig, BridgeHandle, BridgeSnapshot, DepositClaimRequest,
    DepositClaimResponse, DepositEvent, DepositStatus, LoggingWatcher, WithdrawRequest,
    WithdrawStatus,
};
use l2_core::fees::{compute_m2m_fee, FeeSchedule, M2mFeeBreakdown};
use l2_core::forced_inclusion::{
    ForceIncludeRequest, ForceIncludeResponse, ForceIncludeStatus, ForcedInclusionConfig,
    InclusionTicket,
};
use l2_core::{canonical_hash, ChainId, Hash32, Tx};
use l2_leader::{LeaderConfig, LeaderSet, LeaderState, PubKey};
use l2_storage::m2m::{ForcedClass, M2mStorage};
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
    /// Poster mode: "contract" (default) or "raw" (legacy)
    #[arg(long, env = "L2_POSTER_MODE", default_value = "contract")]
    pub poster_mode: String,
}

/// Poster mode selection.
///
/// Contract mode is the default and recommended for production.
/// Raw mode is kept for debugging and backwards compatibility only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PosterMode {
    /// Contract-based posting using L2BatchEnvelopeV1 (default, recommended).
    ///
    /// Features:
    /// - Deterministic idempotency keys
    /// - Proper finality/inclusion tracking
    /// - Versioned envelope format
    /// - Batch chaining via prev_batch_hash
    #[default]
    Contract,
    /// Raw posting using IPPAN RPC /tx endpoint.
    ///
    /// **Legacy/Debug only**. Use only when:
    /// - Contract posting is unavailable
    /// - Debugging L1 connectivity issues
    /// - Backwards compatibility required
    Raw,
}

impl std::str::FromStr for PosterMode {
    type Err = std::convert::Infallible;

    /// Parse from string (env var or CLI arg).
    /// Never fails - unknown values default to Contract mode.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "raw" | "legacy" => Self::Raw,
            _ => Self::Contract, // default
        })
    }
}

impl Settings {
    /// Validate settings at startup. Fails fast on invalid configuration.
    pub(crate) fn validate(&self) -> Result<(), NodeError> {
        // If contract posting requested, ensure the feature is enabled
        #[cfg(not(feature = "contract-posting"))]
        {
            let mode: PosterMode = self.poster_mode.parse().unwrap();
            if mode == PosterMode::Contract {
                return Err(NodeError::Config(
                    "L2_POSTER_MODE=contract requires the 'contract-posting' feature, \
                     but it is not enabled. Either set L2_POSTER_MODE=raw or rebuild \
                     with --features contract-posting"
                        .to_string(),
                ));
            }
        }

        // Validate leader configuration for posting
        // Only leaders should post batches in single mode
        if self.leader_mode == "single" && !self.is_leader && self.batcher_enabled {
            warn!(
                "batcher_enabled=true on non-leader node in single mode; \
                 batches will not be posted until this node becomes leader"
            );
        }

        // Validate chain ID is non-zero
        if self.chain_id == 0 {
            return Err(NodeError::Config("L2_CHAIN_ID must be > 0".to_string()));
        }

        // Validate admission cap
        if self.admission_cap == 0 {
            return Err(NodeError::Config(
                "L2_ADMISSION_CAP must be > 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Get the parsed poster mode.
    pub fn get_poster_mode(&self) -> PosterMode {
        self.poster_mode.parse().unwrap()
    }

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
    // Contract posting metrics - tracked for observability
    #[allow(dead_code)] // Exposed via /metrics endpoint
    contract_submit_total: IntCounter,
    #[allow(dead_code)] // Exposed via /metrics endpoint
    contract_submit_retries_total: IntCounter,
    #[allow(dead_code)] // Exposed via /metrics endpoint
    contract_already_known_total: IntCounter,
    #[allow(dead_code)] // Exposed via /metrics endpoint
    contract_failed_total: IntCounter,
    // Settlement lifecycle metrics
    settlement_created: IntGauge,
    settlement_submitted: IntGauge,
    settlement_included: IntGauge,
    settlement_finalised: IntGauge,
    settlement_failed: IntGauge,
    #[allow(dead_code)] // Will be used when reconciler tracking is complete
    settlement_recovered_total: IntCounter,
    #[allow(dead_code)] // Will be used when reconciler tracking is complete
    last_reconcile_ms: IntGauge,
    // M2M fee metrics
    m2m_fee_reserved_total: IntCounter,
    #[allow(dead_code)] // Incremented by batcher (separate crate)
    m2m_fee_finalised_total: IntCounter,
    m2m_quota_reject_total: IntCounter,
    m2m_insufficient_balance_reject_total: IntCounter,
    m2m_forced_included_total: IntCounter,
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

        let leader_epoch_idx =
            IntGauge::with_opts(Opts::new("l2_epoch_idx", "Current epoch index"))
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

        // Contract posting metrics
        let contract_submit_total = IntCounter::with_opts(Opts::new(
            "l2_contract_submit_total",
            "Total contract batch submissions",
        ))
        .expect("contract submit counter");

        let contract_submit_retries_total = IntCounter::with_opts(Opts::new(
            "l2_contract_submit_retries_total",
            "Total contract batch submission retries",
        ))
        .expect("contract retries counter");

        let contract_already_known_total = IntCounter::with_opts(Opts::new(
            "l2_contract_already_known_total",
            "Total contract submissions with AlreadyKnown response",
        ))
        .expect("contract already known counter");

        let contract_failed_total = IntCounter::with_opts(Opts::new(
            "l2_contract_failed_total",
            "Total contract batch submission failures",
        ))
        .expect("contract failed counter");

        // Settlement lifecycle metrics
        let settlement_created = IntGauge::with_opts(Opts::new(
            "l2_settlement_created",
            "Number of batches in Created state",
        ))
        .expect("settlement created gauge");

        let settlement_submitted = IntGauge::with_opts(Opts::new(
            "l2_settlement_submitted",
            "Number of batches in Submitted state",
        ))
        .expect("settlement submitted gauge");

        let settlement_included = IntGauge::with_opts(Opts::new(
            "l2_settlement_included",
            "Number of batches in Included state",
        ))
        .expect("settlement included gauge");

        let settlement_finalised = IntGauge::with_opts(Opts::new(
            "l2_settlement_finalised",
            "Number of batches in Finalised state",
        ))
        .expect("settlement finalised gauge");

        let settlement_failed = IntGauge::with_opts(Opts::new(
            "l2_settlement_failed",
            "Number of batches in Failed state",
        ))
        .expect("settlement failed gauge");

        let settlement_recovered_total = IntCounter::with_opts(Opts::new(
            "l2_settlement_recovered_total",
            "Total batches recovered by reconciler",
        ))
        .expect("settlement recovered counter");

        let last_reconcile_ms = IntGauge::with_opts(Opts::new(
            "l2_last_reconcile_ms",
            "Timestamp of last reconciliation cycle (ms since epoch)",
        ))
        .expect("last reconcile gauge");

        // M2M fee metrics
        let m2m_fee_reserved_total = IntCounter::with_opts(Opts::new(
            "l2_m2m_fee_reserved_total",
            "Total M2M fees reserved",
        ))
        .expect("m2m fee reserved counter");

        let m2m_fee_finalised_total = IntCounter::with_opts(Opts::new(
            "l2_m2m_fee_finalised_total",
            "Total M2M fees finalised",
        ))
        .expect("m2m fee finalised counter");

        let m2m_quota_reject_total = IntCounter::with_opts(Opts::new(
            "l2_m2m_quota_reject_total",
            "Total M2M quota rejections",
        ))
        .expect("m2m quota reject counter");

        let m2m_insufficient_balance_reject_total = IntCounter::with_opts(Opts::new(
            "l2_m2m_insufficient_balance_reject_total",
            "Total M2M insufficient balance rejections",
        ))
        .expect("m2m insufficient balance counter");

        let m2m_forced_included_total = IntCounter::with_opts(Opts::new(
            "l2_m2m_forced_included_total",
            "Total M2M forced inclusion transactions",
        ))
        .expect("m2m forced included counter");

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
            Box::new(contract_submit_total.clone()),
            Box::new(contract_submit_retries_total.clone()),
            Box::new(contract_already_known_total.clone()),
            Box::new(contract_failed_total.clone()),
            Box::new(settlement_created.clone()),
            Box::new(settlement_submitted.clone()),
            Box::new(settlement_included.clone()),
            Box::new(settlement_finalised.clone()),
            Box::new(settlement_failed.clone()),
            Box::new(settlement_recovered_total.clone()),
            Box::new(last_reconcile_ms.clone()),
            Box::new(m2m_fee_reserved_total.clone()),
            Box::new(m2m_fee_finalised_total.clone()),
            Box::new(m2m_quota_reject_total.clone()),
            Box::new(m2m_insufficient_balance_reject_total.clone()),
            Box::new(m2m_forced_included_total.clone()),
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
            contract_submit_total,
            contract_submit_retries_total,
            contract_already_known_total,
            contract_failed_total,
            settlement_created,
            settlement_submitted,
            settlement_included,
            settlement_finalised,
            settlement_failed,
            settlement_recovered_total,
            last_reconcile_ms,
            m2m_fee_reserved_total,
            m2m_fee_finalised_total,
            m2m_quota_reject_total,
            m2m_insufficient_balance_reject_total,
            m2m_forced_included_total,
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

    fn update_settlement_counts(&self, counts: &l2_storage::SettlementStateCounts) {
        self.settlement_created
            .set(i64::try_from(counts.created).unwrap_or(i64::MAX));
        self.settlement_submitted
            .set(i64::try_from(counts.submitted).unwrap_or(i64::MAX));
        self.settlement_included
            .set(i64::try_from(counts.included).unwrap_or(i64::MAX));
        self.settlement_finalised
            .set(i64::try_from(counts.finalised).unwrap_or(i64::MAX));
        self.settlement_failed
            .set(i64::try_from(counts.failed).unwrap_or(i64::MAX));
    }

    #[allow(dead_code)] // Will be used when reconciler tracking is complete
    fn set_last_reconcile_ms(&self, ts: u64) {
        self.last_reconcile_ms
            .set(i64::try_from(ts).unwrap_or(i64::MAX));
    }

    fn update_leader_state(&self, state: &LeaderState) {
        self.leader_is_leader
            .set(if state.is_leader { 1 } else { 0 });
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
    reconciler: Option<SettlementReconcilerHandle>,
    metrics: Metrics,
    queue_depth: Arc<AtomicUsize>,
    // Leader rotation state
    leader_config: Option<LeaderConfig>,
    leader_state: Arc<RwLock<LeaderState>>,
    leader_endpoints: std::collections::HashMap<String, String>,
    http_client: reqwest::Client,
    // Forced inclusion config
    forced_config: ForcedInclusionConfig,
    // M2M fee storage
    m2m_storage: Option<Arc<M2mStorage>>,
    // M2M fee schedule
    fee_schedule: FeeSchedule,
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
    settlement: SettlementInfo,
    forced_inclusion: ForcedInclusionInfo,
    m2m_fees: M2mFeesInfo,
}

#[derive(Serialize)]
struct M2mFeesInfo {
    /// Whether M2M fee storage is enabled.
    enabled: bool,
    /// Fee schedule summary.
    schedule: Option<l2_core::fees::FeeScheduleSummary>,
    /// Total machines registered.
    total_machines: u64,
    /// Machines with forced inclusion privileges.
    forced_machines: u64,
    /// Total fees reserved (lifetime, scaled).
    total_reserved_scaled: u64,
    /// Total fees finalized (lifetime, scaled).
    total_finalised_scaled: u64,
    /// Pending reservations count.
    pending_reservations: u64,
}

#[derive(Serialize)]
struct SettlementInfo {
    /// Poster mode: "contract" or "raw"
    poster_mode: String,
    /// Last submitted batch hash (hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    last_submitted_batch_hash: Option<String>,
    /// Last idempotency key (hex, contract mode only)
    #[serde(skip_serializing_if = "Option::is_none")]
    last_idempotency_key: Option<String>,
    /// Last L1 tx ID
    #[serde(skip_serializing_if = "Option::is_none")]
    last_l1_tx_id: Option<String>,
    /// Number of pending submissions
    pending_submissions: u64,
    /// Number of confirmed submissions
    confirmed_submissions: u64,
    /// Settlement lifecycle state counts
    lifecycle: SettlementLifecycleInfo,
    /// In-flight batches summary
    in_flight: InFlightInfo,
    /// Last finalised batch info
    #[serde(skip_serializing_if = "Option::is_none")]
    last_finalised: Option<LastFinalisedInfo>,
    /// Last reconciliation timestamp (ms since epoch)
    #[serde(skip_serializing_if = "Option::is_none")]
    last_reconcile_ms: Option<u64>,
}

#[derive(Serialize)]
struct SettlementLifecycleInfo {
    /// Batches created but not yet submitted
    created: u64,
    /// Batches submitted to L1, awaiting inclusion
    submitted: u64,
    /// Batches included in L1 block, awaiting finality
    included: u64,
    /// Batches finalised on L1
    finalised: u64,
    /// Batches that failed settlement
    failed: u64,
    /// Total in-flight batches (created + submitted + included)
    in_flight_total: u64,
}

#[derive(Serialize)]
struct InFlightInfo {
    /// Number of submitted batches awaiting inclusion
    submitted_count: usize,
    /// Number of included batches awaiting finality
    included_count: usize,
    /// Age of oldest submitted batch (ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    oldest_submitted_age_ms: Option<u64>,
    /// Age of oldest included batch (ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    oldest_included_age_ms: Option<u64>,
}

#[derive(Serialize)]
struct LastFinalisedInfo {
    /// Batch hash (hex)
    batch_hash: String,
    /// Timestamp when finalised (ms since epoch)
    finalised_at_ms: u64,
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

    // Validate settings (fail fast on invalid config)
    settings.validate()?;

    let poster_mode = settings.get_poster_mode();
    info!(
        ?settings,
        poster_mode = ?poster_mode,
        "starting l2-node"
    );
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
    // RPC client for legacy poster mode (kept for backwards compatibility)
    let _rpc_client = if !settings.ippan_rpc_url.is_empty() {
        let rpc_config = IppanRpcConfig {
            base_url: settings.ippan_rpc_url.clone(),
            timeout_ms: IppanRpcConfig::DEFAULT_TIMEOUT_MS,
            retry_max: IppanRpcConfig::DEFAULT_RETRY_MAX,
        };
        ippan_rpc::IppanRpcClient::new(rpc_config).ok()
    } else {
        None
    };

    // Initialize M2M fee schedule and storage (before batcher so it can use it)
    let fee_schedule = FeeSchedule::default();
    let m2m_storage: Option<Arc<M2mStorage>> =
        match M2mStorage::open(storage.db(), fee_schedule.clone()) {
            Ok(m2m) => {
                info!("M2M fee storage initialized");
                Some(Arc::new(m2m))
            }
            Err(e) => {
                warn!(error = %e, "failed to initialize M2M storage, fee features disabled");
                None
            }
        };

    // Determine if we should start batcher (leader-only in single mode, always in rotating mode)
    let should_start_batcher =
        settings.batcher_enabled && (settings.leader_mode == "rotating" || settings.is_leader);

    if should_start_batcher {
        let config = BatcherConfig {
            max_batch_txs: 256,
            max_batch_bytes: 512 * 1024,
            max_wait_ms: 1_000,
            chain_id: ChainId(settings.chain_id),
        };

        // Create poster based on L2_POSTER_MODE and IPPAN_RPC_URL
        let poster: Arc<dyn BatchPoster> = match poster_mode {
            #[cfg(feature = "contract-posting")]
            PosterMode::Contract => {
                info!(
                    mode = "contract",
                    "using contract-based batch poster (L2BatchEnvelopeV1)"
                );
                let config = ContractPosterConfig::from_env();
                // Create mock L1 client for MVP (will be replaced with real HTTP client)
                let mock_client = l2_core::l1_contract::mock_client::MockL1Client::new("mainnet");
                let adapter = BlockingL1ClientAdapter::new(mock_client);
                Arc::new(ContractBatchPoster::new(
                    adapter,
                    Arc::clone(&storage),
                    config,
                ))
            }
            #[cfg(not(feature = "contract-posting"))]
            PosterMode::Contract => {
                // This should not happen due to validate() check, but handle gracefully
                error!("contract-posting feature not enabled, falling back to logging poster");
                Arc::new(LoggingBatchPoster {})
            }
            PosterMode::Raw => {
                if !settings.ippan_rpc_url.is_empty() {
                    info!(
                        mode = "raw",
                        url = %settings.ippan_rpc_url,
                        "using raw IPPAN RPC poster (legacy)"
                    );
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
                    info!(
                        mode = "raw",
                        "using logging batch poster (IPPAN_RPC_URL not set)"
                    );
                    Arc::new(LoggingBatchPoster {})
                }
            }
        };

        let handle = spawn_batcher(
            config,
            Arc::clone(&storage),
            poster,
            m2m_storage.clone(),
            Some(fee_schedule.clone()),
        );
        batcher_handle = Some(handle);

        // Run crash recovery check before starting reconciler
        let recovery_info = run_startup_recovery(&storage);
        if recovery_info.in_flight_count > 0 {
            info!(
                submitted = recovery_info.submitted_count,
                included = recovery_info.included_count,
                "startup recovery: found in-flight batches, reconciler will resume"
            );
        }

        // Spawn settlement reconciler (leader-only in production)
        let reconciler_config = SettlementReconcilerConfig {
            hub: "fin".to_string(),
            chain_id: settings.chain_id,
            ..SettlementReconcilerConfig::from_env()
        };
        info!(
            interval_ms = reconciler_config.interval_ms,
            batch_limit = reconciler_config.batch_limit,
            finality_confirmations = reconciler_config.finality_confirmations,
            "starting settlement reconciler"
        );

        // Create L1 client adapter for reconciler
        #[cfg(feature = "contract-posting")]
        let l1_client_for_reconciler = {
            let mock_client = l2_core::l1_contract::mock_client::MockL1Client::new("mainnet");
            Some(BlockingL1ClientAdapter::new(mock_client))
        };
        #[cfg(not(feature = "contract-posting"))]
        let l1_client_for_reconciler: Option<
            l2_batcher::BlockingL1ClientAdapter<l2_core::l1_contract::mock_client::MockL1Client>,
        > = None;

        reconciler_handle = Some(spawn_settlement_reconciler(
            reconciler_config,
            Arc::clone(&storage),
            l1_client_for_reconciler,
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
        m2m_storage,
        fee_schedule,
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
        // M2M fee endpoints
        .route("/m2m/fee/estimate", post(m2m_fee_estimate))
        .route("/m2m/balance/{machine_id}", get(m2m_get_balance))
        .route("/m2m/topup", post(m2m_topup))
        .route("/m2m/schedule", get(m2m_get_schedule))
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

    // Build settlement info
    let poster_mode_str = match state.settings.get_poster_mode() {
        PosterMode::Contract => "contract",
        PosterMode::Raw => "raw",
    };

    // Get last posted batch info for settlement status
    let last_posted = state
        .storage
        .list_posted(1)
        .ok()
        .and_then(|v| v.into_iter().next());
    let last_l1_tx_id = last_posted
        .as_ref()
        .and_then(|e| e.state.l1_tx().map(String::from));

    // Get settlement lifecycle counts
    let settlement_counts = state.storage.count_settlement_states().unwrap_or_default();

    // Get in-flight summary
    let in_flight_summary = get_in_flight_summary(&state.storage, 10);
    let current_ms = now_ms();

    // Calculate ages for in-flight batches
    let oldest_submitted_age_ms = in_flight_summary
        .oldest_submitted_ms
        .map(|ts| current_ms.saturating_sub(ts));
    let oldest_included_age_ms = in_flight_summary
        .oldest_included_ms
        .map(|ts| current_ms.saturating_sub(ts));

    // Get last finalised batch
    let last_finalised = state
        .storage
        .get_last_finalised_batch("fin", state.settings.chain_id)
        .ok()
        .flatten()
        .map(|(hash, ts)| LastFinalisedInfo {
            batch_hash: hash.to_hex(),
            finalised_at_ms: ts,
        });

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
            last_batch_hash: batcher_snapshot.last_batch_hash.clone(),
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
        settlement: SettlementInfo {
            poster_mode: poster_mode_str.to_string(),
            last_submitted_batch_hash: batcher_snapshot.last_batch_hash,
            last_idempotency_key: None, // Would require storing in batcher snapshot
            last_l1_tx_id,
            pending_submissions: posting_counts.pending,
            confirmed_submissions: posting_counts.confirmed,
            lifecycle: SettlementLifecycleInfo {
                created: settlement_counts.created,
                submitted: settlement_counts.submitted,
                included: settlement_counts.included,
                finalised: settlement_counts.finalised,
                failed: settlement_counts.failed,
                in_flight_total: settlement_counts.in_flight(),
            },
            in_flight: InFlightInfo {
                submitted_count: in_flight_summary.submitted_count,
                included_count: in_flight_summary.included_count,
                oldest_submitted_age_ms,
                oldest_included_age_ms,
            },
            last_finalised,
            last_reconcile_ms: None, // TODO: track this in reconciler state
        },
        forced_inclusion: ForcedInclusionInfo {
            enabled: true,
            queue_depth: forced_counts.queued,
            max_epochs: state.forced_config.max_epochs,
            max_per_account_per_epoch: state.forced_config.max_per_account_per_epoch,
        },
        m2m_fees: {
            if let Some(m2m) = &state.m2m_storage {
                let stats = m2m.get_stats().unwrap_or_default();
                M2mFeesInfo {
                    enabled: true,
                    schedule: Some(state.fee_schedule.summary()),
                    total_machines: stats.total_machines,
                    forced_machines: stats.forced_machines,
                    total_reserved_scaled: stats.total_reserved_scaled,
                    total_finalised_scaled: stats.total_fees_paid_scaled,
                    pending_reservations: stats.pending_reservations,
                }
            } else {
                M2mFeesInfo {
                    enabled: false,
                    schedule: None,
                    total_machines: 0,
                    forced_machines: 0,
                    total_reserved_scaled: 0,
                    total_finalised_scaled: 0,
                    pending_reservations: 0,
                }
            }
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

    // Update settlement lifecycle counts
    if let Ok(counts) = state.storage.count_settlement_states() {
        state.metrics.update_settlement_counts(&counts);
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

    // Create transaction (preserve from for hash computation before move)
    let machine_id = req.from.clone();
    let tx = Tx {
        chain_id: ChainId(req.chain_id),
        nonce: req.nonce,
        from: req.from,
        payload: payload.clone(),
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

    // M2M Fee reservation (if M2M storage is enabled)
    let mut fee_reserved_scaled: Option<u64> = None;
    let mut is_forced_tx = false;
    if let Some(m2m) = &state.m2m_storage {
        // Compute fee based on payload size
        // Using conservative estimates: 1 exec unit per byte, 1 write
        let data_bytes = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        let exec_units = data_bytes; // 1:1 ratio for simplicity
        let writes = 1u32;

        match compute_m2m_fee(&state.fee_schedule, exec_units, data_bytes, writes) {
            Ok(breakdown) => {
                let fee_amount = breakdown.total_fee.scaled();

                // Check if machine has forced inclusion privileges
                let forced_class = m2m
                    .forced_class(&machine_id)
                    .unwrap_or(ForcedClass::Standard);
                is_forced_tx = forced_class == ForcedClass::ForcedInclusion;

                // Apply quota or forced usage limit based on class
                if is_forced_tx {
                    // Forced inclusion machines bypass normal quota but have daily limit
                    match m2m.apply_forced_usage(&machine_id, data_bytes, now_ms()) {
                        Ok(()) => {
                            debug!(
                                machine_id = %machine_id,
                                "forced inclusion applied"
                            );
                        }
                        Err(e) => {
                            // Daily forced limit exceeded
                            state.dequeue();
                            state.metrics.tx_rejected.inc();
                            return (
                                StatusCode::TOO_MANY_REQUESTS,
                                Json(SubmitTxResponse {
                                    tx_hash: tx_hash.to_hex(),
                                    accepted: false,
                                    error: Some(format!("forced inclusion limit exceeded: {e}")),
                                    forwarded: None,
                                }),
                            );
                        }
                    }
                } else {
                    // Standard machines subject to normal quota
                    let quota_result = m2m.apply_quota(
                        &machine_id,
                        fee_amount,
                        now_ms(),
                        100_000_000, // 100 IPN max per window (configurable)
                        60_000,      // 1 minute window
                    );

                    if let Err(e) = quota_result {
                        state.dequeue();
                        state.metrics.tx_rejected.inc();
                        state.metrics.m2m_quota_reject_total.inc();
                        return (
                            StatusCode::TOO_MANY_REQUESTS,
                            Json(SubmitTxResponse {
                                tx_hash: tx_hash.to_hex(),
                                accepted: false,
                                error: Some(format!("quota exceeded: {e}")),
                                forwarded: None,
                            }),
                        );
                    }
                }

                // Try to reserve fee (both forced and standard pay fees)
                let reserve_result = m2m.reserve_fee(
                    &machine_id,
                    tx_hash.0,
                    fee_amount,
                    breakdown,
                    is_forced_tx,
                    now_ms(),
                );

                match reserve_result {
                    Ok(()) => {
                        fee_reserved_scaled = Some(fee_amount);
                        state.metrics.m2m_fee_reserved_total.inc();
                        if is_forced_tx {
                            state.metrics.m2m_forced_included_total.inc();
                        }
                        debug!(
                            machine_id = %machine_id,
                            tx_hash = %tx_hash.to_hex(),
                            fee_amount = fee_amount,
                            "reserved fee for tx"
                        );
                    }
                    Err(l2_storage::m2m::M2mStorageError::InsufficientBalance {
                        required,
                        available,
                    }) => {
                        state.dequeue();
                        state.metrics.tx_rejected.inc();
                        state.metrics.m2m_insufficient_balance_reject_total.inc();
                        return (
                            StatusCode::PAYMENT_REQUIRED,
                            Json(SubmitTxResponse {
                                tx_hash: tx_hash.to_hex(),
                                accepted: false,
                                error: Some(format!(
                                    "insufficient balance: required {}, available {}",
                                    required, available
                                )),
                                forwarded: None,
                            }),
                        );
                    }
                    Err(l2_storage::m2m::M2mStorageError::MachineNotFound { .. }) => {
                        // Machine not registered - allow tx through without fee (MVP behavior)
                        // In production, this would reject
                        debug!(
                            machine_id = %machine_id,
                            "machine not found, allowing tx without fee reservation"
                        );
                    }
                    Err(e) => {
                        // Other errors - allow tx through with warning
                        warn!(
                            machine_id = %machine_id,
                            error = %e,
                            "fee reservation error, allowing tx through"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    machine_id = %machine_id,
                    error = %e,
                    "fee computation error, allowing tx through"
                );
            }
        }
    }
    // Track reserved fee (used in batcher finalization)
    let _ = fee_reserved_scaled;

    // Store transaction
    if let Err(e) = state.storage.put_tx(&tx) {
        // Release reservation if store fails
        if let Some(m2m) = &state.m2m_storage {
            let _ = m2m.release_reservation(&machine_id, tx_hash.0, now_ms());
        }
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

    // If forced inclusion tx, create forced queue entry for priority processing
    if is_forced_tx {
        // Get current epoch info
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

        let ticket = InclusionTicket::new(
            tx_hash,
            machine_id.clone(),
            current_ms,
            epoch_ms,
            state.forced_config.max_epochs,
            current_epoch,
        );

        if let Err(e) = state.storage.put_forced_ticket(&ticket) {
            warn!(
                error = %e,
                tx_hash = %tx_hash.to_hex(),
                "failed to create forced inclusion ticket (tx will still be processed)"
            );
        } else {
            info!(
                tx_hash = %tx_hash.to_hex(),
                machine_id = %machine_id,
                expires_at = ticket.expires_at_ms,
                "created forced inclusion ticket"
            );
        }
    }

    // Submit to batcher
    if let Err(e) = batcher.submit_tx(tx).await {
        // Release reservation if batcher submission fails
        if let Some(m2m) = &state.m2m_storage {
            let _ = m2m.release_reservation(&machine_id, tx_hash.0, now_ms());
        }
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
    let node_pubkey = state
        .leader_config
        .as_ref()
        .map(|c| c.node_pubkey.to_hex())
        .unwrap_or_default();
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
            Ok(deposit) => (StatusCode::OK, Json(serde_json::to_value(deposit).unwrap())),
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

// ============== M2M Fee Endpoints ==============

/// Request for fee estimation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FeeEstimateRequest {
    /// Number of execution units.
    exec_units: u64,
    /// Number of data bytes.
    data_bytes: u64,
    /// Number of storage writes.
    writes: u32,
}

/// Response for fee estimation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FeeEstimateResponse {
    /// Fee breakdown.
    breakdown: M2mFeeBreakdown,
    /// Schedule summary.
    schedule: l2_core::fees::FeeScheduleSummary,
}

/// Response for balance query.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BalanceResponse {
    /// Machine ID.
    machine_id: String,
    /// Available balance (scaled).
    balance_scaled: u64,
    /// Reserved balance (scaled).
    reserved_scaled: u64,
    /// Forced inclusion class.
    forced_class: ForcedClass,
}

/// Request for devnet top-up.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TopupRequest {
    /// Machine ID to top up.
    machine_id: String,
    /// Amount to add (scaled).
    amount_scaled: u64,
}

/// Response for top-up.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TopupResponse {
    /// Whether the top-up succeeded.
    success: bool,
    /// New balance after top-up (scaled).
    new_balance_scaled: Option<u64>,
    /// Error message if failed.
    error: Option<String>,
}

/// Estimate fee for a transaction.
async fn m2m_fee_estimate(
    state: axum::extract::State<AppState>,
    Json(req): Json<FeeEstimateRequest>,
) -> impl IntoResponse {
    // Compute fee using the schedule
    match compute_m2m_fee(
        &state.fee_schedule,
        req.exec_units,
        req.data_bytes,
        req.writes,
    ) {
        Ok(breakdown) => {
            let response = FeeEstimateResponse {
                breakdown,
                schedule: state.fee_schedule.summary(),
            };
            (
                StatusCode::OK,
                Json(serde_json::to_value(response).unwrap()),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("fee computation error: {e}")
            })),
        ),
    }
}

/// Get balance for a machine.
async fn m2m_get_balance(
    state: axum::extract::State<AppState>,
    Path(machine_id): Path<String>,
) -> impl IntoResponse {
    let m2m = match &state.m2m_storage {
        Some(m) => m,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "M2M storage not available"
                })),
            )
        }
    };

    // Validate machine ID
    if let Err(e) = M2mStorage::validate_machine_id(&machine_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("invalid machine_id: {e}")
            })),
        );
    }

    // Get account info
    match m2m.get_account(&machine_id) {
        Ok(Some(account)) => {
            let response = BalanceResponse {
                machine_id: account.machine_id,
                balance_scaled: account.balance_scaled,
                reserved_scaled: account.reserved_scaled,
                forced_class: account.forced_class,
            };
            (
                StatusCode::OK,
                Json(serde_json::to_value(response).unwrap()),
            )
        }
        Ok(None) => {
            // Return zero balance for unknown machines
            let response = BalanceResponse {
                machine_id,
                balance_scaled: 0,
                reserved_scaled: 0,
                forced_class: ForcedClass::Standard,
            };
            (
                StatusCode::OK,
                Json(serde_json::to_value(response).unwrap()),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("storage error: {e}")
            })),
        ),
    }
}

/// Top up balance (devnet only).
async fn m2m_topup(
    state: axum::extract::State<AppState>,
    Json(req): Json<TopupRequest>,
) -> impl IntoResponse {
    // Check if devnet mode
    let devnet = std::env::var("DEVNET")
        .map(|s| s == "1" || s.to_lowercase() == "true")
        .unwrap_or(false);

    if !devnet {
        return (
            StatusCode::FORBIDDEN,
            Json(TopupResponse {
                success: false,
                new_balance_scaled: None,
                error: Some("top-up only available in devnet mode (DEVNET=1)".to_string()),
            }),
        );
    }

    let m2m = match &state.m2m_storage {
        Some(m) => m,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(TopupResponse {
                    success: false,
                    new_balance_scaled: None,
                    error: Some("M2M storage not available".to_string()),
                }),
            )
        }
    };

    // Validate machine ID
    if let Err(e) = M2mStorage::validate_machine_id(&req.machine_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(TopupResponse {
                success: false,
                new_balance_scaled: None,
                error: Some(format!("invalid machine_id: {e}")),
            }),
        );
    }

    // Top up
    match m2m.topup(&req.machine_id, req.amount_scaled, now_ms()) {
        Ok(new_balance) => (
            StatusCode::OK,
            Json(TopupResponse {
                success: true,
                new_balance_scaled: Some(new_balance.scaled()),
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(TopupResponse {
                success: false,
                new_balance_scaled: None,
                error: Some(format!("top-up error: {e}")),
            }),
        ),
    }
}

/// Get fee schedule.
async fn m2m_get_schedule(state: axum::extract::State<AppState>) -> impl IntoResponse {
    let summary = state.fee_schedule.summary();
    Json(serde_json::to_value(summary).unwrap())
}

// ============== Startup Recovery ==============

/// Information about in-flight batches found during startup recovery.
#[derive(Debug, Clone, Default)]
struct StartupRecoveryInfo {
    /// Number of batches in Submitted state.
    submitted_count: usize,
    /// Number of batches in Included state.
    included_count: usize,
    /// Total in-flight batches.
    in_flight_count: usize,
}

/// Run startup recovery check to detect in-flight batches from previous session.
///
/// This function:
/// 1. Queries storage for batches in non-terminal states
/// 2. Logs recovery information
/// 3. Returns counts for metrics
///
/// The actual reconciliation is handled by the settlement reconciler,
/// which runs immediately on startup.
fn run_startup_recovery(storage: &Storage) -> StartupRecoveryInfo {
    let summary = get_in_flight_summary(storage, 100);
    let counts = get_settlement_counts(storage);

    let info = StartupRecoveryInfo {
        submitted_count: summary.submitted_count,
        included_count: summary.included_count,
        in_flight_count: summary.submitted_count + summary.included_count,
    };

    if info.in_flight_count > 0 {
        info!(
            submitted = info.submitted_count,
            included = info.included_count,
            created = counts.created,
            finalised = counts.finalised,
            failed = counts.failed,
            "crash recovery: detected batches from previous session"
        );

        // Log oldest in-flight batches for debugging
        if let Some(oldest_submitted) = summary.oldest_submitted_ms {
            let age_ms = now_ms().saturating_sub(oldest_submitted);
            debug!(
                oldest_submitted_ms = oldest_submitted,
                age_ms = age_ms,
                "oldest submitted batch"
            );
        }
        if let Some(oldest_included) = summary.oldest_included_ms {
            let age_ms = now_ms().saturating_sub(oldest_included);
            debug!(
                oldest_included_ms = oldest_included,
                age_ms = age_ms,
                "oldest included batch"
            );
        }
    } else {
        debug!("startup recovery: no in-flight batches found (clean state)");
    }

    info
}

// ============== Utility Functions ==============

fn now_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}
