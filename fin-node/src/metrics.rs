#![forbid(unsafe_code)]
// Prometheus histogram/gauge APIs use `f64`.
#![allow(clippy::float_arithmetic)]
#![allow(clippy::float_cmp)]
// Prometheus gauge APIs use `f64`.
#![allow(clippy::disallowed_types)]

use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Gauge, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    Opts, Registry, TextEncoder,
};
use std::time::Instant;

static START: Lazy<Instant> = Lazy::new(Instant::now);

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

pub static L1_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("l1_requests_total", "Total L1 RPC requests"),
        &["method", "status"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static L1_REQUEST_FAILURES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("l1_request_failures_total", "Total L1 RPC request failures"),
        &["reason"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static SUBMIT_BATCHES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("submit_batches_total", "Total submitted batches"),
        &["result"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static PROCESS_UPTIME_SECONDS: Lazy<Gauge> = Lazy::new(|| {
    let g = Gauge::with_opts(Opts::new(
        "process_uptime_seconds",
        "Process uptime in seconds",
    ))
    .expect("metric");
    REGISTRY.register(Box::new(g.clone())).expect("register");
    g
});

pub static RECON_PENDING_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    let g = IntGaugeVec::new(
        Opts::new("recon_pending_total", "Total pending reconciliation items"),
        &["kind"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(g.clone())).expect("register");
    g
});

pub static RECON_CHECKS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("recon_checks_total", "Total reconciliation checks"),
        &["kind", "result"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static RECON_FAILURES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("recon_failures_total", "Total reconciliation failures"),
        &["kind", "reason"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static HTTP_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("http_requests_total", "Total HTTP requests"),
        &["route", "status"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static HTTP_REQUEST_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    let opts = HistogramOpts::new(
        "http_request_duration_seconds",
        "HTTP request duration (seconds)",
    )
    // Reasonable default buckets for a small node.
    .buckets(vec![
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]);
    let h = HistogramVec::new(opts, &["route"]).expect("metric");
    REGISTRY.register(Box::new(h.clone())).expect("register");
    h
});

pub static RATE_LIMITED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("rate_limited_total", "Total rate-limited requests"),
        &["scope"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static PAYLOAD_REJECTED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("payload_rejected_total", "Total rejected payloads"),
        &["reason"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static PRUNING_DELETED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("pruning_deleted_total", "Total deleted items by pruning"),
        &["kind"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static HA_IS_LEADER: Lazy<IntGauge> = Lazy::new(|| {
    let g = IntGauge::with_opts(Opts::new(
        "ha_is_leader",
        "Whether this node is leader (0/1)",
    ))
    .expect("metric");
    REGISTRY.register(Box::new(g.clone())).expect("register");
    g
});

pub static HA_LEADER_CHANGES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("ha_leader_changes_total", "Total leadership transitions"),
        &["event"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static HA_LOCK_ACQUIRE_FAILURES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "ha_lock_acquire_failures_total",
            "Total HA lock acquire failures",
        ),
        &["reason"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static HA_LOCK_PROVIDER: Lazy<IntGaugeVec> = Lazy::new(|| {
    let g = IntGaugeVec::new(
        Opts::new(
            "ha_lock_provider",
            "Active HA lock provider (1 for active provider type)",
        ),
        &["type"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(g.clone())).expect("register");
    g
});

pub static HA_LOCK_ERRORS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("ha_lock_errors_total", "Total HA lock provider errors"),
        &["provider", "reason"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static RECEIPTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("receipts_total", "Total receipts by state"),
        &["hub", "state"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static SNAPSHOTS_CREATED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("snapshots_created_total", "Total snapshots created"),
        &["result"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static SNAPSHOT_FAILURES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "snapshot_failures_total",
            "Total snapshot failures (create/restore)",
        ),
        &["op", "reason"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static BOOTSTRAP_RESTORE_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    let opts = HistogramOpts::new(
        "bootstrap_restore_seconds",
        "Bootstrap restore duration (seconds)",
    )
    .buckets(vec![
        0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0,
    ]);
    let h = HistogramVec::new(opts, &["result"]).expect("metric");
    REGISTRY.register(Box::new(h.clone())).expect("register");
    h
});

pub static DELTAS_APPLIED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("deltas_applied_total", "Total applied delta snapshots"),
        &["result"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static DELTA_APPLY_FAILURES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "delta_apply_failures_total",
            "Total delta snapshot apply failures",
        ),
        &["reason"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static SNAPSHOT_DELTA_CREATED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "snapshot_delta_created_total",
            "Total delta snapshots created",
        ),
        &["result"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static SNAPSHOT_DELTA_SIZE_BYTES: Lazy<IntGaugeVec> = Lazy::new(|| {
    let g = IntGaugeVec::new(
        Opts::new(
            "snapshot_delta_size_bytes",
            "Delta snapshot size in bytes (last created)",
        ),
        &["scope"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(g.clone())).expect("register");
    g
});

// ============================================================
// Encryption-at-rest metrics (feature: encryption-at-rest)
// ============================================================

pub static ENCRYPTION_ENCRYPT_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::with_opts(Opts::new(
        "encryption_encrypt_total",
        "Total encryption operations (AEAD)",
    ))
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static ENCRYPTION_DECRYPT_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::with_opts(Opts::new(
        "encryption_decrypt_total",
        "Total decryption operations (AEAD)",
    ))
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static ENCRYPTION_FAILURES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "encryption_failures_total",
            "Total encryption/decryption failures",
        ),
        &["reason"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static ENCRYPTION_REWRAP_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    let opts = HistogramOpts::new("encryption_rewrap_seconds", "Rewrap duration (seconds)")
        .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 300.0]);
    let h = HistogramVec::new(opts, &["tree"]).expect("metric");
    REGISTRY.register(Box::new(h.clone())).expect("register");
    h
});

// ============================================================
// Remote bootstrap (fetcher) metrics
// ============================================================

pub static BOOTSTRAP_FETCH_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "bootstrap_fetch_total",
            "Total remote bootstrap fetch attempts",
        ),
        &["result"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static BOOTSTRAP_BYTES_DOWNLOADED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::with_opts(Opts::new(
        "bootstrap_bytes_downloaded_total",
        "Total bytes downloaded by remote bootstrap fetcher",
    ))
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static BOOTSTRAP_VERIFY_FAILURES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::with_opts(Opts::new(
        "bootstrap_verify_failures_total",
        "Total remote bootstrap verification failures",
    ))
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static BOOTSTRAP_PEER_FAILURES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "bootstrap_peer_failures_total",
            "Total bootstrap peer download failures",
        ),
        &["peer"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static BOOTSTRAP_QUORUM_MISMATCHES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::with_opts(Opts::new(
        "bootstrap_quorum_mismatches_total",
        "Total bootstrap peer quorum failures",
    ))
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static BOOTSTRAP_RESTORE_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "bootstrap_restore_total",
            "Total remote bootstrap restore attempts",
        ),
        &["result"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

// ============================================================
// Multi-source bootstrap hardening metrics
// ============================================================

pub static BOOTSTRAP_INDEX_QUORUM_FAILURES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::with_opts(Opts::new(
        "bootstrap_index_quorum_failures_total",
        "Total bootstrap index quorum failures",
    ))
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static BOOTSTRAP_ARTIFACT_QUORUM_FAILURES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::with_opts(Opts::new(
        "bootstrap_artifact_quorum_failures_total",
        "Total bootstrap artifact quorum failures",
    ))
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static BOOTSTRAP_MIRROR_LATENCY_MS: Lazy<HistogramVec> = Lazy::new(|| {
    let opts = HistogramOpts::new(
        "bootstrap_mirror_latency_ms",
        "Bootstrap mirror request latency (ms)",
    )
    .buckets(vec![
        5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
    ]);
    let h = HistogramVec::new(opts, &["source"]).expect("metric");
    REGISTRY.register(Box::new(h.clone())).expect("register");
    h
});

pub static BOOTSTRAP_MIRROR_HASH_MISMATCH_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "bootstrap_mirror_hash_mismatch_total",
            "Total bootstrap mirror hash mismatches (quorum/verification)",
        ),
        &["source"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static BOOTSTRAP_ROLLBACK_BLOCKED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::with_opts(Opts::new(
        "bootstrap_rollback_blocked_total",
        "Total bootstrap rollbacks blocked by anti-rollback guard",
    ))
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

// ============================================================
// L2 Multi-Hub Metrics
// ============================================================

pub static L2_QUEUE_DEPTH: Lazy<IntGaugeVec> = Lazy::new(|| {
    let g = IntGaugeVec::new(
        Opts::new("l2_queue_depth", "L2 transaction queue depth per hub"),
        &["hub"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(g.clone())).expect("register");
    g
});

pub static L2_FORCED_QUEUE_DEPTH: Lazy<IntGaugeVec> = Lazy::new(|| {
    let g = IntGaugeVec::new(
        Opts::new(
            "l2_forced_queue_depth",
            "L2 forced transaction queue depth per hub",
        ),
        &["hub"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(g.clone())).expect("register");
    g
});

pub static L2_BATCHES_CREATED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("l2_batches_created_total", "Total L2 batches created per hub"),
        &["hub"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static L2_BATCHES_SUBMITTED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "l2_batches_submitted_total",
            "Total L2 batches submitted per hub",
        ),
        &["hub"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static L2_BATCHES_FINALISED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "l2_batches_finalised_total",
            "Total L2 batches finalised per hub",
        ),
        &["hub"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static L2_IN_FLIGHT_BATCHES: Lazy<IntGaugeVec> = Lazy::new(|| {
    let g = IntGaugeVec::new(
        Opts::new(
            "l2_in_flight_batches",
            "L2 in-flight batches (submitted but not finalised) per hub",
        ),
        &["hub"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(g.clone())).expect("register");
    g
});

pub static L2_M2M_FEE_FINALISED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "l2_m2m_fee_finalised_total",
            "Total M2M fees finalised (scaled, M2M hub only)",
        ),
        &["hub"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static L2_ORGANISER_CHOSEN_HUB: Lazy<IntGaugeVec> = Lazy::new(|| {
    let g = IntGaugeVec::new(
        Opts::new(
            "l2_organiser_chosen_hub",
            "Last organiser chosen hub (1 for chosen, 0 otherwise)",
        ),
        &["hub"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(g.clone())).expect("register");
    g
});

pub static L2_ORGANISER_DECISIONS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::with_opts(Opts::new(
        "l2_organiser_decisions_total",
        "Total organiser V2 decisions made",
    ))
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static L2_TXS_RECEIVED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("l2_txs_received_total", "Total L2 transactions received per hub"),
        &["hub"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

pub static L2_TXS_BATCHED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "l2_txs_batched_total",
            "Total L2 transactions batched per hub",
        ),
        &["hub"],
    )
    .expect("metric");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
});

/// Update L2 organiser chosen hub metric.
pub fn set_l2_chosen_hub(chosen_hub: &str) {
    // Clear all and set chosen
    for hub in &["fin", "data", "m2m", "world", "bridge"] {
        L2_ORGANISER_CHOSEN_HUB
            .with_label_values(&[hub])
            .set(if *hub == chosen_hub { 1 } else { 0 });
    }
}

pub fn gather_text() -> String {
    PROCESS_UPTIME_SECONDS.set(START.elapsed().as_secs_f64());
    let mf = REGISTRY.gather();
    let mut out = Vec::new();
    TextEncoder::new().encode(&mf, &mut out).expect("encode");
    String::from_utf8(out).unwrap_or_default()
}
