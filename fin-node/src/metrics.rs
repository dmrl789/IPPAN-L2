#![forbid(unsafe_code)]
// Prometheus histogram/gauge APIs use `f64`.
#![allow(clippy::float_arithmetic)]
#![allow(clippy::float_cmp)]
// Prometheus gauge APIs use `f64`.
#![allow(clippy::disallowed_types)]

use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Gauge, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
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

pub fn gather_text() -> String {
    PROCESS_UPTIME_SECONDS.set(START.elapsed().as_secs_f64());
    let mf = REGISTRY.gather();
    let mut out = Vec::new();
    TextEncoder::new().encode(&mf, &mut out).expect("encode");
    String::from_utf8(out).unwrap_or_default()
}
