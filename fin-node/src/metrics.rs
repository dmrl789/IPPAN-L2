#![forbid(unsafe_code)]
// Prometheus gauge APIs use `f64`.
#![allow(clippy::disallowed_types)]

use once_cell::sync::Lazy;
use prometheus::{Encoder, Gauge, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder};
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

pub fn gather_text() -> String {
    PROCESS_UPTIME_SECONDS.set(START.elapsed().as_secs_f64());
    let mf = REGISTRY.gather();
    let mut out = Vec::new();
    TextEncoder::new().encode(&mf, &mut out).expect("encode");
    String::from_utf8(out).unwrap_or_default()
}
