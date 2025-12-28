# Performance Tuning Playbook

This document provides guidance for tuning IPPAN L2 system performance. It covers the key configuration knobs, their expected impact, and how to use the benchmark suite to validate changes.

## Table of Contents

- [Overview](#overview)
- [Running Benchmarks](#running-benchmarks)
- [Profiling with Flamegraphs](#profiling-with-flamegraphs)
- [Tuning Knobs Reference](#tuning-knobs-reference)
- [Scenario-Specific Tuning](#scenario-specific-tuning)
- [Monitoring in Production](#monitoring-in-production)

---

## Overview

The L2 system has several critical performance paths:

| Path | Description | Key Metrics |
|------|-------------|-------------|
| **Batcher** | Collects transactions and builds batches | Throughput (txs/sec), Batch fill time |
| **Organiser** | Decides batch parameters (size, timing) | Decision latency, Queue depth responsiveness |
| **M2M Accounting** | Fee reservation and finalization | Reserve latency, Finalize throughput |
| **Reconciler** | Tracks settlement state transitions | Scan latency, State transition rate |
| **Bridge Proofs** | Verifies external chain events | Attestation verify time, Merkle verify time |

---

## Running Benchmarks

### Quick Start

```bash
# Run all benchmark scenarios
cargo run --release -p l2-bench -- run

# Run specific scenarios
cargo run --release -p l2-bench -- run --scenarios batcher,organiser

# Run with more iterations for stable results
cargo run --release -p l2-bench -- run --iterations 10000

# Output results to JSON
cargo run --release -p l2-bench -- run --output results.json

# List available scenarios
cargo run --release -p l2-bench -- list
```

### Criterion Microbenchmarks

For more detailed measurements of hot functions:

```bash
# Core functions (fees, encoding, batch envelope)
cargo bench -p l2-core --bench core_benchmarks

# Batcher/organiser functions
cargo bench -p l2-batcher --bench batcher_benchmarks

# Bridge functions (attestation, Merkle)
cargo bench -p l2-bridge --bench bridge_benchmarks
cargo bench -p l2-bridge --bench bridge_benchmarks --features merkle-proofs
```

### Interpreting Results

The `bench.json` output contains:

```json
{
  "metadata": {
    "git_commit": "abc123...",
    "cpu_info": "Intel...",
    "timestamp_ms": 1700000000000
  },
  "results": [
    {
      "name": "batcher_throughput",
      "ops": 50000,
      "duration_ms": 1234,
      "latency": {
        "min_us": 10,
        "max_us": 500,
        "mean_us": 50,
        "p50_us": 45,
        "p95_us": 120,
        "p99_us": 250
      }
    }
  ],
  "summary": {
    "total_duration_ms": 5000,
    "scenarios_run": 6,
    "scenarios_passed": 6
  }
}
```

Key metrics to watch:
- **p50_us**: Median latency (typical case)
- **p95_us**: Tail latency (important for SLAs)
- **p99_us**: Extreme tail latency
- **ops/sec**: Throughput capability

---

## Profiling with Flamegraphs

### Enable Profiling

Build with the `profiling` feature to add tracing spans:

```bash
cargo build --release -p l2-batcher --features profiling
```

### Generate Flamegraphs

Install `cargo-flamegraph`:

```bash
cargo install flamegraph
```

Run with profiling:

```bash
# Linux (requires perf)
cargo flamegraph --release -p l2-bench -- run --scenarios batcher

# Alternative: use perf directly
perf record -g cargo run --release -p l2-bench -- run
perf script | inferno-collapse-perf | inferno-flamegraph > flamegraph.svg
```

### Profiling Spans

The following hot paths have `tracing::instrument` spans when the `profiling` feature is enabled:

| Crate | Function | Span Name |
|-------|----------|-----------|
| l2-core | `compute_m2m_fee` | `compute_m2m_fee` |
| l2-core | `BatchPayload::new` | `batch_payload_new` |
| l2-core | `BatchPayload::hash` | `batch_payload_hash` |
| l2-core | `BatchEnvelope::new_unsigned` | `batch_envelope_new_unsigned` |
| l2-core | `BatchEnvelope::signing_bytes` | `batch_envelope_signing_bytes` |
| l2-core | `compute_tx_root` | `compute_tx_root` |
| l2-core | `NoopOrganiser::decide` | `noop_organiser_decide` |
| l2-batcher | `GbdtOrganiserV1::decide` | `gbdt_organiser_decide` |
| l2-batcher | `run_reconcile_cycle` | `reconcile_cycle` |
| l2-storage | `reserve_fee_by_tx_id` | `m2m_reserve_fee` |
| l2-storage | `finalise_fee_by_tx_id` | `m2m_finalise_fee` |

---

## Tuning Knobs Reference

### Organiser Policy Bounds

Located in `l2-core/src/organiser.rs`:

| Parameter | Default | Range | Impact |
|-----------|---------|-------|--------|
| `min_sleep_ms` | 10 | 1-1000 | Lower = more responsive, higher CPU |
| `max_sleep_ms` | 5000 | 100-60000 | Upper bound for idle sleep |
| `min_max_txs` | 1 | 1-100 | Minimum batch size |
| `max_max_txs` | 1024 | 100-10000 | Maximum batch size |
| `min_max_bytes` | 1024 | 512-1MB | Minimum batch bytes |
| `max_max_bytes` | 1MB | 64KB-4MB | Maximum batch bytes |
| `min_forced_drain_max` | 0 | 0-100 | Minimum forced tx drain |
| `max_forced_drain_max` | 256 | 100-1000 | Maximum forced tx drain |

**Impact Summary:**
- **`min_sleep_ms`**: Lower values make the batcher more responsive to queue buildup but increase CPU usage during idle periods.
- **`max_max_txs`**: Higher values allow larger batches, improving throughput but increasing memory usage and settlement latency.
- **`max_max_bytes`**: Controls batch size in bytes; larger batches are more efficient but take longer to fill.

### GBDT Organiser Thresholds

The GBDT (Gradient Boosted Decision Tree) organiser uses heuristics to decide batch parameters:

| Threshold | Default | Impact |
|-----------|---------|--------|
| `queue_high` | 500 | Above this, reduce sleep time |
| `queue_critical` | 1000 | Above this, maximize batch size |
| `backpressure_threshold` | 3 | In-flight batches before throttling |
| `forced_high` | 100 | Forced queue depth trigger |

**Tuning Guidelines:**
- If latency is high, lower `queue_high` to react sooner
- If throughput is low, raise `max_max_txs` and `max_max_bytes`
- If CPU is high during idle, raise `min_sleep_ms`

### M2M Fee Parameters

Located in `l2-core/src/fees.rs`:

| Parameter | Default | Impact |
|-----------|---------|--------|
| `base_fee_per_tx` | 100 | Minimum fee per transaction |
| `bytes_fee_per_byte` | 1 | Fee per byte of tx data |
| `priority_multiplier` | 1.5 | Multiplier for priority txs |

### Reconciler Configuration

Located in `l2-batcher/src/reconciler.rs`:

| Parameter | Default | Impact |
|-----------|---------|--------|
| `poll_interval_ms` | 5000 | How often to scan for state changes |
| `max_concurrent_checks` | 10 | Parallel settlement checks |
| `retry_delay_ms` | 1000 | Delay before retrying failed ops |

**Tuning Guidelines:**
- Lower `poll_interval_ms` for faster settlement confirmation
- Increase `max_concurrent_checks` if settlement is bottlenecked

### Bridge Verification Limits

Located in `l2-bridge/src/eth_merkle.rs`:

| Parameter | Default | Impact |
|-----------|---------|--------|
| `max_proof_nodes` | 32 | Maximum MPT proof depth |
| `max_proof_bytes` | 64KB | Total proof size limit |
| `max_header_rlp_bytes` | 8KB | Block header size limit |
| `max_receipt_rlp_bytes` | 32KB | Receipt size limit |
| `max_recursion_depth` | 64 | MPT recursion limit |

**Security vs. Performance:**
- Higher limits allow more complex proofs but increase DoS surface
- Lower limits are more secure but may reject valid proofs

---

## Scenario-Specific Tuning

### High Throughput (Many Small Transactions)

```toml
[organiser.bounds]
min_sleep_ms = 1
max_max_txs = 2048
max_max_bytes = 2097152  # 2MB

[reconciler]
poll_interval_ms = 1000
```

### Low Latency (Fast Confirmation)

```toml
[organiser.bounds]
min_sleep_ms = 1
max_sleep_ms = 100
min_max_txs = 1

[reconciler]
poll_interval_ms = 500
```

### Resource Constrained (Limited Memory/CPU)

```toml
[organiser.bounds]
min_sleep_ms = 100
max_max_txs = 256
max_max_bytes = 262144  # 256KB

[reconciler]
poll_interval_ms = 10000
max_concurrent_checks = 3
```

### High Volume Bridge Proofs

```toml
[bridge.verification]
max_proof_nodes = 48
max_proof_bytes = 131072  # 128KB

[bridge.reconciler]
poll_interval_ms = 2000
batch_size = 50
```

---

## Monitoring in Production

### Key Metrics to Track

| Metric | Healthy Range | Alert Threshold |
|--------|---------------|-----------------|
| `batcher_queue_depth` | 0-100 | > 500 |
| `batcher_batch_fill_ms` | 10-100 | > 500 |
| `m2m_reserve_latency_p99` | < 10ms | > 50ms |
| `reconciler_scan_latency` | < 100ms | > 1000ms |
| `bridge_verify_latency_p95` | < 50ms | > 200ms |

### Prometheus Metrics

The system exposes metrics at `/metrics`:

```
# Batcher
l2_batcher_queue_depth
l2_batcher_batches_created_total
l2_batcher_batch_size_bytes

# M2M
l2_m2m_fees_reserved_total
l2_m2m_fees_finalized_total
l2_m2m_reserve_latency_seconds

# Reconciler
l2_reconciler_cycles_total
l2_reconciler_batches_submitted
l2_reconciler_batches_included

# Bridge
l2_bridge_proofs_verified_total
l2_bridge_proofs_rejected_total
l2_bridge_verify_latency_seconds
```

### Alerting Rules

Example Prometheus alerting rules:

```yaml
groups:
  - name: l2-performance
    rules:
      - alert: BatcherQueueHigh
        expr: l2_batcher_queue_depth > 500
        for: 5m
        annotations:
          summary: "Batcher queue depth is high"
          
      - alert: M2MLatencyHigh
        expr: histogram_quantile(0.99, l2_m2m_reserve_latency_seconds) > 0.05
        for: 2m
        annotations:
          summary: "M2M fee reservation latency is high"
```

---

## Appendix: Benchmark Scenarios

| Scenario | Description | Key Output |
|----------|-------------|------------|
| `batcher_throughput` | Measures batch building speed | txs/sec, batch fill time |
| `organiser_overhead` | Measures decision overhead | decisions/sec, latency |
| `m2m_accounting` | Measures fee operations | reserve/finalize latency |
| `reconciler_scan` | Measures state scanning | scan latency, transitions/sec |
| `bridge_attestation_verify` | Measures attestation checks | verifications/sec |
| `bridge_merkle_verify` | Measures Merkle proofs | verifications/sec |

Run `cargo run --release -p l2-bench -- list` for the current list of available scenarios.
