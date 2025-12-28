# IPPAN L2 Profiling Guide

This document explains how to profile the IPPAN L2 system using the `profiling` feature flag and generate flamegraphs.

## Enabling Profiling

The `profiling` feature adds tracing spans to hot paths throughout the codebase:

- **l2-core**: `compute_m2m_fee`, `compute_tx_root`, batch envelope building
- **l2-batcher**: organiser `decide()`, reconciler iteration
- **l2-storage**: M2M reserve/finalise operations
- **l2-bridge**: Merkle proof verification (when enabled)

### Build with Profiling

```bash
# Build with profiling enabled
cargo build --release --features profiling

# Or for specific crates
cargo build --release -p l2-batcher --features profiling
```

## Generating Flamegraphs

### Using cargo-flamegraph

1. Install cargo-flamegraph:

```bash
cargo install flamegraph
```

2. Run with profiling:

```bash
# Generate flamegraph from benchmark
cargo flamegraph --release --features profiling -p l2-bench -- run --scenario all --txs 10000 --out bench.json
```

3. View the generated `flamegraph.svg` in a browser.

### Using perf (Linux)

1. Build with debug symbols:

```bash
RUSTFLAGS="-C debuginfo=2" cargo build --release --features profiling -p l2-bench
```

2. Record with perf:

```bash
perf record -g --call-graph dwarf target/release/l2-bench run --scenario m2m_accounting --txs 50000 --out bench.json
```

3. Generate report:

```bash
perf report -g
```

4. Or generate flamegraph:

```bash
perf script | stackcollapse-perf.pl | flamegraph.pl > perf-flamegraph.svg
```

## Tracing Spans

The following tracing spans are available when `profiling` is enabled:

### l2-core

| Span Name | Function | Description |
|-----------|----------|-------------|
| `envelope_build` | `BatchEnvelope::new_unsigned` | Building batch envelopes |
| `compute_m2m_fee` | `compute_m2m_fee` | M2M fee calculation |
| `compute_tx_root` | `compute_tx_root` | Transaction root computation |

### l2-batcher

| Span Name | Function | Description |
|-----------|----------|-------------|
| `gbdt_organiser_decide` | `GbdtOrganiserV1::decide` | Organiser decision making |
| `reconcile_iteration` | `run_reconcile_cycle` | Settlement reconciliation |

### l2-storage

| Span Name | Function | Description |
|-----------|----------|-------------|
| `m2m_reserve_fee` | `reserve_fee_by_tx_id` | Fee reservation |
| `m2m_finalise_fee` | `finalise_fee_by_tx_id` | Fee finalization |

## Using tracing-subscriber

For runtime profiling with tracing output:

```rust
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

tracing_subscriber::registry()
    .with(fmt::layer())
    .with(EnvFilter::from_default_env())
    .init();
```

Run with span tracing:

```bash
RUST_LOG=debug RUST_LOG_SPAN_EVENTS=new,close cargo run --release --features profiling ...
```

## Performance Tips

1. **Always profile in release mode** - Debug builds have significant overhead.

2. **Use consistent workloads** - The l2-bench tool provides deterministic benchmarks.

3. **Disable logging in production** - Set `RUST_LOG=error` for minimal overhead.

4. **Profile specific scenarios** - Use targeted benchmarks rather than full suite.

5. **Compare across commits** - Save benchmark JSON outputs to track regressions.

## Overhead

The profiling feature adds approximately:
- 10-50ns per span enter/exit (release mode)
- Negligible memory overhead

For production, disable the `profiling` feature entirely.
