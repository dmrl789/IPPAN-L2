# GBDT Organiser for L2 Batch Scheduling

This document describes the GBDT (Gradient Boosted Decision Tree) Organiser, a **policy-only** component that influences batch scheduling and fairness for IPPAN L2.

## Overview

The organiser controls:

1. **Batch Timing** - How long to wait before building the next batch
2. **Batch Sizing** - Maximum transactions and bytes per batch
3. **Forced Queue Draining** - Rate at which forced inclusion transactions are processed

**Critical constraint**: The organiser **never** changes fee rates or accepts unpaid transactions. Fee pricing is determined solely by the [M2M Fee Model](./M2M_FEES.md).

## Design Principles

### Determinism

All organiser decisions are:

1. **Reproducible**: Same inputs always produce identical outputs (bit-exact)
2. **Integer-only**: No floats (`f32`/`f64` forbidden), no floating-point arithmetic
3. **No randomness**: No RNG, no non-deterministic operations
4. **Bounded**: All outputs are clamped to hard policy bounds

### Policy-Only

The organiser is a policy layer that influences scheduling without touching settlement truth:

```
┌─────────────────────────────────────────────────────────────┐
│                    Settlement Truth                          │
│  (fees, balances, inclusion rules - IMMUTABLE by organiser) │
└─────────────────────────────────────────────────────────────┘
                              ↑
                              │ never changes
                              │
┌─────────────────────────────────────────────────────────────┐
│                      Organiser Layer                         │
│     (scheduling, timing, fairness - INFLUENCES batching)    │
└─────────────────────────────────────────────────────────────┘
```

## Input Features

The organiser receives observable, deterministic inputs:

| Input | Type | Description |
|-------|------|-------------|
| `now_ms` | `u64` | Current timestamp (milliseconds since epoch) |
| `queue_depth` | `u32` | Transactions waiting in normal queue |
| `forced_queue_depth` | `u32` | Transactions in forced inclusion queue |
| `in_flight_batches` | `u32` | Batches submitted but not yet finalised |
| `recent_quota_rejects` | `u32` | Recent quota rejection count (rolling window) |
| `recent_insufficient_balance` | `u32` | Recent balance rejection count (rolling window) |
| `recent_forced_used_bytes` | `u64` | Recent forced tx bytes (rolling window) |
| `avg_tx_bytes_est` | `u32` | Moving average of tx size (integer EMA) |

### Example Inputs

```json
{
  "now_ms": 1700000000000,
  "queue_depth": 150,
  "forced_queue_depth": 5,
  "in_flight_batches": 2,
  "recent_quota_rejects": 10,
  "recent_insufficient_balance": 3,
  "recent_forced_used_bytes": 50000,
  "avg_tx_bytes_est": 256
}
```

## Decision Outputs

The organiser produces scheduling decisions:

| Output | Type | Description |
|--------|------|-------------|
| `sleep_ms` | `u64` | Time to wait before building next batch |
| `max_txs` | `u32` | Maximum transactions to include |
| `max_bytes` | `u32` | Maximum bytes to include |
| `forced_drain_max` | `u32` | Maximum forced queue txs to drain |

### Example Decision

```json
{
  "sleep_ms": 250,
  "max_txs": 192,
  "max_bytes": 393216,
  "forced_drain_max": 64
}
```

## Policy Bounds

All decisions are clamped to hard bounds that cannot be exceeded:

| Parameter | Min | Max | Description |
|-----------|-----|-----|-------------|
| `sleep_ms` | 10 | 60,000 | Batch interval bounds |
| `max_txs` | 1 | 1,024 | Transactions per batch |
| `max_bytes` | 1,024 | 4,194,304 | Bytes per batch |
| `forced_drain` | 0 | 256 | Forced queue drain cap |

### Custom Bounds

Override defaults via environment variables:

```bash
L2_ORGANISER_SLEEP_MS_MIN=50
L2_ORGANISER_SLEEP_MS_MAX=30000
L2_ORGANISER_MAX_TXS_MIN=10
L2_ORGANISER_MAX_TXS_MAX=500
L2_ORGANISER_MAX_BYTES_MIN=4096
L2_ORGANISER_MAX_BYTES_MAX=1048576
L2_ORGANISER_FORCED_DRAIN_MIN=1
L2_ORGANISER_FORCED_DRAIN_MAX=100
```

## Decision Logic (v1)

The GBDT Organiser v1 uses a compiled decision tree with integer thresholds:

### Sleep Duration

```
if in_flight_batches >= 3:
    sleep_ms = base_sleep * in_flight_batches  # Backpressure
elif queue_depth > 500:
    sleep_ms = base_sleep / 10  # Very fast draining
elif queue_depth > 100:
    sleep_ms = base_sleep / 4   # Fast draining
elif queue_depth > 20:
    sleep_ms = base_sleep / 2   # Moderate draining
else:
    sleep_ms = base_sleep       # Normal operation
```

### Batch Sizing

```
if queue_depth > 500:
    max_txs = base_max_txs      # 100% capacity
elif queue_depth > 100:
    max_txs = base_max_txs * 3/4  # 75% capacity
elif queue_depth > 20:
    max_txs = base_max_txs / 2    # 50% capacity
else:
    max_txs = base_max_txs / 4    # 25% capacity (smaller batches when idle)
```

### Forced Queue Draining

```
if recent_forced_bytes > 100KB:
    reduction_factor = 4  # High forced traffic, reduce
elif recent_forced_bytes > 50KB:
    reduction_factor = 2  # Moderate forced traffic
else:
    reduction_factor = 1  # Normal

if forced_queue_depth > 50:
    forced_drain_max = base_forced / reduction_factor
elif forced_queue_depth > 10:
    forced_drain_max = (base_forced / 2) / reduction_factor
else:
    forced_drain_max = (base_forced / 4) / reduction_factor
```

## API

### Status Endpoint

The `/status` endpoint includes organiser state:

```json
{
  "organiser": {
    "enabled": true,
    "version": "gbdt_v1",
    "last_inputs": {
      "queue_depth": 150,
      "forced_queue_depth": 5,
      "in_flight_batches": 2,
      "...": "..."
    },
    "last_decision": {
      "sleep_ms": 250,
      "max_txs": 192,
      "max_bytes": 393216,
      "forced_drain_max": 64
    },
    "bounds": {
      "sleep_ms_min": 10,
      "sleep_ms_max": 60000,
      "...": "..."
    }
  }
}
```

### Metrics

Prometheus metrics for monitoring:

| Metric | Type | Description |
|--------|------|-------------|
| `l2_organiser_decisions_total` | Counter | Total decisions made |
| `l2_organiser_sleep_ms_last` | Gauge | Last sleep duration |
| `l2_organiser_max_txs_last` | Gauge | Last max_txs value |
| `l2_organiser_max_bytes_last` | Gauge | Last max_bytes value |

## Configuration

### Enable/Disable

```bash
L2_ORGANISER_ENABLED=true   # Enable (default)
L2_ORGANISER_ENABLED=false  # Disable (use static config)
```

### Base Parameters

```bash
L2_ORGANISER_BASE_SLEEP_MS=1000       # Default idle sleep
L2_ORGANISER_BASE_MAX_TXS=256         # Default max transactions
L2_ORGANISER_BASE_MAX_BYTES=524288    # Default max bytes (512KB)
L2_ORGANISER_BASE_FORCED_DRAIN=128    # Default forced drain cap
```

## Safety Guarantees

### Determinism Tests

The organiser is tested for:

1. **Bit-exact reproducibility**: Same inputs → identical outputs
2. **Cross-instance consistency**: Different organiser instances produce same results
3. **Timestamp independence**: Decision logic doesn't depend on wall-clock time

### Bounds Tests

1. All decisions are verified to be within policy bounds
2. Extreme inputs (max u32/u64) don't cause panics or overflow
3. Zero inputs produce valid (positive) outputs

### Monotonic Sanity

1. Higher queue depth doesn't increase sleep (unless backpressure)
2. Higher forced_queue_depth doesn't decrease forced_drain_max
3. Higher queue depth doesn't decrease max_txs

## Version History

| Version | Description |
|---------|-------------|
| `none` | No organiser (static config fallback) |
| `gbdt_v1` | Compiled tree with integer thresholds |

## Future Work

- **Model File Loading**: Load tree from hash-locked JSON file
- **Per-Hub Organisers**: Separate schedulers for FIN/DATA/M2M/WORLD/BRIDGE
- **Hub Fairness**: Balance batch allocation across hubs
- **Adaptive Thresholds**: Learn optimal thresholds from historical data

## References

- [M2M Fee Model](./M2M_FEES.md) - Fee pricing (independent of organiser)
- GBDT Organiser source: `crates/l2-batcher/src/gbdt_organiser.rs`
- Organiser interface: `crates/l2-core/src/organiser.rs`
- Determinism tests: `crates/l2-batcher/tests/organiser_determinism.rs`
