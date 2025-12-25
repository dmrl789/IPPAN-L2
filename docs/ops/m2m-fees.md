# Machine-to-Machine (M2M) Fees

This document describes the deterministic fee model for IPPAN L2 machine-to-machine
operations.

## Overview

M2M fees provide predictable, integer-only pricing for batch settlement operations.
The model is designed for:

1. **Determinism**: Same inputs always produce same fees
2. **Predictability**: Fees can be calculated before execution
3. **Transparency**: Fee breakdowns are auditable
4. **Integer arithmetic**: No floating-point rounding issues

## Fee Model

### Fee Amount

All fees are represented as `FeeAmount`, a 64-bit unsigned integer with
6 decimal places of precision (1,000,000 units = 1 token):

```rust
// 1.5 tokens = 1_500_000
let fee = FeeAmount(1_500_000);
```

### Fee Breakdown

Each operation has a fee breakdown:

```rust
struct M2mFeeBreakdown {
    exec_units: u64,      // Execution units consumed
    data_bytes: u64,      // Data bytes processed
    storage_writes: u32,  // Storage operations
    total_fee: FeeAmount, // Calculated total
}
```

### Fee Policy

Fees are calculated using a deterministic policy:

```rust
struct M2mFeePolicy {
    cost_per_exec_unit: u64,      // Microunits per exec unit
    cost_per_data_byte: u64,      // Microunits per byte
    cost_per_storage_write: u64,  // Microunits per write
}
```

### Calculation

```
total_fee = (exec_units × cost_per_exec_unit)
          + (data_bytes × cost_per_data_byte)
          + (storage_writes × cost_per_storage_write)
```

All arithmetic is saturating (no overflow panics).

## Fee Flow

### 1. Reservation

Before execution, a maximum fee is reserved:

```rust
let reservation = FeeReservation {
    request_id: "req-123",
    max_fee: FeeAmount(1_000_000),  // 1 token max
    reserved_at_ms: timestamp,
};
```

### 2. Execution

Operation executes and actual resources are measured:

```rust
let actual = M2mFeeBreakdown {
    exec_units: 5000,
    data_bytes: 1024,
    storage_writes: 3,
    total_fee: policy.calculate(5000, 1024, 3),
};
```

### 3. Finalization

Reserved fee is finalized with actual usage:

```rust
let finalized = reservation.finalize(actual);
// finalized.breakdown - actual resources used
// finalized.refund - unused reservation returned
```

## Batch Aggregation

Fees are aggregated per batch:

```rust
struct BatchFeeAggregate {
    batch_id: String,
    operation_count: u32,
    total_exec_units: u64,
    total_data_bytes: u64,
    total_storage_writes: u64,
    total_fee: FeeAmount,
}
```

This aggregate is included in batch settlement metadata for auditing.

## Configuration

### Default Policy

```toml
[fees.m2m]
cost_per_exec_unit = 10        # 0.00001 tokens per unit
cost_per_data_byte = 1         # 0.000001 tokens per byte
cost_per_storage_write = 1000  # 0.001 tokens per write
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `L2_FEE_EXEC_UNIT` | 10 | Cost per execution unit |
| `L2_FEE_DATA_BYTE` | 1 | Cost per data byte |
| `L2_FEE_STORAGE_WRITE` | 1000 | Cost per storage write |

## Examples

### Simple Transaction

```rust
// 1000 exec units, 256 bytes, 1 write
let policy = M2mFeePolicy::default();
let fee = policy.calculate(1000, 256, 1);
// = (1000 × 10) + (256 × 1) + (1 × 1000)
// = 10000 + 256 + 1000
// = 11256 microunits (0.011256 tokens)
```

### Large Data Operation

```rust
// 5000 exec units, 100KB data, 10 writes
let fee = policy.calculate(5000, 102400, 10);
// = (5000 × 10) + (102400 × 1) + (10 × 1000)
// = 50000 + 102400 + 10000
// = 162400 microunits (0.1624 tokens)
```

### Batch of 100 Operations

```rust
let aggregate = BatchFeeAggregate {
    operation_count: 100,
    total_exec_units: 500_000,
    total_data_bytes: 1_000_000,
    total_storage_writes: 100,
    total_fee: FeeAmount(6_100_000), // 6.1 tokens
};
```

## Integration

### Batcher Integration

The batcher tracks fees for each operation:

```rust
// On operation submission
let reservation = fee_service.reserve(max_fee)?;

// After execution
let actual = measure_resources(&result);
let finalized = reservation.finalize(actual);

// Add to batch aggregate
batch.add_fee(finalized);
```

### Settlement Metadata

Fee aggregates are included in settlement:

```json
{
  "batch_id": "batch-abc",
  "fee_aggregate": {
    "operation_count": 50,
    "total_exec_units": 250000,
    "total_data_bytes": 500000,
    "total_storage_writes": 50,
    "total_fee": 3050000
  }
}
```

## Monitoring

### Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `l2_fee_reserved_total` | Counter | Total fees reserved |
| `l2_fee_finalized_total` | Counter | Total fees finalized |
| `l2_fee_refunded_total` | Counter | Total refunds |
| `l2_fee_per_batch_avg` | Gauge | Average fee per batch |

### Status Endpoint

```json
{
  "fees": {
    "policy": {
      "cost_per_exec_unit": 10,
      "cost_per_data_byte": 1,
      "cost_per_storage_write": 1000
    },
    "totals_24h": {
      "reserved": 10000000,
      "finalized": 8500000,
      "refunded": 1500000
    }
  }
}
```

## Design Principles

### Why Integer-Only?

1. **Determinism**: Floating-point arithmetic can vary across platforms
2. **Auditability**: Exact values can be verified
3. **Simplicity**: No rounding mode considerations
4. **Precision**: 6 decimal places covers most use cases

### Why Reservation Model?

1. **Predictability**: Users know max cost upfront
2. **Atomicity**: Fees are guaranteed before execution
3. **Fairness**: Unused fees are returned
4. **Simplicity**: No complex credit/debit tracking

### Why Per-Resource Pricing?

1. **Transparency**: Each resource has clear cost
2. **Flexibility**: Can adjust individual costs
3. **Fairness**: Pay for what you use
4. **Optimization**: Incentivizes efficient operations

## Future Considerations

### Not Implemented (Intentionally)

The following are explicitly **not** part of the current model:

- **Dynamic pricing**: Fees are static, not demand-based
- **Auctions**: No bidding or priority pricing
- **Discounts**: No volume or time-based discounts
- **Complex models**: No tiered or graduated pricing

These may be considered for future versions but are not needed for
the current M2M use case.

### Potential Enhancements

Future versions may add:

1. **Fee estimation API**: Predict fee before submission
2. **Batch discounts**: Lower per-op cost in large batches
3. **Priority lanes**: Optional higher fees for faster processing

## Troubleshooting

### Fee Calculation Mismatch

**Symptoms**: Client calculates different fee than node

**Resolution**:
1. Verify policy values match
2. Check for integer overflow
3. Ensure same calculation order

### Reservation Failures

**Symptoms**: Cannot reserve fees

**Resolution**:
1. Check account balance
2. Verify max_fee is reasonable
3. Review reservation limits

### Unexpected Refunds

**Symptoms**: Large refunds indicate over-reservation

**Resolution**:
1. Review reservation estimation
2. Adjust max_fee calculations
3. Monitor actual vs reserved ratios

## See Also

- [Settlement Lifecycle](../SETTLEMENT_LIFECYCLE.md)
- [Restart Recovery](restart-recovery.md)
- [API Documentation](../API.md)
