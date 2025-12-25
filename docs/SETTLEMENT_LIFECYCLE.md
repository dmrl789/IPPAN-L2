# Settlement Lifecycle

This document describes the complete settlement lifecycle for IPPAN L2 batches,
from creation to L1 finality.

## Overview

The settlement lifecycle tracks batches through a deterministic state machine
that ensures:

1. **Crash safety**: State survives node restarts
2. **Idempotency**: Re-submissions never produce duplicate settlements
3. **Recovery**: In-flight batches are automatically reconciled
4. **Observability**: Every state transition is logged and metriced

## State Machine

```
┌─────────┐     ┌───────────┐     ┌──────────┐     ┌───────────┐
│ Created │────▶│ Submitted │────▶│ Included │────▶│ Finalised │
└─────────┘     └───────────┘     └──────────┘     └───────────┘
     │               │                 │
     │               │                 │
     ▼               ▼                 ▼
┌─────────────────────────────────────────────────────────────┐
│                          Failed                              │
└─────────────────────────────────────────────────────────────┘
```

### States

| State | Description | Terminal? |
|-------|-------------|-----------|
| `Created` | Batch has been created and stored locally | No |
| `Submitted` | Batch has been submitted to L1 | No |
| `Included` | Batch is included in an L1 block | No |
| `Finalised` | Batch has reached L1 finality | Yes |
| `Failed` | Settlement failed | Yes |

### Transitions

State transitions are **monotonic**: once a batch reaches a terminal state,
it cannot transition to any other state.

Valid transitions:
- `Created → Submitted`: When batch is posted to L1
- `Submitted → Included`: When L1 reports inclusion
- `Included → Finalised`: When finality confirmations reached
- `* → Failed`: Any non-terminal state can transition to Failed

Invalid transitions (will be rejected):
- Any state → earlier state (going backwards)
- Terminal state → any state
- Skipping states (e.g., Created → Included)

## Idempotency Guarantees

### Idempotency Key Derivation

Each batch has a deterministic idempotency key derived from:

```
idempotency_key = blake3(
    "ippan-l1l2" ||
    contract_version ||
    hub ||
    batch_id ||
    sequence ||
    payload_hash
)
```

This ensures:
1. **Determinism**: Same batch always produces same key
2. **Uniqueness**: Different batches produce different keys
3. **Replay safety**: L1 can detect duplicate submissions

### Crash Recovery

On restart, the node:

1. Scans storage for batches in non-terminal states
2. Logs recovery information
3. Starts the reconciler to continue processing

The reconciler handles:
- `Submitted` batches: Queries L1 for inclusion status
- `Included` batches: Queries L1 for finality status

### AlreadyKnown Handling

If L1 responds with "AlreadyKnown" for a batch submission:
- This is treated as **success**, not an error
- The original L1 tx ID is returned
- No duplicate settlement occurs

## Persistence

### Storage Trees

The settlement state machine uses dedicated storage trees:

| Tree | Key | Value |
|------|-----|-------|
| `settlement_state` | batch_hash (32 bytes) | SettlementState |
| `meta` | `last_finalised_batch:{hub}:{chain_id}` | hash + timestamp |

### Crash Consistency

All state transitions are:
1. Validated before persistence
2. Written atomically to sled
3. Flushed before returning success

This ensures that a crash at any point leaves the system in a consistent state.

## Reconciliation

The settlement reconciler runs:
- Once immediately on startup (crash recovery)
- Periodically based on `L2_RECONCILE_INTERVAL_MS` (default: 10s)

### Reconciliation Phases

**Phase 1: Submitted → Included**
1. List all batches in `Submitted` state
2. For each, query L1 for inclusion status by idempotency key
3. If included, transition to `Included` state

**Phase 2: Included → Finalised**
1. List all batches in `Included` state
2. For each, query L1 for finality (confirmations)
3. If finality reached, transition to `Finalised` state

### Stale Batch Handling

If a batch remains in `Submitted` state beyond `L2_RECONCILE_STALE_MS`:
- It is marked as `Failed`
- The failure reason includes the age
- Manual investigation may be required

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `L2_RECONCILE_INTERVAL_MS` | 10000 | Reconciliation cycle interval |
| `L2_RECONCILE_BATCH_LIMIT` | 100 | Max batches per cycle |
| `L2_RECONCILE_STALE_MS` | 300000 | Stale threshold (5 min) |
| `L2_FINALITY_CONFIRMATIONS` | 6 | L1 blocks for finality |

## Monitoring

### /status Endpoint

The `/status` endpoint includes:

```json
{
  "settlement": {
    "poster_mode": "contract",
    "lifecycle": {
      "created": 0,
      "submitted": 2,
      "included": 1,
      "finalised": 100,
      "failed": 0,
      "in_flight_total": 3
    },
    "in_flight": {
      "submitted_count": 2,
      "included_count": 1,
      "oldest_submitted_age_ms": 5000,
      "oldest_included_age_ms": 2000
    },
    "last_finalised": {
      "batch_hash": "0xabc...",
      "finalised_at_ms": 1700000000000
    }
  }
}
```

### Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `l2_settlement_created` | Gauge | Batches in Created state |
| `l2_settlement_submitted` | Gauge | Batches in Submitted state |
| `l2_settlement_included` | Gauge | Batches in Included state |
| `l2_settlement_finalised` | Gauge | Batches in Finalised state |
| `l2_settlement_failed` | Gauge | Batches in Failed state |
| `l2_settlement_recovered_total` | Counter | Total recovered batches |
| `l2_last_reconcile_ms` | Gauge | Last reconciliation timestamp |

## Best Practices

### For Operators

1. **Monitor in-flight counts**: High counts may indicate L1 issues
2. **Alert on failures**: Any `Failed` batch needs investigation
3. **Check reconciliation timestamps**: Stale timestamps indicate issues
4. **Review stale threshold**: Adjust based on L1 block times

### For Developers

1. **Never modify idempotency key logic**: This breaks replay safety
2. **Always use the state machine**: Don't bypass transitions
3. **Test crash recovery**: Run tests with simulated crashes
4. **Validate state transitions**: Invalid transitions indicate bugs

## Troubleshooting

### Batch Stuck in Submitted

1. Check L1 connectivity
2. Verify idempotency key is valid
3. Check if L1 transaction was actually submitted
4. Look for L1 errors in logs

### Batch Stuck in Included

1. Check L1 finality progress
2. Verify `L2_FINALITY_CONFIRMATIONS` setting
3. Check for L1 reorgs

### Many Failed Batches

1. Review failure reasons in storage
2. Check L1 health
3. Verify node configuration
4. Check network connectivity

## See Also

- [Restart Recovery](ops/restart-recovery.md)
- [M2M Fees](ops/m2m-fees.md)
- [L1 Contract](L1_L2_CONTRACT.md)
