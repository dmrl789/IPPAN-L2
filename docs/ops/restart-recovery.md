# Restart Recovery Operations

This document describes how to perform safe restarts and understand the
automatic recovery process for IPPAN L2 nodes.

## Overview

IPPAN L2 is designed for crash-safe operation. When a node restarts:

1. Storage is opened and validated
2. In-flight batches are detected
3. The reconciler is started to resume processing
4. Normal operation continues automatically

No manual intervention is required for normal restarts.

## Automatic Recovery Process

### Startup Sequence

```
1. Open storage (schema validation)
2. Load configuration
3. Scan for in-flight batches
4. Log recovery summary
5. Start settlement reconciler
6. Start HTTP server
7. Resume normal batching
```

### In-Flight Detection

On startup, the node scans for batches in non-terminal states:

| State | Recovery Action |
|-------|-----------------|
| `Created` | Re-submit to batcher queue |
| `Submitted` | Reconciler queries L1 for status |
| `Included` | Reconciler checks finality |
| `Finalised` | No action needed |
| `Failed` | No action needed |

### Recovery Logging

The startup process logs:

```
INFO startup recovery: found in-flight batches, reconciler will resume
  submitted=2 included=1
```

This helps operators understand the node state.

## Safe Restart Procedures

### Graceful Shutdown

For the safest restart:

```bash
# Send SIGTERM for graceful shutdown
kill -TERM <pid>

# Or with systemd
systemctl stop l2-node
```

The node will:
1. Stop accepting new batches
2. Wait for current batch submission to complete
3. Flush all pending writes
4. Exit cleanly

### Rolling Restart

For zero-downtime updates (with multiple nodes):

```bash
# 1. Drain node from load balancer
# 2. Wait for in-flight batches (check /status)
# 3. Stop node
systemctl stop l2-node

# 4. Update binary/config
# 5. Start node
systemctl start l2-node

# 6. Verify health
curl http://localhost:8080/health

# 7. Add back to load balancer
```

### Emergency Restart

If a node is unresponsive:

```bash
# Force kill (not recommended)
kill -9 <pid>

# Restart
systemctl start l2-node

# Monitor recovery
tail -f /var/log/l2-node.log | grep -i recovery
```

This is safe but may require reconciliation time.

## Monitoring Recovery

### Status Endpoint

Check recovery progress via `/status`:

```bash
curl -s http://localhost:8080/status | jq '.settlement'
```

Key fields:
- `lifecycle.submitted`: Batches awaiting L1 inclusion
- `lifecycle.included`: Batches awaiting finality
- `in_flight.oldest_submitted_age_ms`: How long oldest batch has been waiting

### Logs

Watch for recovery-related logs:

```bash
# Startup recovery
grep "startup recovery" /var/log/l2-node.log

# Reconciliation progress
grep "reconcile" /var/log/l2-node.log

# State transitions
grep "settlement state" /var/log/l2-node.log
```

### Metrics

Monitor via Prometheus:

```promql
# In-flight batches
l2_settlement_submitted + l2_settlement_included

# Successful recoveries
rate(l2_settlement_recovered_total[5m])

# Reconciliation recency
time() - (l2_last_reconcile_ms / 1000)
```

## Troubleshooting

### Recovery Taking Too Long

**Symptoms**: High in-flight count after restart

**Causes**:
1. L1 node is slow or unreachable
2. Many batches were in-flight at crash time
3. Network issues

**Resolution**:
```bash
# Check L1 connectivity
curl -s http://localhost:8080/status | jq '.l1_client'

# Check reconciliation interval
echo $L2_RECONCILE_INTERVAL_MS

# Check for errors
grep -i error /var/log/l2-node.log | tail -20
```

### Batches Stuck After Recovery

**Symptoms**: Batches remain in `Submitted` state

**Causes**:
1. L1 transaction was never actually submitted
2. L1 node lost the transaction
3. Idempotency key mismatch

**Resolution**:
```bash
# Check oldest batch age
curl -s http://localhost:8080/status | jq '.settlement.in_flight.oldest_submitted_age_ms'

# If > stale threshold, batch will be marked Failed
# Check failed batches
grep "Failed" /var/log/l2-node.log
```

### Storage Corruption

**Symptoms**: Node fails to start with schema errors

**Causes**:
1. Disk failure during write
2. Manual modification of storage
3. Version mismatch

**Resolution**:
```bash
# Check storage integrity
# (requires node stopped)
ls -la /var/lib/l2-node/storage/

# If corrupted, restore from backup or snapshot
# See: docs/SNAPSHOTS.md
```

### Duplicate Settlements

**Symptoms**: Same data settled multiple times on L1

**Causes**:
1. Idempotency key bug (should not happen)
2. Running multiple nodes with same identity
3. Manual L1 submission

**Resolution**:
1. This should not happen with normal operation
2. Check for duplicate node deployments
3. Review L1 contract logs

## Best Practices

### Before Restart

1. Check `/status` for in-flight batches
2. Wait for low in-flight count if possible
3. Review recent logs for errors
4. Ensure L1 connectivity

### During Restart

1. Use graceful shutdown
2. Monitor shutdown logs
3. Verify clean exit

### After Restart

1. Check startup logs
2. Verify recovery summary
3. Monitor in-flight counts decreasing
4. Check for errors in reconciliation

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `L2_RECONCILE_INTERVAL_MS` | 10000 | How often to check L1 |
| `L2_RECONCILE_STALE_MS` | 300000 | When to mark stale |
| `L2_RECONCILE_BATCH_LIMIT` | 100 | Max batches per cycle |
| `L2_FINALITY_CONFIRMATIONS` | 6 | Blocks for finality |

### Tuning for Recovery Speed

For faster recovery (more L1 load):
```bash
export L2_RECONCILE_INTERVAL_MS=5000
export L2_RECONCILE_BATCH_LIMIT=200
```

For lighter L1 load:
```bash
export L2_RECONCILE_INTERVAL_MS=30000
export L2_RECONCILE_BATCH_LIMIT=50
```

## Recovery Guarantees

IPPAN L2 guarantees:

1. **No data loss**: All created batches are persisted
2. **No duplicates**: Idempotency prevents double-settlement
3. **Eventual consistency**: All batches reach terminal state
4. **Determinism**: Same inputs produce same outputs

These guarantees hold even with:
- Hard crashes (kill -9)
- Power failures
- Network partitions (when L1 becomes reachable again)

## See Also

- [Settlement Lifecycle](../SETTLEMENT_LIFECYCLE.md)
- [M2M Fees](m2m-fees.md)
- [Operations Guide](../OPS.md)
- [Snapshots](../SNAPSHOTS.md)
