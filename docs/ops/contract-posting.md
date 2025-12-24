# Contract Posting Operations Runbook

This document provides operational guidance for running IPPAN L2 with contract-based batch posting.

## Prerequisites

1. L2 node built with `contract-posting` feature:
   ```bash
   cargo build --release --features contract-posting
   ```

2. L1 endpoint configured and accessible

3. Leader node configured for batch posting

## Configuration

### Required Environment Variables

```bash
# Posting mode (default: contract)
export L2_POSTER_MODE=contract

# Hub identifier
export L2_HUB_ID=fin

# L1 connection (configure as needed for your L1 setup)
export L1_RPC_URL=https://your-l1-node:8545

# Chain configuration
export L2_CHAIN_ID=1337
```

### Optional Environment Variables

```bash
# Retry configuration
export L2_POST_MAX_RETRIES=3        # Max retry attempts (1-10)
export L2_POST_RETRY_DELAY_MS=500   # Base retry delay in ms
export L2_L1_TIMEOUT_MS=30000       # L1 request timeout

# Advanced
export L2_FORCE_REPOST=false        # Force repost (use with caution)
export L2_MAX_PAYLOAD_SIZE=1048576  # Max payload size (1MB default)
export L2_BATCH_FEE=0               # Protocol fee (scaled integer)
```

## Startup

### Standard Startup

```bash
./l2-node \
  --db-path /var/lib/l2/data \
  --listen-addr 0.0.0.0:3000 \
  --batcher-enabled true
```

### With Contract Posting Explicit

```bash
L2_POSTER_MODE=contract \
L2_HUB_ID=fin \
./l2-node \
  --db-path /var/lib/l2/data \
  --listen-addr 0.0.0.0:3000
```

### With Raw Mode (Legacy/Debug)

```bash
L2_POSTER_MODE=raw \
IPPAN_RPC_URL=https://rpc.ippan.io \
./l2-node \
  --db-path /var/lib/l2/data \
  --listen-addr 0.0.0.0:3000
```

## Health Checks

### Basic Health

```bash
curl http://localhost:3000/healthz
# Expected: "ok"
```

### Readiness

```bash
curl http://localhost:3000/readyz
# Expected: 200 OK
```

### Settlement Status

```bash
curl -s http://localhost:3000/status | jq '.settlement'
```

Example output:
```json
{
  "poster_mode": "contract",
  "last_submitted_batch_hash": "aabbccdd...",
  "last_l1_tx_id": "l1tx_12345",
  "pending_submissions": 0,
  "confirmed_submissions": 42
}
```

## Monitoring

### Key Metrics

```bash
curl -s http://localhost:3000/metrics | grep l2_contract
```

Watch for:
- `l2_contract_submit_total` - should increase with batches
- `l2_contract_failed_total` - should be 0 or low
- `l2_contract_already_known_total` - indicates idempotent retries

### Alert Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| `l2_contract_failed_total` rate | > 0.1/min | > 1/min |
| `l2_batches_pending` | > 100 | > 1000 |
| `l2_contract_submit_retries_total` rate | > 1/min | > 10/min |

## Troubleshooting

### Batch Not Posting

**Symptoms**: `l2_batches_pending` increasing, no new `posted` batches

**Check**:
1. Is this node the leader?
   ```bash
   curl -s http://localhost:3000/status | jq '.leader'
   ```

2. Is L1 reachable?
   ```bash
   # Check logs for L1 errors
   journalctl -u l2-node | grep -i "L1\|l1_client"
   ```

3. Is the correct poster mode configured?
   ```bash
   curl -s http://localhost:3000/status | jq '.settlement.poster_mode'
   # Should be "contract"
   ```

### AlreadyKnown Responses

**Symptoms**: Many `l2_contract_already_known_total` increments

**Cause**: Usually indicates retries or duplicate submissions

**Action**: This is normal for:
- Node restarts (resubmits pending batches)
- Network retries

Investigate if:
- Happening without restarts
- Rate is very high (> 10/min sustained)

### Failed Submissions

**Symptoms**: `l2_contract_failed_total` increasing

**Check logs**:
```bash
journalctl -u l2-node | grep -i "failed\|error\|rejected"
```

**Common causes**:
1. **L1 timeout**: Increase `L2_L1_TIMEOUT_MS`
2. **Invalid payload**: Check batch data for issues
3. **Fee issues**: Check `L2_BATCH_FEE` configuration
4. **Rate limiting**: Check L1 rate limits

### Batch Chaining Issues

**Symptoms**: `prev_batch_hash` not updating correctly

**Check storage**:
```bash
# Look in logs for chaining messages
journalctl -u l2-node | grep "batch chaining"
```

**Recovery**:
If chaining is corrupted, you may need to:
1. Stop the node
2. Clear the last_batch_hash from storage (advanced)
3. Restart

### Feature Not Enabled

**Symptom**: Error at startup:
```
L2_POSTER_MODE=contract requires the 'contract-posting' feature
```

**Fix**: Rebuild with feature enabled:
```bash
cargo build --release --features contract-posting
```

Or switch to raw mode:
```bash
export L2_POSTER_MODE=raw
```

## Maintenance

### Viewing Batch State

```bash
# Get posting counts
curl -s http://localhost:3000/status | jq '.posting'
```

### Log Rotation

Ensure log rotation is configured for high-volume environments:
```
/var/log/l2-node/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
```

## Emergency Procedures

### Stop Posting (Graceful)

```bash
# Set to non-leader mode
export L2_LEADER=false
systemctl restart l2-node
```

### Switch to Raw Mode

```bash
export L2_POSTER_MODE=raw
export IPPAN_RPC_URL=https://rpc.ippan.io
systemctl restart l2-node
```

### Force Repost (Use Sparingly)

```bash
export L2_FORCE_REPOST=true
systemctl restart l2-node
# Remember to unset after recovery
```

## See Also

- [Settlement Architecture](../SETTLEMENT.md)
- [API Reference](../API.md)
- [Leader Rotation](leader-rotation.md)
