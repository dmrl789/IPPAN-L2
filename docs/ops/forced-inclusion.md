# Forced Inclusion Operations Runbook

This document describes how to use and operate the forced inclusion feature in IPPAN-L2.

## Overview

Forced inclusion provides anti-censorship guarantees:
- Users can request guaranteed transaction inclusion
- Transactions must be included within a bounded number of epochs
- Rate limiting prevents abuse of the forced queue

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `L2_FORCE_INCLUDE_MAX_EPOCHS` | `3` | Max epochs before forced tx must be included |
| `L2_FORCE_MAX_PER_ACCOUNT` | `5` | Max forced txs per account per epoch |
| `L2_FORCE_L1_COMMITMENTS` | `false` | Post commitments to L1 (if supported) |

### Example Configuration

```bash
# Forced inclusion settings
export L2_FORCE_INCLUDE_MAX_EPOCHS=3
export L2_FORCE_MAX_PER_ACCOUNT=5
```

## API Endpoints

### Submit Forced Inclusion Request

```bash
curl -X POST http://localhost:3000/tx/force \
  -H "Content-Type: application/json" \
  -d '{
    "chain_id": 1,
    "from": "user_001",
    "nonce": 42,
    "payload": "48656c6c6f20576f726c64"
  }'
```

Response:

```json
{
  "accepted": true,
  "tx_hash": "abcd1234...",
  "ticket": {
    "tx_hash": "abcd1234...",
    "submitted_at_ms": 1735000000000,
    "expires_at_ms": 1735000030000,
    "requester": "user_001",
    "status": "queued",
    "created_epoch": 100,
    "max_epochs": 3
  }
}
```

### Check Forced Inclusion Status

```bash
curl http://localhost:3000/tx/force/abcd1234...
```

Response:

```json
{
  "tx_hash": "abcd1234...",
  "status": "included",
  "ticket": {
    "tx_hash": "abcd1234...",
    "status": "included",
    "included_batch": "efgh5678..."
  }
}
```

## Ticket Status Values

| Status | Description |
|--------|-------------|
| `queued` | Ticket created, waiting to be included |
| `included` | Transaction included in a batch |
| `expired` | Ticket expired without being included |
| `rejected` | Ticket rejected (invalid, duplicate, etc.) |

## How It Works

### Submission Flow

1. User submits `POST /tx/force` with transaction data
2. Node validates the request:
   - Chain ID matches
   - Payload size within limits
   - No duplicate tickets
   - Account hasn't exceeded per-epoch limit
3. Node creates an `InclusionTicket` with:
   - Expiry time = `submitted_at + epoch_ms * max_epochs`
   - Created epoch = current epoch
4. Ticket is stored in the forced queue

### Batching Priority

The batcher processes transactions in this order:
1. **Forced transactions that are due** (must be included this epoch)
2. **Normal transactions** from the mempool

### Expiry

If a ticket expires before inclusion:
1. Status changes to `expired`
2. Transaction is NOT included
3. User must resubmit if they want to try again

## Status Endpoint

```bash
curl http://localhost:3000/status | jq '.forced_inclusion'
```

Response:

```json
{
  "enabled": true,
  "max_epochs": 3,
  "max_per_account_per_epoch": 5,
  "queue_depth": 2,
  "queue_counts": {
    "queued": 2,
    "included": 15,
    "rejected": 0,
    "expired": 1
  }
}
```

## Metrics

| Metric | Description |
|--------|-------------|
| `l2_forced_queue_depth` | Current number of queued forced tickets |
| `l2_forced_included_total` | Total forced transactions included |

```bash
curl http://localhost:3000/metrics | grep l2_forced
```

## Example Workflow

### User Suspects Censorship

```bash
# 1. Submit normal transaction
TX_HASH=$(curl -s -X POST http://localhost:3000/tx \
  -H "Content-Type: application/json" \
  -d '{"chain_id":1,"from":"alice","nonce":1,"payload":"deadbeef"}' \
  | jq -r '.tx_hash')

# 2. Wait for inclusion (check after a few epochs)
sleep 30
curl http://localhost:3000/tx/$TX_HASH | jq '.status'

# 3. If not included, submit forced inclusion
curl -X POST http://localhost:3000/tx/force \
  -H "Content-Type: application/json" \
  -d '{"chain_id":1,"from":"alice","nonce":1,"payload":"deadbeef"}'

# 4. Transaction will be included within max_epochs
```

### Operator Monitoring

```bash
# Watch forced queue depth
watch -n 5 'curl -s http://localhost:3000/status | jq ".forced_inclusion.queue_depth"'

# Alert if queue is growing
if [ $(curl -s http://localhost:3000/status | jq '.forced_inclusion.queue_depth') -gt 10 ]; then
  echo "ALERT: Forced queue depth is high!"
fi
```

## Troubleshooting

### Request Rejected: Rate Limit

```json
{"accepted": false, "error": "rate limit exceeded for account"}
```

User has exceeded `max_per_account_per_epoch`. Wait for next epoch or use a different account.

### Request Rejected: Duplicate

```json
{"accepted": false, "error": "ticket already exists for this transaction"}
```

Transaction already has a pending forced ticket. Check status instead.

### Tickets Expiring Before Inclusion

1. Check if batcher is running:
   ```bash
   curl http://localhost:3000/status | jq '.batcher.enabled'
   ```
2. Check if node is leader (only leader batches):
   ```bash
   curl http://localhost:3000/status | jq '.leader.is_leader'
   ```
3. Check batch creation frequency

### High Queue Depth

1. Investigate if there's a leader censorship issue
2. Check batcher logs for errors
3. Consider increasing `L2_FORCE_INCLUDE_MAX_EPOCHS`

## Best Practices

1. **User Education**: Inform users about forced inclusion as a fallback mechanism
2. **Rate Limiting**: Keep `max_per_account_per_epoch` reasonable (3-10)
3. **Monitoring**: Alert on queue depth > N and expired tickets
4. **Epoch Sizing**: Balance `max_epochs` with epoch duration for reasonable inclusion guarantee
5. **Audit Logging**: Monitor forced inclusion patterns for potential censorship detection

## Limitations

1. **Not Instant**: Inclusion is guaranteed within `max_epochs`, not immediately
2. **Rate Limited**: Per-account limits prevent spamming the forced queue
3. **Leader Dependency**: Only the leader processes the forced queue
4. **No L1 Fallback**: If IPPAN lacks forced-include contract support, this is best-effort
