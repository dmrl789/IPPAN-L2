# IPPAN-L2 DevNet Operations Runbook

This document describes how to operate the IPPAN-L2 node against the IPPAN DevNet.

## Prerequisites

- Rust toolchain (1.80+)
- IPPAN DevNet RPC endpoint
- Disk space for sled database

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `IPPAN_RPC_URL` | IPPAN DevNet RPC endpoint | `http://devnet.ippan.network:26657` |
| `L2_DB_PATH` | Path to sled database | `./data/l2` |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `L2_LISTEN_ADDR` | `0.0.0.0:3000` | HTTP listen address |
| `L2_CHAIN_ID` | `1` | L2 chain identifier |
| `L2_LEADER` | `true` | Enable leader mode |
| `L2_LEADER_MODE` | `single` | Leader election mode |
| `LEADER_ID` | `sequencer-0` | Sequencer identifier |
| `LEADER_TERM` | `0` | Leader term (static for MVP) |
| `BATCHER_ENABLED` | `true` | Enable batch creation |
| `BRIDGE_ENABLED` | `true` | Enable bridge watcher |
| `L2_ADMISSION_CAP` | `1024` | Max pending transactions |
| `L2_MAX_TX_SIZE` | `65536` | Max transaction payload size |

### RPC Client Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `IPPAN_RPC_TIMEOUT_MS` | `2000` | RPC call timeout |
| `IPPAN_RPC_RETRY_MAX` | `3` | Max RPC retries |

### Posting Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `L2_POST_MODE` | `tx_data` | Posting mode (`tx_data` or `tx_payment_memo`) |
| `L2_FORCE_REPOST` | `false` | Force repost confirmed batches |
| `L2_POST_MAX_RETRIES` | `3` | Max posting retries |
| `L2_POST_RETRY_DELAY_MS` | `500` | Base retry delay |

### Reconciler Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `L2_RECONCILE_INTERVAL_MS` | `10000` | Reconciliation interval |
| `L2_RECONCILE_BATCH_LIMIT` | `100` | Max batches per cycle |
| `L2_RECONCILE_STALE_MS` | `300000` | Stale threshold (5 min) |

## Running the Node

### Leader Mode

```bash
export IPPAN_RPC_URL=http://devnet.ippan.network:26657
export L2_DB_PATH=./data/l2-leader
export L2_LEADER=1
export RUST_LOG=info

cargo run -p l2-node --release
```

### Read-Only Follower

```bash
export IPPAN_RPC_URL=http://devnet.ippan.network:26657
export L2_DB_PATH=./data/l2-follower
export L2_LEADER=0
export BATCHER_ENABLED=0
export RUST_LOG=info

cargo run -p l2-node --release
```

## API Endpoints

### Health & Status

```bash
# Health check
curl http://localhost:3000/healthz

# Readiness check
curl http://localhost:3000/readyz

# Status with metrics
curl http://localhost:3000/status | jq

# Prometheus metrics
curl http://localhost:3000/metrics
```

### Transaction Submission

```bash
# Submit a transaction
curl -X POST http://localhost:3000/tx \
  -H "Content-Type: application/json" \
  -d '{
    "chain_id": 1,
    "from": "sender_001",
    "nonce": 1,
    "payload": "48656c6c6f20576f726c64"
  }'

# Query a transaction
curl http://localhost:3000/tx/<TX_HASH>
```

### Batch Queries

```bash
# Query a batch
curl http://localhost:3000/batch/<BATCH_HASH>
```

## Example curl Commands

### Submit Multiple Transactions

```bash
for i in $(seq 1 20); do
  payload=$(echo "test_tx_$i" | xxd -p | tr -d '\n')
  curl -s -X POST http://localhost:3000/tx \
    -H "Content-Type: application/json" \
    -d "{
      \"chain_id\": 1,
      \"from\": \"test_sender\",
      \"nonce\": $i,
      \"payload\": \"$payload\"
    }"
  echo ""
done
```

### Check Posting Status

```bash
curl http://localhost:3000/status | jq '.posting'
```

Expected output:
```json
{
  "pending": 0,
  "posted": 5,
  "confirmed": 3,
  "failed": 0
}
```

## Troubleshooting

### Node Won't Start

1. Check database path is writable:
   ```bash
   mkdir -p $L2_DB_PATH
   ```

2. Check port is available:
   ```bash
   lsof -i :3000
   ```

3. Check IPPAN RPC is reachable:
   ```bash
   curl $IPPAN_RPC_URL/status
   ```

### Transactions Rejected (429)

Queue is full. Either:
- Wait for batches to be processed
- Increase `L2_ADMISSION_CAP`
- Check batcher logs for errors

### Batches Not Posting

1. Check batcher is enabled:
   ```bash
   curl http://localhost:3000/status | jq '.batcher.enabled'
   ```

2. Check IPPAN RPC is configured:
   ```bash
   echo $IPPAN_RPC_URL
   ```

3. Check for posting errors in logs:
   ```bash
   grep "poster failed" /var/log/l2-node.log
   ```

### Batches Stuck in Posted State

1. Check reconciler is running (leader only)
2. Check IPPAN RPC connectivity
3. Manual confirmation check:
   ```bash
   curl $IPPAN_RPC_URL/tx/<L1_TX_HASH>
   ```

### High Memory Usage

- Check queue depth: `curl http://localhost:3000/status | jq '.queue.depth'`
- Reduce `L2_ADMISSION_CAP` if needed
- Enable pruning (future feature)

## Monitoring

### Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `l2_uptime_ms` | Node uptime | N/A |
| `l2_batcher_queue_depth` | Pending transactions | > 80% capacity |
| `l2_tx_submitted_total` | Total transactions | N/A |
| `l2_tx_rejected_total` | Rejected transactions | > 1% of submitted |
| `l2_batches_pending` | Batches waiting to post | > 10 |
| `l2_batches_posted` | Batches posted to L1 | N/A |
| `l2_batches_confirmed` | Confirmed batches | Should increase |
| `l2_post_failures_total` | Posting failures | > 0 (alert) |

### Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: 'l2-node'
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: '/metrics'
```

## Limitations (MVP)

1. **Single Leader**: No automatic failover. Manual promotion required.
2. **Best-Effort Confirmation**: If IPPAN RPC lacks confirmation endpoint, Posted state is terminal.
3. **No Forced Inclusion**: Censorship resistance not implemented.
4. **No Pruning**: Database grows unbounded (implement pruning before production).
5. **No Compression**: Batch payloads sent uncompressed.

## Support

- GitHub Issues: https://github.com/dmrl789/IPPAN-L2/issues
- Documentation: docs/
- API Reference: docs/API.md
