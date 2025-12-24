# Leader Rotation Operations Runbook

This document describes how to configure and operate leader rotation in IPPAN-L2.

## Overview

Leader rotation provides:
- **Deterministic election**: All nodes agree on the current leader based on epoch
- **Censorship resistance**: No single leader can permanently censor transactions
- **Fault tolerance**: Leader failures only affect one epoch (typically seconds)

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `L2_LEADER_MODE` | `single` | Set to `rotating` to enable rotation |
| `L2_LEADER_SET` | (required) | Comma-separated hex-encoded ed25519 pubkeys |
| `L2_EPOCH_MS` | `10000` | Epoch duration in milliseconds |
| `L2_GENESIS_MS` | (required) | Genesis timestamp (ms since Unix epoch) |
| `L2_NODE_PUBKEY` | (required) | This node's pubkey (hex) |
| `L2_NODE_KEY_PATH` | (optional) | Path to signing key file |
| `L2_FORWARD_TO_LEADER` | `0` | Set to `1` to forward txs to leader |
| `L2_FORWARD_FALLBACK` | `accept` | `accept` or `reject` if forwarding fails |
| `L2_LEADER_ENDPOINTS` | (optional) | Pubkey→URL mappings for forwarding |

### Example Configuration

```bash
# Leader set (3 nodes)
export L2_LEADER_SET="aabbccdd...,11223344...,55667788..."

# Epoch configuration
export L2_EPOCH_MS=10000         # 10 second epochs
export L2_GENESIS_MS=1735000000000  # Fixed genesis timestamp

# This node's identity
export L2_NODE_PUBKEY="aabbccdd..."
export L2_NODE_KEY_PATH="./sequencer.key"

# Enable rotation
export L2_LEADER_MODE=rotating

# Optional: Enable forwarding
export L2_FORWARD_TO_LEADER=1
export L2_LEADER_ENDPOINTS="aabbccdd...:http://node1:3000,11223344...:http://node2:3000"
```

### Generating Node Keys

```bash
# Generate an Ed25519 keypair
openssl genpkey -algorithm ed25519 -out sequencer.key
openssl pkey -in sequencer.key -pubout -outform der | tail -c 32 | xxd -p
```

## How It Works

### Epoch Calculation

```
epoch_idx = floor((current_ms - genesis_ms) / epoch_ms)
```

All nodes with the same `L2_GENESIS_MS` and `L2_EPOCH_MS` will compute identical epoch indices.

### Leader Selection

```
leader_idx = SHA256(epoch_idx) mod len(leader_set)
leader = leader_set[leader_idx]
```

This provides deterministic, fair distribution across the leader set.

### Runtime Behavior

**When this node IS the leader:**
- Accepts transactions directly
- Runs batcher to create batches
- Posts batches to L1
- Runs reconciler to confirm batches

**When this node is NOT the leader:**
- If `L2_FORWARD_TO_LEADER=1`: Forwards transactions to the elected leader
- If forwarding disabled: Accepts to local pool (soft federation mode)
- Does NOT run batcher or reconciler

## Status Endpoint

```bash
curl http://localhost:3000/status | jq '.leader'
```

Example response:

```json
{
  "mode": "rotating",
  "is_leader": true,
  "epoch_idx": 42,
  "epoch_ms": 10000,
  "epoch_start_ms": 1735000420000,
  "epoch_end_ms": 1735000430000,
  "elected_leader_pubkey": "aabbccdd..."
}
```

## Metrics

| Metric | Description |
|--------|-------------|
| `l2_leader_is_leader` | 1 if this node is currently leader, 0 otherwise |
| `l2_epoch_idx` | Current epoch index |
| `l2_tx_forwarded` | Number of transactions forwarded to leader |

```bash
curl http://localhost:3000/metrics | grep l2_leader
```

## Running a Multi-Node Cluster

### Node 1 (Leader Set Member)

```bash
export L2_LEADER_MODE=rotating
export L2_LEADER_SET="aabb...,1122...,5566..."
export L2_EPOCH_MS=10000
export L2_GENESIS_MS=1735000000000
export L2_NODE_PUBKEY="aabb..."
export L2_NODE_KEY_PATH="./node1.key"
export L2_DB_PATH="./data/node1"
export L2_LISTEN_ADDR="0.0.0.0:3001"

cargo run -p l2-node --release
```

### Node 2 (Leader Set Member)

```bash
export L2_LEADER_MODE=rotating
export L2_LEADER_SET="aabb...,1122...,5566..."
export L2_EPOCH_MS=10000
export L2_GENESIS_MS=1735000000000
export L2_NODE_PUBKEY="1122..."
export L2_NODE_KEY_PATH="./node2.key"
export L2_DB_PATH="./data/node2"
export L2_LISTEN_ADDR="0.0.0.0:3002"

cargo run -p l2-node --release
```

### Node 3 (Follower with Forwarding)

```bash
export L2_LEADER_MODE=rotating
export L2_LEADER_SET="aabb...,1122...,5566..."
export L2_EPOCH_MS=10000
export L2_GENESIS_MS=1735000000000
export L2_NODE_PUBKEY="5566..."
export L2_NODE_KEY_PATH="./node3.key"
export L2_DB_PATH="./data/node3"
export L2_LISTEN_ADDR="0.0.0.0:3003"
export L2_FORWARD_TO_LEADER=1
export L2_LEADER_ENDPOINTS="aabb...:http://localhost:3001,1122...:http://localhost:3002,5566...:http://localhost:3003"

cargo run -p l2-node --release
```

## Troubleshooting

### Nodes Disagree on Leader

1. Verify all nodes have identical:
   - `L2_LEADER_SET` (same order!)
   - `L2_GENESIS_MS`
   - `L2_EPOCH_MS`

2. Check system clocks are synchronized (NTP)

### Forwarding Fails

1. Check `L2_LEADER_ENDPOINTS` has correct mappings
2. Verify leader node is reachable:
   ```bash
   curl http://leader-node:3000/healthz
   ```
3. Check logs for forwarding errors

### No Batches Being Created

1. Verify this node is in the leader set:
   ```bash
   curl http://localhost:3000/status | jq '.leader.is_leader'
   ```
2. Check if batcher is enabled:
   ```bash
   curl http://localhost:3000/status | jq '.batcher.enabled'
   ```

## Best Practices

1. **Clock Synchronization**: All nodes MUST have synchronized clocks (< 1 second drift)
2. **Leader Set**: Start with 3-5 nodes for fault tolerance
3. **Epoch Duration**: 10-30 seconds recommended for balance of responsiveness vs. churn
4. **Key Security**: Protect node signing keys; rotate periodically
5. **Monitoring**: Alert on `l2_leader_is_leader` changes to track rotation

## Limitations

1. **No Consensus**: Nodes don't communicate to agree on leader; relies on deterministic calculation
2. **Clock Sensitivity**: Nodes with skewed clocks may disagree on current epoch
3. **No Slashing**: Misbehaving leaders are not automatically removed from the set
4. **Manual Set Updates**: Leader set changes require restarting nodes with new config
