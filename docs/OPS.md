# IPPAN-L2 Operations Guide

This document describes how to run, monitor, and troubleshoot IPPAN-L2 components in production.

## Components Overview

| Component | Type | Purpose |
|-----------|------|---------|
| `fin-node` | Binary | FIN Hub demo/CLI |
| `ippan_eth_oracle_daemon` | Binary | Ethereum oracle daemon |
| `hub-fin` | Library | Finance Hub logic |
| `hub-data` | Library | Data Hub logic |
| `l2-core` | Library | Core types |

## Running Components

### FIN Node

The FIN node can be used as a CLI tool and as a long-running service that exposes health/readiness/metrics.

```bash
# Local (mock) service mode
cargo run -p fin-node -- run

# L1 smoke (read-only)
cargo run -p fin-node -- l1 status
cargo run -p fin-node -- l1 check

# Submit a deterministic envelope + write receipt
cargo run -p fin-node -- submit-batch --hub fin --file ./examples/batch_fin_v1.json

# Devnet/staging (real L1 RPC)
export IPPAN_L2_CONFIG=./configs/devnet.toml
cargo run -p fin-node -- --l1-mode http l1 check
cargo run -p fin-node -- --l1-mode http run
```

### Ethereum Oracle Daemon

The oracle daemon polls IPPAN and pushes scores to Ethereum.

```bash
# Set required environment variables
export IPPAN_RPC_URL=http://127.0.0.1:8080
export ETH_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
export ETH_PRIVATE_KEY=0x...

# Run daemon
cargo run -p ippan_eth_oracle_daemon -- watch \
  --config integrations/eth-oracle/configs/devnet_sepolia.toml

# One-shot dump (no Ethereum push)
cargo run -p ippan_eth_oracle_daemon -- dump \
  --config integrations/eth-oracle/configs/devnet_sepolia.toml
```

## Logging

All components use the `tracing` crate for structured logging.

### Log Levels

| Level | Description |
|-------|-------------|
| `error` | Critical errors requiring attention |
| `warn` | Warnings that may indicate issues |
| `info` | Normal operational messages |
| `debug` | Detailed debugging information |
| `trace` | Very verbose tracing |

### Configuration

```bash
# Set log level via environment
export RUST_LOG=info

# Component-specific levels
export RUST_LOG=ippan_eth_oracle_daemon=debug,ethers=warn

# JSON output (for log aggregation)
export RUST_LOG_FORMAT=json
```

### Log Output Examples

**Info level (default):**
```
2024-01-15T10:30:45Z INFO ippan_eth_oracle_daemon: starting ippan -> ethereum oracle daemon ippan_rpc_url=http://127.0.0.1:8080 eth_rpc_url=https://sepolia...
2024-01-15T10:30:46Z INFO ippan_eth_oracle_daemon: fetched IPPAN scores count=5
2024-01-15T10:30:47Z INFO ippan_eth_oracle_daemon: pushed score updates tx_hash=0x... count=2
```

**JSON format:**
```json
{"timestamp":"2024-01-15T10:30:45Z","level":"INFO","target":"ippan_eth_oracle_daemon","message":"starting daemon","ippan_rpc_url":"http://127.0.0.1:8080"}
```

## Health Endpoints

`fin-node run` exposes:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/healthz` | GET | Liveness check (always returns 200 if running) |
| `/api/v1/readyz` | GET | Readiness check (requires L1 `chain_status`; optional network id match) |
| `/api/v1/metrics` | GET | Prometheus metrics (if enabled) |
| `/api/v1/openapi.json` | GET | OpenAPI 3.1 spec (production integration contract) |
| `/api/v1/ha/status` | GET | HA leader status (if HA enabled) |
| `/api/v1/recon/pending` | GET | Snapshot of pending reconciliation items (bounded) |
| `/api/v1/fin/receipts/:action_id` | GET | FIN action receipt JSON (includes `submit_state`) |
| `/api/v1/data/receipts/:action_id` | GET | DATA action receipt JSON (includes `submit_state`) |
| `/api/v1/linkage/purchase/:purchase_id` | GET | Linkage purchase receipt JSON (includes `*_submit_state` + `overall_status`) |

Notes:
- Legacy unversioned paths (e.g. `/healthz`, `/fin/receipts/:action_id`) may still work for backward compatibility, but new integrations should use `/api/v1/...`.
- All responses include `X-Request-Id` and `X-Api-Version: v1`.

## Rate limiting (fin-node HTTP)

`fin-node` includes a **best-effort in-memory token bucket** rate limiter:

- **Per-IP** bucket: applied to all endpoints except `/healthz`, `/readyz`, `/metrics`.
- **Per-actor** bucket: applied to write endpoints after request parsing (actor derived from request).

### Configuration

Enable and tune via config:

```toml
[rate_limit]
enabled = true
requests_per_minute = 120
burst = 60
```

### Behavior

- **HTTP 429** on limit exceeded
- Includes **`Retry-After`** header (seconds)

### Limitations

- **Per-process only**: if you run multiple `fin-node` instances behind a load balancer, rate limiting is not shared and becomes **best-effort**.

## Retention & pruning (receipts)

`fin-node` can prune old receipt files under `storage.receipts_dir` using the retention policy.

### Configuration

```toml
[limits]
max_receipt_bytes = 262144

[retention]
receipts_days = 30
min_receipts_keep = 1000
```

### Manual pruning

Dry-run (default):

```bash
cargo run -p fin-node -- prune --dry-run
```

Execute:

```bash
cargo run -p fin-node -- prune --execute
```

Safety notes:
- Pruning only targets **receipt JSON files** with parseable timestamps.
- It will always keep at least `retention.min_receipts_keep` newest receipts.

### Health Check Examples

```bash
# Liveness (is the process running?)
curl http://localhost:3000/api/v1/healthz
# Response: {"status": "ok"}

# Readiness (is the service ready to handle requests?)
curl http://localhost:3000/api/v1/readyz
# Response (ready): {"status":"ready","l1":{"ok":true,"network_id":"...","height":123}}
```

## Metrics

### Prometheus Metrics

When metrics are enabled, the following metrics are exposed:

| Metric | Type | Description |
|--------|------|-------------|
| `process_uptime_seconds` | Gauge | Process uptime |
| `l1_requests_total{method,status}` | Counter | L1 requests (status includes `ok`, http code, or error class) |
| `l1_request_failures_total{reason}` | Counter | L1 request failures by reason |
| `submit_batches_total{result}` | Counter | Batch submits (`accepted`,`already_known`,`rejected`) |
| `recon_pending_total{kind}` | Gauge | Pending reconciliation items |
| `recon_checks_total{kind,result}` | Counter | Recon checks (`checked`,`included`,`finalized`, etc.) |
| `recon_failures_total{kind,reason}` | Counter | Recon failures by reason |
| `ha_is_leader` | Gauge | Whether this node is leader (0/1) |
| `ha_leader_changes_total{event}` | Counter | Leadership transitions (`became_leader`,`stepped_down`) |
| `ha_lock_acquire_failures_total{reason}` | Counter | Lock acquisition failures (`contended`,`error`) |
| `ippan_oracle_poll_total` | Counter | Oracle poll iterations |
| `ippan_oracle_push_total` | Counter | Scores pushed to Ethereum |

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'ippan-l2'
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: '/metrics'
```

## Monitoring Checklist

### Critical Alerts

1. **Process Down** - Service not responding to health checks
2. **L1 RPC Failures** - Unable to reach IPPAN CORE
3. **High Error Rate** - Error rate exceeds threshold
4. **Oracle Stale** - No score updates for extended period

### Recommended Dashboards

1. **Overview Dashboard**
   - Process uptime
   - Request rate
   - Error rate
   - Latency percentiles

2. **Oracle Dashboard**
   - Poll success rate
   - Score update frequency
   - Ethereum transaction status
   - Gas usage

## Troubleshooting

### Common Issues

#### 1. Connection Refused to L1 RPC

**Symptom:** `network error talking to IPPAN CORE: connection refused`

**Causes:**
- IPPAN CORE node not running
- Incorrect `l1.base_url` configuration
- Network/firewall issues

**Resolution:**
```bash
# Verify L1 endpoint is reachable
curl -v http://127.0.0.1:8080/health

# Check configuration
cat configs/local.toml | grep base_url
```

#### 2. Missing Environment Variables

**Symptom:** `missing required env var ETH_RPC_URL`

**Resolution:**
```bash
# Set required variables
export IPPAN_RPC_URL=http://127.0.0.1:8080
export ETH_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
export ETH_PRIVATE_KEY=0x...

# Or use .env file
cp integrations/eth-oracle/.env.example .env
# Edit .env with your values
```

#### 3. Oracle Contract Not Deployed

**Symptom:** `oracle_contract_address is zero; daemon will run but skip Ethereum writes`

**Resolution:**
```bash
# Deploy the contract first
cd integrations/eth-oracle/contracts
forge script script/DeployIppanAiOracle.s.sol \
  --rpc-url "$ETH_RPC_URL" \
  --private-key "$ETH_PRIVATE_KEY" \
  --broadcast

# Update config with deployed address
vim integrations/eth-oracle/configs/devnet_sepolia.toml
```

#### 4. Insufficient Gas

**Symptom:** `failed sending updateScores tx: insufficient funds`

**Resolution:**
- Fund the oracle wallet with testnet ETH
- Check gas price settings
- Reduce `max_updates_per_round` to lower gas costs

### Debug Mode

Enable verbose logging for debugging:

```bash
RUST_LOG=debug cargo run -p ippan_eth_oracle_daemon -- watch \
  --config integrations/eth-oracle/configs/devnet_sepolia.toml
```

### Log Analysis

Search logs for specific events:

```bash
# Find all errors
grep -i error /var/log/ippan-l2/daemon.log

# Find L1 RPC failures
grep "L1 RPC" /var/log/ippan-l2/daemon.log

# Find successful score pushes
grep "pushed score updates" /var/log/ippan-l2/daemon.log
```

## Deployment Recommendations

### Systemd Service

```ini
# /etc/systemd/system/ippan-oracle.service
[Unit]
Description=IPPAN Ethereum Oracle Daemon
After=network.target

[Service]
Type=simple
User=ippan
Group=ippan
WorkingDirectory=/opt/ippan-l2
EnvironmentFile=/etc/ippan-l2/env
ExecStart=/opt/ippan-l2/bin/ippan_eth_oracle_daemon watch --config /etc/ippan-l2/oracle.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Docker Deployment

See [LOCAL_RUN.md](LOCAL_RUN.md) for Docker Compose setup.

### Resource Requirements

| Component | CPU | Memory | Disk |
|-----------|-----|--------|------|
| fin-node | 0.5 core | 128MB | 100MB |
| oracle-daemon | 0.5 core | 256MB | 100MB |

## Security

### Key Material

- **ETH_PRIVATE_KEY** - Never log or expose
- Store in secrets manager (Vault, AWS Secrets Manager)
- Use hardware security modules (HSM) for production

### Network Security

- Run behind reverse proxy
- Use TLS for all external connections
- Restrict metrics endpoint to internal network

See [../SECURITY.md](../SECURITY.md) for security policy.

## fin-node audit events (policy/operator friendly)

`fin-node` emits structured `tracing` events for operator/audit workflows:

- **action_attempted**: the node received a request and began evaluation
- **action_denied**: the node rejected the request (policy/compliance)
- **action_applied**: the action was applied locally (sled) and a receipt was produced
- **action_submitted_to_l1**: the batch was submitted to L1 (accepted/rejected metadata)

Common fields include `hub`, `action_kind`, and `action_id` (usable as a deterministic correlation id).
