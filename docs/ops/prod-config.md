# Production Configuration Guide

This guide covers production deployment configuration for IPPAN-L2 FIN Node.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Security Mode](#security-mode)
- [Configuration Files](#configuration-files)
- [Environment Variables](#environment-variables)
- [Systemd Deployment](#systemd-deployment)
- [Docker Deployment](#docker-deployment)
- [Monitoring Setup](#monitoring-setup)
- [Checklist](#checklist)

---

## Prerequisites

1. **System Requirements:**
   - Linux (Debian/Ubuntu recommended)
   - 2+ CPU cores
   - 2+ GB RAM
   - 20+ GB SSD storage
   - Network access to L1 RPC

2. **Software:**
   - Rust 1.80+ (for building)
   - systemd (for service management)
   - Or Docker 24+ (for containerized deployment)

3. **Security:**
   - Non-root user (`ippan`)
   - Firewall configured
   - TLS termination (reverse proxy recommended)

---

## Security Mode

IPPAN-L2 supports three security modes:

### Devnet (default)
```toml
[security]
mode = "devnet"
```
- All endpoints enabled
- No authentication required
- **Use only for local development**

### Staging
```toml
[security]
mode = "staging"
admin_token = "your-32-char-min-token"
```
- ETH header submission requires auth
- Suitable for test networks

### Production
```toml
[security]
mode = "prod"
admin_token = "env:ADMIN_TOKEN"
bridge_submitters = ["pubkey1hex"]
attestor_keys = ["attestor1hex"]
```
- Devnet-only endpoints disabled
- List proofs requires auth
- Strict rate limits
- **Required for production deployments**

---

## Configuration Files

### Main Config: `/etc/ippan-l2/config.toml`

```toml
# Production configuration
# See configs/prod.toml for full example

[node]
label = "prod-fin-node-1"

[security]
mode = "prod"
admin_token = "env:ADMIN_TOKEN"
request_timeout_ms = 30000

[l1]
base_url = "env:L1_BASE_URL"
api_key = "env:L1_API_KEY"

[l1.endpoints]
chain_status = "env:L1_ENDPOINT_CHAIN_STATUS"
submit_batch = "env:L1_ENDPOINT_SUBMIT_BATCH"
get_inclusion = "env:L1_ENDPOINT_GET_INCLUSION"
get_finality = "env:L1_ENDPOINT_GET_FINALITY"

[server]
bind_address = "0.0.0.0:3000"
metrics_enabled = true

[limits]
max_body_bytes = 262144
max_bridge_proof_bytes = 524288

[rate_limit]
enabled = true
requests_per_minute = 120
burst = 30

[storage]
receipts_dir = "/var/lib/ippan-l2/receipts"
fin_db_dir = "/var/lib/ippan-l2/fin_db"
data_db_dir = "/var/lib/ippan-l2/data_db"
audit_db_dir = "/var/lib/ippan-l2/audit_db"

[pruning]
enabled = true
interval_secs = 86400

[logging]
level = "info"
format = "json"
```

### Secrets File: `/etc/ippan-l2/secrets.env`

```bash
# L1 RPC configuration
L1_BASE_URL=https://your-l1-rpc.example.com
L1_API_KEY=your-api-key
L1_ENDPOINT_CHAIN_STATUS=/api/v1/chain/status
L1_ENDPOINT_SUBMIT_BATCH=/api/v1/batches
L1_ENDPOINT_GET_INCLUSION=/api/v1/batches/{id}
L1_ENDPOINT_GET_FINALITY=/api/v1/batches/{l1_tx_id}/finality

# Admin authentication (minimum 32 characters)
ADMIN_TOKEN=your-secure-admin-token-min-32-characters-long
```

**Security:** Set permissions on secrets file:
```bash
chmod 600 /etc/ippan-l2/secrets.env
chown ippan:ippan /etc/ippan-l2/secrets.env
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `IPPAN_L2_CONFIG` | Yes | Path to config file |
| `L1_BASE_URL` | Yes | L1 RPC base URL |
| `L1_API_KEY` | Maybe | L1 RPC API key |
| `L1_ENDPOINT_*` | Yes | L1 endpoint paths |
| `ADMIN_TOKEN` | Prod | Admin authentication token |
| `RUST_LOG` | No | Log level (default: info) |

---

## Systemd Deployment

### 1. Install Binary

```bash
# Build from source
cargo build --release -p fin-node

# Install
sudo mkdir -p /opt/ippan-l2
sudo cp target/release/fin-node /opt/ippan-l2/
sudo chmod +x /opt/ippan-l2/fin-node
```

### 2. Create User

```bash
sudo useradd -r -s /bin/false -d /var/lib/ippan-l2 ippan
sudo mkdir -p /var/lib/ippan-l2/{receipts,fin_db,data_db,audit_db,snapshots}
sudo chown -R ippan:ippan /var/lib/ippan-l2
```

### 3. Install Configuration

```bash
sudo mkdir -p /etc/ippan-l2
sudo cp configs/prod.toml /etc/ippan-l2/config.toml
# Create and edit secrets.env as shown above
```

### 4. Install Service

```bash
sudo cp deploy/systemd/fin-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable fin-node
sudo systemctl start fin-node
```

### 5. Check Status

```bash
sudo systemctl status fin-node
sudo journalctl -u fin-node -f
```

---

## Docker Deployment

### 1. Build Image

```bash
docker build --target fin-node -t ippan-l2/fin-node:latest .
```

### 2. Create Config Volume

```bash
mkdir -p ./prod-config
cp configs/prod.toml ./prod-config/config.toml
# Edit config as needed
```

### 3. Run Container

```bash
docker run -d \
  --name fin-node \
  --restart unless-stopped \
  -p 3000:3000 \
  -v ./prod-config:/app/configs:ro \
  -v fin-data:/var/lib/ippan-l2 \
  -e IPPAN_L2_CONFIG=/app/configs/config.toml \
  -e L1_BASE_URL=${L1_BASE_URL} \
  -e L1_API_KEY=${L1_API_KEY} \
  -e ADMIN_TOKEN=${ADMIN_TOKEN} \
  ippan-l2/fin-node:latest
```

### 4. Using Docker Compose

```bash
# Copy and edit .env
cp .env.example .env
# Edit with production values

# Start with production profile
docker compose --profile prod up -d
```

---

## Monitoring Setup

### Prometheus

Add to Prometheus `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'ippan-l2'
    static_configs:
      - targets: ['fin-node:3000']
    metrics_path: /metrics
    scrape_interval: 15s
```

### Key Metrics

| Metric | Description |
|--------|-------------|
| `http_requests_total` | Total HTTP requests by route |
| `http_request_duration_seconds` | Request latency histogram |
| `http_rate_limited_total` | Rate limited requests |
| `recon_pending_total` | Pending reconciliation items |
| `receipts_total` | Receipts by state |
| `ha_is_leader` | Leadership status |

### Alerting Rules

```yaml
groups:
  - name: ippan-l2
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 5m
        
      - alert: ReconBacklog
        expr: recon_pending_total > 1000
        for: 10m
        
      - alert: HighLatency
        expr: histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m])) > 5
        for: 5m
```

---

## Checklist

### Pre-Deployment

- [ ] Security mode set to `prod`
- [ ] Admin token configured (32+ chars)
- [ ] L1 RPC endpoints configured
- [ ] Rate limiting enabled
- [ ] Storage paths exist with correct permissions
- [ ] Secrets file protected (chmod 600)
- [ ] Firewall rules configured
- [ ] TLS termination set up (if public)

### Post-Deployment

- [ ] Health endpoint responding (`/healthz`)
- [ ] Ready endpoint healthy (`/readyz`)
- [ ] Metrics endpoint accessible (`/metrics`)
- [ ] Prometheus scraping metrics
- [ ] Logs accessible and not leaking secrets
- [ ] Backup strategy for sled databases

### Ongoing

- [ ] Monitor `recon_pending_total` for backlog
- [ ] Review `rate_limited_total` for abuse
- [ ] Check `http_requests_total{status="5xx"}` for errors
- [ ] Rotate admin token periodically
- [ ] Keep up with security updates
