# Deployment (Docker + systemd)

This document describes production-grade ways to run `fin-node`.

## Docker

### Build

```bash
docker build -f Dockerfile.fin-node -t ippan-l2/fin-node:local .
```

### Run (example)

```bash
docker run --rm -p 3000:3000 \
  -e IPPAN_L2_CONFIG=/app/configs/prod.toml \
  -v ./configs:/app/configs:ro \
  -v ./receipts:/app/receipts \
  ippan-l2/fin-node:local run
```

### Docker Compose

```bash
docker compose --profile fin up --build
```

## systemd (bare metal)

### Install

1. Create user:

```bash
sudo useradd -r -s /bin/false ippan || true
```

2. Copy binaries (example paths):

- `/opt/ippan-l2/fin-node`
- `/opt/ippan-l2/ippan_eth_oracle_daemon` (optional)

3. Copy config:

- `/etc/ippan-l2/config.toml`

and export secrets via environment variables (or use a secrets manager).

4. Install units:

```bash
sudo cp deploy/systemd/fin-node.service /etc/systemd/system/fin-node.service
sudo systemctl daemon-reload
sudo systemctl enable --now fin-node
```

### Logs

```bash
sudo journalctl -u fin-node -f
```

## Health / readiness

```bash
curl -sSf http://127.0.0.1:3000/healthz
curl -sSf http://127.0.0.1:3000/readyz
curl -sSf http://127.0.0.1:3000/metrics
```

## HA (multi-node)

`fin-node` supports a lightweight HA mode where **exactly one node** runs background writer loops
(reconciliation/pruning) and followers serve read-only APIs.

See `docs/HA.md` for:

- required **shared storage** assumptions,
- `[ha]` config examples,
- `/api/v1/ha/status` endpoint and HA metrics,
- write routing / `NOT_LEADER` behavior.

