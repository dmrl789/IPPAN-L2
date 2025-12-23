# Devnet Runbook (IPPAN-L2 → real IPPAN CORE devnet)

This document describes how to run `fin-node` against a **real** IPPAN CORE devnet RPC **without modifying IPPAN CORE**.

## Configuration

Use the provided template:

- `configs/devnet.toml`

Fill the following fields with **real values from IPPAN CORE devnet**:

- **`l1.base_url`**: base URL only (scheme + host + port)
- **`l1.endpoints.chain_status`**
- **`l1.endpoints.submit_batch`**
- **`l1.endpoints.get_inclusion`**: must contain `{id}`
- **`l1.endpoints.get_finality`**: must contain `{l1_tx_id}`

Optional:

- **`l1.api_key`**: use `env:L1_API_KEY` (do not commit secrets)
- **`l1.expected_network_id`**: readiness gate

## Run commands

### Read-only smoke (safe)

```bash
export IPPAN_L2_CONFIG=./configs/devnet.toml
cargo run -p fin-node -- --l1-mode http l1 check
```

### Service mode (health/ready/metrics)

```bash
export IPPAN_L2_CONFIG=./configs/devnet.toml
cargo run -p fin-node -- --l1-mode http run
```

Endpoints:

- `GET /healthz`
- `GET /readyz` (requires L1 status reachability; optionally network id match)
- `GET /metrics` (Prometheus)
- `GET /recon/pending` (reconciliation queue snapshot)

### Linkage policy: finality-required entitlements

To require **L1 finality** of the FIN payment before the DATA entitlement is granted:

1) Set in config:

```toml
[linkage]
entitlement_policy = "finality_required"
```

2) Ensure reconciliation is enabled (required for progress):

```toml
[recon]
enabled = true
```

## Manual smoke (optional, uses real devnet)

This is intentionally **not** part of CI.

```bash
export IPPAN_L2_CONFIG=./configs/devnet.toml

# 1) Read-only checks first
cargo run -p fin-node -- --l1-mode http l1 check

# 2) Dry-run submit (does not touch L1)
cargo run -p fin-node -- --l1-mode http submit-batch --hub fin --file ./examples/batch_fin_v1.json --dry-run

# 3) Real submit (writes receipt to receipts/<id>.json)
cargo run -p fin-node -- --l1-mode http submit-batch --hub fin --file ./examples/batch_fin_v1.json

# 4) Inclusion lookup
ID="$(jq -r .idempotency_key receipts/*.json | tail -n 1)"
cargo run -p fin-node -- --l1-mode http l1 inclusion --id "$ID"
```

Alternatively run:

```bash
export IPPAN_L2_CONFIG=./configs/devnet.toml
./scripts/devnet_smoke.sh
```

