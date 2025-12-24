# IPPAN-L2

**IPPAN-L2** hosts the Layer 2 (L2) execution and asset hubs that sit on top of the IPPAN CORE (L1) deterministic settlement layer.

IPPAN-L2 focuses on:
- Tokenisation of real-world assets (RWA)
- NFTs and digital rights
- AI and dataset licensing
- IoT and machine-to-machine (M2M) payments
- Cross-chain bridges and interoperability
- General-purpose applications and marketplaces

All application and asset logic lives in L2 “Hubs”, while IPPAN CORE remains a pure, ultra-fast, deterministic settlement engine.

## L2 Hubs

Planned IPPAN Hubs:

- **IPPAN FIN** – L2 Finance Hub for RWA, bonds, funds, institutional stablecoins.
- **IPPAN DATA** – L2 Data + AI Hub for datasets, models, InfoLAW content, identity state.
- **IPPAN M2M** – L2 Machine-to-Machine Hub for IoT, agents, microtransactions.
- **IPPAN WORLD** – L2 Applications Hub for marketplaces, NFTs, consumer + enterprise apps.
- **IPPAN BRIDGE** – L2 Interoperability Hub for cross-chain asset flows and onboarding.

## Quick Start

```bash
# Clone
git clone https://github.com/dmrl789/IPPAN-L2.git
cd IPPAN-L2

# Run smoke tests (verifies everything works)
./scripts/smoke.sh

# Build
make build

# Run tests
make test
```

### Running the L2 Node

```bash
# Run with logging
export RUST_LOG=info
cargo run -p l2-node --release

# Or with IPPAN DevNet posting enabled
export IPPAN_RPC_URL=http://devnet.ippan.network:26657
export L2_LEADER=1
cargo run -p l2-node --release
```

### API Endpoints

```bash
# Health checks
curl -s http://localhost:3000/healthz
curl -s http://localhost:3000/readyz

# Status with batch/posting info
curl -s http://localhost:3000/status | jq

# Prometheus metrics
curl -s http://localhost:3000/metrics

# Submit a transaction
curl -X POST http://localhost:3000/tx \
  -H "Content-Type: application/json" \
  -d '{"chain_id": 1, "from": "alice", "nonce": 1, "payload": "48656c6c6f"}'

# Query transaction
curl -s http://localhost:3000/tx/<TX_HASH>

# Query batch
curl -s http://localhost:3000/batch/<BATCH_HASH>
```

### DevNet Smoke Test

```bash
# Run smoke test against local node
./scripts/devnet_smoke.sh http://localhost:3000
```

See [docs/DEV.md](docs/DEV.md) for detailed development instructions.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IPPAN_RPC_URL` | (empty) | IPPAN DevNet RPC endpoint for posting |
| `L2_DB_PATH` | `./data/l2` | Sled database path |
| `L2_LISTEN_ADDR` | `0.0.0.0:3000` | HTTP listen address |
| `L2_CHAIN_ID` | `1` | L2 chain identifier |
| `L2_LEADER` | `true` | Enable leader mode (accepts writes) |
| `L2_ADMISSION_CAP` | `1024` | Max pending transactions (429 when full) |
| `BATCHER_ENABLED` | `true` | Enable batch creation |

See [docs/ops/devnet-runbook.md](docs/ops/devnet-runbook.md) for full configuration reference.

## Project Structure

```
IPPAN-L2/
├── crates/
│   ├── l2-core/       # Core types and primitives (canonical encoding + hashing)
│   ├── l2-storage/    # Sled-backed persistence for tx/batches/receipts
│   ├── l2-batcher/    # Deterministic batching loop + poster trait
│   ├── l2-bridge/     # Bridge watcher skeleton
│   └── l2-node/       # Axum HTTP node exposing health/status/metrics
├── l2-core/           # Legacy path kept for backward compatibility
├── hub-fin/           # Finance Hub implementation
├── hub-data/          # Data Hub implementation
├── fin-node/          # FIN Hub executable
├── integrations/
│   └── eth-oracle/    # Ethereum Oracle integration
├── configs/           # Configuration files
├── docs/              # Documentation
└── scripts/           # Development scripts
```

## Documentation

- [DEV.md](docs/DEV.md) - Development guide
- [CONFIG.md](docs/CONFIG.md) - Configuration reference
- [OPS.md](docs/OPS.md) - Operations guide
- [SNAPSHOTS.md](docs/SNAPSHOTS.md) - Snapshot format + guarantees
- [DR.md](docs/DR.md) - Disaster recovery procedures (L2-grade)
- [WHITEPAPER.md](docs/WHITEPAPER.md) - Whitepaper-ready notes (Limitations & Resilience)
- [LOCAL_RUN.md](docs/LOCAL_RUN.md) - Running locally
- [API.md](docs/API.md) - API reference
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - Node/batcher/bridge components
- [OpenAPI (fin-node)](docs/openapi/README.md) - Production API contract + SDK stub generation
- [HUB-FIN MVP](docs/hub-fin/README.md) - Finance hub MVP v1 docs (actions + API)
- [HUB-DATA MVP](docs/hub-data/README.md) - Data hub MVP v1 docs (datasets + licenses + attestations)
- [HUB linkage](docs/hubs/LINKAGE.md) - Cross-hub IDs and invariants
- [Buy license](docs/hubs/BUY_LICENSE.md) - End-to-end payment → entitlement workflow
- [architecture.md](docs/architecture.md) - System architecture
- [SECURITY_MODEL.md](docs/SECURITY_MODEL.md) - Threat model and mitigations
- [LEADER.md](docs/LEADER.md) - Sequencer/leader model and rotation notes
- [DevNet Runbook](docs/ops/devnet-runbook.md) - Operations guide for DevNet deployment

## Status

Production integration phase:
- ✅ L2 core types (batches, proofs, hub IDs, canonical encoding)
- ✅ BatchEnvelope with ed25519 sequencer signatures
- ✅ FIN Hub MVP v1 (CREATE_ASSET, MINT_UNITS, TRANSFER_UNITS)
- ✅ DATA Hub MVP v1 (REGISTER_DATASET, ISSUE_LICENSE, APPEND_ATTESTATION)
- ✅ IPPAN RPC client (timeouts, retries, tx posting)
- ✅ L2 Node with tx ingress + 429 backpressure
- ✅ Single-leader sequencer mode
- ✅ Batch posting to IPPAN DevNet
- ✅ Reconciler for L1 confirmation tracking
- ✅ Persistent posting state (Pending → Posted → Confirmed)
- ✅ DevNet E2E tests
- ✅ Ethereum Oracle integration
- ✅ CI/CD pipeline
- 🔄 Production deployment (planned)

This repo does **not** contain IPPAN CORE code. CORE lives in the main IPPAN repository.

## Contributing

1. Run `make check` before committing
2. Follow the [development guide](docs/DEV.md)
3. See [SECURITY.md](SECURITY.md) for security policy

## License

MIT OR Apache-2.0
