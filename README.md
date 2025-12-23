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

# Run FIN node demo
make run-fin-node

# Run tests
make test
```

See [docs/DEV.md](docs/DEV.md) for detailed development instructions.

## Project Structure

```
IPPAN-L2/
├── l2-core/           # Core types and primitives
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
- [LOCAL_RUN.md](docs/LOCAL_RUN.md) - Running locally
- [API.md](docs/API.md) - API reference
- [architecture.md](docs/architecture.md) - System architecture

## Status

Production integration phase:
- ✅ L2 core types (batches, proofs, hub IDs)
- ✅ FIN Hub (tokenization, transfers)
- ✅ DATA Hub (content attestations)
- ✅ Ethereum Oracle integration
- ✅ CI/CD pipeline
- ✅ Security baseline
- 🔄 HTTP endpoints (planned)
- 🔄 Production deployment (planned)

This repo does **not** contain IPPAN CORE code. CORE lives in the main IPPAN repository.

## Contributing

1. Run `make check` before committing
2. Follow the [development guide](docs/DEV.md)
3. See [SECURITY.md](SECURITY.md) for security policy

## License

MIT OR Apache-2.0
