# Running IPPAN-L2 Locally

This guide describes how to run IPPAN-L2 components locally for development and testing.

## Prerequisites

- **Rust** 1.80+ (pinned in `rust-toolchain.toml`)
- **Docker** (optional, for containerized runs)
- **Foundry** (optional, for Solidity development)

## Quick Start

```bash
# Clone and enter repository
git clone https://github.com/dmrl789/IPPAN-L2.git
cd IPPAN-L2

# Run smoke tests (verifies everything works)
./scripts/smoke.sh

# Run FIN node demo
./scripts/run_local.sh fin-node
```

## Using the Run Script

The `scripts/run_local.sh` script provides convenient commands:

```bash
# Show help
./scripts/run_local.sh help

# Build all components
./scripts/run_local.sh build

# Run FIN node demo
./scripts/run_local.sh fin-node

# Run oracle daemon (requires environment variables)
export IPPAN_RPC_URL=http://127.0.0.1:8080
export ETH_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
export ETH_PRIVATE_KEY=0x...
./scripts/run_local.sh oracle

# Dump oracle scores (no Ethereum push)
./scripts/run_local.sh dump
```

## Using Make

The Makefile provides standard targets:

```bash
make build        # Build release
make test         # Run tests
make clippy       # Run linter
make fmt          # Format code
make check        # Full check (fmt + clippy + test)
make run-fin-node # Run FIN node
```

## Using Docker

### Build Images

```bash
# Build all images
docker-compose build

# Build specific target
docker build --target fin-node -t ippan-fin-node .
docker build --target oracle-daemon -t ippan-oracle-daemon .
```

### Run with Docker Compose

```bash
# Run FIN node
docker-compose --profile fin up

# Run oracle daemon
export ETH_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
export ETH_PRIVATE_KEY=0x...
docker-compose --profile oracle up
```

### Run Individual Containers

```bash
# FIN node
docker run -it --rm \
  -v $(pwd)/configs:/app/configs:ro \
  ippan-fin-node --config /app/configs/local.toml

# Oracle daemon
docker run -it --rm \
  -e IPPAN_RPC_URL=http://host.docker.internal:8080 \
  -e ETH_RPC_URL=$ETH_RPC_URL \
  -e ETH_PRIVATE_KEY=$ETH_PRIVATE_KEY \
  -v $(pwd)/integrations/eth-oracle/configs:/app/configs:ro \
  ippan-oracle-daemon watch --config /app/configs/devnet_sepolia.toml
```

## Component-Specific Instructions

### FIN Node

The FIN node is currently a demo CLI that processes a batch of transactions:

```bash
# Basic run
cargo run -p fin-node

# With custom parameters
cargo run -p fin-node -- \
  --batch-id "test-batch-001" \
  --from acc-alice \
  --to acc-bob \
  --amount 100 \
  --symbol EURX \
  --decimals 6
```

**Output example:**
```json
{
  "hub": "Fin",
  "batch_id": "test-batch-001",
  "l1_reference": "dummy-l1-tx",
  "finalised": true,
  "asset_id": "asset-demo-eurx",
  "decimals": 6,
  "balances": {
    "acc-alice": 0,
    "acc-bob": 10000000
  }
}
```

### Oracle Daemon

The oracle daemon polls IPPAN and pushes scores to Ethereum:

```bash
# Set environment variables
export IPPAN_RPC_URL=http://127.0.0.1:8080
export ETH_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
export ETH_PRIVATE_KEY=0x...

# Run in watch mode (continuous)
cargo run -p ippan_eth_oracle_daemon -- watch \
  --config integrations/eth-oracle/configs/devnet_sepolia.toml

# One-shot dump (debug)
cargo run -p ippan_eth_oracle_daemon -- dump \
  --config integrations/eth-oracle/configs/devnet_sepolia.toml
```

**Note:** If `oracle_contract_address` is `0x0...0`, the daemon runs but skips Ethereum writes (useful for testing).

### Solidity Contracts

```bash
cd integrations/eth-oracle/contracts

# Install Foundry if needed
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Build
forge build

# Test
forge test -vvv

# Deploy
forge script script/DeployIppanAiOracle.s.sol \
  --rpc-url "$ETH_RPC_URL" \
  --private-key "$ETH_PRIVATE_KEY" \
  --broadcast
```

## Configuration

### Local Config

Edit `configs/local.toml` for local development:

```toml
[l1]
base_url = "http://127.0.0.1:8080"
api_key = ""

[server]
bind_address = "127.0.0.1:3000"

[logging]
level = "debug"
format = "pretty"
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `IPPAN_L2_CONFIG` | Config file path | `configs/local.toml` |
| `IPPAN_RPC_URL` | IPPAN CORE RPC URL | `http://127.0.0.1:8080` |
| `ETH_RPC_URL` | Ethereum RPC URL | (required for oracle) |
| `ETH_PRIVATE_KEY` | Ethereum private key | (required for oracle) |
| `RUST_LOG` | Log level | `info` |

## Smoke Tests

Run smoke tests to verify everything is working:

```bash
./scripts/smoke.sh
```

This checks:
- Prerequisites (Rust, Cargo)
- Build passes
- Tests pass
- Clippy passes
- Format check passes
- Binaries build
- Config files exist
- Documentation exists
- CI configuration exists

## Troubleshooting

### Build Fails

```bash
# Clean and rebuild
cargo clean
cargo build --workspace
```

### Tests Fail

```bash
# Run with verbose output
cargo test --workspace -- --nocapture
```

### Oracle Can't Connect

Check:
1. IPPAN_RPC_URL is correct
2. ETH_RPC_URL is correct and reachable
3. ETH_PRIVATE_KEY is set and has funds

### Docker Permission Denied

```bash
# Add user to docker group
sudo usermod -aG docker $USER
# Log out and back in
```

## Development Workflow

1. Make changes
2. Run `make fmt` to format
3. Run `make clippy` to lint
4. Run `make test` to test
5. Run `./scripts/smoke.sh` for full check
6. Commit and push
