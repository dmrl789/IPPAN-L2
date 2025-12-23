# IPPAN-L2 Development Guide

This document describes how to build, test, and run the IPPAN-L2 workspace.

## Prerequisites

- **Rust**: Version 1.83.0 or later (pinned in `rust-toolchain.toml`)
- **Foundry** (optional): For Solidity contract development
- **Make**: For convenience targets

## Quick Start

```bash
# Clone the repository
git clone https://github.com/dmrl789/IPPAN-L2.git
cd IPPAN-L2

# Run full check (format, lint, test)
make check

# Or individually:
make fmt        # Format code
make clippy     # Run linter
make test       # Run tests
```

## Building

```bash
# Debug build (faster compilation)
make build-debug

# Release build (optimized)
make build
```

## Testing

```bash
# Run all workspace tests
make test

# Run tests with output
cargo test --workspace -- --nocapture

# Run specific test
cargo test -p hub-fin -- fin_state_applies_basic_flow
```

## Code Quality

### Formatting

```bash
# Format all code
make fmt

# Check formatting without changes
make fmt-check
```

### Linting

```bash
# Run clippy with strict warnings
make clippy
```

The workspace enforces these lint rules:
- No unsafe code (`forbid`)
- No floating point arithmetic (`deny`)
- No floating point comparisons (`deny`)
- Strict integer casting rules (`deny`)

### Security Audits

```bash
# Check for known vulnerabilities
make audit

# Check dependencies with cargo-deny
make deny
```

## Running Components

### FIN Node Demo

```bash
# Run a demo batch
make run-fin-node

# With custom parameters
cargo run -p fin-node -- \
  --batch-id my-batch \
  --from acc-alice \
  --to acc-bob \
  --amount 100
```

### Ethereum Oracle Daemon

```bash
# Set required environment variables
export IPPAN_RPC_URL=http://127.0.0.1:8080
export ETH_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
export ETH_PRIVATE_KEY=0x...

# Run the daemon
make run-oracle-daemon

# Or dump scores without pushing to Ethereum
make dump-oracle
```

### Solidity Contracts

```bash
# Build contracts
make contracts-build

# Test contracts
make contracts-test

# Deploy (requires ETH_RPC_URL and ETH_PRIVATE_KEY)
cd integrations/eth-oracle/contracts
forge script script/DeployIppanAiOracle.s.sol \
  --rpc-url "$ETH_RPC_URL" \
  --private-key "$ETH_PRIVATE_KEY" \
  --broadcast
```

## Project Structure

```
IPPAN-L2/
├── l2-core/           # Core types and primitives
├── hub-fin/           # Finance Hub implementation
├── hub-data/          # Data Hub implementation
├── fin-node/          # FIN Hub executable
├── integrations/
│   └── eth-oracle/    # Ethereum Oracle integration
│       ├── contracts/ # Solidity contracts (Foundry)
│       ├── daemon/    # Rust daemon
│       └── configs/   # Configuration files
├── docs/              # Documentation
└── configs/           # Application configs
```

## Configuration

See [CONFIG.md](CONFIG.md) for detailed configuration documentation.

Configuration files are loaded from:
1. TOML file specified by `--config` flag
2. Environment variable `IPPAN_L2_CONFIG`
3. Default: `configs/local.toml`

Environment variables override TOML values.

## Documentation

```bash
# Generate and open API documentation
make docs
```

## Troubleshooting

### Rust version mismatch

The project uses a pinned Rust version. Install it with:

```bash
rustup install 1.83.0
rustup override set 1.83.0
```

### Missing clippy/rustfmt

```bash
rustup component add clippy rustfmt
```

### Foundry not found

Install Foundry:

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

## Contributing

1. Run `make check` before committing
2. Follow existing code style
3. Add tests for new functionality
4. Update documentation as needed

See [CONTRIBUTING.md](../CONTRIBUTING.md) for more details.
