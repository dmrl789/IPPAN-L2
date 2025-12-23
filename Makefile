# IPPAN-L2 Makefile
# Production-grade build, test, and development commands

.PHONY: all build test clippy fmt check audit clean run-fin-node run-oracle-daemon help

# Default target
all: check

# Build all workspace crates in release mode
build:
	cargo build --workspace --release

# Build in debug mode (faster)
build-debug:
	cargo build --workspace

# Run all tests
test:
	cargo test --workspace --all-features

# Run clippy with strict warnings
clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

# Format code
fmt:
	cargo fmt --all

# Check formatting without modifying
fmt-check:
	cargo fmt --all -- --check

# Full check (fmt + clippy + test)
check: fmt-check clippy test

# Security audit (requires cargo-audit)
audit:
	@command -v cargo-audit >/dev/null 2>&1 || { echo "Installing cargo-audit..."; cargo install cargo-audit; }
	cargo audit

# Security deny check (requires cargo-deny)
deny:
	@command -v cargo-deny >/dev/null 2>&1 || { echo "Installing cargo-deny..."; cargo install cargo-deny; }
	cargo deny check

# Clean build artifacts
clean:
	cargo clean

# Run fin-node demo
run-fin-node:
	cargo run -p fin-node -- --batch-id demo-$(shell date +%s)

# Run eth-oracle daemon (requires config)
run-oracle-daemon:
	cargo run -p ippan_eth_oracle_daemon -- watch --config integrations/eth-oracle/configs/devnet_sepolia.toml

# Dump oracle scores (one-shot)
dump-oracle:
	cargo run -p ippan_eth_oracle_daemon -- dump --config integrations/eth-oracle/configs/devnet_sepolia.toml

# Build Solidity contracts (requires foundry)
contracts-build:
	cd integrations/eth-oracle/contracts && forge build

# Test Solidity contracts
contracts-test:
	cd integrations/eth-oracle/contracts && forge test

# Generate documentation
docs:
	cargo doc --workspace --no-deps --open

# Install development dependencies
dev-deps:
	cargo install cargo-audit cargo-deny

# Help
help:
	@echo "IPPAN-L2 Makefile targets:"
	@echo ""
	@echo "  all              - Run full check (default)"
	@echo "  build            - Build all crates in release mode"
	@echo "  build-debug      - Build all crates in debug mode"
	@echo "  test             - Run all tests"
	@echo "  clippy           - Run clippy with strict warnings"
	@echo "  fmt              - Format code"
	@echo "  fmt-check        - Check formatting"
	@echo "  check            - Full check (fmt + clippy + test)"
	@echo "  audit            - Run cargo-audit security check"
	@echo "  deny             - Run cargo-deny dependency check"
	@echo "  clean            - Clean build artifacts"
	@echo "  run-fin-node     - Run fin-node demo"
	@echo "  run-oracle-daemon - Run eth-oracle daemon"
	@echo "  dump-oracle      - Dump oracle scores"
	@echo "  contracts-build  - Build Solidity contracts"
	@echo "  contracts-test   - Test Solidity contracts"
	@echo "  docs             - Generate and open documentation"
	@echo "  dev-deps         - Install development dependencies"
	@echo "  help             - Show this help"
