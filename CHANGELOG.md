# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Production integration baseline
  - CI/CD pipeline with GitHub Actions (fmt, clippy, test, audit, deny, solidity)
  - Security baseline with `cargo-deny` and `cargo-audit`
  - Dependabot configuration for automated dependency updates
  - SECURITY.md vulnerability reporting policy
- Configuration system
  - Centralized config files (`configs/local.toml`, `dev.toml`, `prod.toml`)
  - Environment variable overrides
  - `docs/CONFIG.md` configuration reference
- Development tooling
  - Makefile with standard targets (build, test, clippy, fmt, audit)
  - `scripts/run_local.sh` local development runner
  - `scripts/smoke.sh` smoke test script
  - Docker and docker-compose support
- Documentation
  - `docs/DEV.md` development guide
  - `docs/OPS.md` operations guide
  - `docs/LOCAL_RUN.md` local running guide
  - `docs/API.md` API reference
- API stability
  - Golden fixture tests for serialization compatibility
  - Documented stability guarantees
- Workspace improvements
  - Normalized `Cargo.toml` metadata across crates
  - Workspace-level lint configuration
  - Pinned toolchain with `rust-toolchain.toml`

### Changed
- Updated Rust toolchain to stable channel
- Moved lint configuration to workspace level

### Fixed
- Clippy warning in `config.rs` (needless_question_mark)
- Formatting issues across codebase

## [0.1.0] - 2024-XX-XX

### Added
- Initial release
- Core types (`l2-core`)
  - `L2TransactionEnvelope` - Generic transaction wrapper
  - `L2HubId` - Hub identifier enum
  - `L2Batch`, `L2BatchId` - Batch types
  - `FixedAmount` - Deterministic fixed-point arithmetic
  - `AccountId`, `AssetId` - Identifier types
  - `SettlementRequest`, `SettlementResult` - L1 settlement types
  - `L1SettlementClient` trait
- FIN Hub (`hub-fin`)
  - `FinState` - Ledger state
  - `FinOperation` - Register, Mint, Burn, Transfer
  - `FinHubEngine` - Batch processing and settlement
  - `FinStateStore` trait with in-memory implementation
- DATA Hub (`hub-data`)
  - `DataState` - Attestation registry
  - `Attestation` - Content attestation type
  - `DataHubEngine` - Attestation processing
- FIN Node (`fin-node`)
  - CLI demo binary
  - Dummy L1 client
  - HTTP L1 client (prepared but not wired)
- Ethereum Oracle (`integrations/eth-oracle`)
  - `IppanAiOracle` Solidity contract
  - Oracle daemon with polling
  - Subject ID derivation (BLAKE3)
  - Score diffing with rate limiting
  - On-chain label storage

[Unreleased]: https://github.com/dmrl789/IPPAN-L2/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dmrl789/IPPAN-L2/releases/tag/v0.1.0
