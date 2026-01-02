# Migration Notes: Multi-Hub + Settlement Contract (Hardened)

**Date:** 2026-01-02
**Revision:** `ippan-l2-hubs-settlement-harden`

## Overview
This revision refactors IPPAN-L2 into a 2-layer architecture with multiple execution hubs settling on IPPAN CORE.

## Breaking Changes
*   **`l2-core`**:
    *   Renamed/Refactored core types: `L2Tx` is now an alias for `L2TransactionEnvelope`.
    *   Enforced **Canonical Encoding v1**: All serialized types (`BatchCommitment`, `SettlementRequest`) now include a version header.
    *   `L1SettlementClient` trait updated to stricter types (`l1_contract::L1InclusionProof`).
*   **Removed**: Old monolithic settlement assumptions in `fin-node` (replaced by `l2-engine` + Hubs).

## New Components
*   **`crates/l2-hub`**: Defines `HubStateMachine` trait.
*   **`crates/l2-engine`**: Implements Hub Registry, Router, and Settlement Loop.
*   **`crates/hub-fin` / `hub-data`**: Reference implementations of deterministic hubs.

## CI & Safety
*   **Strict Determinism**: `crates/l2-core` prevents use of `f32`/`f64` and `unsafe` via CI gate.
*   **Canonical Encoding**: Verified strictly in `common::canonical`.

## Testing
*   Run full suite: `cargo test --workspace --all-features`
*   Verify encoding: `cargo test -p l2-core --test canonical_encoding`
