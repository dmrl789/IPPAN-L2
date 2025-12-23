# IPPAN FIN Hub – Specification (Draft)

> **Note (MVP v1 implemented):** The production-ready HUB-FIN MVP is documented under `docs/hub-fin/`
> (see `docs/hub-fin/README.md`). This draft spec below describes an earlier, broader design and may
> not match the current MVP surface.

The IPPAN FIN Hub is a Layer 2 (L2) execution environment for financial
instruments running on top of IPPAN CORE (L1). It supports:

- Real-world asset (RWA) tokenisation
- Fungible token issuance (funds, bonds, stablecoins)
- Mint, burn and transfer operations
- Batch settlement via IPPAN CORE

## 1. Core Types

Implemented in `hub-fin` and `l2-core`:

- `L2HubId::Fin` – identifier for the FIN Hub.
- `AssetId` – opaque identifier for fungible assets (e.g. `asset-eurx`).
- `AccountId` – opaque identifier for accounts at L2.
- `FixedAmount` – fixed-point integer type (no floats) with a global scale
  factor (1e6) used for balances and fees.
- `FinOperation` – enum representing high-level operations:
  - `RegisterFungibleAsset`
  - `Mint`
  - `Burn`
  - `Transfer`
- `FinTransaction` – wraps a `tx_id` and a `FinOperation`.
  - This matches the shared envelope pattern in `l2-core`:
    `L2TransactionEnvelope<FinOperation> = { hub, tx_id, payload }`.

## 2. State Model

State is represented by:

- `FinState`:
  - `assets: BTreeMap<AssetId, FungibleAssetMeta>`
  - `accounts: BTreeMap<AccountId, AccountState>`

- `FungibleAssetMeta`:
  - `symbol: String`
  - `name: String`
  - `decimals: u8`

- `AccountState`:
  - `balances: BTreeMap<AssetId, FixedAmount>`

State transitions are performed by `FinState::apply_operation(&FinOperation)`:

- Registers assets (re-registration currently errors)
- Mints to target account (requires asset to exist)
- Burns from account (requires sufficient balance)
- Transfers between accounts (requires sufficient balance)

All arithmetic uses `FixedAmount` to guarantee deterministic behaviour,
with explicit overflow checks.

## 3. State Store Abstraction

- `FinStateStore` trait defines:
  - `load_state() -> FinState`
  - `save_state(&FinState) -> Result<(), FinStateError>`

- `InMemoryFinStateStore` implements `FinStateStore` for testing and dev.

A production implementation will integrate with a database or persistence
layer and may support snapshots, versioning and rollbacks.

## 4. L1 Settlement

FIN batches are built and settled via `FinHubEngine`:

- Takes an `L1SettlementClient` and a `FinStateStore`.
- `submit_batch(batch_id, txs, fee)`:
  1. Loads the current `FinState`.
  2. Applies each `FinTransaction.op` via `apply_operation`.
  3. Persists updated state using `save_state`.
  4. Builds an `L2Batch` with the transaction count.
  5. Constructs a `SettlementRequest` including the hub ID and batch.
  6. Calls `L1SettlementClient::submit_settlement`.

Settlement results are represented by `SettlementResult` (from `l2-core`),
which includes the `hub`, `batch_id`, an opaque `l1_reference` and a
`finalised` flag.

## 5. Node Binary (fin-node)

The `fin-node` crate provides a simple development binary that:

- Parses CLI arguments (e.g. `--batch-id`).
- Constructs a `FinHubEngine` using:
  - `DummyL1Client` (stub implementation of `L1SettlementClient`)
  - `InMemoryFinStateStore` for state.
- Builds a demo batch with:
  - asset registration
  - a sample transfer
- Submits the batch to the dummy client and prints a JSON summary.

This binary is a placeholder that will be replaced with a real FIN Hub
node that:

- Connects to IPPAN CORE via RPC
- Exposes its own RPC / API
- Manages persistent state storage
- Handles configuration and operator keys

## 6. Determinism and Safety

- All numeric values use `FixedAmount` (integer-based fixed point).
- `f32` and `f64` are forbidden by Clippy lints.
- `unsafe` Rust is forbidden.
- Overflows in arithmetic are handled explicitly and treated as errors.

This design ensures that FIN Hub execution remains deterministic and
compatible with IPPAN's audit and verification goals.
