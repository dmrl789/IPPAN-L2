# HUB-FIN MVP (v1) — Scope

This document defines the **minimal, production-ready skeleton** for HUB-FIN MVP v1.

## Goals (MVP)

- **Two concrete FIN actions** with deterministic execution:
  - **CREATE_ASSET**: define an asset class (RWA instrument).
  - **MINT_UNITS**: mint units of an asset to an account (allocation ledger).
- **Deterministic state transitions**:
  - No floats anywhere; **fixed-point / scaled integers only** for amounts.
  - Canonical encoding + stable hashes (fixture-backed).
  - Idempotent application via deterministic duplicate detection.
- **Emit L1 contract envelopes**:
  - HUB-FIN never talks to L1 directly; it produces `HubPayloadEnvelopeV1` bytes for fin-node.
- **State query via fin-node API**:
  - Minimal `/fin/*` HTTP endpoints for submitting actions and reading state.
- **Tests + fixtures + docs**:
  - Golden fixtures enforce canonical byte stability.

## Non-goals (MVP)

- Transfers, orderbooks, AMM, lending, liquidation, etc.
- L1 consensus assumptions: the hub produces envelopes only; L1 finality semantics remain L1-defined.

## Actions (exactly two)

### ACTION A — CREATE_ASSET (v1)

- Defines a new asset class.
- **Deterministic asset id**:
  - `asset_id = blake3(name || issuer || symbol)` (UTF-8 bytes; exact concatenation defined in `docs/hub-fin/ACTIONS.md`).

### ACTION B — MINT_UNITS (v1)

- Mints new units of an existing asset to a target account.
- Uses a **scaled integer `u128` amount** (no floats).
- Idempotent via `action_id` (hash of canonical action bytes) and persisted `applied:<action_id>`.

## Storage choice

- **sled** key-value database (single-process, embedded).
- Deterministic keys:
  - `asset:<hex(asset_id)> -> AssetDef (serde JSON)`
  - `bal:<hex(asset_id)>:<account> -> u128 (big-endian bytes)`
  - `applied:<hex(action_id)> -> 1`
  - `apply_receipt:<hex(action_id)> -> JSON bytes` (local apply receipt)
  - `receipt:<hex(action_id)> -> JSON bytes` (fin-node receipt incl. L1 submit)

Rationale:
- Smallest persistent KV store not already present in repo.
- Supports atomic batches for apply + receipt writes.

## fin-node API endpoints (MVP)

All endpoints are versioned in their **response shapes** and return deterministic ids:

- `POST /fin/actions`
  - Body: a tagged union of `CreateAssetV1` or `MintUnitsV1`
  - Returns: `action_id`, `batch_id`, `idempotency_key`, `local_apply_status`, `l1_submit_result`, `receipt_path`
- `GET /fin/assets/:asset_id_hex`
  - Returns: asset definition (if exists)
- `GET /fin/balances?asset_id=...&account=...`
  - Returns: `amount_scaled_u128`
- `GET /fin/receipts/:action_id_hex`
  - Returns: stored action receipt (if exists)

## Determinism rules (MVP)

- **No floats** (repo-wide clippy denies float arithmetic; MVP maintains this).
- **Canonical JSON** for hashing:
  - Object keys sorted lexicographically recursively.
  - Compact JSON bytes.
- **Stable hashing**:
  - `action_id = blake3(canonical_bytes(action))`.
  - `HubPayloadEnvelopeV1.payload = canonical_bytes(FinEnvelopeV1)`.

## Runtime storage paths (fin-node)

- `storage.fin_db_dir` (default `fin_db`): sled DB directory for FIN state
- `storage.receipts_dir` (default `receipts`): receipt output directory

