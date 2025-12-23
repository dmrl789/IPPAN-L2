# L1 ↔ L2 Contract (IPPAN CORE ↔ IPPAN-L2)

This document specifies the **minimal, versioned integration contract** between:

- **IPPAN CORE (L1)**: provides chain status + accepts deterministic L2 envelopes + serves inclusion/finality proofs.
- **IPPAN-L2 (L2)**: produces deterministic, versioned envelopes and submits them via a transport-agnostic client.

Non-goals (v1):
- Defining IPPAN CORE’s consensus/finality internals.
- Inventing endpoint paths or extending CORE APIs from this repo.
- Mandating a single transport (HTTP is one adapter, not the contract).

## PHASE 0 — Found expectations in this repo (no guessing)

The following existing expectations were discovered by scanning this repository:

- **Environment/config**:
  - `IPPAN_RPC_URL` used for CORE/devnet HTTP base URL in scripts/docs:
    - `scripts/run_local.sh`
    - `docs/LOCAL_RUN.md`
    - `docker-compose.yml`
    - `integrations/eth-oracle/daemon/src/config.rs`
    - `integrations/eth-oracle/configs/devnet_sepolia.toml`
- **Known/mentioned L1 HTTP paths**:
  - `GET /validators` (CometBFT-style) used by oracle integration:
    - `integrations/eth-oracle/daemon/src/ippan_client.rs`
    - `integrations/eth-oracle/README.md`
  - Health endpoints mentioned in ops docs:
    - `GET {IPPAN_RPC_URL}/health` referenced in troubleshooting:
      - `docs/OPS.md`
    - Planned L2 node endpoints (local service): `GET /healthz`, `GET /readyz`
      - `docs/OPS.md`
- **Existing L2 “settlement” types/traits in this repo**:
  - `l2-core`: `L2Batch`, `SettlementRequest`, `SettlementResult`, `L1SettlementClient`
    - `l2-core/src/lib.rs`
  - `hub-fin` and `hub-data` currently call `L1SettlementClient::submit_settlement`
    - `hub-fin/src/lib.rs`
    - `hub-data/src/lib.rs`
- **Hard-coded endpoint assumptions that must NOT be treated as contract**:
  - `fin-node` currently assumes a placeholder path `POST {base_url}/l2/settle` (explicitly marked “for now”)
    - `fin-node/src/main.rs`

> **STOP CONDITION NOTE**: This repo does not currently contain a definitive, production L1 RPC surface for batch submission/inclusion/finality. Therefore, the HTTP adapter in this repo must require an explicit endpoint map in config and fail fast if missing.

## Contract surface (v1)

The v1 contract is implemented in `l2-core::l1_contract`:

- **Versioned wire types**:
  - `ContractVersion` (`"v1"`)
  - `L1ChainStatus`
  - `L1SubmitResult`
  - `L1InclusionProof` (opaque bytes for v1)
  - `HubPayloadEnvelopeV1`
  - `L2BatchEnvelopeV1`
- **Deterministic encoding + hashing**:
  - Canonical encoding: canonical JSON with recursively-sorted object keys
  - Hash: `blake3(canonical_bytes)`
- **Idempotency**:
  - `IdempotencyKey` is derived deterministically from:
    - contract version, hub id, batch id, sequence, and canonical payload hash
- **Transport-agnostic client trait**:
  - `trait L1Client` (chain status, submit batch, query inclusion, query finality)

### v1 wire types (JSON)

All v1 types are `serde`-friendly JSON structs with explicit field names.

#### `HubPayloadEnvelopeV1`

- **Purpose**: a hub-produced payload that `fin-node` submits to L1 as part of a batch envelope.
- **Fields**:
  - `contract_version`: `"v1"`
  - `hub`: `"Fin" | "Data" | ...` (existing `L2HubId`)
  - `schema_version`: hub-defined string, e.g. `"hub-fin.payload.v1"`
  - `content_type`: e.g. `"application/json"`
  - `payload`: base64url (no padding) encoded bytes

#### `L2BatchEnvelopeV1`

- **Purpose**: the canonical object submitted from L2 -> L1.
- **Fields**:
  - `contract_version`: `"v1"`
  - `hub`: hub id
  - `batch_id`: opaque string
  - `sequence`: `u64` monotonic sequence (0 if unknown)
  - `tx_count`: `u64`
  - `commitment`: optional string (opaque for v1)
  - `fee`: fixed-point scaled integer (`i128`, scale = 1e6)
  - `payload`: `HubPayloadEnvelopeV1`
  - `idempotency_key`: base64url (no padding) 32-byte key derived from v1 rules

#### `L1ChainStatus`

- **Purpose**: L1 status for smoke/health and basic coordination.
- **Fields**:
  - `network_id`: string
  - `height`: `u64`
  - `finalized_height`: optional `u64`
  - `time_micros`: `u64` (HashTimer™ semantics L1-defined)

#### `L1SubmitResult`

- **Purpose**: L1 acknowledgement for submission.
- **Fields**:
  - `accepted`: boolean
  - `already_known`: boolean (idempotent replay success)
  - `l1_tx_id`: optional string
  - `error_code`: optional string (L1-defined)
  - `message`: optional string

#### `L1InclusionProof`

- **Purpose**: inclusion/finality proof container (opaque for v1).
- **Fields**:
  - `l1_tx_id`: string
  - `height`: `u64`
  - `finalized`: boolean
  - `proof`: base64url (no padding) bytes (format L1-defined)

### Deterministic encoding & hashing

- **Canonical bytes**: JSON serialization with recursively sorted object keys.
- **Canonical hash**: `blake3(canonical_bytes)` (32 bytes).
- **Golden fixtures**: pinned in `l2-core/tests/fixtures/l1_contract/v1/` and enforced by tests.

### Idempotency & replay safety (v1)

`IdempotencyKey` is derived as:

`blake3("ippan-l1l2" || version || hub || batch_id || sequence || payload_canonical_hash)`

Rules:
- L2 must submit the same envelope with the same idempotency key on retries.
- L1 must treat “already known” as success and return a stable `l1_tx_id` for the same idempotency key.

## Configuration (HTTP adapter)

The HTTP adapter is **feature-gated** (`l2-core` feature `l1-http`) and requires:

- `base_url`
- `endpoints.chain_status`
- `endpoints.submit_batch`
- `endpoints.get_inclusion` (supports `{id}`)
- `endpoints.get_finality` (supports `{l1_tx_id}`)

No defaults are assumed in code.

## Required L1 capabilities (trait)

L1 must provide capabilities matching:

- `chain_status() -> L1ChainStatus`
- `submit_batch(&L2BatchEnvelopeV1) -> L1SubmitResult`
- `get_inclusion(&IdempotencyKey) -> Option<L1InclusionProof>`
- `get_finality(&L1TxId) -> Option<L1InclusionProof>`

## Security considerations

- Do not log secrets (API keys/tokens).
- Treat idempotency keys as replay protection primitives (still require L1-side enforcement).
- Envelopes are validated before submission; derived fields must match derivation rules.

## Compatibility / versioning

Every wire type is versioned (`ContractVersion`) and backed by golden fixtures in:
`l2-core/tests/fixtures/l1_contract/v1/`.

Future versions must:
- Add new versions without breaking v1 fixtures.
- Prefer additive fields with defaults; never change the meaning of existing fields.

## TODOs for IPPAN CORE team (required to satisfy this contract)

This repo intentionally does **not** invent CORE endpoints. To enable real integration, CORE must:

1. Expose **chain status** returning `L1ChainStatus`.
2. Expose **batch submission** accepting `L2BatchEnvelopeV1` and returning `L1SubmitResult` with idempotent replay behavior.
3. Expose **inclusion lookup** by `IdempotencyKey` returning `L1InclusionProof` (or 404/None).
4. Expose **finality lookup** by `L1TxId` returning `L1InclusionProof` (or 404/None).
5. Publish the **exact endpoint paths** so `l1.endpoints.*` can be configured without guessing.

