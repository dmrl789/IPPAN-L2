# HUB-FIN (Finance Hub) — MVP v1

HUB-FIN is the finance-focused IPPAN L2 hub. In the MVP v1, it supports **exactly two deterministic actions**:

- **CREATE_ASSET**: define a new asset class (RWA instrument)
- **MINT_UNITS**: mint units of an asset to an account (allocation ledger)

The hub **never calls L1 directly**. Instead, it produces a `HubPayloadEnvelopeV1` payload which `fin-node` wraps into an `L2BatchEnvelopeV1` and submits to L1 using the configured `L1Client`.

## Determinism

- No floats: amounts are **scaled integers** (`u128` for mint amounts).
- Canonical bytes: canonical JSON (sorted keys, compact encoding).
- Stable hashing:
  - `action_id = blake3(canonical_bytes(action))`

## Docs

- `docs/hub-fin/MVP_SCOPE.md`: MVP scope and chosen endpoints
- `docs/hub-fin/ACTIONS.md`: action schemas + validation rules
- `docs/hub-fin/API.md`: fin-node HTTP API + curl examples

