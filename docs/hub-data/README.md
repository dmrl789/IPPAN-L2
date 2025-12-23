# HUB-DATA MVP v1

**HUB-DATA** is the IPPAN L2 hub for datasets/models/content metadata, licensing, and attestations.

It is intentionally minimal:

- Stores **hashes + pointers** (no file hosting)
- Emits **deterministic envelopes** (no direct L1 calls)
- Applies actions to **sled-backed state** with idempotency and drift-protected fixtures

## What’s included

- Dataset registration (`REGISTER_DATASET_V1`)
- License issuance (`ISSUE_LICENSE_V1`) with a small rights enum and optional informational price
- Attestation log (`APPEND_ATTESTATION_V1`) (append-only)
- fin-node HTTP endpoints under `/data/*`
- Local receipts under `receipts/data/<action_id>.json`
- Optional deterministic state export: `fin-node data export-state --out ./data_state_snapshot.json`

## Docs

- [`docs/hub-data/MVP_SCOPE.md`](MVP_SCOPE.md)
- [`docs/hub-data/ACTIONS.md`](ACTIONS.md)
- [`docs/hub-data/API.md`](API.md)

