# HUB-DATA MVP v1 — Scope

This document defines the minimal, production-real **HUB-DATA MVP v1**: datasets + licenses + attestations, with deterministic envelopes, sled-backed state, and fin-node HTTP query/submit surfaces.

## Goals

- Dataset registration (metadata + immutable content hash pointer)
- License issuance (grant rights to an account; optional informational price)
- Attestation log (append-only statements about dataset/model/version)
- Query API for dataset + licenses + attestations
- Deterministic envelopes + fixtures + tests

## Non-goals

- Marketplace, payments, settlement logic (handled by HUB-FIN)
- Hosting actual files (store pointers/hashes only)
- L1 calls from the hub crate (fin-node submits batches to L1)

## Actions (exactly three)

- `REGISTER_DATASET_V1`
- `ISSUE_LICENSE_V1`
- `APPEND_ATTESTATION_V1`

See `docs/hub-data/ACTIONS.md` for schemas + rules.

## Deterministic envelope format

- **Envelope type**: `hub_data::DataEnvelopeV1`
- **Canonical bytes**: canonical JSON with object keys sorted recursively
- **Action id**: `action_id = blake3(canonical_bytes(action))`
- **Hub payload**:
  - `schema_version`: `hub-data.envelope.v1`
  - `content_type`: `application/ippan.hub-data.v1`
  - `payload`: canonical JSON bytes of `DataEnvelopeV1`

## Storage (sled)

Keys (byte strings, lexicographically ordered):

- `dataset:<hex(dataset_id)>` → `RegisterDatasetV1`
- `license:<hex(license_id)>` → `IssueLicenseV1`
- `lic_by_dataset:<hex(dataset_id)>:<hex(license_id)>` → `1`
- `attest:<hex(attestation_id)>` → `AppendAttestationV1`
- `att_by_dataset:<hex(dataset_id)>:<hex(attestation_id)>` → `1`
- `applied:<hex(action_id)>` → `1`
- `apply_receipt:<hex(action_id)>` → canonical JSON of apply receipt
- `receipt:<hex(action_id)>` → fin-node “final receipt” JSON (includes L1 submission metadata)

## fin-node HTTP surfaces

All endpoints return JSON with `schema_version: 1`.

### Create/apply/submit

- `POST /data/datasets` → build+apply+submit `REGISTER_DATASET_V1`
- `POST /data/licenses` → build+apply+submit `ISSUE_LICENSE_V1`
- `POST /data/attestations` → build+apply+submit `APPEND_ATTESTATION_V1`

### Queries

- `GET /data/datasets/:dataset_id`
- `GET /data/datasets/:dataset_id/licenses`
- `GET /data/datasets/:dataset_id/attestations`
- `GET /data/licenses/:license_id`

## Receipts

fin-node persists action receipts under:

- `receipts/data/<action_id>.json`

These receipts include:

- action id + derived ids (dataset/license/attestation)
- local apply outcome
- batch id + idempotency key + canonical hash
- L1 submit result

