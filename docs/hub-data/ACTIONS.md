# HUB-DATA MVP v1 — Actions

All HUB-DATA actions are **deterministic**, **idempotent**, and **privacy-safe by default** (store hashes + pointers, not raw private content).

## Common conventions

- **IDs** are 32 bytes encoded as lowercase hex in JSON.
- **Canonical bytes** are canonical JSON with recursively sorted object keys.
- **Action id**: `action_id = blake3(canonical_bytes(action))`
- **Tag normalization**:
  - trim whitespace
  - lowercase (ASCII)
  - sort lexicographically
  - de-duplicate

## Action A — `REGISTER_DATASET_V1`

Purpose: register a dataset/model with immutable content pointer and metadata.

Fields (`hub_data::RegisterDatasetV1`):

- `dataset_id`: `blake3(owner || name || content_hash || schema_version)`
- `owner`: `AccountId`
- `name`: 1..=96 chars
- `description`: optional, <= 512 chars
- `content_hash`: 32-byte hash (algorithm out-of-scope; store bytes)
- `pointer_uri`: optional, <= 512 chars (e.g., `ipfs://...`, `https://...`, `ar://...`)
- `mime_type`: optional, <= 96 chars
- `tags`: list of tags (<= 16 items, each <= 32 chars), normalized + sorted
- `schema_version`: `u32` (dataset format, not contract version)

Rules:

- `dataset_id` must be unique; duplicates are **rejected**
- tags must already be normalized/sorted/deduped before hashing/serialization
- no private content stored

## Action B — `ISSUE_LICENSE_V1`

Purpose: grant rights to an account for a dataset/model.

Fields (`hub_data::IssueLicenseV1`):

- `dataset_id`: target dataset/model
- `license_id`: `blake3(dataset_id || licensee || rights || terms_hash || expires_at || nonce)`
- `licensor`: must equal `dataset.owner` in MVP v1
- `licensee`: account being granted rights
- `rights`: enum `{ view, use, commercial_use, derivative_use }`
- `terms_uri`: optional, <= 512 chars
- `terms_hash`: optional 32-byte hash (recommended if `terms_uri` present)
- `expires_at`: optional unix seconds (informational storage only)
- `price_microunits`: optional informational price (no settlement in MVP v1)
- `nonce`: client-provided nonce included in `license_id` derivation

Rules:

- dataset must exist
- `licensor == dataset.owner` (MVP rule)
- duplicate `license_id` is treated as **idempotent success/no-op**

## Action C — `APPEND_ATTESTATION_V1`

Purpose: append-only signed-ish statement about a dataset (quality, provenance, evaluation hash).

Fields (`hub_data::AppendAttestationV1`):

- `dataset_id`
- `attestation_id`: `blake3(dataset_id || attestor || statement_hash || ref_hash || nonce)`
- `attestor`
- `statement`: optional short text (<= 280 chars) for UX only
- `statement_hash`: 32-byte hash of the statement payload (preferred for privacy)
- `ref_hash`: optional 32-byte hash (e.g. evaluation report / model card)
- `ref_uri`: optional <= 512 chars
- `nonce`: client-provided nonce included in `attestation_id` derivation

Rules:

- dataset must exist
- attestations are append-only; never mutate, only add
- duplicate `attestation_id` is treated as **idempotent success/no-op**

