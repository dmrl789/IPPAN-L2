# Audit Mode (Forensics Export + Verifiable Event Log)

This document defines **AuditBundleV1** and the on-node **append-only audit event log** used to export, replay, and verify IPPAN L2 activity in an auditor-friendly, deterministic way.

## Goals / non-goals

- **Goals**
  - Export a complete, verifiable event log of L2 actions.
  - Reproduce hub state from scratch via replay using exported artifacts.
  - Verify envelope integrity (blake3 hashes) and idempotency.
  - Correlate L2 actions with L1 inclusion/finality metadata (idempotency keys, tx ids, proof hashes).
  - Generate a deterministic human-readable report bundle.
- **Non-goals**
  - SIEM connectors / streaming ingestion. Keep it **self-contained** and **deterministic**.

## Determinism rules (hard requirements)

Audit exports are required to be deterministic:

- **Same node state + same export options ⇒ same bundle bytes** (and thus same `manifest.json` hashes).
- No private keys or secrets in bundles.
- Bundle file ordering is stable (lexicographic path order).
- Archive metadata is normalized (`mtime=0`, `uid=0`, `gid=0`, fixed modes).

### `exported_at` determinism

`manifest.json.exported_at` is **derived**, not “current time”:

- It is set to the **max `occurred_at_unix_secs`** among exported events (or `0` if none).

This keeps `manifest.json` deterministic for a given state/scope.

## AuditBundleV1 format

**AuditBundleV1** is a `tar` archive containing:

- `manifest.json`
- `envelopes/` (canonical envelope bytes, one file per `action_id`)
- `receipts/`  (receipt JSON per `action_id` / `purchase_id`)
- `proofs/`    (inclusion/finality proof blobs or JSON references)
- `indexes/`   (sorted indexes for review)
- `report/`    (human-readable deterministic summaries)

### Directory layout

Example:

```text
audit_bundle_v1.tar
├── manifest.json
├── envelopes/
│   ├── fin/
│   │   ├── <action_id_hex>.json
│   └── data/
│       ├── <action_id_hex>.json
├── receipts/
│   ├── fin/
│   │   └── actions/<action_id_hex>.json
│   ├── data/
│   │   └── <action_id_hex>.json
│   └── linkage/
│       └── <purchase_id_hex>.json
├── proofs/
│   ├── <id>.inclusion.json
│   └── <id>.finality.json
├── indexes/
│   ├── events.jsonl
│   ├── actions.csv
│   └── state_hashes.json
└── report/
    ├── summary.md
    ├── fin_assets.md
    ├── data_datasets.md
    └── linkage.md
```

### `manifest.json` schema

```json
{
  "audit_bundle_version": 1,
  "ippan_l2_version": "x.y.z",
  "exported_at": 0,
  "export_scope": { "from_epoch": 0, "to_epoch": 0, "hubs": ["fin"], "subjects": {} },
  "files": [{ "path": "indexes/events.jsonl", "blake3": "<hex>", "bytes": 123 }],
  "root_hash": "<hex>",
  "optional_operator_signature": { "pubkey": "<hex>", "sig": "<hex>" }
}
```

Fields:

- **`audit_bundle_version`**: always `1` for this format.
- **`ippan_l2_version`**: `CARGO_PKG_VERSION` of `fin-node` at export time.
- **`exported_at`**: deterministic derived timestamp (see determinism rules).
- **`export_scope`**: the exact filter inputs used to produce this export.
- **`files`**: all files in the tar (excluding the tar container), each with:
  - `path`: bundle-relative path
  - `blake3`: `blake3(file_bytes)` hex
  - `bytes`: file byte length
- **`root_hash`**: `blake3(concat(sorted(file_hashes)))` where `file_hashes` is the list of raw 32-byte file hashes ordered by `path` ascending.
- **Self-reference note**: `manifest.json` is not included in `files` (otherwise it would be self-referential).
- **`optional_operator_signature`**: present only when manifest signing is enabled and invoked.

## Append-only audit event log (on-node)

The node persists an append-only audit log in sled, intended to survive pruning of receipts/state.

Keys:

- `audit:last_seq` → big-endian `u64`
- `audit:event:<seq_be>` → `EventRecordV1` JSON bytes
- `audit:envelope:<hub>/<action_id_hex>` → canonical envelope bytes (JSON)

### `EventRecordV1`

Each event includes:

- `seq` (`u64`): monotonically increasing, atomically allocated.
- `occurred_at_unix_secs` (`u64`): operational timestamp.
- `epoch` (`u64`): snapshot/bootstrap epoch at write time (if known; else `0`).
- `hub` (`fin|data|linkage|system`)
- `kind` (`action_applied|action_submitted|receipt_written|inclusion_observed|finality_observed|recon_step|...`)
- `action_id` (optional, hex32) and/or `purchase_id` (optional)
- `envelope_hash` (optional, hex blake3 of canonical envelope bytes)
- `receipt_ref` (optional, bundle-relative path or receipt key)
- `submit_state` (optional snapshot of `SubmitState`)
- `subjects` (optional): extracted dataset/asset/account references for filtering
- `signer_pubkey` (optional): feature-gated when signed envelopes exist

## L1 correlation

Receipts and events carry L1 correlation fields:

- `idempotency_key` (base64url)
- `l1_tx_id` (string)
- `proof_hash` (base64url/hex depending on upstream)

Audit bundles export these as:

- `receipts/.../*.json` (the full receipt JSON)
- `proofs/*.inclusion.json` / `proofs/*.finality.json` reference objects (or raw blobs if stored).

## CLI

Implemented under:

- `fin-node audit export ...`
- `fin-node audit replay ...`
- `fin-node audit sign ...` (feature-gated)

