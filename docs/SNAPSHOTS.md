# State Snapshots (SnapshotV1) — Format & Guarantees

IPPAN-L2 snapshots are **operational** artifacts used for disaster recovery and migration.

They are explicitly **not** part of consensus and must **never** affect deterministic hashes or action IDs.

## Guarantees

- **Deterministic export order**: all stores are exported in lexicographic key order.
- **Portable & auditable**: single `.tar` file containing versioned components + a human-readable `manifest.json`.
- **Restore is idempotent**: safe to re-run with `--force` (wipes then restores exactly).
- **No secrets**: private keys and secret material are excluded by design.
- **Leader-only operation**:
  - In HA mode, scheduled snapshots only run on the leader.
  - The `snapshot create` CLI enforces leadership by acquiring the HA lock (when HA is enabled).
- **CI-safe**: snapshot logic is testable with the mock L1 client (no real L1 access required).

## Artifact layout (tar)

SnapshotV1 is a plain tar archive containing:

- `manifest.json`
- `hub-fin.kv`
- `hub-data.kv`
- `linkage.kv`
- `receipts.kv`
- `recon.kv`

### KV file format (`*.kv`)

Each `*.kv` is a deterministic stream of key/value records:

- `u32` big-endian: key length
- `u32` big-endian: value length
- key bytes
- value bytes

For sled-backed stores, keys are the raw sled keys (ASCII prefixes like `asset:` / `dataset:` etc).

For file-backed receipts (`receipts.kv` / `linkage.kv`), keys are UTF-8 relative paths under `[storage].receipts_dir`.

## `manifest.json` (v1 schema)

Fields:

```json
{
  "snapshot_version": 1,
  "ippan_l2_version": "x.y.z",
  "created_at": 1730000000,
  "node_id": "fin-node-1",
  "state_versions": {
    "data": 2,
    "fin": 2,
    "linkage": 1,
    "recon": 1
  },
  "counts": {
    "assets": 0,
    "balances": 0,
    "data_applied": 0,
    "data_receipts": 0,
    "datasets": 0,
    "delegations": 0,
    "entitlements": 0,
    "fin_applied": 0,
    "fin_receipts": 0,
    "licenses": 0,
    "linkage_receipts": 0,
    "receipts_files": 0
  },
  "hash": "<blake3 hex>"
}
```

## Integrity hash rules

- The manifest hash is computed as `blake3(canonical_ordered_contents)`.
- Canonical content order is **sorted by component filename**.
- The hash is for **integrity/audit only** (detect partial/corrupt snapshots); it does not affect consensus.

## Commands

Create:

```bash
fin-node --config ./configs/prod.toml snapshot create --out ./snapshots/l2-snapshot-YYYYMMDD-HHMMSS.tar
```

Restore:

```bash
fin-node --config ./configs/prod.toml snapshot restore --from ./snapshots/l2-snapshot-YYYYMMDD-HHMMSS.tar --force
```

## Configuration

```toml
[snapshots]
enabled = true
output_dir = "./snapshots"
max_snapshots = 10

# Optional hooks (no hard dependency; executed by the node)
post_snapshot_hook = "/usr/local/bin/upload_snapshot.sh"
pre_restore_hook = "/usr/local/bin/prepare_restore.sh"

[snapshots.schedule]
enabled = true
# Simplified daily cron: "M H * * *" (UTC)
cron = "0 2 * * *"
```

## Hook examples

See:

- `docs/examples/upload_snapshot_s3.sh`
- `docs/examples/upload_snapshot_scp.sh`
- `docs/examples/prepare_restore.sh`

