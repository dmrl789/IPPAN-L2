## Bootstrap sets (base + delta chain)

This document describes how to **fast-onboard a new `fin-node` instance** by restoring:

- **Base snapshot**: a full, authoritative state capture at time \(T0\)
- **Delta snapshots**: an **append-only** sequence of key/value changes between snapshot epochs
- **Bootstrap index**: an operator-published catalog that points at the newest base + its deltas

This is an **operational acceleration** mechanism for L2 node sync. It must **not** change any
deterministic execution semantics.

### Terms

- **BaseSnapshot**: full state tarball at time \(T0\).
- **DeltaSnapshot**: state diffs between epochs \(E_i \rightarrow E_{i+1}\), applied in order.
- **BootstrapSet**: `{ base, [delta_1..delta_n], index }` where each delta references the base.

### Safety invariants

- **Leader-only generation**: base + deltas must only be cut by the HA leader.
- **Base is authoritative**: deltas are only *after* the base, never “fix” the base.
- **Append-only diffs**: deltas contain `put` and `del` (tombstone) operations.
- **Deterministic ordering**: delta records are sorted deterministically and hashed.
- **Interruption-safe restore**: bootstrap restore is resume-capable via a progress file.
- **No secrets**: snapshots never include private keys or secret env/config.

## How a new node joins

### 1) Fetch the bootstrap set (operator responsibility)

Operators publish artifacts to a shared location (filesystem, object store, etc.):

- One **base** tarball
- A list of **delta** tarballs that chain forward from that base
- `index.json` describing the latest set

`fin-node` can generate the index, but does not upload artifacts.

### 2) Restore base + apply deltas

High-level flow:

1. **Restore the base** snapshot into empty local state.
2. **Apply deltas in order** (by epoch).
3. **Resume normal operation**:
   - start the server
   - reconciliation loop catches up on L1 finality as usual

The bootstrap restore path **does not modify consensus semantics**; it only sets local durable
state to an equivalent state faster than replaying from scratch.

### 3) Reconciliation loop resumes

After bootstrap restore, `fin-node` continues its existing reconciliation loop:

- It verifies inclusion/finality via L1 (or mock mode in tests)
- It repairs any missing finality transitions for receipts/workflows

## Artifact formats (v1)

### Base snapshot (SnapshotV1 tar)

The base snapshot uses the existing `SnapshotV1` tar format (`manifest.json`, `hub-fin.kv`,
`hub-data.kv`, `recon.kv`, `receipts.kv`, `linkage.kv`).

The base snapshot’s `manifest.hash` is used as `base_snapshot_id` for deltas and indexes.

### Delta snapshot (DeltaSnapshotV1 tar)

Each delta snapshot tar contains:

- `delta_manifest.json`
- `changes.jsonl`

Delta records are append-only changes:

- `put`: `{ store, op:"put", key_hex, value_b64 }`
- `del`: `{ store, op:"del", key_hex }`

Stores are logical namespaces:

- `fin` (hub-fin sled)
- `data` (hub-data sled)
- `recon` (fin-node recon sled)
- `receipts` (receipt files under `receipts_dir`)
- `linkage` (linkage receipt files under `receipts_dir/linkage`)

### Bootstrap index (index.json)

Operators publish an index for automation:

- `latest.base`: newest base snapshot (path + hash + created_at)
- `latest.deltas`: ordered deltas for that base
- `history`: optional previous bases + their deltas

## Operator commands (examples)

### Cut a base snapshot (leader-only)

```bash
fin-node --config ./fin-node.toml snapshot base --out ./snapshots/base-20251223.tar
```

### Cut a delta snapshot (leader-only)

```bash
fin-node --config ./fin-node.toml snapshot delta --out ./snapshots/deltas/delta-<from>-<to>.tar
```

### Publish/update the index (no upload; writes index.json)

```bash
fin-node --config ./fin-node.toml snapshot publish-index --dir ./snapshots
```

### Restore bootstrap set (resume-capable)

```bash
fin-node --config ./fin-node.toml bootstrap restore \
  --base ./snapshots/base-20251223.tar \
  --deltas ./snapshots/deltas/*.tar
```

If interrupted, re-run the same command; it resumes from `bootstrap_progress.json`.

## Limitations (current)

- Delta format is v1 (forward-compatible, but not compressed beyond tar).
- Restore applies deltas locally; it does not fetch from remote URLs.
- No delta compaction/merge yet.
- No encrypted transport (operator should use secure storage/transport).

