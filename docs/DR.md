# Disaster Recovery (DR) — IPPAN-L2 (L2-grade)

This document describes **operational recovery** for IPPAN-L2 nodes using deterministic state snapshots.

IPPAN CORE (L1) is responsible for Layer-1 ordering/finality. This guide covers **L2 execution state** only.

## Recoverable vs Non-Recoverable State

### Recoverable (included in snapshots)

- **HUB-FIN state**: assets, balances, delegations, transfer allow/deny lists.
- **HUB-DATA state**: datasets, listings, licenses, attestations, entitlements, allowlists.
- **Linkage receipts**: purchase workflow receipts (`receipts/linkage/*.json`).
- **Submission receipts + submit_state**:
  - Action receipts (FIN/DATA) persisted to sled and disk (contains `submit_state`).
  - Batch submission receipts persisted under the receipts directory root.
- **Recon queue state**: pending reconciliation items (`fin-node-recon` sled tree).
- **Applied action index**: idempotency/applied markers inside hub stores (`applied:*` keys).
- **State version markers**: hub `state_version` keys.

### Non-recoverable (excluded by design)

- **Private keys / secrets**: never included in snapshots.
- **Ephemeral locks**: HA leader lock state is not restored.
- **In-flight HTTP requests**: request handling is transient.
- **Local metrics counters**: recomputed on restart.
- **Temporary caches / test failpoints**: not part of execution state.

## Restore Procedure (SnapshotV1)

### Preconditions

- The node must be **stopped** (do not restore while `fin-node run` is active).
- Restore is **idempotent** when used with `--force` (re-wipes and re-imports the same snapshot).
- Restore does **not**:
  - restore HA leadership,
  - submit anything to L1 automatically.

### Steps

1. Copy the snapshot artifact to the target host (e.g. from cold storage).
2. Ensure configuration points to the intended storage locations:
   - `[storage].fin_db_dir`, `[storage].data_db_dir`, `[storage].recon_db_dir`, `[storage].receipts_dir`
3. Restore:

```bash
fin-node --config ./configs/prod.toml snapshot restore --from ./snapshots/l2-snapshot-YYYYMMDD-HHMMSS.tar --force
```

4. Start the node:

```bash
fin-node --config ./configs/prod.toml run
```

5. Observe reconciliation progress (if enabled):
   - `GET /recon/pending`
   - metrics: `recon_pending_total`, `recon_checks_total`, `recon_failures_total`

## Disaster Scenarios

### Single-node disk loss

- Restore latest snapshot onto a new host and restart.

### HA cluster leader crash

- Followers continue to serve reads.
- A new leader is elected via the configured lock provider.
- After restore on the new leader, reconciliation resumes from `submit_state` and recon queue.

## Limitations

- Snapshots are **operational** artifacts (integrity/audit), not consensus inputs.
- This does not provide L1-level recovery; it assumes IPPAN CORE is the source of truth for ordering/finality.

