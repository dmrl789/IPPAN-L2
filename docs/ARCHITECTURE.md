# IPPAN-L2 Architecture (MVP refresh)

## Components

- **l2-node**: Axum-based HTTP server exposing health/readiness/status/metrics. Hosts background tasks for batching and bridge watchers.
- **l2-core**: Deterministic types, canonical serialization, hashing utilities, and common identifiers.
- **l2-storage**: Sled-backed persistence with schema versioning and namespaced trees for tx pool, batches, receipts, and meta.
- **l2-batcher**: Deterministic batching loop that collects transactions, computes canonical hashes, stores batches, and calls the posting interface.
- **l2-bridge**: L1 watcher + message handling skeleton for deposits/withdrawals and cross-domain messaging.

## Data Flow

1. **Tx ingress**: Transactions enter l2-node (future `/tx`). They are stored in `tx_pool` with canonical encoding.
2. **Batching**: l2-batcher drains the queue until `max_batch_bytes`, `max_batch_txs`, or `max_wait_ms` is reached. It builds a `Batch` (canonical encoding + BLAKE3 hash) and persists it.
3. **Posting**: A `BatchPoster` implementation (stubbed in MVP) is called to submit the batch to IPPAN L1. The poster receives the canonical hash for DA/logging.
4. **Bridge events**: l2-bridge watches L1 (stub) for `DepositEvent` / `WithdrawRequest` / `Message` updates and records them in storage for replay/audit.
5. **Status surfaces**: `/status` reports service metadata, leader info, queue depth, last batch hash/time, and bridge activity. `/metrics` exposes Prometheus counters/gauges.

## Storage Layout

- `tx_pool/` – keyed by tx hash; value = canonical `Tx` bytes
- `batches/` – keyed by batch hash; value = canonical `Batch` bytes
- `receipts/` – keyed by tx hash; value = canonical `Receipt` bytes
- `meta/` – schema version + status markers (e.g., last posted batch)

Schema version is stored under `meta:schema_version` and must be bumped on layout changes.

## Hashing & Canonical Encoding

- Canonical encoding uses `bincode` with fixed-int encoding and little-endian order, disallowing trailing bytes.
- Hashes are 32-byte BLAKE3 digests encoded as lowercase hex for external representation.
- No floating-point values are permitted in any serialized structure.

## Textual Component Diagram

```
+----------------+       +----------------+       +-----------------+
|  REST Clients  | --->  |    l2-node     | --->  |  Prometheus     |
+----------------+       | (axum router)  |       +-----------------+
                         |   |       |    |
                         |   |       |    +--> Bridge (stub watcher)
                         |   |       +--> Batcher (loop + poster)
                         |   +--> sled storage
                         +--> tracing logs
```

## Future Hardening (roadmap markers)

- Swap sled with pluggable KV (RocksDB/SQLite) behind a trait.
- Add DA commitments + proof plumbing to `BatchPoster`.
- Introduce leader rotation + forced inclusion endpoints once L1 contract details are frozen.
- Attach structured observability (tracing spans) to batching and bridge pipelines.
