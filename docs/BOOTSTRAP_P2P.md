# Bootstrap P2P distribution (MVP: peer-list HTTP gateway)

This document describes the **optional**, **opt-in** P2P-like distribution mode for `fin-node` remote bootstrap artifacts.

## Implementation path chosen (Phase 0)

**PATH B (peer-list HTTP gateway mode)**.

This repository currently does **not** include an embedded P2P networking stack (e.g. `libp2p` / `ipndht`). For MVP we implement:

- a pluggable `BootstrapSource` interface,
- a **peer list** mode where peers are just base URLs hosting the same artifacts,
- quorum verification across peers (detects a single malicious/tampered peer),
- bounded concurrency + global rate limiting,
- **fallback to the primary HTTP remote**.

An `IpndhtSource` hook is provided behind a feature flag for future integration.

## Content addressing (Phase 2)

Peers can host artifacts by hash using these **content-addressed paths**:

- Base artifacts:
  - `/artifacts/base/<hash>.tar`
- Delta artifacts:
  - `/artifacts/delta/<hash>.tar`
- (Optional) index by hash:
  - `/index/<hash>.json`

Notes:

- `<hash>` is the existing artifact hash already used by the bootstrap index:
  - base: `manifest.hash` from SnapshotV1
  - delta: `delta_manifest.hash` from DeltaSnapshotV1
- `fin-node` always verifies the artifact integrity after download (hash/integrity checks), regardless of the path used to fetch it.

## Bootstrap index schema extension (backward compatible)

`index.json` remains schema_version `1`, but `latest.base` and `latest.deltas[]` may include:

- `size`: size in bytes of the artifact tar file
- `ca_path`: content-addressed relative path (e.g. `artifacts/base/<hash>.tar`)

If `ca_path` is absent, `fin-node` falls back to the existing `path` field.

## Peer list mode (Phase 3)

### Config

```toml
[bootstrap.p2p]
enabled = true
peers = [
  "https://peer1.example.com/ippan-l2",
  "https://peer2.example.com/ippan-l2",
]
quorum = 2
max_failures = 3

[bootstrap.transfer]
max_concurrency = 4
max_mbps = 20
per_peer_timeout_ms = 20000
```

### Behavior

- **Index fetch**:
  - tries the primary `[bootstrap.remote].base_url` first,
  - if it fails, tries peers in order.
- **Artifact fetch**:
  - attempts downloads from peers (parallel, bounded),
  - verifies integrity (hash/integrity) for every downloaded artifact,
  - quorum policy:
    - `quorum=1`: accept the first peer that yields a valid artifact
    - `quorum>=2`: require `N` distinct peers to successfully produce a valid artifact (same expected hash)
  - if quorum cannot be achieved within limits/timeouts, **falls back** to the primary HTTP remote.

## How to host artifacts on peers

For a simple static HTTP peer:

- Host `index.json` at `<peer_base_url>/<index_path>` (same as primary), or only host artifacts (index can still come from primary).
- Host artifacts at either:
  - the original paths used in `index.json` (e.g. `base.tar`, `deltas/delta-1-2.tar`), and/or
  - the content-addressed paths in `ca_path` (recommended for peers):
    - `artifacts/base/<hash>.tar`
    - `artifacts/delta/<hash>.tar`

## Limitations (MVP)

- Peers are configured manually (no discovery/DHT).
- Quorum requires downloading from multiple peers (bandwidth trade-off).
- No peer reputation/pinning/incentives.
- `IpndhtSource` is a stub unless future transport integration is added.

