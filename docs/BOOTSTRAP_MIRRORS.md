# Bootstrap Mirrors + Quorum Verification

This document describes production-grade remote bootstrap sourcing for `fin-node` using **multiple snapshot mirrors**, **quorum verification**, and **pinned trusted snapshot sets**.

## Concepts

- **Index**: `index.json` published alongside artifacts; it points to the latest base snapshot and its ordered delta chain.
- **Artifact**: a base snapshot tar (`SnapshotV1`) or a delta tar (`DeltaSnapshotV1`).
- **Hash verification (mandatory)**:
  - **Index hash**: `blake3(index_bytes)` over the fetched `index.json` bytes.
  - **Artifact hash**: the manifest hash embedded in the artifact (verified by parsing/validating the tar).
- **Quorum**: require \(N\) independent sources to agree on the same hash (and optionally identical bytes).

## Configuration

Remote bootstrap is enabled under `[bootstrap.remote]` (existing config), while multi-source behavior is controlled by `[bootstrap.sources]` and optional `[bootstrap.pinned]`.

### Single source (default / backward compatible)

```toml
[bootstrap.remote]
enabled = true
name = "default"
base_url = "https://snapshots1.example.com/ippan-l2"
index_path = "index.json"
download_dir = "./bootstrap_cache"
max_download_mb = 4096
connect_timeout_ms = 3000
read_timeout_ms = 30000
concurrency = 4

[bootstrap.sources]
mode = "single"
```

### Mirrors + quorum (index + artifacts)

```toml
[bootstrap.remote]
enabled = true
name = "default"
base_url = "https://snapshots1.example.com/ippan-l2" # used as fallback primary unless sources.primary is set
index_path = "index.json"
download_dir = "./bootstrap_cache"
max_download_mb = 4096
connect_timeout_ms = 3000
read_timeout_ms = 30000
concurrency = 4

[bootstrap.sources]
mode = "mirrors_quorum"
primary = "https://snapshots1.example.com/ippan-l2"
mirrors = [
  "https://snapshots2.example.com/ippan-l2",
  "https://snapshots3.example.com/ippan-l2",
]
quorum = 2
max_sources = 5

# Artifact quorum:
# - hash_only: download from best source, verify vs index
# - bytes_quorum: download from N sources, require identical bytes hash
artifact_quorum_mode = "hash_only"
artifact_quorum = 1
```

### Optional: signature verification for index

Signatures are optional, but if enabled they are verified **per source** before that source can count toward index quorum.

```toml
[bootstrap.signing]
enabled = true
required = true
publisher_pubkeys = [
  "0123...abcd" # 32-byte Ed25519 pubkey hex
]
```

## Pinned trusted snapshot set

Pinned mode ignores the remote `latest` pointer and **only** accepts explicitly pinned hashes.

```toml
[bootstrap.remote]
enabled = true
name = "default"
base_url = "https://snapshots1.example.com/ippan-l2"
index_path = "index.json"
download_dir = "./bootstrap_cache"
max_download_mb = 4096

[bootstrap.sources]
mode = "pinned"
primary = "https://snapshots1.example.com/ippan-l2"
mirrors = ["https://snapshots2.example.com/ippan-l2"]
max_sources = 5

[bootstrap.pinned]
base_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
delta_hashes = [
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
]
# Optional: enforce a specific index.json bytes hash for auditing
index_hash = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
```

Pinned mode downloads artifacts using **content-addressed paths**:

- `artifacts/base/<base_hash>.tar`
- `artifacts/delta/<delta_hash>.tar`

If your repository layout differs, you must publish these content-addressed paths (recommended).

## Operational notes

- **Compatibility checks**: bootstrap refuses snapshot sets that fail version compatibility checks (major/minor mismatch) or state version requirements.
- **Bounded behavior**: selection is bounded by `max_sources` and download concurrency is bounded by `[bootstrap.transfer]` + `[bootstrap.remote].concurrency`.
- **Provenance**: each fetch records which source provided the index and which sources provided each artifact.

