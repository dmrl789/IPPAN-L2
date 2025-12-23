# Bootstrap trust model (remote snapshot fetcher)

This document defines the **minimal trust model** for `fin-node` remote bootstrap (operator-managed snapshot repository).

The remote bootstrap flow is:

1. Fetch `index.json` from an operator-provided base URL.
2. Select the `latest.base` and required `latest.deltas`.
3. Download artifacts into a local cache (resume-safe).
4. Verify integrity + compatibility **before** restoring.
5. Optionally verify a publisher signature over `index.json`.

This mechanism is **not** consensus-critical: it affects **only operational state replication** (DR / new node provisioning).

## What is trusted

- **Snapshot publisher (operator)**: the party who produces base + delta snapshots and publishes `index.json`.
- **Integrity via hashes** (always-on): `fin-node` verifies content hashes (blake3) against the values in `index.json`.
- **Optional publisher signature verification** (configurable): if enabled, `fin-node` verifies an Ed25519 signature over the canonical bytes of `index.json` using allowlisted publisher public keys.
 - **Optional peer-list distribution** (P2P-like, opt-in): when enabled, peers are treated as **untrusted byte sources**; integrity still relies on hash/integrity checks (and optional index signatures), not on peer honesty.

## What is NOT assumed

- **Remote server honesty beyond serving bytes**: the HTTP server is not trusted to be correct; it may serve stale or tampered content.
- **No implicit trust in transport**: HTTPS is recommended, but the security model relies on **hash verification** (and optional signature verification), not on TLS alone.
- **No remote code execution**: fetched artifacts are treated as data only; no hooks/scripts from the remote are executed.

## Threats mitigated

- **Corruption / tampering**: any bit flips or malicious modifications are detected by **hash mismatch** checks.
- **Path traversal / filesystem overwrite**: artifact paths from `index.json` are validated to be **relative** and to contain **no traversal segments**; downloads are confined to the configured cache directory.
- **Downgrade attacks**:
  - `index.json` schema version is validated.
  - Snapshot compatibility is checked (snapshot version, `ippan_l2_version` major/minor compatibility, and state version requirements).
- **Unauthorized publisher** (when signing is enabled and required): if `required=true`, missing/invalid signatures cause bootstrap to refuse.
 - **Single-peer tampering (peer-list mode)**: when `bootstrap.p2p.quorum >= 2`, `fin-node` requires multiple distinct peers to independently produce a valid artifact before acceptance, reducing risk from one malicious mirror.

## Threats explicitly NOT mitigated

- **Availability attacks**: the remote server can be down, slow, or rate-limited.
- **Malicious but correctly signed snapshots**: if the operator’s signing key is compromised (or the operator is malicious), signatures will validate. Hash verification will not detect “validly produced but malicious” snapshots.
- **Bandwidth exhaustion at the network layer**: the fetcher enforces maximum expected download size, but cannot prevent upstream network saturation.
 - **Malicious index without signatures**: if index signatures are disabled, a malicious mirror could serve a crafted `index.json` that points to attacker-controlled artifacts (whose internal hashes/integrity would still verify against that attacker-controlled index). Enabling signing is recommended when using multiple mirrors.

## Signing workflow (optional)

When signing is enabled:

- The snapshot publisher produces `index.json`.
- The publisher computes the signature over the **canonical bytes of `index.json`**:
  - message = `IPPAN-L2:BOOTSTRAP_INDEX:V1\n` || `index.json` bytes
  - signature scheme: **Ed25519**
- The publisher uploads:
  - `index.json`
  - `index.sig` (hex-encoded 64-byte Ed25519 signature)

`fin-node` verifies the signature against the configured allowlist of publisher public keys.

