# Encryption at Rest (L2 Stores, Snapshots, Audit Bundles)

This repository supports **optional encryption at rest** for institutional deployments.

Encryption at rest is **operational only**:

- It **does not** change canonical envelope bytes, action IDs, or any consensus-critical hashing.
- It **does** change how bytes are stored on disk (sled values and exported artifacts).

> Feature gate: build with `--features encryption-at-rest` (default: OFF).

## Threat model & scope

### What is protected (when enabled)

- **Local L2 state databases (sled)**:
  - Hub stores (`hub-fin`, `hub-data`)
  - fin-node stores (audit log, bootstrap metadata, recon, policy, etc.)
  - Protection is applied by **encrypting stored values** (key bytes stay as-is).

- **Snapshots / deltas**:
  - Snapshot tar archives can be wrapped into an encrypted container.
  - Delta snapshot artifacts (base+delta workflows) can be wrapped similarly.

- **Audit bundles**:
  - Audit export tar archives can be wrapped into an encrypted container.

### What is NOT protected

- **In-memory data** (process memory, swap, core dumps)
- **Network traffic** (use TLS/mTLS separately)
- **L1 on-chain data** (public by design)
- **Host compromise**:
  - If an attacker can read the encryption key from disk or environment, encryption at rest does not help.

## Cryptography

- Primitive: **AEAD** using **XChaCha20-Poly1305** (32-byte key, 24-byte nonce).
- Each stored value / artifact is encrypted with a fresh random nonce.
- **Associated data (AAD)** binds ciphertext to its intended context:
  - store/namespace name
  - relevant key identifier(s)
  - schema/version fields
  - (for archives) the archive type and manifest root hash (when available)

This prevents ciphertext from being moved across stores or interpreted under the wrong context.

## Key management (MVP)

### Key format

- **Master key**: 32 bytes (hex encoded on disk).
- Keys are identified by an operator-chosen **key id** (e.g. `k1`, `k2`).

### Key provider

The default provider is file-based:

- `key_path`: path to a file containing **32-byte hex**
- `key_id`: id for the key at `key_path`
- `old_keys_dir`: optional directory containing old keys for decrypting historical data
- `keyring`: ordered list of key ids that are acceptable for decrypt (newest first)

### Critical warnings

- **Never store keys in the repo**, snapshot archives, audit bundles, receipts, or logs.
- **Lost key = unrecoverable data**. There is no safe “password reset” for encrypted-at-rest state.

## Rotation (basic)

Rotation is supported at two layers:

- **New writes**: use the current key (by id) for all new encrypted values.
- **Old reads**: historical values can be decrypted using keys in the keyring / old key directory.

Optional maintenance:

- **Rewrap**: re-encrypt existing values from old key ids to a new key id.
  - This reduces the operational need to keep old keys online.

## Migration & mixed mode

Encrypted-at-rest is designed to support upgrading existing plaintext DBs.

- Migration iterates keys in deterministic order and:
  - encrypts values that are plaintext
  - skips values already in encrypted format

To avoid accidental “silent plaintext” in production:

- `allow_plaintext_read` defaults to **false**.
- In dev, you can temporarily enable plaintext reads to migrate safely.

## Operational guidance

### Recommended practices

- **File permissions**:
  - master key files should be readable only by the fin-node user (e.g. `0400` or `0600`)
  - DB directories should be restricted (e.g. `0700`)

- **Backups**:
  - Back up encrypted DBs and encrypted snapshots.
  - Ensure the backup system **does not** capture key material.

- **Offline key escrow**:
  - Store key material in a controlled offline process (break-glass).
  - Document key ids and where corresponding key files live.

- **Separation of duties**:
  - Operators who can read DB files should not automatically have access to key files.

### Failure modes & recovery

- **ENCRYPTION_KEY_MISSING**:
  - A key id referenced by stored data is not available to the provider.

- **ENCRYPTION_DECRYPT_FAILED**:
  - Wrong key, corrupted data, or ciphertext moved across contexts.

- **ENCRYPTION_UNSUPPORTED_VERSION**:
  - Stored value/archive uses a future version.

When these occur, the node will refuse to read affected data unless a dev-only escape hatch is used.

## Limitations (current MVP)

- No KMS/HSM integration (hooks are provided; implement your own KeyProvider).
- No transparent per-tenant keys.
- No automatic “online rotation orchestration”; operators control key rollout.

