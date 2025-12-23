# Signed Envelopes (v1, feature-gated)

This document specifies **IPPAN-L2 signed envelopes** for FIN/DATA/LINKAGE payloads.

All signing/verification behavior is **feature-gated** behind Cargo feature:

- `signed-envelopes` (**default OFF**)

## Chosen scheme + formats (Phase 0)

- **Signature scheme**: **Ed25519**
  - Rationale: no existing L2 envelope signing scheme was present in the workspace; Ed25519 is widely-used and stable.
- **What is signed**: **only canonical bytes** of the *inner envelope* (the same canonical JSON bytes used for deterministic hashing elsewhere in the system).
- **Domain separation**: enabled (recommended)
  - Prefix bytes: `IPPAN-L2:SIGNED_ENVELOPE:V1\n`
- **Signer identifier (SignerId)**:
  - `pubkey`: **32 bytes** Ed25519 public key
  - JSON encoding: lowercase **hex string** (64 hex chars)
- **Signature bytes (SignatureBytes)**:
  - `sig`: **64 bytes** Ed25519 signature
  - JSON encoding: lowercase **hex string** (128 hex chars)
- **Key file format (fin-node)**:
  - simplest format: **raw 32-byte seed in hex** (64 hex chars) stored in a local file
  - the seed is used to derive the Ed25519 signing keypair deterministically

## Canonical signing message (Phase 2)

Let `inner` be an envelope value (e.g. `FinEnvelopeV1`, `DataEnvelopeV1`, `LinkageReceiptV1`).

- `inner_bytes = canonical_bytes(inner)` (deterministic canonical JSON, same style used for envelope hashing)
- `domain = b"IPPAN-L2:SIGNED_ENVELOPE:V1\n"`
- `message = domain || inner_bytes`
- `signature = ed25519_sign(seed_or_private_key, message)`
- `verify = ed25519_verify(pubkey, message, signature)`

`SignedEnvelopeV1.signed_hash` is used for indexing:

- `signed_hash = blake3(inner_bytes)` (32 bytes)

## Notes / non-goals

- This feature does **not** define a full key management UX. `fin-node` loads a local key from disk (optional) and always verifies signatures when present/required.
- `AccountId` remains an **opaque string identifier** used by policy/validation. It is not a cryptographic identity.

