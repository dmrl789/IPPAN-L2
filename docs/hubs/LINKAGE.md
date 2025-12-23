# HUB-FIN ↔ HUB-DATA Linkage (Payments + Entitlements) — MVP v1

This document defines the minimal, deterministic linkage “contract” between HUB-FIN and HUB-DATA.

## Invariants (global)

- **Determinism**: all hashes are BLAKE3 over canonicalized / unambiguous bytes. No floats anywhere.
- **Integer microunits**: prices and amounts are integer microunits (`u128`).
- **Explicit cross-hub linking**: every step references stable IDs (`purchase_id`, `action_id`, canonical hashes).
- **No hub-to-hub HTTP**: linkage happens via shared types (`l2-core::hub_linkage`) and fin-node orchestration.
- **Idempotent**: payment and entitlement granting are replay-safe.
- **Recoverable**: fin-node persists a resume-safe linkage receipt and can continue after partial failure.

## IDs and derivations

### `purchase_id` (v1)

`purchase_id` is a stable 32-byte identifier for a purchase attempt.

Derivation (see `l2-core/src/hub_linkage/mod.rs`):

- Inputs:
  - `dataset_id` (32 bytes)
  - `licensee` (AccountId string bytes)
  - `price_microunits` (`u128`, big-endian)
  - `currency_asset_id` (32 bytes; HUB-FIN asset id)
  - `terms_hash` (optional 32 bytes)
  - `nonce` (string bytes; caller-chosen)
- Hash:
  - `purchase_id = blake3(prefix || dataset_id || licensee || price || currency_asset_id || terms_hash || nonce)`

Notes:
- Implementation uses a fixed prefix and `\0` separators to prevent ambiguity.

### `payment_ref`

References a HUB-FIN payment deterministically:

- `fin_action_id`: FIN action id (BLAKE3 hash of canonical FIN action JSON).
- `fin_receipt_hash`: deterministic canonical hash of either:
  - the FIN action envelope, or
  - the FIN action receipt, or
  - the L1 batch envelope that carried the FIN action.

MVP policy: fin-node uses the canonical hash of the L1 batch envelope containing the FIN action.

### `entitlement_ref`

References a HUB-DATA entitlement grant deterministically:

- `data_action_id`: DATA action id (BLAKE3 hash of canonical DATA action JSON).
- `license_id`: deterministic license id derived by HUB-DATA for the entitlement.

## Linkage receipt

fin-node persists a resume-safe `LinkageReceiptV1` at:

`receipts/linkage/<purchase_id>.json`

Fields:
- `purchase_id`, `dataset_id`, `listing_id`, `licensee`
- `price_microunits`, `currency_asset_id`
- `payment_ref` (optional until paid)
- `entitlement_ref` (optional until granted)
- `status`: `created | paid | entitled | failed_recoverable`
- `last_error` (optional, sanitized)

