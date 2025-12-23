# HUB-FIN Actions (MVP v1)

This document defines the **exact action schemas** for the HUB-FIN MVP v1, along with validation and hashing rules.

## Shared rules

- **No floats**: all amounts are fixed-point **scaled integers**.
- **Canonical bytes**: actions and envelopes are encoded as **canonical JSON**:
  - recursively sort object keys lexicographically
  - serialize as compact JSON bytes (UTF-8)
- **Action id**:
  - `action_id = blake3(canonical_bytes(action))` (32 bytes)
- **Account id type**:
  - `to_account` uses `l2_core::AccountId` (a bounded string).

## Action enum (v1)

Actions are represented as a tagged union with a `type` field:

- `create_asset_v1`
- `mint_units_v1`

## CREATE_ASSET (v1)

### Purpose

Defines a new financial asset class (RWA “instrument”).

### Fields

- **asset_id**: 32 bytes (hex string in JSON)
  - must equal `blake3(name || issuer || symbol)` (UTF-8 byte concatenation)
- **name**: string, bounded
- **symbol**: string, bounded
- **issuer**: string, bounded
- **decimals**: `u8` (0..=18)
- **metadata_uri**: optional string, bounded

### Rules

- `asset_id` must be unique (reject if exists)
- all strings are trimmed and must be non-empty

## MINT_UNITS (v1)

### Purpose

Mints units of an existing asset to an account (allocation ledger).

### Fields

- **asset_id**: 32 bytes (hex string in JSON)
- **to_account**: `AccountId` (string)
- **amount**: scaled integer `u128`
  - encoded as a JSON string (e.g. `"20000000"`)
  - must be `> 0`
- **client_tx_id**: string, bounded
  - included in the action hash; replays with the same `client_tx_id` produce the same `action_id`
- **memo**: optional string, bounded

### Rules

- referenced `asset_id` must exist
- deterministic overflow checks on balance addition

