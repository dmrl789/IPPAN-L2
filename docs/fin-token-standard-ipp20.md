# FIN Token Standard (IPP20-like, Deterministic)

This document describes a minimal fungible asset standard for the IPPAN FIN hub.

## Overview

FIN fungible assets follow an IPP20-like model:

- **asset_id**: global identifier (opaque string)
- **symbol**: short ticker (string)
- **name**: human-readable name (string)
- **decimals**: display precision (integer)
- **balances**: integer-only amounts per account

## Determinism Requirements

- All quantities are **integers** (no floating point).
- Transfers, mints, burns, and fees must use deterministic integer arithmetic.
- No VM is assumed; the hub executes a small, auditable set of operations.

## Operations (Current)

- `RegisterFungibleAsset { asset_id, symbol, name, decimals }`
- `Mint { asset_id, to, amount }`
- `Burn { asset_id, from, amount }`
- `Transfer { asset_id, from, to, amount }`

## Notes

- `decimals` is metadata that affects display and client-side unit conversion.
- Hub execution must remain deterministic across architectures and implementations.

