# IPPAN-L2 Coding Conventions

## Determinism and Numeric Types

IPPAN-L2 must be deterministic and suitable for cross-architecture verification.
Therefore:

- **No `f32` or `f64` types** are allowed in production code.
- All monetary and quantitative values must use fixed-point integer types
  (e.g., `i64` / `i128` with an explicit SCALE).
- `unsafe` Rust is forbidden in this repository.
- `clippy::float_arithmetic` and related lints are treated as hard errors.

## General Guidelines

- Keep L2-core as small and pure as possible: types, traits, and interfaces.
- Hub-specific logic should live in per-hub crates (e.g. `hub-fin`, `hub-data`).
