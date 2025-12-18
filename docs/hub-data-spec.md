# IPPAN DATA Hub – Specification (Draft)

The IPPAN DATA Hub is the Layer 2 (L2) environment for content and data
attestations. It enables identities to prove authorship, publication, or
verification of digital artefacts (videos, articles, posts, datasets, etc.)
without storing the content on-chain.

- Content is represented by `ContentHash` (hash of file / canonical record).
- Attestations are represented by `Attestation`.
- State is tracked in `DataState` keyed by `ContentHash`.
- The engine (`DataHubEngine`) applies attestations and submits batches
  to IPPAN CORE via the shared `L1SettlementClient` interface.

All logic is deterministic, integer-based (no floats), and safe Rust (no `unsafe`).
