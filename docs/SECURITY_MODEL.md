# IPPAN-L2 Security Model (MVP)

## Threat Model

- **Sequencer/leader censorship:** a single leader could delay or drop txs.
- **Batch equivocation:** conflicting batches could be posted if state is not anchored.
- **Replay/ordering manipulation:** reordering of mempool entries before batching.
- **DoS:** unbounded tx ingress or slow storage could starve batching and readiness.
- **State divergence:** non-canonical serialization or non-deterministic hashing causing forks.

## Trust Assumptions

- Operators run audited binaries built from this repo (no supply-chain tampering).
- L1 contract / RPC endpoint faithfully returns canonical ordering and timestamps.
- Storage is local and crash-consistent (sled durability guarantees).

## Mitigations (MVP)

- **Determinism:** canonical `bincode` encoding + BLAKE3 hashing; float usage prohibited by linting.
- **Schema versioning:** `meta:schema_version` gate prevents silent layout changes.
- **Readiness gating:** `/readyz` fails if storage fails to open; status reflects batcher/bridge activity.
- **Resource bounds:** batching thresholds cap tx/byte counts; queues are bounded channels.
- **Auditability:** hashes exposed in status/logs; golden vectors guard canonical encoding.

## Roadmap Hardening

- Multi-leader rotation with leases and forced inclusion (documented in `docs/LEADER.md`).
- Batch commitments anchored to DA layer + proofs verified in posting path.
- Rate limiting + admission control for public transaction ingress.
- Verifiable build pipeline + SBOM publication.
