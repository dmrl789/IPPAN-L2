# IPPAN-L2 — Product Requirements Document (PRD)

**Audience:** Core contributors, maintainers, protocol engineers
**Depth:** Detailed / implementation-oriented
**Status:** Draft
**Owner:** IPPAN Core Team
**Repository:** IPPAN-L2
**Last updated:** 2025-12-24

---

## 0. L2 MVP Scope (2025 Q1 refresh)

### Problem statement

IPPAN CORE delivers deterministic settlement, but application and asset workloads need higher throughput, batching, and bridge-like UX. The MVP for IPPAN-L2 must therefore:

* Batch user transactions deterministically and post them back to L1
* Provide health/readiness/metrics endpoints for operability
* Offer a minimal bridge/message surface so deposits/withdrawals can be tracked
* Keep deterministic serialization and hashing so nodes cannot disagree

### MVP scope (in / out)

* **In:** batching skeleton, bridge/watch skeleton, REST API (`/healthz`, `/readyz`, `/status`, `/metrics`), canonical hashing, sled-backed persistence, OpenAPI contract, CI gates.
* **Out (roadmap):** production L1 posting, proof verification, fraud/validity proofs, multi-leader rotation, GPU/TEE acceleration, on-chain enforcement of forced inclusion.

### Functional requirements

* Accept transactions into a mempool and cut batches deterministically based on byte/tx/time thresholds.
* Persist txs, batches, receipts, and meta state with schema versioning.
* Expose status showing leader mode, queue depth, batcher/bridge last activity.
* Emit Prometheus metrics for operability.

### Non-functional requirements

* Deterministic serialization (no floats, canonical encoding for hashing).
* Reproducible builds and pinned toolchains.

### Interfaces

* REST API for operators and SDKs (OpenAPI documented) with health/ready/status + stubs for tx/batch retrieval.
* Internal traits for posting batches to L1 (`BatchPoster`) and watching L1 (`L1Watcher`).

### Milestones

1. **MVP (this repo):** runnable node with status/metrics, sled persistence, canonical hashing tests.
2. **Beta:** real L1 posting path, bridge event ingestion, horizontal scaling playbook.
3. **Production:** leader rotation, forced inclusion, multi-DC HA, DA integration.

## 1. Purpose of This Document

This PRD defines **what IPPAN-L2 is expected to do**, **why it exists**, and **what constraints must never be violated**, from the perspective of contributors working on the codebase.

It serves to:

* Align contributors on **scope and invariants**
* Prevent architectural drift
* Make PR review objective and reproducible
* Separate **product intent** from **implementation details**

This document **does not replace**:

* `WHITEPAPER.md` (vision & theory)
* `DEV.md` (how to build/run)
* `API.md` (endpoint-level contracts)

---

## 2. Product Overview

### 2.1 What is IPPAN-L2?

IPPAN-L2 is a **Layer-2 execution and coordination layer** built on top of IPPAN L1, providing:

* Deterministic execution environments (“Hubs”)
* High-throughput domain-specific logic
* Trust-minimized settlement back to L1
* Explicit separation between **execution** and **final ordering**

IPPAN-L2 **does not compete with IPPAN L1**.
It extends it.

---

### 2.2 Why IPPAN-L2 Exists

IPPAN L1 is optimized for:

* Deterministic ordering (HashTimer / IPPAN Time)
* Global auditability
* Fairness and reproducibility

However, not all workloads belong on L1.

IPPAN-L2 exists to:

* Offload domain-specific logic
* Reduce L1 congestion
* Enable experimentation without violating L1 invariants
* Support vertical use-cases (finance, data, M2M, worlds)

---

## 3. Design Principles (Hard Constraints)

These principles are **non-negotiable**.
Any PR violating them must be rejected.

### 3.1 Determinism First

* No probabilistic behavior in consensus-relevant paths
* No time-dependent logic except via L1 timestamps
* Identical inputs must produce identical outputs across nodes

### 3.2 L2 Is Not Sovereign

* L2 **cannot override** L1 ordering or finality
* L2 state is always subordinate to L1 settlement

### 3.3 Explicit Boundaries

* Clear API boundaries between:

  * L2 ↔ L1
  * Hub ↔ Hub
  * Execution ↔ Settlement

### 3.4 Contributor-Readable Code

* Clarity > cleverness
* Debuggability > micro-optimizations
* Deterministic logs preferred over silent behavior

---

## 4. In Scope / Out of Scope

### 4.1 In Scope

* L2 hub framework
* Deterministic execution pipelines
* L1 settlement hooks
* Developer-facing APIs (HTTP / RPC)
* Documentation for contributors

### 4.2 Explicitly Out of Scope

* Tokenomics design
* Wallet UX
* Frontend applications
* Governance policy
* Marketing or adoption strategy

---

## 5. Users & Personas (Contributor View)

### 5.1 Primary Users

**Core Contributors**

* Implement protocol logic
* Maintain determinism and safety
* Review PRs

**Integrators**

* Build L2 hubs or services
* Consume APIs
* Rely on strong guarantees

### 5.2 Secondary Users

* Auditors
* Researchers
* Infrastructure operators

---

## 6. Architecture Overview (Conceptual)

IPPAN-L2 is composed of **independent but coordinated hubs**, each with:

* Local execution logic
* Deterministic state machine
* Settlement adapter to L1

### Example Hub Categories

* FIN Hub — financial logic
* DATA Hub — attestations, records
* M2M Hub — machine-to-machine coordination
* WORLD Hub — simulation / virtual environments
* BRIDGE Hub — cross-network adapters

Each hub:

* Can be enabled/disabled independently
* Must conform to the same settlement interface
* Must be replayable from L1 data alone

---

## 7. Functional Requirements

### FR-1: Deterministic Execution

* Hub execution must be fully deterministic
* No floating-point math in consensus-relevant paths
* Explicit ordering of all operations

### FR-2: Hub Registration

* Hubs must self-declare:

  * Capabilities
  * Version
  * Settlement mode
* Registration must be auditable

### FR-3: L1 Settlement Interface

* L2 state transitions must be commit-able to L1
* Settlement must include:

  * State root / commitment
  * Deterministic metadata
  * Verifiable linkage to execution

### FR-4: Replayability

* A hub must be replayable from:

  * L1 data
  * Hub-local logs
* Replay must reproduce identical state

### FR-5: API Exposure

* Stable APIs for:

  * Submission
  * Query
  * Status
* API behavior must be deterministic under identical inputs

---

## 8. Non-Functional Requirements

### NFR-1: Performance

* Designed for high throughput
* Performance optimizations must not compromise determinism

### NFR-2: Reliability

* Crash-safe state transitions
* Explicit error handling
* No hidden retries

### NFR-3: Security

* No implicit trust between hubs
* Defensive input validation
* Clear failure modes

### NFR-4: Observability

* Structured logs
* Deterministic identifiers
* Contributor-friendly diagnostics

---

## 9. Dependencies

### Internal

* IPPAN L1 node / RPC
* Shared data structures and formats

### External

* Rust toolchain
* CI environment
* Optional external chains (via Bridge Hub)

All dependencies must be:

* Version-pinned
* Documented
* Auditable

---

## 10. Contributor Workflow Expectations

### Code Contributions

* PRs must reference this PRD where relevant
* Behavioral changes require PRD alignment
* Tests are mandatory for consensus-relevant code

### Documentation Contributions

* Docs are first-class
* Architecture changes must update docs
* Ambiguity is a bug

---

## 11. Risks & Mitigations

| Risk                      | Impact   | Mitigation               |
| ------------------------- | -------- | ------------------------ |
| Accidental nondeterminism | Critical | CI determinism tests     |
| Hub divergence            | High     | Strict settlement checks |
| Over-engineering          | Medium   | Scope discipline         |
| Contributor confusion     | Medium   | Clear PRD + docs         |

---

## 12. Open Questions (Living Section)

* Should hub versions be enforced at settlement time?
* How strict should backward compatibility be?
* Do we allow experimental hubs on main L2?

(Questions here must be resolved before major releases.)

---

## 13. Success Criteria

IPPAN-L2 is considered **successful** when:

* Contributors can implement a new hub without touching L1
* L2 state can be deterministically replayed
* PR reviews can objectively reference requirements
* No contributor needs “oral tradition” to understand behavior

---

## 14. Change Log

| Version | Date       | Notes         |
| ------- | ---------- | ------------- |
| 1.0     | 2025-12-24 | Initial draft |
