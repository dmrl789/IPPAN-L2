# IPPAN Layer Architecture

## 1. Overview

IPPAN is a two-layer architecture:

- **IPPAN CORE (L1)** – deterministic settlement, ordering, timestamping, validator consensus and fee redistribution.
- **IPPAN Hubs (L2)** – programmable execution environments for tokenisation, NFTs, data, AI, IoT and cross-chain interoperability.

All asset and application logic is executed at L2. All final settlement, ordering and HashTimer™-anchored state commitments are handled by IPPAN CORE.

## 2. IPPAN CORE (L1)

IPPAN CORE is the base layer and provides:

- Deterministic consensus and BlockDAG ordering
- HashTimer™ microsecond-level timestamps
- Finality of batches and commitments coming from L2
- Fee collection and redistribution to validators
- Audit-grade, regulator-ready state history

CORE holds no application logic and no asset-specific rules. It focuses exclusively on:

- Transaction ordering
- Time anchoring
- Validation
- State commitment
- Fee accounting

This keeps L1 fast, predictable and easier to audit.

## 3. IPPAN Hubs (L2)

IPPAN Hubs are L2 execution environments that:

- Implement token standards and asset logic
- Maintain L2 state (balances, ownership, contracts)
- Batch transactions and commit proofs to CORE
- Define domain-specific rules (finance, data, IoT, etc.)

Each Hub is logically distinct but shares a common settlement interface with CORE. The current Hub set:

- **IPPAN FIN** – Finance / RWA / stablecoins
- **IPPAN DATA** – Data, AI models, InfoLAW content, identity
- **IPPAN M2M** – IoT and machine-to-machine payments
- **IPPAN WORLD** – General applications and marketplaces
- **IPPAN BRIDGE** – Cross-chain and interoperability

### Multiple Hubs, one settlement contract

IPPAN supports multiple Hubs (FIN, DATA, and later M2M/WORLD/BRIDGE) that all share:

- A common settlement contract (traits and types in `l2-core`, e.g. `FixedAmount`, `L2Batch`,
  `SettlementRequest`, and `L1SettlementClient`)
- Separate state, logic, and storage per Hub (each Hub defines its own deterministic state machine)
- The same deterministic rules for reproducibility and auditability (no floating point, no `unsafe`)

## 4. L1 / L2 Contract

At a high level, the contract between CORE and Hubs is:

- L2 → L1:
  - Batches of executed transactions
  - State commitments (e.g., state roots, proofs)
  - Fee payments in IPN
  - HashTimer™ anchors

- L1 → L2:
  - Deterministic ordering of batches
  - Finality guarantees
  - Confirmation of commitments
  - Fee redistribution to validators

L2 Hubs are free to implement their own internal execution model (e.g., rollup-style, sidechain-style, or custom), as long as they honour the settlement contract with CORE.

## 5. Economic Separation

- **Protocol fees (CORE):** collected when L2 batches are settled and redistributed to validators under the IPN economic model.
- **Business / issuer fees (L2):** commercial fees, royalties, and service charges defined by the Hub or applications; these remain off-core and are not redistributed by the protocol.

This separation enables a sustainable protocol economy while allowing flexible business models on top.

## 6. Roadmap (High-Level)

1. Define minimal L2 core types and settlement API.
2. Finalise Hub identifiers and interfaces.
3. Specify IPPAN FIN (RWA + finance) as the first production Hub.
4. Add IPPAN DATA and IPPAN M2M hub specs.
5. Implement a reference L2 engine and devnet for testing.
6. Integrate with IPPAN CORE RPC for settlement and proof verification.
