# IPPAN Hubs (L2 Execution Environments)

IPPAN Hubs are specialised L2 environments that run on top of IPPAN CORE and anchor their state and security to the deterministic L1. Each Hub is focused on a specific domain and can evolve independently while maintaining a common settlement interface.

## IPPAN FIN – Finance Hub

The **IPPAN FIN** Hub is designed for:

- Real-world asset (RWA) tokenisation
- Bonds and money markets
- Funds and structured products
- Institutional stablecoins
- Regulated settlement flows

Key properties:

- Deterministic finality via IPPAN CORE
- High-throughput batch processing of financial transactions
- Hooks for compliance, KYC/AML and reporting
- Support for fungible token standards (e.g., IPP20) and financial NFTs

Implementation status (this repo):

- `hub-fin`: reference engine + deterministic state machine, using `FixedAmount` and the shared
  `L1SettlementClient` settlement interface.
- `fin-node`: demo node binary that builds a batch and submits via a dummy client today.
- State is stored in an in-memory store today; a persistent store can be added later without
  changing the L1 settlement contract.

## IPPAN DATA – Data & AI Hub

The **IPPAN DATA** Hub focuses on:

- Tokenised datasets and data streams
- Machine learning model licensing
- InfoLAW content and legal reasoning artefacts
- Identity-related state and claims
- Provenance and usage tracking for data

It leverages IPPAN’s deterministic timestamps for:

- Data lineage
- Auditability and regulatory compliance
- Fair revenue-sharing models for data contributors and model authors

Implementation status (this repo):

- `hub-data`: reference engine for content attestations (hash + metadata), using `FixedAmount` and
  the shared `L1SettlementClient` settlement interface.
- State is stored in an in-memory store today; a persistent store can be added later.

## IPPAN M2M – Machine-to-Machine Hub

The **IPPAN M2M** Hub is built for:

- IoT microtransactions
- Autonomous agent payments
- Smart meter and grid settlement
- Device-to-device contracts (compute, bandwidth, storage)

It targets extremely high transaction volumes with:

- Batched settlements at L1
- Minimal per-event fees
- Strong ordering guarantees for time-critical operations

## IPPAN WORLD – Applications Hub

The **IPPAN WORLD** Hub supports:

- Consumer and enterprise dApps
- Marketplaces and e-commerce flows
- NFTs for rights, media and experiences
- Loyalty, points and gamified economies

It acts as a general-purpose playground for application builders and integrators.

## IPPAN BRIDGE – Interoperability Hub

The **IPPAN BRIDGE** Hub provides:

- Cross-chain asset onboarding and redemption
- Stablecoin and RWA bridges to external networks
- Liquidity routing between ecosystems
- Unified settlement and audit of bridged flows via IPPAN CORE

This Hub is the entry and exit point for assets linking IPPAN to the broader digital asset universe.

## Next Steps

- Define minimal technical interfaces (APIs, proofs) between each Hub and IPPAN CORE.
- Specify per-Hub token standards and contract models.
- Implement reference L2 engines and testnets for at least IPPAN FIN and IPPAN DATA.
