# IPPAN Hub Registry

This document defines the canonical Hubs in the IPPAN-L2 network.

## Hub IDs
The Hub ID matches the deterministic ordering defined in `l2-core`.

| ID | Name | Purpose | Crate |
| :--- | :--- | :--- | :--- |
| `0` | **FIN** | Financial operations, RWA, Stablecoins. High security. | `hub-fin` |
| `1` | **DATA** | Data attestation, AI model weights, InfoLAW. High throughput. | `hub-data` |
| `2` | **M2M** | Machine-to-Machine micropayments, IoT. Low latency. | *Planned* |
| `3` | **WORLD** | General purpose dApps, Marketplaces. | *Planned* |
| `4` | **BRIDGE** | Cross-chain interoperability and messaging. | `crates/l2-bridge` |

## Architecture
Each Hub implements the `HubStateMachine` trait from `l2-hub`. Use `l2-engine` to register and route transactions to the appropriate Hub.
