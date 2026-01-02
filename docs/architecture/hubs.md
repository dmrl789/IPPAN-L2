# L2 Hubs

A **Hub** is an isolated, deterministic execution domain within IPPAN-L2.

## Concept
Each Hub is a state machine that transitions based on ordered transactions. Hubs share the same L2 Engine (host) but maintain separate opaque states.

### Core Contracts
All Hubs must implement the `HubStateMachine` trait:

1.  **Determinism**: Given `State_A` and `Tx_1`, the output `State_B` and `Receipt_1` must be identical on every machine, forever.
    *   No floating point.
    *   No wall-clock time (use L1 block time if needed).
    *   No iteration over unsorted hashmaps.
2.  **Isolation**: A panic in one Hub must not crash the Engine or corrupt other Hubs.

## Known Hubs

| Hub ID | Name | Purpose |
| :--- | :--- | :--- |
| `FIN` | Financial | Asset management, transfers, payments. |
| `DATA` | Data | Data anchoring, attestation, provenance. |
| `M2M` | Machine | Fee payments, automation (optional). |
| `WORLD` | World | Bridge to external events/oracles (optional). |
| `BRIDGE`| Bridge | Cross-hub intent coordination. |

## Lifecycle
1.  **Apply**: Engine calls `apply_tx(tx)` -> returns `Receipt`.
2.  **Batch**: Periodically, Engine calls `execute_batch(txs)`.
3.  **Commit**: Hub produces `BatchCommitment` (State Root, Tx Root).
