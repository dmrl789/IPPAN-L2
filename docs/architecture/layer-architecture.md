# Layer Architecture

IPPAN-L2 implements a strict **2-Layer Architecture** to separate consensus/settlement from execution.

## 1. IPPAN CORE (Layer 1)
**Role**: Settlement, Ordering, and Finality.

* **Responsibility**: Accepts deterministic envelopes (Batches) from L2, orders them, and provides a "time anchor" (block height/hash).
* **State**: Unaware of L2 business logic. Only verifies that the submission pays the required L1 fees and comes from a valid source (if permissioned).
* **Interface**: expose `chain_status`, `submit_batch`, `get_inclusion`.

## 2. IPPAN-L2 (Layer 2)
**Role**: Execution, Batching, and Proofs.

* **Responsibility**:
    * **Hub Routing**: Routes transactions to specific functional domains (Hubs).
    * **Execution**: Hubs apply transactions deterministically to update their local state.
    * **Batching**: Aggregates processed transactions into `L2Batch` envelopes.
    * **Settlement**: Computes a `BatchCommitment` (Merkle roots) and submits it to L1.
* **Hubs**: Isolated execution environments (e.g., FIN, DATA, WORLD) that share the same Settlement Client.

## Diagram
```mermaid
graph TD
    User[User / Client] -->|L2 Tx| Engine[L2 Engine]
    Engine -->|Route| Hub[L2 Hub (FIN/DATA)]
    Hub -->|Execute| State[Hub State]
    Hub -->|Receipt| Engine
    Engine -->|Aggregate| Batch[L2 Batch]
    Batch -->|Commitment| L1[IPPAN CORE (L1)]
    L1 -->|Finality| Engine
```
