# Settlement Lifecycle

This document describes the lifecycle of an L2 transaction from submission to L1 finality.

## 1. Submission (L2)
*   **User** submits an `L2Tx` to a specific Hub (e.g., `FinHub`).
*   **Hub** validates and applies the transaction to its deterministic state (`HubStateMachine::apply_tx`).
*   **Receipt** is returned to the user immediately (soft confirmation).

## 2. Batching (L2 Engine)
*   **L2 Engine** aggregates transactions into a batch.
*   **Hub** executes the batch (`execute_batch`) and produces Merkle roots (`state_root`, `tx_root`, `receipts_root`).
*   **Hub** exports a `BatchCommitment` containing these roots, the version, and sequence number.

## 3. Settlement Request (L2 -> L1)
*   **L2 Engine** constructs a `SettlementRequest` wrapping the `L2Batch` and `BatchCommitment`.
*   The request is canonically encoded (versioned) and signed (if configured).
*   **L2 Node** submits this request to IPPAN CORE via `L1SettlementClient`.

## 4. L1 Settlement (IPPAN CORE)
*   **IPPAN CORE** receives the batch envelope.
*   It verifies:
    *   Canonical encoding and version `v1`.
    *   Idempotency key (to prevent replay).
    *   Fee payment (`FixedAmount`).
*   On success, L1 records the commitment hash and emits an event/receipt.

## 5. Finality (L1 -> L2)
*   **L2 Node** polls L1 for finality (`get_finality`).
*   Once L1 finalizes the block containing the commitment, the batch is considered **Finalized**.
*   This status is propagated to the Hubs to update their "safe" head.
