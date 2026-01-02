# Economics

IPPAN-L2 economics are designed for machine-to-machine (M2M) predictability.

## Principles
1.  **Integer Math**: All amounts are `u64` or `u128` scaled fixed-point (e.g., 6 decimals). No floats.
2.  **Predictability**: Fees should be calculable offline.

## Fee Types

### 1. Protocol Fee (L1 Rent)
*   **Paid by**: The L2 Node Operator.
*   **Paid to**: IPPAN CORE (L1 Validators).
*   **Mechanism**: Standard L1 transaction fees for `submit_settlement`.
*   **Cost Driver**: Data availability (call-data size) and frequency of batches.

### 2. Hub Fee (Execution Cost)
*   **Paid by**: The User / L2 Transaction Sender.
*   **Paid to**: The L2 Hub / Operator.
*   **Mechanism**: Deducted from the user's L2 account balance (in `FIN` hub).
*   **Components**:
    *   **Base Fee**: Fixed cost per tx.
    *   **Compute Fee**: Scaled by execution units.
    *   **Storage Fee**: Scaled by bytes written/stored.

## Fee Abstraction
Hubs may implement custom fee logic (e.g., `M2M` hub paying for `DATA` hub usage), but the base calculation must remain deterministic.
