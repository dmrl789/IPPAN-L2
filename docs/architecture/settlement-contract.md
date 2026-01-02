# Settlement Contract

The **Settlement Contract** defines the interface between L2 execution and L1 finality. It resides in `crates/l2-core`.

## Objects

### `L2Transaction`
The fundamental atomic unit of input.
*   `hub_id`: Target Hub.
*   `nonce`: Replay protection.
*   `payload`: Opaque hub-specific bytes.
*   `signature`: Cryptographic proof of authority.

### `L2Batch`
A generic container for a sequence of transactions.

### `BatchCommitment`
The summary structure committed to L1.
*   `version`: Contract version (v1).
*   `hub_id`: Origin Hub.
*   `sequence`: Monotonic batch count.
*   `state_root`: Merkle root of the Hub state after usage.
*   `tx_root`: Merkle root of the included transactions.
*   `receipts_root`: Merkle root of execution results.

### `SettlementRequest`
The payload sent to L1. Contains the `BatchCommitment` and any necessary proofs (e.g., signature aggregation).

## Interface: `L1SettlementClient`

The L2 Engine uses this trait to talk to L1.

```rust
trait L1SettlementClient {
    /// Get current L1 status (height, time).
    fn chain_status(&self) -> Result<L1ChainStatus>;

    /// Submit a batch commitment.
    fn submit_settlement(&self, req: SettlementRequest) -> Result<SettlementReceipt>;

    /// Check inclusion/finality of a previous submission.
    fn get_finality(&self, tx_id: &str) -> Result<L1InclusionProof>;
}
```

## Guarantees
*   **Idempotency**: Submitting the same `SettlementRequest` multiple times is safe.
*   **Ordering**: L1 dictates the authoritative order of chunks.
