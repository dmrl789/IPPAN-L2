#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

use l2_core::{BatchCommitment, L2HubId, L2Tx, Receipt};

/// Interface for a deterministic L2 Hub state machine.
///
/// Hubs must implement this to plug into the L2 Engine.
pub trait HubStateMachine {
    /// Identifier of this hub.
    fn hub_id(&self) -> L2HubId;

    /// Apply a single transaction to the state and return a receipt.
    ///
    /// This must be deterministic: same state + same tx = same receipt + same new state.
    fn apply_tx(&mut self, tx: &L2Tx) -> Receipt;

    /// Execute a batch of transactions and return the Merkle roots.
    ///
    /// Returns: (state_root, receipts_root, tx_root)
    ///
    /// The `tx_root` is typically computed from the input txs, but is returned
    /// here for convenience in constructing the commitment.
    fn execute_batch(&mut self, txs: &[L2Tx]) -> (String, String, String);

    /// Export the current state as a commitment for the settlement layer.
    ///
    /// This assumes a batch was just executed.
    fn export_commitment(&self, batch_id: l2_core::L2BatchId, sequence: u64) -> BatchCommitment;
}
