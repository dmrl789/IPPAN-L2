use l2_core::{BatchCommitment, L2BatchId, L2HubId, L2Tx, Receipt, Hash32};
use l2_hub::HubStateMachine;

/// Financial Hub State Machine.
pub struct FinHub {
    state_root: Hash32,
}

impl FinHub {
    pub fn new() -> Self {
        Self {
            state_root: Hash32([0u8; 32]),
        }
    }
}

impl Default for FinHub {
    fn default() -> Self {
        Self::new()
    }
}

impl HubStateMachine for FinHub {
    fn hub_id(&self) -> L2HubId {
        L2HubId::Fin
    }

    fn apply_tx(&mut self, _tx: &L2Tx) -> Receipt {
        // Placeholder execution logic
        // In a real impl, this would update balances/ledgers.
        Receipt {
            tx_hash: Hash32([0u8; 32]), // Placeholder hash
            success: true,
            message: Some("FinHub: tx applied".to_string()),
        }
    }

    fn execute_batch(&mut self, txs: &[L2Tx]) -> (String, String, String) {
        // Placeholder batch execution
        // Returns (state_root, receipts_root, tx_root)
        // For now, we update the state root hash based on tx count to show change.
        
        let tx_count = txs.len();
        // Simple mock update
        self.state_root.0[0] = self.state_root.0[0].wrapping_add(tx_count as u8);

        (
            self.state_root.to_hex(),
            Hash32([0xAA; 32]).to_hex(), // Mock receipts root
            Hash32([0xBB; 32]).to_hex(), // Mock tx root
        )
    }

    fn export_commitment(&self, batch_id: L2BatchId, sequence: u64) -> BatchCommitment {
        BatchCommitment {
            version: "v1".to_string(),
            hub_id: L2HubId::Fin,
            batch_id,
            sequence,
            state_root: self.state_root.to_hex(),
            tx_root: Hash32([0xBB; 32]).to_hex(),
            receipts_root: Hash32([0xAA; 32]).to_hex(),
        }
    }
}
