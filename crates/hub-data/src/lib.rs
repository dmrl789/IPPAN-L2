use l2_core::{BatchCommitment, L2BatchId, L2HubId, L2Tx, Receipt, Hash32};
use l2_hub::HubStateMachine;

/// Data Attestation Hub State Machine.
pub struct DataHub {
    state_root: Hash32,
}

impl DataHub {
    pub fn new() -> Self {
        Self {
            state_root: Hash32([0u8; 32]),
        }
    }
}

impl Default for DataHub {
    fn default() -> Self {
        Self::new()
    }
}

impl HubStateMachine for DataHub {
    fn hub_id(&self) -> L2HubId {
        L2HubId::Data
    }

    fn apply_tx(&mut self, _tx: &L2Tx) -> Receipt {
        Receipt {
            tx_hash: Hash32([0u8; 32]),
            success: true,
            message: Some("DataHub: tx applied".to_string()),
        }
    }

    fn execute_batch(&mut self, _txs: &[L2Tx]) -> (String, String, String) {
        (
            self.state_root.to_hex(),
            Hash32([0xCC; 32]).to_hex(),
            Hash32([0xDD; 32]).to_hex(),
        )
    }

    fn export_commitment(&self, batch_id: L2BatchId, sequence: u64) -> BatchCommitment {
        BatchCommitment {
            version: "v1".to_string(),
            hub_id: L2HubId::Data,
            batch_id,
            sequence,
            state_root: self.state_root.to_hex(),
            tx_root: Hash32([0xDD; 32]).to_hex(),
            receipts_root: Hash32([0xCC; 32]).to_hex(),
        }
    }
}
