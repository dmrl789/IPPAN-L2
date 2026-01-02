use l2_core::{
    FixedAmount, L1SettlementClient, L2Batch, L2BatchId, L2HubId, L2Tx, Receipt, SettlementError,
    SettlementRequest, SettlementResult,
};
use l2_hub::HubStateMachine;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// The L2 Engine managing hubs and settlement.
pub struct L2Engine {
    hubs: HashMap<L2HubId, Arc<Mutex<dyn HubStateMachine + Send + Sync>>>,
    l1_client: Arc<dyn L1SettlementClient + Send + Sync>,
}

impl L2Engine {
    pub fn new(l1_client: Arc<dyn L1SettlementClient + Send + Sync>) -> Self {
        Self {
            hubs: HashMap::new(),
            l1_client,
        }
    }

    /// Register a hub instance.
    pub fn register_hub(&mut self, hub: Arc<Mutex<dyn HubStateMachine + Send + Sync>>) {
        // We need to lock it briefly to get the ID, or assumes the caller validates it.
        // For simplicity, we assume we can get the ID from a "dry" call or passed in.
        // But since we can't call async method on lock easily in constructor,
        // we'll assume the caller registers correctly for now or rely on an async init.
        // Wait, HubStateMachine::hub_id is synchronous (reference to &self).
        // So we can lock/unlock.
        let id = {
            let h = hub.blocking_lock();
            h.hub_id()
        };
        self.hubs.insert(id, hub);
    }

    /// Submit a transaction to the appropriate hub.
    pub async fn submit_tx(&self, tx: L2Tx) -> Result<Receipt, String> {
        let hub_arc = self.hubs.get(&tx.hub).ok_or("Hub not found")?;
        let mut hub: tokio::sync::MutexGuard<'_, dyn HubStateMachine + Send + Sync> =
            hub_arc.lock().await;
        Ok(hub.apply_tx(&tx))
    }

    /// Trigger batch execution and settlement for a specific hub.
    ///
    /// In a real engine, this would select pending txs from a mempool.
    /// Here we take a list of txs to batch immediately.
    pub async fn settle_batch(
        &self,
        hub_id: L2HubId,
        batch_id: L2BatchId,
        txs: Vec<L2Tx>,
    ) -> Result<SettlementResult, anyhow::Error> {
        if txs.is_empty() {
            return Err(anyhow::anyhow!("Batch cannot be empty"));
        }

        let hub_arc = self
            .hubs
            .get(&hub_id)
            .ok_or(anyhow::anyhow!("Hub {} not registered", hub_id))?;
        let mut hub: tokio::sync::MutexGuard<'_, dyn HubStateMachine + Send + Sync> =
            hub_arc.lock().await;

        // 1. Execute Batch
        let _ = hub.execute_batch(&txs);

        // 2. Export Commitment
        // Using a simple sequence counter mock (in real engine, engine tracks sequence).
        let sequence = 1;
        let commitment = hub.export_commitment(batch_id.clone(), sequence);

        // 3. Create Settlement Request
        let req = SettlementRequest {
            hub: hub_id,
            batch: L2Batch::new(hub_id, batch_id.clone(), txs.len() as u64)
                .with_commitment(commitment.commitment_hash()?.to_hex()),
            fee: FixedAmount::from_units(1, 6), // Mock protocol fee
        };

        // 4. Submit to L1
        let result = self.l1_client.submit_settlement(req)?;
        Ok(result)
    }
}

// Mock L1 Client for testing/reference
pub struct MockSettlementClient;

impl L1SettlementClient for MockSettlementClient {
    fn chain_status(&self) -> Result<l2_core::l1_contract::L1ChainStatus, SettlementError> {
        Err(SettlementError::Internal("Not implemented".into()))
    }

    fn submit_settlement(
        &self,
        request: SettlementRequest,
    ) -> Result<SettlementResult, SettlementError> {
        Ok(SettlementResult {
            hub: request.hub,
            batch_id: request.batch.batch_id,
            l1_reference: "mock_l1_tx_id".to_string(),
            finalised: false,
        })
    }

    fn get_finality(
        &self,
        _tx_id: &str,
    ) -> Result<l2_core::l1_contract::L1InclusionProof, SettlementError> {
        Err(SettlementError::Internal("Not implemented".into()))
    }
}
