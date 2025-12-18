#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::disallowed_types)]

//! IPPAN FIN – Finance Hub
//!
//! This crate will host the execution logic for the finance-focused
//! IPPAN L2 Hub (RWA, bonds, funds, stablecoins).
//!
//! For now we define minimal traits and types and rely on l2-core
//! for the shared settlement abstractions.

use l2_core::{
    FixedAmount, L1SettlementClient, L2Batch, L2BatchId, L2HubId, SettlementError,
    SettlementRequest, SettlementResult,
};

/// Logical identifier used for IPPAN FIN batches.
pub const HUB_ID: L2HubId = L2HubId::Fin;

/// Represents a high-level financial transaction in the FIN Hub.
/// This is a placeholder for now and will be expanded with
/// token operations, RWA actions, etc.
#[derive(Debug, Clone)]
pub struct FinTransaction {
    /// Opaque transaction payload (to be defined).
    pub payload: Vec<u8>,
}

/// Engine responsible for building L2 batches from FIN transactions
/// and submitting them to IPPAN CORE.
pub struct FinHubEngine<C: L1SettlementClient> {
    client: C,
}

impl<C: L1SettlementClient> FinHubEngine<C> {
    /// Create a new engine with the given settlement client.
    pub fn new(client: C) -> Self {
        Self { client }
    }

    /// Build a simple batch from a list of FIN transactions and submit it
    /// to IPPAN CORE for settlement.
    pub fn submit_batch(
        &self,
        batch_id: L2BatchId,
        txs: &[FinTransaction],
        fee: FixedAmount,
    ) -> Result<SettlementResult, SettlementError> {
        let batch = L2Batch::new(HUB_ID, batch_id, txs.len() as u64);
        let request = SettlementRequest {
            hub: HUB_ID,
            batch,
            fee,
        };

        self.client.submit_settlement(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyClient;

    impl L1SettlementClient for DummyClient {
        fn submit_settlement(
            &self,
            request: SettlementRequest,
        ) -> Result<SettlementResult, SettlementError> {
            Ok(SettlementResult {
                hub: request.hub,
                batch_id: request.batch.batch_id,
                l1_reference: "dummy".to_string(),
                finalised: true,
            })
        }
    }

    #[test]
    fn fin_hub_engine_submits_batch() {
        let client = DummyClient;
        let engine = FinHubEngine::new(client);
        let txs = vec![
            FinTransaction {
                payload: vec![1, 2, 3],
            },
            FinTransaction {
                payload: vec![4, 5, 6],
            },
        ];

        let batch_id = L2BatchId("batch-001".to_string());
        let fee = FixedAmount::from_units(1, 6); // 1.000000

        let result = engine.submit_batch(batch_id.clone(), &txs, fee).unwrap();
        assert_eq!(result.hub, HUB_ID);
        assert_eq!(result.batch_id.0, batch_id.0);
        assert!(result.finalised);
    }
}
