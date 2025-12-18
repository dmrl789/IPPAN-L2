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

use serde::{Deserialize, Serialize};

use l2_core::{
    AccountId, AssetId, FixedAmount, L1SettlementClient, L2Batch, L2BatchId, L2HubId,
    SettlementError, SettlementRequest, SettlementResult,
};

/// Logical identifier used for IPPAN FIN batches.
pub const HUB_ID: L2HubId = L2HubId::Fin;

/// High-level financial operation supported by the FIN Hub.
///
/// This enum is intentionally minimal and will be expanded with
/// richer semantics as the tokenisation layer matures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FinOperation {
    /// Register a new fungible asset (e.g., tokenised fund, bond, stablecoin).
    RegisterFungibleAsset {
        asset_id: AssetId,
        symbol: String,
        name: String,
        decimals: u8,
    },

    /// Mint new units of a fungible asset to a target account.
    Mint {
        asset_id: AssetId,
        to: AccountId,
        amount: FixedAmount,
    },

    /// Burn units of a fungible asset from a target account.
    Burn {
        asset_id: AssetId,
        from: AccountId,
        amount: FixedAmount,
    },

    /// Transfer units of a fungible asset between two accounts.
    Transfer {
        asset_id: AssetId,
        from: AccountId,
        to: AccountId,
        amount: FixedAmount,
    },
}

/// Represents a FIN transaction as it will be included in a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinTransaction {
    /// Opaque identifier for the transaction, unique within the hub context.
    pub tx_id: String,
    /// The operation to be executed.
    pub op: FinOperation,
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

        let asset = AssetId::new("asset-eur-stable");
        let from = AccountId::new("acc-alice");
        let to = AccountId::new("acc-bob");

        let txs = vec![
            FinTransaction {
                tx_id: "tx-1".to_string(),
                op: FinOperation::RegisterFungibleAsset {
                    asset_id: asset.clone(),
                    symbol: "EURX".to_string(),
                    name: "Example Euro Stablecoin".to_string(),
                    decimals: 6,
                },
            },
            FinTransaction {
                tx_id: "tx-2".to_string(),
                op: FinOperation::Transfer {
                    asset_id: asset.clone(),
                    from,
                    to,
                    amount: FixedAmount::from_units(10, 6), // 10.000000
                },
            },
        ];

        let batch_id = L2BatchId("batch-001".to_string());
        let fee = FixedAmount::from_units(1, 6); // 1.000000

        let result = engine.submit_batch(batch_id.clone(), &txs, fee).unwrap();
        assert_eq!(result.hub, HUB_ID);
        assert_eq!(result.batch_id.0, batch_id.0);
        assert!(result.finalised);
    }

    #[test]
    fn fin_transaction_serializes_to_json() {
        let asset = AssetId::new("asset-eur-stable");
        let tx = FinTransaction {
            tx_id: "tx-serialize".to_string(),
            op: FinOperation::Mint {
                asset_id: asset,
                to: AccountId::new("acc-alice"),
                amount: FixedAmount::from_units(5, 6),
            },
        };

        let json = serde_json::to_string(&tx).expect("serialize");
        assert!(json.contains("tx-serialize"));
    }
}
