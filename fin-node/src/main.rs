#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

use clap::Parser;
use hub_fin::{FinHubEngine, FinOperation, FinTransaction, InMemoryFinStateStore, HUB_ID};
use l2_core::{
    AccountId, AssetId, FixedAmount, L1SettlementClient, L2BatchId, SettlementError,
    SettlementRequest, SettlementResult,
};

/// Simple dummy IPPAN FIN Hub node.
///
/// This is a placeholder binary that builds a batch and "submits" it
/// to a dummy L1 client, printing the result as JSON.
#[derive(Parser, Debug)]
#[command(author, version, about = "IPPAN FIN Hub (dev stub)")]
struct Args {
    /// Batch identifier to use for the demo batch.
    #[arg(long, default_value = "demo-batch-001")]
    batch_id: String,
}

/// Dummy L1 client that simulates successful settlement.
struct DummyL1Client;

impl L1SettlementClient for DummyL1Client {
    fn submit_settlement(
        &self,
        request: SettlementRequest,
    ) -> Result<SettlementResult, SettlementError> {
        let batch_id = request.batch.batch_id;
        Ok(SettlementResult {
            hub: request.hub,
            batch_id,
            l1_reference: "dummy-l1-tx".to_string(),
            finalised: true,
        })
    }
}

fn main() {
    let args = Args::parse();

    let client = DummyL1Client;
    let store = InMemoryFinStateStore::new();
    // TODO: expose read-only state snapshots from FinHubEngine so the node
    // can print post-batch balances for debugging.
    let engine = FinHubEngine::new(client, store);

    let asset = AssetId::new("asset-demo-eurx");
    let from = AccountId::new("acc-alice");
    let to = AccountId::new("acc-bob");

    let txs = vec![
        FinTransaction {
            tx_id: "tx-register".to_string(),
            op: FinOperation::RegisterFungibleAsset {
                asset_id: asset.clone(),
                symbol: "EURX".to_string(),
                name: "Demo EUR Stablecoin".to_string(),
                decimals: 6,
            },
        },
        FinTransaction {
            tx_id: "tx-mint".to_string(),
            op: FinOperation::Mint {
                asset_id: asset.clone(),
                to: from.clone(),
                amount: FixedAmount::from_units(20, 6),
            },
        },
        FinTransaction {
            tx_id: "tx-transfer".to_string(),
            op: FinOperation::Transfer {
                asset_id: asset,
                from,
                to,
                amount: FixedAmount::from_units(10, 6),
            },
        },
    ];

    let batch_id = L2BatchId(args.batch_id);
    let fee = FixedAmount::from_units(1, 6);

    let result = engine
        .submit_batch(batch_id.clone(), &txs, fee)
        .expect("settlement");

    let output = serde_json::json!({
        "hub": format!("{:?}", HUB_ID),
        "batch_id": batch_id.0,
        "l1_reference": result.l1_reference,
        "finalised": result.finalised,
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
