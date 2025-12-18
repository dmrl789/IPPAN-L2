#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

use clap::Parser;
use hub_fin::{
    AccountState, FinHubEngine, FinOperation, FinState, FinTransaction, InMemoryFinStateStore,
    HUB_ID,
};
use l2_core::{
    AccountId, AssetId, FixedAmount, L1SettlementClient, L2BatchId, SettlementError,
    SettlementRequest, SettlementResult,
};
use std::collections::BTreeMap;

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

    /// Asset identifier to register and use for the transfer.
    #[arg(long, default_value = "asset-demo-eurx")]
    asset_id: String,

    /// Asset symbol (e.g. EURX).
    #[arg(long, default_value = "EURX")]
    symbol: String,

    /// Asset display name (e.g. Demo EUR Stablecoin).
    #[arg(long, default_value = "Demo EUR Stablecoin")]
    name: String,

    /// Asset decimals (integer, deterministic).
    #[arg(long, default_value_t = 6)]
    decimals: u8,

    /// Sender account identifier.
    #[arg(long, default_value = "acc-alice")]
    from: String,

    /// Recipient account identifier.
    #[arg(long, default_value = "acc-bob")]
    to: String,

    /// Transfer amount in integral units (deterministic integer).
    #[arg(long, default_value_t = 10)]
    amount: i128,
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
    let asset = AssetId::new(args.asset_id.clone());
    let from = AccountId::new(args.from.clone());
    let to = AccountId::new(args.to.clone());
    let transfer_amount = FixedAmount::from_units(args.amount, u32::from(args.decimals));

    // Seed initial state with a sender balance so the demo transfer can succeed
    // without minting (the demo batch intentionally uses only Register+Transfer).
    let mut seeded = FinState::default();
    let mut balances = BTreeMap::new();
    balances.insert(asset.clone(), transfer_amount);
    seeded.accounts.insert(
        from.clone(),
        AccountState {
            balances: balances.clone(),
        },
    );
    let store = InMemoryFinStateStore::with_state(seeded);
    let engine = FinHubEngine::new(client, store);

    let txs = vec![
        FinTransaction {
            tx_id: "tx-register".to_string(),
            op: FinOperation::RegisterFungibleAsset {
                asset_id: asset.clone(),
                symbol: args.symbol.clone(),
                name: args.name.clone(),
                decimals: args.decimals,
            },
        },
        FinTransaction {
            tx_id: "tx-transfer".to_string(),
            op: FinOperation::Transfer {
                asset_id: asset,
                from,
                to,
                amount: transfer_amount,
            },
        },
    ];

    let batch_id = L2BatchId(args.batch_id);
    let fee = FixedAmount::from_units(1, 6);

    let result = engine
        .submit_batch(batch_id.clone(), &txs, fee)
        .expect("settlement");

    let state = engine.snapshot_state();
    let from_account = AccountId::new(args.from);
    let to_account = AccountId::new(args.to);
    let asset_id = AssetId::new(args.asset_id);

    let from_balance_scaled = state
        .accounts
        .get(&from_account)
        .and_then(|acc| acc.balances.get(&asset_id))
        .map(|a| a.into_scaled())
        .unwrap_or(0);
    let to_balance_scaled = state
        .accounts
        .get(&to_account)
        .and_then(|acc| acc.balances.get(&asset_id))
        .map(|a| a.into_scaled())
        .unwrap_or(0);

    let output = serde_json::json!({
        "hub": format!("{:?}", HUB_ID),
        "batch_id": batch_id.0,
        "l1_reference": result.l1_reference,
        "finalised": result.finalised,
        "asset_id": asset_id.0,
        "decimals": args.decimals,
        "balances": {
            from_account.0: from_balance_scaled,
            to_account.0: to_balance_scaled,
        }
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
