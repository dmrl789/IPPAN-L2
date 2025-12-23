#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

use clap::Parser;
use hub_fin::{
    AccountState, FinHubEngine, FinOperation, FinState, FinTransaction, InMemoryFinStateStore, HUB_ID,
};
use l2_core::{
    l1_contract::{
        http_client::{HttpL1Client, L1RpcConfig},
        mock_client::MockL1Client,
        L1Client, L2BatchEnvelopeV1,
    },
    AccountId, AssetId, FixedAmount, L2BatchId,
};
use std::collections::BTreeMap;
use std::fs;

/// Simple dummy IPPAN FIN Hub node.
///
/// This is a placeholder binary that builds a batch and "submits" it
/// to a dummy L1 client, printing the result as JSON.
#[derive(Parser, Debug)]
#[command(author, version, about = "IPPAN FIN Hub (dev stub)")]
struct Args {
    /// L1 mode:
    /// - mock: offline deterministic mock client (default)
    /// - http: real HTTP adapter (requires endpoint map in config)
    #[arg(long, value_enum, default_value_t = L1Mode::Mock)]
    l1_mode: L1Mode,

    /// Print L1 chain status (smoke path) and exit.
    #[arg(long, default_value_t = false)]
    smoke_l1: bool,

    /// Submit a prebuilt contract envelope (v1) JSON file to L1 and exit.
    #[arg(long)]
    submit_batch: Option<String>,

    /// Batch identifier to use for the demo batch.
    #[arg(long, default_value = "demo-batch-001")]
    batch_id: String,

    /// Monotonic sequence number for the demo batch envelope.
    #[arg(long, default_value_t = 0)]
    sequence: u64,

    /// Path to a TOML config file describing the L1 endpoint (optional).
    #[arg(long)]
    config: Option<String>,

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

#[derive(Debug, serde::Deserialize)]
struct FinNodeConfig {
    #[serde(default)]
    pub l1: Option<L1RpcConfig>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum L1Mode {
    Mock,
    Http,
}

fn resolve_env_refs(mut v: toml::Value) -> Result<toml::Value, String> {
    fn walk(v: &mut toml::Value) -> Result<(), String> {
        match v {
            toml::Value::String(s) => {
                if let Some(var) = s.strip_prefix("env:") {
                    let var = var.trim();
                    if var.is_empty() {
                        return Err("invalid env: reference (empty var name)".to_string());
                    }
                    let val = std::env::var(var)
                        .map_err(|_| format!("missing required environment variable: {var}"))?;
                    *s = val;
                }
            }
            toml::Value::Array(arr) => {
                for x in arr {
                    walk(x)?;
                }
            }
            toml::Value::Table(map) => {
                for (_, x) in map.iter_mut() {
                    walk(x)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    walk(&mut v)?;
    Ok(v)
}

fn load_config(path: &str) -> Result<FinNodeConfig, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("failed to read config {path}: {e}"))?;
    let parsed: toml::Value =
        toml::from_str(&raw).map_err(|e| format!("failed to parse config {path}: {e}"))?;
    let resolved = resolve_env_refs(parsed)?;
    resolved
        .try_into::<FinNodeConfig>()
        .map_err(|e| format!("failed to decode config {path}: {e}"))
}

fn main() {
    let args = Args::parse();

    let cfg = args
        .config
        .as_deref()
        .map(load_config)
        .transpose()
        .expect("failed to load config");

    let client: Box<dyn L1Client> = match args.l1_mode {
        L1Mode::Mock => Box::new(MockL1Client::default()),
        L1Mode::Http => {
            let l1 = cfg
                .as_ref()
                .and_then(|c| c.l1.clone())
                .expect("missing [l1] config for --l1-mode http");
            Box::new(HttpL1Client::new(l1).expect("invalid L1 HTTP config"))
        }
    };

    if args.smoke_l1 {
        let status = client.chain_status().expect("chain_status");
        println!("{}", serde_json::to_string_pretty(&status).unwrap());
        return;
    }

    if let Some(path) = args.submit_batch.as_deref() {
        let raw = fs::read_to_string(path).expect("failed to read batch file");
        let env: L2BatchEnvelopeV1 = serde_json::from_str(&raw).expect("invalid L2BatchEnvelopeV1 JSON");
        env.validate().expect("envelope validation failed");
        let result = client.submit_batch(&env).expect("submit_batch");
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        return;
    }

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
    let engine = FinHubEngine::new(store);

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

    let env = engine
        .build_batch_envelope_v1(batch_id.clone(), args.sequence, &txs, fee)
        .expect("build_batch_envelope_v1");

    let submit = client.submit_batch(&env).expect("submit_batch");

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
        "idempotency_key": env.idempotency_key,
        "l1": submit,
        "asset_id": asset_id.0,
        "decimals": args.decimals,
        "balances": {
            from_account.0: from_balance_scaled,
            to_account.0: to_balance_scaled,
        }
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
