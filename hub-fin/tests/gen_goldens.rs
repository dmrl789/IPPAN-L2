use hub_fin::canonical::canonical_json_bytes;
use hub_fin::{AmountU128, Hex32};
use hub_fin::{CreateAssetV1, MintUnitsV1, TransferUnitsV1};
use hub_fin::{FinActionV1, FinEnvelopeV1};
use l2_core::AccountId;

// Helper test to print canonical bytes + hashes for fixtures.
// Run with: `cargo test -p hub-fin --test gen_goldens -- --ignored --nocapture`
#[test]
#[ignore]
fn print_goldens() {
    let create = CreateAssetV1 {
        asset_id: hub_fin::validation::derive_asset_id(
            "Example Euro Stablecoin",
            "issuer-001",
            "EURX",
        ),
        name: "Example Euro Stablecoin".to_string(),
        symbol: "EURX".to_string(),
        issuer: "issuer-001".to_string(),
        decimals: 6,
        metadata_uri: Some("https://example.com/eurx".to_string()),
    };
    let create_action = FinActionV1::CreateAssetV1(create.clone());
    let create_env = FinEnvelopeV1::new(create_action.clone()).unwrap();

    let mint = MintUnitsV1 {
        asset_id: create.asset_id,
        to_account: AccountId::new("acc-alice"),
        amount: AmountU128(20_000_000),
        client_tx_id: "mint-001".to_string(),
        memo: Some("genesis allocation".to_string()),
    };
    let mint_action = FinActionV1::MintUnitsV1(mint.clone());
    let mint_env = FinEnvelopeV1::new(mint_action.clone()).unwrap();

    let transfer = TransferUnitsV1 {
        asset_id: create.asset_id,
        from_account: AccountId::new("acc-alice"),
        to_account: AccountId::new("acc-bob"),
        amount: AmountU128(5_000_000),
        client_tx_id: "pay-001".to_string(),
        memo: Some("payment".to_string()),
        purchase_id: None,
    };
    let transfer_action = FinActionV1::TransferUnitsV1(transfer.clone());
    let transfer_env = FinEnvelopeV1::new(transfer_action.clone()).unwrap();

    for (label, action, env) in [
        ("create_asset_v1", create_action.clone(), create_env.clone()),
        ("mint_units_v1", mint_action, mint_env),
        ("transfer_units_v1", transfer_action, transfer_env),
    ] {
        let action_bytes = canonical_json_bytes(&action).unwrap();
        let action_hash = blake3::hash(&action_bytes);
        let env_bytes = env.canonical_bytes().unwrap();
        let env_hash = blake3::hash(&env_bytes);

        println!("== {label} ==");
        println!("action_id_hex={}", hex::encode(action_hash.as_bytes()));
        println!("envelope_action_id_hex={}", env.action_id.to_hex());
        println!(
            "action_canonical_json={}",
            String::from_utf8(action_bytes).unwrap()
        );
        println!(
            "envelope_canonical_json={}",
            String::from_utf8(env_bytes).unwrap()
        );
        println!("envelope_hash_hex={}", hex::encode(env_hash.as_bytes()));
        println!();
    }

    // quick sanity: action hash equals envelope action_id
    let bytes = canonical_json_bytes(&create_action).unwrap();
    let mut id = [0u8; 32];
    id.copy_from_slice(blake3::hash(&bytes).as_bytes());
    assert_eq!(Hex32(id), create_env.action_id);
}
