use base64::Engine as _;
use fin_node::fin_api::FinApi;
use hub_fin::{FinActionRequestV1, FinStore};
use l2_core::l1_contract::{mock_client::MockL1Client, IdempotencyKey, L1Client};
use std::path::PathBuf;
use std::sync::Arc;

fn decode_idempotency_key(b64url: &str) -> IdempotencyKey {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64url.as_bytes())
        .expect("base64url decode");
    assert_eq!(decoded.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    IdempotencyKey(out)
}

#[test]
fn fin_api_submit_create_asset_and_mint_updates_state_and_writes_receipts() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fin_db = tmp.path().join("fin_db");
    let receipts_dir = tmp.path().join("receipts");

    let l1 = Arc::new(MockL1Client::default());
    let store = FinStore::open(&fin_db).expect("open fin store");
    let api = FinApi::new(l1.clone(), store, receipts_dir.clone());

    // 1) Create asset
    let create_body = serde_json::json!({
        "type": "create_asset_v1",
        "name": "Example Euro Stablecoin",
        "symbol": "EURX",
        "issuer": "issuer-001",
        "decimals": 6,
        "metadata_uri": "https://example.com/eurx"
    });
    let create_req: FinActionRequestV1 = serde_json::from_value(create_body).expect("create req");
    let create = api
        .submit_action_obj(create_req.into_action())
        .expect("submit create");
    assert!(PathBuf::from(&create.receipt_path).exists());
    let asset_id = create.asset_id.clone().expect("asset_id");
    assert_eq!(create.local_apply_outcome, hub_fin::ApplyOutcome::Applied);

    // Asset query works
    let asset = api
        .get_asset(&asset_id)
        .expect("get asset")
        .expect("asset exists");
    assert_eq!(asset["symbol"], "EURX");

    // 2) Mint units
    let mint_body = serde_json::json!({
        "type": "mint_units_v1",
        "asset_id": asset_id,
        "to_account": "acc-alice",
        "amount": "20000000",
        "client_tx_id": "mint-001",
        "memo": "genesis allocation"
    });
    let mint_req: FinActionRequestV1 = serde_json::from_value(mint_body.clone()).expect("mint req");
    let mint = api
        .submit_action_obj(mint_req.into_action())
        .expect("submit mint");
    assert!(PathBuf::from(&mint.receipt_path).exists());
    assert_eq!(mint.local_apply_outcome, hub_fin::ApplyOutcome::Applied);

    // Balance query works
    let bal = api
        .get_balance(mint.asset_id.as_deref().unwrap(), "acc-alice")
        .expect("get balance");
    assert_eq!(bal, "20000000");

    // Receipt query works
    let receipt_raw = api
        .get_receipt(&mint.action_id)
        .expect("get receipt")
        .expect("receipt exists");
    let receipt: serde_json::Value = serde_json::from_slice(&receipt_raw).expect("receipt json");
    assert_eq!(receipt["schema_version"], 2);
    assert_eq!(receipt["action_id"], mint.action_id);

    // L1 submit was called (mock inclusion exists).
    let key = decode_idempotency_key(&mint.idempotency_key);
    let inclusion = l1.get_inclusion(&key).expect("get inclusion");
    assert!(inclusion.is_some());

    // 3) Replay same mint => already applied + already known at L1.
    let mint_req2: FinActionRequestV1 = serde_json::from_value(mint_body).expect("mint req2");
    let mint2 = api
        .submit_action_obj(mint_req2.into_action())
        .expect("submit mint replay");
    assert_eq!(
        mint2.local_apply_outcome,
        hub_fin::ApplyOutcome::AlreadyApplied
    );
    assert!(mint2.l1_submit_result.already_known);
}
