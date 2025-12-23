use hub_fin::canonical::canonical_json_bytes;
use hub_fin::{apply, ApplyOutcome, FinActionV1, FinEnvelopeV1, FinStore};
use hub_fin::{AmountU128, MintUnitsV1};
use l2_core::AccountId;

fn fixture(path: &str) -> String {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(path);
    let s = std::fs::read_to_string(root).expect("read fixture");
    s.trim_end_matches(['\n', '\r']).to_string()
}

#[test]
fn golden_create_asset_v1_action_and_envelope_bytes_are_stable() {
    let action_json = fixture("create_asset_v1.action.canon.json");
    let env_json = fixture("create_asset_v1.envelope.canon.json");
    let expected_id = fixture("create_asset_v1.action_id.hex");

    let action: FinActionV1 = serde_json::from_str(&action_json).expect("parse action");
    let action_bytes = canonical_json_bytes(&action).expect("canonical bytes");
    assert_eq!(action_bytes, action_json.as_bytes());

    let got_id = hex::encode(blake3::hash(&action_bytes).as_bytes());
    assert_eq!(got_id, expected_id);

    let env = FinEnvelopeV1::new(action).expect("env");
    assert_eq!(env.action_id.to_hex(), expected_id);
    let env_bytes = env.canonical_bytes().expect("env bytes");
    assert_eq!(env_bytes, env_json.as_bytes());
}

#[test]
fn golden_mint_units_v1_action_and_envelope_bytes_are_stable() {
    let action_json = fixture("mint_units_v1.action.canon.json");
    let env_json = fixture("mint_units_v1.envelope.canon.json");
    let expected_id = fixture("mint_units_v1.action_id.hex");

    let action: FinActionV1 = serde_json::from_str(&action_json).expect("parse action");
    let action_bytes = canonical_json_bytes(&action).expect("canonical bytes");
    assert_eq!(action_bytes, action_json.as_bytes());

    let got_id = hex::encode(blake3::hash(&action_bytes).as_bytes());
    assert_eq!(got_id, expected_id);

    let env = FinEnvelopeV1::new(action).expect("env");
    assert_eq!(env.action_id.to_hex(), expected_id);
    let env_bytes = env.canonical_bytes().expect("env bytes");
    assert_eq!(env_bytes, env_json.as_bytes());
}

#[test]
fn golden_transfer_units_v1_action_and_envelope_bytes_are_stable() {
    let action_json = fixture("transfer_units_v1.action.canon.json");
    let env_json = fixture("transfer_units_v1.envelope.canon.json");
    let expected_id = fixture("transfer_units_v1.action_id.hex");

    let action: FinActionV1 = serde_json::from_str(&action_json).expect("parse action");
    let action_bytes = canonical_json_bytes(&action).expect("canonical bytes");
    assert_eq!(action_bytes, action_json.as_bytes());

    let got_id = hex::encode(blake3::hash(&action_bytes).as_bytes());
    assert_eq!(got_id, expected_id);

    let env = FinEnvelopeV1::new(action).expect("env");
    assert_eq!(env.action_id.to_hex(), expected_id);
    let env_bytes = env.canonical_bytes().expect("env bytes");
    assert_eq!(env_bytes, env_json.as_bytes());
}

#[test]
fn apply_is_idempotent_and_updates_balances() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = FinStore::open(tmp.path()).expect("open store");

    // Apply CREATE_ASSET
    let create_action: FinActionV1 =
        serde_json::from_str(&fixture("create_asset_v1.action.canon.json")).unwrap();
    let create_env = FinEnvelopeV1::new(create_action).unwrap();
    let r1 = apply(&create_env, &store).expect("apply create");
    assert_eq!(r1.outcome, ApplyOutcome::Applied);

    let r2 = apply(&create_env, &store).expect("replay create");
    assert_eq!(r2.outcome, ApplyOutcome::AlreadyApplied);

    // Apply MINT_UNITS
    let mint_action: FinActionV1 =
        serde_json::from_str(&fixture("mint_units_v1.action.canon.json")).unwrap();
    let mint_env = FinEnvelopeV1::new(mint_action).unwrap();
    let r3 = apply(&mint_env, &store).expect("apply mint");
    assert_eq!(r3.outcome, ApplyOutcome::Applied);

    // Balance updated
    let asset_id = r3.asset_id.unwrap();
    let account = r3.to_account.unwrap();
    let bal = store
        .get_balance(asset_id, &account.0)
        .expect("get balance");
    assert_eq!(bal, AmountU128(20_000_000));

    // Replay mint is idempotent
    let r4 = apply(&mint_env, &store).expect("replay mint");
    assert_eq!(r4.outcome, ApplyOutcome::AlreadyApplied);
    let bal2 = store.get_balance(asset_id, &account.0).unwrap();
    assert_eq!(bal2, AmountU128(20_000_000));

    // Apply TRANSFER_UNITS (alice -> bob)
    let transfer_action: FinActionV1 =
        serde_json::from_str(&fixture("transfer_units_v1.action.canon.json")).unwrap();
    let transfer_env = FinEnvelopeV1::new(transfer_action).unwrap();

    // Seed alice balance (from mint fixture).
    let r5 = apply(&transfer_env, &store).expect("apply transfer");
    assert_eq!(r5.outcome, ApplyOutcome::Applied);

    let alice = AccountId::new("acc-alice");
    let bob = AccountId::new("acc-bob");
    let bal_alice = store.get_balance(asset_id, &alice.0).unwrap();
    let bal_bob = store.get_balance(asset_id, &bob.0).unwrap();
    assert_eq!(bal_alice, AmountU128(15_000_000));
    assert_eq!(bal_bob, AmountU128(5_000_000));

    // Replay transfer is idempotent (no double charge).
    let r6 = apply(&transfer_env, &store).expect("replay transfer");
    assert_eq!(r6.outcome, ApplyOutcome::AlreadyApplied);
    let bal_alice2 = store.get_balance(asset_id, &alice.0).unwrap();
    let bal_bob2 = store.get_balance(asset_id, &bob.0).unwrap();
    assert_eq!(bal_alice2, AmountU128(15_000_000));
    assert_eq!(bal_bob2, AmountU128(5_000_000));
}

#[test]
fn mint_overflow_is_rejected_and_not_marked_applied() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = FinStore::open(tmp.path()).expect("open store");

    // Create asset
    let create_action: FinActionV1 =
        serde_json::from_str(&fixture("create_asset_v1.action.canon.json")).unwrap();
    let create_env = FinEnvelopeV1::new(create_action).unwrap();
    apply(&create_env, &store).unwrap();
    let asset_id = create_env.action.clone().into_create_asset().asset_id;

    // Set balance to max-1
    store
        .set_balance(asset_id, "acc-alice", AmountU128(u128::MAX - 1))
        .unwrap();

    let mint = MintUnitsV1 {
        asset_id,
        to_account: AccountId::new("acc-alice"),
        amount: AmountU128(2),
        actor: Some(AccountId::new("issuer-001")),
        client_tx_id: "overflow-001".to_string(),
        memo: None,
    };
    let env = FinEnvelopeV1::new(FinActionV1::MintUnitsV1(mint)).unwrap();

    let err = apply(&env, &store).unwrap_err().to_string();
    assert!(err.contains("overflow"), "{err}");
    assert!(!store.is_applied(env.action_id).unwrap());
}

// Small helper for extracting inner types in tests without exposing extra API.
trait IntoCreateAsset {
    fn into_create_asset(self) -> hub_fin::CreateAssetV1;
}
impl IntoCreateAsset for FinActionV1 {
    fn into_create_asset(self) -> hub_fin::CreateAssetV1 {
        match self {
            FinActionV1::CreateAssetV1(a) => a,
            _ => panic!("expected create asset action"),
        }
    }
}
