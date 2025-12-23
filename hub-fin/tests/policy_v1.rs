use hub_fin::{apply_with_policy, AmountU128, CreateAssetV1, FinActionV1, FinEnvelopeV1, FinStore};
use hub_fin::{MintPolicyV1, MintUnitsV1, TransferPolicyV1, TransferUnitsV1};
use l2_core::policy::PolicyMode;
use l2_core::AccountId;

fn create_asset(asset_issuer: &AccountId) -> CreateAssetV1 {
    CreateAssetV1 {
        asset_id: hub_fin::validation::derive_asset_id("X", asset_issuer, "X"),
        name: "X".to_string(),
        symbol: "X".to_string(),
        issuer: asset_issuer.clone(),
        decimals: 6,
        metadata_uri: None,
        actor: Some(asset_issuer.clone()),
        mint_policy: MintPolicyV1::IssuerOnly,
        transfer_policy: TransferPolicyV1::Free,
    }
}

#[test]
fn strict_create_asset_requires_actor_and_matches_issuer() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = FinStore::open(tmp.path()).expect("open store");

    let issuer = AccountId::new("issuer-001");
    let mut asset = create_asset(&issuer);
    asset.actor = Some(AccountId::new("acc-mallory"));
    let env = FinEnvelopeV1::new(FinActionV1::CreateAssetV1(asset)).unwrap();

    let err = apply_with_policy(&env, &store, PolicyMode::Strict, &[])
        .unwrap_err()
        .to_string();
    assert!(err.contains("policy:unauthorized"), "{err}");
}

#[test]
fn strict_mint_respects_issuer_only_policy() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = FinStore::open(tmp.path()).expect("open store");
    let issuer = AccountId::new("issuer-001");

    // create asset
    let create_env = FinEnvelopeV1::new(FinActionV1::CreateAssetV1(create_asset(&issuer))).unwrap();
    apply_with_policy(&create_env, &store, PolicyMode::Strict, &[]).unwrap();
    let asset_id = match create_env.action {
        FinActionV1::CreateAssetV1(a) => a.asset_id,
        _ => unreachable!(),
    };

    // mint by non-issuer
    let mint = MintUnitsV1 {
        asset_id,
        to_account: AccountId::new("acc-alice"),
        amount: AmountU128(1),
        actor: Some(AccountId::new("acc-mallory")),
        client_tx_id: "m-001".to_string(),
        memo: None,
    };

    let env = FinEnvelopeV1::new(FinActionV1::MintUnitsV1(mint)).unwrap();
    let err = apply_with_policy(&env, &store, PolicyMode::Strict, &[])
        .unwrap_err()
        .to_string();
    assert!(err.contains("policy:unauthorized"), "{err}");
}

#[test]
fn strict_transfer_requires_delegation_for_operator() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = FinStore::open(tmp.path()).expect("open store");
    let issuer = AccountId::new("issuer-001");

    // create asset
    let create_env = FinEnvelopeV1::new(FinActionV1::CreateAssetV1(create_asset(&issuer))).unwrap();
    apply_with_policy(&create_env, &store, PolicyMode::Strict, &[]).unwrap();
    let asset_id = match create_env.action {
        FinActionV1::CreateAssetV1(a) => a.asset_id,
        _ => unreachable!(),
    };

    // seed balance for from_account
    let from = AccountId::new("acc-alice");
    store
        .set_balance(asset_id, &from.0, AmountU128(10))
        .unwrap();

    let operator = AccountId::new("acc-operator");
    let to = AccountId::new("acc-bob");
    let transfer = TransferUnitsV1 {
        asset_id,
        from_account: from.clone(),
        to_account: to,
        amount: AmountU128(1),
        actor: Some(operator.clone()),
        client_tx_id: "t-001".to_string(),
        memo: None,
        purchase_id: None,
    };
    let env = FinEnvelopeV1::new(FinActionV1::TransferUnitsV1(transfer.clone())).unwrap();
    let err = apply_with_policy(&env, &store, PolicyMode::Strict, &[])
        .unwrap_err()
        .to_string();
    assert!(err.contains("policy:delegation_required"), "{err}");

    // grant delegation and retry
    store
        .set_delegation(&from.0, &operator.0, asset_id)
        .unwrap();
    let env2 = FinEnvelopeV1::new(FinActionV1::TransferUnitsV1(transfer)).unwrap();
    let r = apply_with_policy(&env2, &store, PolicyMode::Strict, &[]).unwrap();
    assert_eq!(r.outcome, hub_fin::ApplyOutcome::Applied);
}
