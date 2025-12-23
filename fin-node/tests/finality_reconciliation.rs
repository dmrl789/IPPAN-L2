use fin_node::data_api::DataApi;
use fin_node::fin_api::FinApi;
use fin_node::linkage::{BuyLicenseRequestV1, LinkageApi};
use fin_node::policy_runtime::PolicyRuntime;
use fin_node::recon::{ReconLoopConfig, Reconciler};
use fin_node::recon_store::ReconStore;
use hub_data::{
    CreateListingRequestV1, LicenseRightsV1, PriceMicrounitsU128, RegisterDatasetRequestV1,
};
use hub_fin::{AmountU128, CreateAssetV1, FinActionV1, MintUnitsV1};
use l2_core::hub_linkage::{EntitlementPolicy, LinkageOverallStatus};
use l2_core::l1_contract::mock_client::MockL1Client;
use l2_core::AccountId;
use std::sync::Arc;

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn setup(
    policy: EntitlementPolicy,
) -> (
    tempfile::TempDir,
    Arc<MockL1Client>,
    FinApi,
    hub_fin::FinStore,
    DataApi,
    hub_data::DataStore,
    LinkageApi,
    ReconStore,
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let receipts = tmp.path().join("receipts");
    let fin_db = tmp.path().join("fin_db");
    let data_db = tmp.path().join("data_db");
    let recon_db = tmp.path().join("recon_db");

    let l1 = Arc::new(MockL1Client::default());
    let recon = ReconStore::open(&recon_db).expect("recon store");

    let fin_store = hub_fin::FinStore::open(&fin_db).expect("fin store");
    let data_store = hub_data::DataStore::open(&data_db).expect("data store");
    let pr = PolicyRuntime::default();

    let fin_api = FinApi::new_with_policy_and_recon(
        l1.clone(),
        fin_store.clone(),
        receipts.clone(),
        pr.clone(),
        Some(recon.clone()),
    );
    let data_api = DataApi::new_with_policy_and_recon(
        l1.clone(),
        data_store.clone(),
        receipts.clone(),
        pr,
        Some(recon.clone()),
    );
    let linkage_api = LinkageApi::new_with_policy_and_recon(
        fin_api.clone(),
        data_api.clone(),
        receipts,
        policy,
        Some(recon.clone()),
    );

    (
        tmp,
        l1,
        fin_api,
        fin_store,
        data_api,
        data_store,
        linkage_api,
        recon,
    )
}

fn bootstrap_asset_and_balance(fin_api: &FinApi, buyer: &AccountId) -> hub_fin::Hex32 {
    let issuer = AccountId::new("issuer-001");
    let asset_id = hub_fin::validation::derive_asset_id("Example Euro Stablecoin", &issuer, "EURX");
    let create = CreateAssetV1 {
        asset_id,
        name: "Example Euro Stablecoin".to_string(),
        symbol: "EURX".to_string(),
        issuer: issuer.clone(),
        decimals: 6,
        metadata_uri: None,
        actor: Some(issuer.clone()),
        mint_policy: hub_fin::MintPolicyV1::IssuerOnly,
        transfer_policy: hub_fin::TransferPolicyV1::Free,
    };
    fin_api
        .submit_action_obj(FinActionV1::CreateAssetV1(create))
        .expect("create asset");

    let mint = MintUnitsV1 {
        asset_id,
        to_account: buyer.clone(),
        amount: AmountU128(2_000_000),
        actor: Some(issuer),
        client_tx_id: "mint-001".to_string(),
        memo: None,
    };
    fin_api
        .submit_action_obj(FinActionV1::MintUnitsV1(mint))
        .expect("mint");

    asset_id
}

fn bootstrap_dataset_and_listing(
    data_api: &DataApi,
    seller: &AccountId,
    currency_asset_id: hub_fin::Hex32,
) -> (hub_data::Hex32, hub_data::Hex32) {
    let reg = data_api
        .submit_register_dataset(RegisterDatasetRequestV1 {
            owner: seller.clone(),
            name: "Example Dataset v1".to_string(),
            description: None,
            content_hash: hub_data::Hex32::from_hex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            )
            .unwrap(),
            pointer_uri: None,
            mime_type: None,
            tags: vec![],
            schema_version: 1,
            attestation_policy: hub_data::AttestationPolicyV1::Anyone,
        })
        .expect("register dataset");
    let dataset_id_hex = reg.dataset_id.expect("dataset_id");
    let dataset_id = hub_data::Hex32::from_hex(&dataset_id_hex).unwrap();

    let listing = data_api
        .submit_create_listing(CreateListingRequestV1 {
            dataset_id,
            licensor: seller.clone(),
            rights: LicenseRightsV1::Use,
            price_microunits: PriceMicrounitsU128(1_000_000),
            currency_asset_id: hub_data::Hex32(currency_asset_id.0),
            terms_uri: Some("https://example.com/terms/v1".to_string()),
            terms_hash: Some(
                hub_data::Hex32::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
            ),
        })
        .expect("create listing");
    let listing_id_hex = listing.listing_id.expect("listing_id");
    let listing_id = hub_data::Hex32::from_hex(&listing_id_hex).unwrap();

    (dataset_id, listing_id)
}

#[test]
fn optimistic_linkage_grants_entitlement_immediately() {
    let (_tmp, _l1, fin_api, _fin_store, data_api, data_store, linkage_api, _recon) =
        setup(EntitlementPolicy::Optimistic);
    let buyer = AccountId::new("acc-buyer");
    let seller = AccountId::new("acc-seller");

    let currency_asset_id = bootstrap_asset_and_balance(&fin_api, &buyer);
    let (dataset_id, listing_id) =
        bootstrap_dataset_and_listing(&data_api, &seller, currency_asset_id);

    let r = linkage_api
        .buy_license(BuyLicenseRequestV1 {
            dataset_id,
            listing_id,
            buyer_account: buyer.clone(),
            nonce: Some("nonce-opt-001".to_string()),
            memo: None,
        })
        .expect("buy");

    assert_eq!(r.overall_status, LinkageOverallStatus::EntitledFinal);
    assert!(r.entitlement_ref.is_some());

    let ent = data_store.get_entitlement(r.purchase_id).unwrap();
    assert!(ent.is_some());
}

#[test]
fn finality_required_linkage_gates_entitlement_until_payment_final() {
    let (_tmp, l1, fin_api, _fin_store, data_api, _data_store, linkage_api, recon) =
        setup(EntitlementPolicy::FinalityRequired);
    let buyer = AccountId::new("acc-buyer");
    let seller = AccountId::new("acc-seller");

    let currency_asset_id = bootstrap_asset_and_balance(&fin_api, &buyer);
    let (dataset_id, listing_id) =
        bootstrap_dataset_and_listing(&data_api, &seller, currency_asset_id);

    let mut r = linkage_api
        .buy_license(BuyLicenseRequestV1 {
            dataset_id,
            listing_id,
            buyer_account: buyer.clone(),
            nonce: Some("nonce-fin-001".to_string()),
            memo: None,
        })
        .expect("buy");

    assert_eq!(
        r.overall_status,
        LinkageOverallStatus::PaymentPendingFinality
    );
    assert!(r.payment_ref.is_some());
    assert!(r.entitlement_ref.is_none());

    // Stage payment inclusion/finality: 2 empty polls, then appears.
    let pay_key = match &r.payment_submit_state {
        l2_core::finality::SubmitState::Submitted {
            idempotency_key, ..
        } => idempotency_key.clone(),
        _ => panic!("expected payment SubmitState::Submitted"),
    };
    l1.set_staged_delays_b64(&pay_key, 2, 2)
        .expect("stage payment");

    let reconciler = Reconciler::new(
        l1.clone(),
        fin_api.clone(),
        data_api.clone(),
        linkage_api.clone(),
        recon.clone(),
        ReconLoopConfig {
            interval_secs: 1,
            batch_limit: 50,
            max_scan: 5_000,
            max_attempts: 100,
            base_delay_secs: 1,
            max_delay_secs: 10,
        },
    );

    let mut now = unix_now_secs();

    // Drive until entitlement gets submitted (payment finalized triggers continuation).
    for _ in 0..10 {
        reconciler.tick(now);
        now += 1;
        r = linkage_api
            .get_purchase_receipt(&r.purchase_id.to_hex())
            .unwrap()
            .unwrap();
        if r.overall_status == LinkageOverallStatus::EntitlementPendingFinality {
            break;
        }
    }
    assert_eq!(
        r.overall_status,
        LinkageOverallStatus::EntitlementPendingFinality
    );
    assert!(r.entitlement_ref.is_some());

    // Stage entitlement inclusion/finality.
    let ent_key = match &r.entitlement_submit_state {
        l2_core::finality::SubmitState::Submitted {
            idempotency_key, ..
        } => idempotency_key.clone(),
        _ => panic!("expected entitlement SubmitState::Submitted"),
    };
    l1.set_staged_delays_b64(&ent_key, 1, 1)
        .expect("stage entitlement");

    // Drive until fully final.
    for _ in 0..10 {
        reconciler.tick(now);
        now += 1;
        r = linkage_api
            .get_purchase_receipt(&r.purchase_id.to_hex())
            .unwrap()
            .unwrap();
        if r.overall_status == LinkageOverallStatus::EntitledFinal {
            break;
        }
    }

    assert_eq!(r.overall_status, LinkageOverallStatus::EntitledFinal);
    assert!(r.entitlement_ref.is_some());
}

#[test]
fn recon_is_restart_safe_for_finality_required() {
    let (tmp, l1, fin_api, fin_store, data_api, data_store, linkage_api, recon) =
        setup(EntitlementPolicy::FinalityRequired);
    let buyer = AccountId::new("acc-buyer");
    let seller = AccountId::new("acc-seller");

    let currency_asset_id = bootstrap_asset_and_balance(&fin_api, &buyer);
    let (dataset_id, listing_id) =
        bootstrap_dataset_and_listing(&data_api, &seller, currency_asset_id);

    let r = linkage_api
        .buy_license(BuyLicenseRequestV1 {
            dataset_id,
            listing_id,
            buyer_account: buyer.clone(),
            nonce: Some("nonce-restart-001".to_string()),
            memo: None,
        })
        .expect("buy");

    let pay_key = match &r.payment_submit_state {
        l2_core::finality::SubmitState::Submitted {
            idempotency_key, ..
        } => idempotency_key.clone(),
        _ => panic!("expected payment SubmitState::Submitted"),
    };
    l1.set_staged_delays_b64(&pay_key, 0, 0)
        .expect("stage payment immediate");

    // First tick: payment will finalize and entitlement will be submitted.
    let reconciler1 = Reconciler::new(
        l1.clone(),
        fin_api.clone(),
        data_api.clone(),
        linkage_api.clone(),
        recon.clone(),
        ReconLoopConfig {
            interval_secs: 1,
            batch_limit: 50,
            max_scan: 5_000,
            max_attempts: 100,
            base_delay_secs: 1,
            max_delay_secs: 10,
        },
    );
    let mut now = unix_now_secs();
    reconciler1.tick(now);
    now += 1;

    // Simulate process restart by dropping all handles holding the sled db.
    drop(reconciler1);
    drop(linkage_api);
    drop(data_api);
    drop(fin_api);
    drop(recon);
    drop(fin_store);
    drop(data_store);

    // Simulate restart: reopen recon store + rebuild APIs/reconciler from disk.
    let receipts = tmp.path().join("receipts");
    let fin_db = tmp.path().join("fin_db");
    let data_db = tmp.path().join("data_db");
    let recon_db = tmp.path().join("recon_db");

    let recon2 = ReconStore::open(&recon_db).expect("reopen recon");
    let fin_store2 = hub_fin::FinStore::open(&fin_db).expect("reopen fin");
    let data_store2 = hub_data::DataStore::open(&data_db).expect("reopen data");
    let pr = PolicyRuntime::default();
    let fin_api2 = FinApi::new_with_policy_and_recon(
        l1.clone(),
        fin_store2,
        receipts.clone(),
        pr.clone(),
        Some(recon2.clone()),
    );
    let data_api2 = DataApi::new_with_policy_and_recon(
        l1.clone(),
        data_store2,
        receipts.clone(),
        pr,
        Some(recon2.clone()),
    );
    let linkage_api2 = LinkageApi::new_with_policy_and_recon(
        fin_api2.clone(),
        data_api2.clone(),
        receipts,
        EntitlementPolicy::FinalityRequired,
        Some(recon2.clone()),
    );

    let reconciler2 = Reconciler::new(
        l1.clone(),
        fin_api2.clone(),
        data_api2.clone(),
        linkage_api2.clone(),
        recon2.clone(),
        ReconLoopConfig {
            interval_secs: 1,
            batch_limit: 50,
            max_scan: 5_000,
            max_attempts: 100,
            base_delay_secs: 1,
            max_delay_secs: 10,
        },
    );

    // Drive until entitlement gets submitted post-restart, then stage its finality.
    let mut r2 = linkage_api2
        .get_purchase_receipt(&r.purchase_id.to_hex())
        .unwrap()
        .unwrap();
    let mut staged_entitlement = false;
    for _ in 0..30 {
        reconciler2.tick(now);
        now += 1;
        r2 = linkage_api2
            .get_purchase_receipt(&r.purchase_id.to_hex())
            .unwrap()
            .unwrap();
        if !staged_entitlement {
            if let l2_core::finality::SubmitState::Submitted {
                idempotency_key, ..
            } = &r2.entitlement_submit_state
            {
                l1.set_staged_delays_b64(idempotency_key, 0, 1)
                    .expect("stage entitlement");
                staged_entitlement = true;
            }
        }
        if r2.overall_status == LinkageOverallStatus::EntitledFinal {
            break;
        }
    }

    assert_eq!(r2.overall_status, LinkageOverallStatus::EntitledFinal);
}
