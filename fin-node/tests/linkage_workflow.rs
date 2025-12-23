use fin_node::data_api::DataApi;
use fin_node::fin_api::FinApi;
use fin_node::linkage::{BuyLicenseRequestV1, LinkageApi};
use hub_data::{
    CreateListingRequestV1, LicenseRightsV1, PriceMicrounitsU128, RegisterDatasetRequestV1,
};
use hub_fin::{AmountU128, CreateAssetV1, FinActionV1, MintUnitsV1};
use l2_core::hub_linkage::{derive_purchase_id_v1, Hex32 as LinkHex32, LinkageStatus};
use l2_core::l1_contract::mock_client::MockL1Client;
use l2_core::AccountId;
use std::sync::Arc;

fn setup() -> (
    tempfile::TempDir,
    FinApi,
    hub_fin::FinStore,
    DataApi,
    hub_data::DataStore,
    LinkageApi,
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let receipts = tmp.path().join("receipts");
    let fin_db = tmp.path().join("fin_db");
    let data_db = tmp.path().join("data_db");
    let l1 = Arc::new(MockL1Client::default());

    let fin_store = hub_fin::FinStore::open(&fin_db).expect("fin store");
    let data_store = hub_data::DataStore::open(&data_db).expect("data store");

    let fin_api = FinApi::new(l1.clone(), fin_store.clone(), receipts.clone());
    let data_api = DataApi::new(l1, data_store.clone(), receipts.clone());
    let linkage_api = LinkageApi::new(fin_api.clone(), data_api.clone(), receipts);

    (tmp, fin_api, fin_store, data_api, data_store, linkage_api)
}

fn bootstrap_asset_and_balance(fin_api: &FinApi, buyer: &AccountId) -> hub_fin::Hex32 {
    let asset_id =
        hub_fin::validation::derive_asset_id("Example Euro Stablecoin", "issuer-001", "EURX");
    let create = CreateAssetV1 {
        asset_id,
        name: "Example Euro Stablecoin".to_string(),
        symbol: "EURX".to_string(),
        issuer: "issuer-001".to_string(),
        decimals: 6,
        metadata_uri: None,
    };
    fin_api
        .submit_action_obj(FinActionV1::CreateAssetV1(create))
        .expect("create asset");

    let mint = MintUnitsV1 {
        asset_id,
        to_account: buyer.clone(),
        amount: AmountU128(2_000_000),
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
fn buy_license_happy_path_and_idempotency() {
    let (_tmp, fin_api, fin_store, data_api, data_store, linkage_api) = setup();
    let buyer = AccountId::new("acc-buyer");
    let seller = AccountId::new("acc-seller");

    let currency_asset_id = bootstrap_asset_and_balance(&fin_api, &buyer);
    let (dataset_id, listing_id) =
        bootstrap_dataset_and_listing(&data_api, &seller, currency_asset_id);

    let req = BuyLicenseRequestV1 {
        dataset_id,
        listing_id,
        buyer_account: buyer.clone(),
        nonce: Some("nonce-001".to_string()),
        memo: Some("test purchase".to_string()),
    };

    let r1 = linkage_api.buy_license(req.clone()).expect("buy");
    assert_eq!(r1.status, LinkageStatus::Entitled);
    assert!(r1.payment_ref.is_some());
    assert!(r1.entitlement_ref.is_some());

    // Balance updates: buyer -1, seller +1 (in microunits).
    let bal_buyer = fin_store
        .get_balance(currency_asset_id, &buyer.0)
        .expect("buyer balance");
    let bal_seller = fin_store
        .get_balance(currency_asset_id, &seller.0)
        .expect("seller balance");
    assert_eq!(bal_buyer, AmountU128(1_000_000));
    assert_eq!(bal_seller, AmountU128(1_000_000));

    // Entitlement stored.
    let ent = data_store
        .get_entitlement(r1.purchase_id)
        .expect("get entitlement");
    assert!(ent.is_some());

    // Idempotent replay: no double charge, still entitled, same purchase id.
    let r2 = linkage_api.buy_license(req).expect("buy replay");
    assert_eq!(r2.purchase_id, r1.purchase_id);
    assert_eq!(r2.status, LinkageStatus::Entitled);

    let bal_buyer2 = fin_store.get_balance(currency_asset_id, &buyer.0).unwrap();
    let bal_seller2 = fin_store.get_balance(currency_asset_id, &seller.0).unwrap();
    assert_eq!(bal_buyer2, AmountU128(1_000_000));
    assert_eq!(bal_seller2, AmountU128(1_000_000));
}

#[test]
fn buy_license_recovery_after_payment() {
    let (tmp, fin_api, fin_store, data_api, data_store, linkage_api) = setup();
    let buyer = AccountId::new("acc-buyer");
    let seller = AccountId::new("acc-seller");

    let currency_asset_id = bootstrap_asset_and_balance(&fin_api, &buyer);
    let (dataset_id, listing_id) =
        bootstrap_dataset_and_listing(&data_api, &seller, currency_asset_id);

    // Enable failpoint file under receipts dir (scoped to this tempdir).
    let receipts_dir = tmp.path().join("receipts");
    std::fs::create_dir_all(receipts_dir.join("linkage")).unwrap();
    std::fs::write(
        receipts_dir.join("linkage").join("_fail_after_payment"),
        b"1",
    )
    .unwrap();

    let req = BuyLicenseRequestV1 {
        dataset_id,
        listing_id,
        buyer_account: buyer.clone(),
        nonce: Some("nonce-002".to_string()),
        memo: None,
    };

    let err = linkage_api
        .buy_license(req.clone())
        .unwrap_err()
        .to_string();
    assert!(err.contains("failpoint"), "{err}");

    // Payment happened exactly once.
    let bal_buyer = fin_store.get_balance(currency_asset_id, &buyer.0).unwrap();
    let bal_seller = fin_store.get_balance(currency_asset_id, &seller.0).unwrap();
    assert_eq!(bal_buyer, AmountU128(1_000_000));
    assert_eq!(bal_seller, AmountU128(1_000_000));

    // Receipt exists and is recoverable.
    let listing = data_store.get_listing(listing_id).unwrap().unwrap();
    let terms_hash = listing.terms_hash.as_ref().map(|x| LinkHex32(x.0));
    let purchase_id = derive_purchase_id_v1(
        &LinkHex32(dataset_id.0),
        &buyer,
        listing.price_microunits.0,
        &LinkHex32(listing.currency_asset_id.0),
        terms_hash.as_ref(),
        "nonce-002",
    );
    let r = linkage_api
        .get_purchase_receipt(&purchase_id.to_hex())
        .unwrap()
        .unwrap();
    assert_eq!(r.status, LinkageStatus::FailedRecoverable);
    assert!(r.payment_ref.is_some());
    assert!(r.entitlement_ref.is_none());

    // Disable failpoint and rerun: should resume without repeating payment.
    std::fs::remove_file(receipts_dir.join("linkage").join("_fail_after_payment")).unwrap();
    let r2 = linkage_api.buy_license(req).expect("resume");
    assert_eq!(r2.status, LinkageStatus::Entitled);
    assert!(r2.entitlement_ref.is_some());

    let bal_buyer2 = fin_store.get_balance(currency_asset_id, &buyer.0).unwrap();
    let bal_seller2 = fin_store.get_balance(currency_asset_id, &seller.0).unwrap();
    assert_eq!(bal_buyer2, AmountU128(1_000_000));
    assert_eq!(bal_seller2, AmountU128(1_000_000));
}
