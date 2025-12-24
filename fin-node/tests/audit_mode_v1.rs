use assert_cmd::Command;
use fin_node::data_api::DataApi;
use fin_node::fin_api::FinApi;
use fin_node::linkage::{BuyLicenseRequestV1, LinkageApi};
use hub_data::{
    CreateListingRequestV1, LicenseRightsV1, PriceMicrounitsU128, RegisterDatasetRequestV1,
};
use hub_fin::{AmountU128, CreateAssetV1, FinActionV1, MintUnitsV1};
use l2_core::l1_contract::mock_client::MockL1Client;
use l2_core::AccountId;
use std::sync::Arc;

fn fin_node_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("fin-node"))
}

#[test]
fn audit_export_is_deterministic_and_replay_verifies() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // Use default paths (no config required): ./fin_db ./data_db ./audit_db ./receipts
    let receipts_dir = tmp.path().join("receipts");
    let fin_db = tmp.path().join("fin_db");
    let data_db = tmp.path().join("data_db");
    let audit_db = tmp.path().join("audit_db");

    std::fs::create_dir_all(&receipts_dir).expect("receipts dir");

    let l1 = Arc::new(MockL1Client::default());
    let fin_store = hub_fin::FinStore::open(&fin_db).expect("fin store");
    let data_store = hub_data::DataStore::open(&data_db).expect("data store");
    let audit = fin_node::audit_store::AuditStore::open(&audit_db).expect("audit store");

    let fin_api = FinApi::new(l1.clone(), fin_store.clone(), receipts_dir.clone())
        .with_audit(Some(audit.clone()));
    let data_api =
        DataApi::new(l1, data_store.clone(), receipts_dir.clone()).with_audit(Some(audit.clone()));
    let linkage_api = LinkageApi::new(fin_api.clone(), data_api.clone(), receipts_dir.clone())
        .with_audit(Some(audit));

    // Minimal scenario:
    let issuer = AccountId::new("issuer-001");
    let buyer = AccountId::new("acc-buyer");
    let seller = AccountId::new("acc-seller");

    // FIN: create asset + mint to buyer
    let asset_id = hub_fin::validation::derive_asset_id("Example Euro Stablecoin", &issuer, "EURX");
    fin_api
        .submit_action_obj(FinActionV1::CreateAssetV1(CreateAssetV1 {
            asset_id,
            name: "Example Euro Stablecoin".to_string(),
            symbol: "EURX".to_string(),
            issuer: issuer.clone(),
            decimals: 6,
            metadata_uri: None,
            actor: Some(issuer.clone()),
            mint_policy: hub_fin::MintPolicyV1::IssuerOnly,
            transfer_policy: hub_fin::TransferPolicyV1::Free,
        }))
        .expect("create asset");

    fin_api
        .submit_action_obj(FinActionV1::MintUnitsV1(MintUnitsV1 {
            asset_id,
            to_account: buyer.clone(),
            amount: AmountU128(2_000_000),
            actor: Some(issuer),
            client_tx_id: "mint-001".to_string(),
            memo: None,
        }))
        .expect("mint");

    // DATA: register dataset + create listing
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
    let dataset_id = hub_data::Hex32::from_hex(reg.dataset_id.as_ref().unwrap()).unwrap();

    let listing = data_api
        .submit_create_listing(CreateListingRequestV1 {
            dataset_id,
            licensor: seller,
            rights: LicenseRightsV1::Use,
            price_microunits: PriceMicrounitsU128(1_000_000),
            currency_asset_id: hub_data::Hex32(asset_id.0),
            terms_uri: Some("https://example.com/terms/v1".to_string()),
            terms_hash: Some(
                hub_data::Hex32::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
            ),
        })
        .expect("create listing");
    let listing_id = hub_data::Hex32::from_hex(listing.listing_id.as_ref().unwrap()).unwrap();

    // LINKAGE: buy license (optimistic path: creates payment + entitlement immediately)
    linkage_api
        .buy_license(BuyLicenseRequestV1 {
            dataset_id,
            listing_id,
            buyer_account: buyer,
            nonce: Some("nonce-001".to_string()),
            memo: Some("audit test".to_string()),
        })
        .expect("buy license");

    // Release sled file locks before invoking the CLI (which opens the same DBs).
    drop(linkage_api);
    drop(data_api);
    drop(fin_api);
    drop(data_store);
    drop(fin_store);

    // Export twice, should be byte-identical.
    let out1 = tmp.path().join("audit1.tar");
    let out2 = tmp.path().join("audit2.tar");

    fin_node_cmd()
        .current_dir(tmp.path())
        .args(["audit", "export", "--out", out1.to_string_lossy().as_ref()])
        .assert()
        .success();
    fin_node_cmd()
        .current_dir(tmp.path())
        .args(["audit", "export", "--out", out2.to_string_lossy().as_ref()])
        .assert()
        .success();

    let b1 = std::fs::read(&out1).expect("read audit1");
    let b2 = std::fs::read(&out2).expect("read audit2");
    assert_eq!(b1, b2, "audit export must be deterministic");

    // Replay + verify.
    fin_node_cmd()
        .current_dir(tmp.path())
        .args([
            "audit",
            "replay",
            "--from",
            out1.to_string_lossy().as_ref(),
            "--verify",
            "true",
        ])
        .assert()
        .success();
}
