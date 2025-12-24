#![forbid(unsafe_code)]

use fin_node::config::SnapshotsConfig;
use fin_node::recon_store::ReconStore;
use fin_node::snapshot::{create_snapshot_v1_tar, restore_snapshot_v1_tar, SnapshotSources};
use fin_node::{data_api::DataApi, fin_api::FinApi, linkage::LinkageApi};
use hub_data::{
    actions::{CreateListingRequestV1, RegisterDatasetRequestV1},
    Hex32 as DataHex32,
};
use hub_fin::actions::{CreateAssetV1, MintPolicyV1, TransferPolicyV1};
use hub_fin::validation::derive_asset_id;
use l2_core::l1_contract::mock_client::MockL1Client;
use l2_core::AccountId;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

fn collect_files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    if !root.exists() {
        return out;
    }
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        if let Ok(rd) = fs::read_dir(dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    walk(&p, root, out);
                } else if p.is_file() {
                    let rel = p
                        .strip_prefix(root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .replace('\\', "/");
                    let bytes = fs::read(&p).unwrap_or_default();
                    out.insert(rel, bytes);
                }
            }
        }
    }
    walk(root, root, &mut out);
    out
}

fn export_tree_bytes_fin(store: &hub_fin::FinStore) -> Vec<u8> {
    let mut v = Vec::new();
    store.export_kv_v1(&mut v).expect("export fin kv");
    v
}

fn export_tree_bytes_data(store: &hub_data::DataStore) -> Vec<u8> {
    let mut v = Vec::new();
    store.export_kv_v1(&mut v).expect("export data kv");
    v
}

fn export_tree_bytes_recon(store: &ReconStore) -> Vec<u8> {
    let mut v = Vec::new();
    store.export_kv_v1(&mut v).expect("export recon kv");
    v
}

#[test]
fn snapshot_roundtrip_restores_identical_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fin_db = tmp.path().join("fin_db");
    let data_db = tmp.path().join("data_db");
    let recon_db = tmp.path().join("recon_db");
    let receipts_dir = tmp.path().join("receipts");
    let audit_db = tmp.path().join("audit_db");
    fs::create_dir_all(&receipts_dir).expect("receipts dir");

    let l1 = Arc::new(MockL1Client::default());
    let fin_store = hub_fin::FinStore::open(&fin_db).expect("fin store");
    let data_store = hub_data::DataStore::open(&data_db).expect("data store");
    let recon_store = ReconStore::open(&recon_db).expect("recon store");
    let audit = fin_node::audit_store::AuditStore::open(&audit_db).expect("audit store");

    let fin_api = FinApi::new_with_policy_and_recon(
        l1.clone(),
        fin_store.clone(),
        receipts_dir.clone(),
        fin_node::policy_runtime::PolicyRuntime::default(),
        Some(recon_store.clone()),
    )
    .with_audit(Some(audit.clone()));
    let data_api = DataApi::new_with_policy_and_recon(
        l1.clone(),
        data_store.clone(),
        receipts_dir.clone(),
        fin_node::policy_runtime::PolicyRuntime::default(),
        Some(recon_store.clone()),
    )
    .with_audit(Some(audit.clone()));
    let linkage_api = LinkageApi::new_with_policy_and_recon(
        fin_api.clone(),
        data_api.clone(),
        receipts_dir.clone(),
        l2_core::hub_linkage::EntitlementPolicy::Optimistic,
        Some(recon_store.clone()),
    )
    .with_audit(Some(audit));

    // Seed FIN state: create asset (deterministic asset_id) and mint balance to buyer.
    let issuer = AccountId::new("acc-issuer");
    let name = "USD Stable".to_string();
    let symbol = "USD".to_string();
    let asset_id = derive_asset_id(&name, &issuer, &symbol);
    let create_asset = CreateAssetV1 {
        asset_id,
        name,
        symbol,
        issuer: issuer.clone(),
        decimals: 6,
        metadata_uri: None,
        actor: Some(issuer.clone()),
        mint_policy: MintPolicyV1::IssuerOnly,
        transfer_policy: TransferPolicyV1::Free,
    };
    let _ = fin_api
        .submit_action_obj(hub_fin::FinActionV1::CreateAssetV1(create_asset))
        .expect("create asset");

    let buyer = AccountId::new("acc-buyer");
    let mint = hub_fin::actions::MintUnitsV1 {
        asset_id,
        to_account: buyer.clone(),
        amount: hub_fin::AmountU128(5_000_000),
        actor: Some(issuer.clone()),
        client_tx_id: "mint-001".to_string(),
        memo: None,
    };
    let _ = fin_api
        .submit_action_obj(hub_fin::FinActionV1::MintUnitsV1(mint))
        .expect("mint");

    // Seed DATA state: dataset + listing.
    let ds = data_api
        .submit_register_dataset(RegisterDatasetRequestV1 {
            owner: issuer.clone(),
            name: "Dataset A".to_string(),
            description: None,
            content_hash: DataHex32::from_hex(
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
    let dataset_id = ds.dataset_id.clone().expect("dataset id");

    let listing = data_api
        .submit_create_listing(CreateListingRequestV1 {
            dataset_id: DataHex32::from_hex(&dataset_id).unwrap(),
            licensor: issuer.clone(),
            rights: hub_data::LicenseRightsV1::Use,
            price_microunits: hub_data::PriceMicrounitsU128(1_000_000),
            currency_asset_id: hub_data::Hex32(asset_id.0),
            terms_uri: None,
            terms_hash: None,
        })
        .expect("create listing");
    let listing_id = listing.listing_id.clone().expect("listing_id");

    // Seed linkage: buy license (writes linkage receipt under receipts/linkage).
    let _ = linkage_api
        .buy_license(fin_node::linkage::BuyLicenseRequestV1 {
            dataset_id: DataHex32::from_hex(&dataset_id).unwrap(),
            listing_id: DataHex32::from_hex(&listing_id).unwrap(),
            buyer_account: buyer.clone(),
            nonce: Some("purchase-001".to_string()),
            memo: None,
        })
        .expect("buy license");

    let fin_before = export_tree_bytes_fin(fin_api.store());
    let data_before = export_tree_bytes_data(data_api.store());
    let recon_before = export_tree_bytes_recon(&recon_store);
    let receipts_before = collect_files(&receipts_dir);

    // Create snapshot.
    let cfg = SnapshotsConfig {
        enabled: true,
        output_dir: tmp.path().join("snapshots").to_string_lossy().to_string(),
        max_snapshots: 10,
        ..SnapshotsConfig::default()
    };
    let snapshot_path = tmp.path().join("snapshots").join("roundtrip.tar");
    let _manifest = create_snapshot_v1_tar(
        &cfg,
        &snapshot_path,
        SnapshotSources {
            fin: fin_api.store(),
            data: data_api.store(),
            recon: Some(&recon_store),
            receipts_dir: &receipts_dir,
            node_id: "test-node",
        },
    )
    .expect("snapshot create");

    // Wipe state dirs.
    drop(linkage_api);
    drop(data_api);
    drop(fin_api);
    drop(recon_store);
    // Remove dirs completely.
    let _ = fs::remove_dir_all(&fin_db);
    let _ = fs::remove_dir_all(&data_db);
    let _ = fs::remove_dir_all(&recon_db);
    let _ = fs::remove_dir_all(&receipts_dir);

    // Re-open empty stores and restore.
    let fin_store2 = hub_fin::FinStore::open(&fin_db).expect("fin store2");
    let data_store2 = hub_data::DataStore::open(&data_db).expect("data store2");
    let recon_store2 = ReconStore::open(&recon_db).expect("recon store2");
    let receipts_dir2 = receipts_dir; // same path

    restore_snapshot_v1_tar(
        &cfg,
        &snapshot_path,
        &fin_store2,
        &data_store2,
        Some(&recon_store2),
        &receipts_dir2,
        true,
    )
    .expect("restore");

    let fin_after = export_tree_bytes_fin(&fin_store2);
    let data_after = export_tree_bytes_data(&data_store2);
    let recon_after = export_tree_bytes_recon(&recon_store2);
    let receipts_after = collect_files(&receipts_dir2);

    assert_eq!(fin_before, fin_after);
    assert_eq!(data_before, data_after);
    assert_eq!(recon_before, recon_after);
    assert_eq!(receipts_before, receipts_after);
}

#[test]
fn snapshot_detects_corruption_via_hash_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fin_db = tmp.path().join("fin_db");
    let data_db = tmp.path().join("data_db");
    let recon_db = tmp.path().join("recon_db");
    let receipts_dir = tmp.path().join("receipts");
    fs::create_dir_all(&receipts_dir).expect("receipts dir");

    let l1 = Arc::new(MockL1Client::default());
    let fin_store = hub_fin::FinStore::open(&fin_db).expect("fin store");
    let data_store = hub_data::DataStore::open(&data_db).expect("data store");
    let recon_store = ReconStore::open(&recon_db).expect("recon store");

    let fin_api = FinApi::new_with_policy_and_recon(
        l1.clone(),
        fin_store.clone(),
        receipts_dir.clone(),
        fin_node::policy_runtime::PolicyRuntime::default(),
        Some(recon_store.clone()),
    );

    // One action so snapshot isn't empty.
    let issuer = AccountId::new("acc-issuer");
    let asset_id = derive_asset_id("USD", &issuer, "USD");
    let create_asset = CreateAssetV1 {
        asset_id,
        name: "USD".to_string(),
        symbol: "USD".to_string(),
        issuer: issuer.clone(),
        decimals: 6,
        metadata_uri: None,
        actor: Some(issuer.clone()),
        mint_policy: MintPolicyV1::IssuerOnly,
        transfer_policy: TransferPolicyV1::Free,
    };
    let _ = fin_api
        .submit_action_obj(hub_fin::FinActionV1::CreateAssetV1(create_asset))
        .expect("create asset");

    let cfg = SnapshotsConfig {
        enabled: true,
        output_dir: tmp.path().join("snapshots").to_string_lossy().to_string(),
        max_snapshots: 10,
        ..SnapshotsConfig::default()
    };
    let snapshot_path = tmp.path().join("snapshots").join("corrupt.tar");
    let _ = create_snapshot_v1_tar(
        &cfg,
        &snapshot_path,
        SnapshotSources {
            fin: fin_api.store(),
            data: &data_store,
            recon: Some(&recon_store),
            receipts_dir: &receipts_dir,
            node_id: "test-node",
        },
    )
    .expect("snapshot create");

    // Corrupt the tar by flipping a byte.
    let mut bytes = fs::read(&snapshot_path).expect("read tar");
    if let Some(b) = bytes.get_mut(10) {
        *b = b.wrapping_add(1);
    }
    fs::write(&snapshot_path, bytes).expect("write tar");

    let fin_store2 = hub_fin::FinStore::open(tmp.path().join("fin_db2")).expect("fin2");
    let data_store2 = hub_data::DataStore::open(tmp.path().join("data_db2")).expect("data2");
    let recon_store2 = ReconStore::open(tmp.path().join("recon_db2")).expect("recon2");
    let receipts_dir2 = tmp.path().join("receipts2");

    let err = restore_snapshot_v1_tar(
        &cfg,
        &snapshot_path,
        &fin_store2,
        &data_store2,
        Some(&recon_store2),
        &receipts_dir2,
        true,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("hash mismatch")
            || err.to_string().contains("tar error")
            || err.to_string().contains("corrupt"),
        "unexpected error: {err}"
    );
}

#[test]
fn restore_preserves_idempotency_keys_and_l1_deduplication() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fin_db = tmp.path().join("fin_db");
    let data_db = tmp.path().join("data_db");
    let recon_db = tmp.path().join("recon_db");
    let receipts_dir = tmp.path().join("receipts");
    fs::create_dir_all(&receipts_dir).expect("receipts dir");

    // Keep the same mock L1 across pre/post restore to observe idempotency dedup (already_known).
    let l1 = Arc::new(MockL1Client::default());

    // Pre-restore node.
    let fin_store = hub_fin::FinStore::open(&fin_db).expect("fin store");
    let data_store = hub_data::DataStore::open(&data_db).expect("data store");
    let recon_store = ReconStore::open(&recon_db).expect("recon store");
    let fin_api = FinApi::new_with_policy_and_recon(
        l1.clone(),
        fin_store.clone(),
        receipts_dir.clone(),
        fin_node::policy_runtime::PolicyRuntime::default(),
        Some(recon_store.clone()),
    );

    let issuer = AccountId::new("acc-issuer");
    let name = "USD Stable".to_string();
    let symbol = "USD".to_string();
    let asset_id = derive_asset_id(&name, &issuer, &symbol);
    let create_asset_action = CreateAssetV1 {
        asset_id,
        name,
        symbol,
        issuer: issuer.clone(),
        decimals: 6,
        metadata_uri: None,
        actor: Some(issuer.clone()),
        mint_policy: MintPolicyV1::IssuerOnly,
        transfer_policy: TransferPolicyV1::Free,
    };

    let r1 = fin_api
        .submit_action_obj(hub_fin::FinActionV1::CreateAssetV1(
            create_asset_action.clone(),
        ))
        .expect("submit once");
    assert!(!r1.l1_submit_result.already_known);

    // Snapshot.
    let cfg = SnapshotsConfig {
        enabled: true,
        output_dir: tmp.path().join("snapshots").to_string_lossy().to_string(),
        max_snapshots: 10,
        ..SnapshotsConfig::default()
    };
    let snapshot_path = tmp.path().join("snapshots").join("idem.tar");
    let _ = create_snapshot_v1_tar(
        &cfg,
        &snapshot_path,
        SnapshotSources {
            fin: fin_api.store(),
            data: &data_store,
            recon: Some(&recon_store),
            receipts_dir: &receipts_dir,
            node_id: "test-node",
        },
    )
    .expect("snapshot create");

    drop(fin_api);
    drop(recon_store);
    drop(fin_store);
    let _ = fs::remove_dir_all(&fin_db);
    let _ = fs::remove_dir_all(&data_db);
    let _ = fs::remove_dir_all(&recon_db);
    let _ = fs::remove_dir_all(&receipts_dir);

    // Restore to a new node (same storage paths).
    let fin_store2 = hub_fin::FinStore::open(&fin_db).expect("fin store2");
    let data_store2 = hub_data::DataStore::open(&data_db).expect("data store2");
    let recon_store2 = ReconStore::open(&recon_db).expect("recon store2");
    restore_snapshot_v1_tar(
        &cfg,
        &snapshot_path,
        &fin_store2,
        &data_store2,
        Some(&recon_store2),
        &receipts_dir,
        true,
    )
    .expect("restore");

    let fin_api2 = FinApi::new_with_policy_and_recon(
        l1.clone(),
        fin_store2.clone(),
        receipts_dir.clone(),
        fin_node::policy_runtime::PolicyRuntime::default(),
        Some(recon_store2.clone()),
    );

    // Re-submit same action: local should be idempotent and L1 should return already_known.
    let r2 = fin_api2
        .submit_action_obj(hub_fin::FinActionV1::CreateAssetV1(create_asset_action))
        .expect("submit twice");
    assert_eq!(
        r2.local_apply_outcome,
        hub_fin::ApplyOutcome::AlreadyApplied
    );
    assert!(r2.l1_submit_result.already_known);
}
