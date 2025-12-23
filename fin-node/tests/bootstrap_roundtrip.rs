#![forbid(unsafe_code)]

use fin_node::bootstrap_store::BootstrapStore;
use fin_node::config::SnapshotsConfig;
use fin_node::data_api::DataApi;
use fin_node::fin_api::FinApi;
use fin_node::linkage::LinkageApi;
use fin_node::recon_store::ReconStore;
use fin_node::{bootstrap, snapshot};
use hub_data::{Hex32 as DataHex32, RegisterDatasetRequestV1};
use hub_fin::{CreateAssetV1, MintPolicyV1, MintUnitsV1, TransferPolicyV1};
use l2_core::l1_contract::mock_client::MockL1Client;
use l2_core::AccountId;
use std::fs;
use std::path::Path;
use std::sync::Arc;

fn export_store_kv_bytes_fin(store: &hub_fin::FinStore) -> Vec<u8> {
    let mut out = Vec::new();
    store.export_kv_v1(&mut out).expect("export fin");
    out
}

fn export_store_kv_bytes_data(store: &hub_data::DataStore) -> Vec<u8> {
    let mut out = Vec::new();
    store.export_kv_v1(&mut out).expect("export data");
    out
}

fn export_store_kv_bytes_recon(store: &fin_node::recon_store::ReconStore) -> Vec<u8> {
    let mut out = Vec::new();
    store.export_kv_v1(&mut out).expect("export recon");
    out
}

fn collect_files(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    if !root.exists() {
        return out;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(p);
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = fs::read(&p).unwrap_or_default();
            out.push((rel, bytes));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn base_plus_delta_roundtrip_restores_identical_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let receipts_dir = tmp.path().join("receipts");
    let fin_db = tmp.path().join("fin_db");
    let data_db = tmp.path().join("data_db");
    let recon_db = tmp.path().join("recon_db");
    let bootstrap_db = tmp.path().join("bootstrap_db");
    let snapshots_dir = tmp.path().join("snapshots");
    fs::create_dir_all(&snapshots_dir).expect("snapshots dir");

    let l1 = Arc::new(MockL1Client::default());
    let fin_store = hub_fin::FinStore::open(&fin_db).expect("fin store");
    let data_store = hub_data::DataStore::open(&data_db).expect("data store");
    let recon_store = ReconStore::open(&recon_db).expect("recon store");
    let bootstrap_store = BootstrapStore::open(&bootstrap_db).expect("bootstrap store");

    // Base boundary is epoch 0 -> 1.
    fin_store.set_changelog_epoch(0).expect("fin epoch");
    data_store.set_changelog_epoch(0).expect("data epoch");
    recon_store.set_changelog_epoch(0).expect("recon epoch");
    bootstrap_store.set_epoch(0).expect("boot epoch");

    let fin_api = FinApi::new_with_policy_recon_and_limits(
        l1.clone(),
        fin_store.clone(),
        receipts_dir.clone(),
        fin_node::policy_runtime::PolicyRuntime::default(),
        Some(recon_store.clone()),
        hub_fin::validation::ValidationLimits::default(),
    )
    .with_bootstrap(Some(bootstrap_store.clone()));

    let data_api = DataApi::new_with_policy_recon_and_limits(
        l1.clone(),
        data_store.clone(),
        receipts_dir.clone(),
        fin_node::policy_runtime::PolicyRuntime::default(),
        Some(recon_store.clone()),
        hub_data::validation::ValidationLimits::default(),
    )
    .with_bootstrap(Some(bootstrap_store.clone()));

    let linkage_api = LinkageApi::new_with_policy_and_recon(
        fin_api.clone(),
        data_api.clone(),
        receipts_dir.clone(),
        l2_core::hub_linkage::EntitlementPolicy::Optimistic,
        Some(recon_store.clone()),
    )
    .with_bootstrap(Some(bootstrap_store.clone()));

    // Seed some state before base snapshot.
    let issuer = AccountId::new("acc-issuer");
    let asset_id = hub_fin::validation::derive_asset_id("USD Stable", &issuer, "USD");
    let create_asset = CreateAssetV1 {
        asset_id,
        name: "USD Stable".to_string(),
        symbol: "USD".to_string(),
        issuer: issuer.clone(),
        decimals: 6,
        metadata_uri: None,
        actor: Some(issuer.clone()),
        mint_policy: MintPolicyV1::IssuerOnly,
        transfer_policy: TransferPolicyV1::Free,
    };
    fin_api
        .submit_action_obj(hub_fin::FinActionV1::CreateAssetV1(create_asset))
        .expect("create asset");
    fin_api
        .submit_action_obj(hub_fin::FinActionV1::MintUnitsV1(MintUnitsV1 {
            asset_id,
            to_account: AccountId::new("acc-alice"),
            amount: hub_fin::AmountU128(1_000_000),
            actor: Some(issuer.clone()),
            memo: None,
            client_tx_id: "mint-001".to_string(),
        }))
        .expect("mint");

    let dataset = data_api
        .submit_register_dataset(RegisterDatasetRequestV1 {
            owner: AccountId::new("acc-alice"),
            name: "Dataset".to_string(),
            description: None,
            content_hash: DataHex32::from_hex(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            pointer_uri: None,
            mime_type: None,
            tags: vec![],
            schema_version: 1,
            attestation_policy: hub_data::AttestationPolicyV1::Anyone,
        })
        .expect("register dataset");
    let dataset_id = dataset.dataset_id.expect("dataset_id");

    // Cut base snapshot.
    let snapshots_cfg = SnapshotsConfig {
        enabled: true,
        output_dir: snapshots_dir.to_string_lossy().to_string(),
        ..SnapshotsConfig::default()
    };
    let base_path = snapshots_dir.join("base.tar");
    let base_manifest = snapshot::create_snapshot_v1_tar(
        &snapshots_cfg,
        &base_path,
        snapshot::SnapshotSources {
            fin: fin_api.store(),
            data: data_api.store(),
            recon: Some(&recon_store),
            receipts_dir: &receipts_dir,
            node_id: "test-node",
        },
    )
    .expect("base snapshot");
    bootstrap_store
        .set_base_snapshot_id(&base_manifest.hash)
        .expect("set base id");

    // Clear epoch 0 logs and advance to epoch 1 (post-base).
    fin_store.delete_changelog_epoch(0).ok();
    data_store.delete_changelog_epoch(0).ok();
    recon_store.delete_changelog_epoch(0).ok();
    bootstrap_store.delete_changelog_epoch(0).ok();
    fin_store.set_changelog_epoch(1).expect("fin epoch 1");
    data_store.set_changelog_epoch(1).expect("data epoch 1");
    recon_store.set_changelog_epoch(1).expect("recon epoch 1");
    bootstrap_store.set_epoch(1).expect("boot epoch 1");

    // Mutate state after base (recorded into epoch 1 changelogs).
    let _ = linkage_api
        .buy_license(fin_node::linkage::BuyLicenseRequestV1 {
            dataset_id: DataHex32::from_hex(&dataset_id).unwrap(),
            // No listing -> create listing first
            listing_id: DataHex32::from_hex(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap(),
            buyer_account: AccountId::new("acc-bob"),
            nonce: Some("purchase-001".to_string()),
            memo: None,
        })
        .err();

    // A simpler deterministic post-base mutation: write a synthetic receipt file.
    fs::create_dir_all(receipts_dir.join("fin").join("actions")).unwrap();
    let extra_path = receipts_dir.join("fin").join("actions").join("extra.json");
    fs::write(&extra_path, br#"{"schema_version":1}"#).unwrap();
    // Log the file write into bootstrap store (mimics runtime receipt persistence).
    bootstrap_store
        .record_put(
            "receipts",
            b"fin/actions/extra.json",
            br#"{"schema_version":1}"#,
        )
        .unwrap();

    // Cut delta 1->2.
    let delta_path = snapshots_dir.join("delta-1-2.tar");
    let _delta_manifest = bootstrap::create_delta_snapshot_v1_tar(
        &delta_path,
        &base_manifest.hash,
        1,
        2,
        bootstrap::DeltaSources {
            fin: &fin_store,
            data: &data_store,
            recon: Some(&recon_store),
            bootstrap: &bootstrap_store,
        },
    )
    .expect("delta create");

    let fin_before = export_store_kv_bytes_fin(&fin_store);
    let data_before = export_store_kv_bytes_data(&data_store);
    let recon_before = export_store_kv_bytes_recon(&recon_store);
    let receipts_before = collect_files(&receipts_dir);

    // Wipe everything.
    drop(linkage_api);
    drop(data_api);
    drop(fin_api);
    drop(recon_store);
    let _ = fs::remove_dir_all(&fin_db);
    let _ = fs::remove_dir_all(&data_db);
    let _ = fs::remove_dir_all(&recon_db);
    let _ = fs::remove_dir_all(&receipts_dir);

    // Re-open and restore base + delta.
    let fin2 = hub_fin::FinStore::open(&fin_db).expect("fin2");
    let data2 = hub_data::DataStore::open(&data_db).expect("data2");
    let recon2 = ReconStore::open(&recon_db).expect("recon2");
    fs::create_dir_all(&receipts_dir).unwrap();

    let _ = snapshot::restore_snapshot_v1_tar(
        &snapshots_cfg,
        &base_path,
        &fin2,
        &data2,
        Some(&recon2),
        &receipts_dir,
        true,
    )
    .expect("restore base");
    let parsed = bootstrap::parse_delta_snapshot_v1_tar(&delta_path).expect("parse delta");
    bootstrap::apply_delta_changes_v1(&parsed.changes, &fin2, &data2, Some(&recon2), &receipts_dir)
        .expect("apply delta");

    assert_eq!(export_store_kv_bytes_fin(&fin2), fin_before);
    assert_eq!(export_store_kv_bytes_data(&data2), data_before);
    assert_eq!(export_store_kv_bytes_recon(&recon2), recon_before);
    assert_eq!(collect_files(&receipts_dir), receipts_before);
}

#[test]
fn bootstrap_restore_is_resume_capable_via_progress_epoch() {
    // Minimal unit-level resume check: progress epoch gates which deltas are applied.
    let tmp = tempfile::tempdir().expect("tempdir");
    let receipts_dir = tmp.path().join("receipts");
    let fin_db = tmp.path().join("fin_db");
    let data_db = tmp.path().join("data_db");
    let recon_db = tmp.path().join("recon_db");
    let bootstrap_db = tmp.path().join("bootstrap_db");
    let snapshots_dir = tmp.path().join("snapshots");
    fs::create_dir_all(&snapshots_dir).expect("snapshots dir");
    fs::create_dir_all(&receipts_dir).expect("receipts dir");

    let fin_store = hub_fin::FinStore::open(&fin_db).expect("fin store");
    let data_store = hub_data::DataStore::open(&data_db).expect("data store");
    let recon_store = ReconStore::open(&recon_db).expect("recon store");
    let bootstrap_store = BootstrapStore::open(&bootstrap_db).expect("bootstrap store");

    // Base id is arbitrary for this unit check.
    let base_id = "basehash";
    bootstrap_store.set_base_snapshot_id(base_id).unwrap();

    // Build two empty deltas: 1->2 and 2->3.
    fin_store.set_changelog_epoch(1).unwrap();
    data_store.set_changelog_epoch(1).unwrap();
    recon_store.set_changelog_epoch(1).unwrap();
    bootstrap_store.set_epoch(1).unwrap();
    let d12 = snapshots_dir.join("d12.tar");
    bootstrap::create_delta_snapshot_v1_tar(
        &d12,
        base_id,
        1,
        2,
        bootstrap::DeltaSources {
            fin: &fin_store,
            data: &data_store,
            recon: Some(&recon_store),
            bootstrap: &bootstrap_store,
        },
    )
    .unwrap();

    fin_store.set_changelog_epoch(2).unwrap();
    data_store.set_changelog_epoch(2).unwrap();
    recon_store.set_changelog_epoch(2).unwrap();
    bootstrap_store.set_epoch(2).unwrap();
    let d23 = snapshots_dir.join("d23.tar");
    bootstrap::create_delta_snapshot_v1_tar(
        &d23,
        base_id,
        2,
        3,
        bootstrap::DeltaSources {
            fin: &fin_store,
            data: &data_store,
            recon: Some(&recon_store),
            bootstrap: &bootstrap_store,
        },
    )
    .unwrap();

    // Progress indicates we already applied up to epoch 2, so only 2->3 should be considered next.
    let progress_path = tmp.path().join("bootstrap_progress.json");
    let progress = bootstrap::BootstrapProgressV1 {
        schema_version: 1,
        base_snapshot_id: base_id.to_string(),
        last_applied_to_epoch: 2,
    };
    bootstrap::write_progress_atomic(&progress_path, &progress).unwrap();
    let loaded = bootstrap::read_progress(&progress_path).unwrap().unwrap();
    assert_eq!(loaded.last_applied_to_epoch, 2);
}

#[test]
fn retention_prunes_old_bases_and_their_deltas() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let receipts_dir = tmp.path().join("receipts");
    let fin_db = tmp.path().join("fin_db");
    let data_db = tmp.path().join("data_db");
    let recon_db = tmp.path().join("recon_db");
    let bootstrap_db = tmp.path().join("bootstrap_db");
    let snapshots_dir = tmp.path().join("snapshots");
    fs::create_dir_all(&snapshots_dir).expect("snapshots dir");

    let fin_store = hub_fin::FinStore::open(&fin_db).expect("fin store");
    let data_store = hub_data::DataStore::open(&data_db).expect("data store");
    let recon_store = ReconStore::open(&recon_db).expect("recon store");
    let bootstrap_store = BootstrapStore::open(&bootstrap_db).expect("bootstrap store");

    let snapshots_cfg = SnapshotsConfig {
        enabled: true,
        output_dir: snapshots_dir.to_string_lossy().to_string(),
        ..SnapshotsConfig::default()
    };

    // Create base1 then base2 (ensure created_at differs).
    fs::create_dir_all(&receipts_dir).unwrap();
    let base1_path = snapshots_dir.join("base1.tar");
    let base1 = snapshot::create_snapshot_v1_tar(
        &snapshots_cfg,
        &base1_path,
        snapshot::SnapshotSources {
            fin: &fin_store,
            data: &data_store,
            recon: Some(&recon_store),
            receipts_dir: &receipts_dir,
            node_id: "test-node",
        },
    )
    .expect("base1");
    // Mutate receipts so base2 hash differs.
    fs::write(receipts_dir.join("marker.json"), br#"{"v":2}"#).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));
    let base2_path = snapshots_dir.join("base2.tar");
    let base2 = snapshot::create_snapshot_v1_tar(
        &snapshots_cfg,
        &base2_path,
        snapshot::SnapshotSources {
            fin: &fin_store,
            data: &data_store,
            recon: Some(&recon_store),
            receipts_dir: &receipts_dir,
            node_id: "test-node",
        },
    )
    .expect("base2");

    // Create one delta per base.
    fin_store.set_changelog_epoch(1).unwrap();
    data_store.set_changelog_epoch(1).unwrap();
    recon_store.set_changelog_epoch(1).unwrap();
    bootstrap_store.set_epoch(1).unwrap();
    let deltas_dir = snapshots_dir.join("deltas");
    fs::create_dir_all(&deltas_dir).unwrap();
    let d1 = deltas_dir.join("delta-base1.tar");
    bootstrap::create_delta_snapshot_v1_tar(
        &d1,
        &base1.hash,
        1,
        2,
        bootstrap::DeltaSources {
            fin: &fin_store,
            data: &data_store,
            recon: Some(&recon_store),
            bootstrap: &bootstrap_store,
        },
    )
    .unwrap();
    let d2 = deltas_dir.join("delta-base2.tar");
    bootstrap::create_delta_snapshot_v1_tar(
        &d2,
        &base2.hash,
        1,
        2,
        bootstrap::DeltaSources {
            fin: &fin_store,
            data: &data_store,
            recon: Some(&recon_store),
            bootstrap: &bootstrap_store,
        },
    )
    .unwrap();

    // Retain only 1 base -> base1 + its deltas should be removed.
    bootstrap::rotate_bootstrap_dir_v1(&snapshots_dir, 1, 1);
    assert!(!base1_path.exists());
    assert!(base2_path.exists());
    assert!(!d1.exists());
    assert!(d2.exists());
}
