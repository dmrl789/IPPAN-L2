use fin_node::fin_api::FinApi;
use fin_node::policy_runtime::{ComplianceConfig, ComplianceStrategy, PolicyRuntime};
use fin_node::policy_store::PolicyStore;
use hub_fin::{CreateAssetV1, FinActionV1, FinStore, MintPolicyV1, TransferPolicyV1};
use l2_core::l1_contract::mock_client::MockL1Client;
use l2_core::policy::PolicyMode;
use l2_core::AccountId;
use std::sync::Arc;

fn mk_asset(actor: &AccountId, issuer: &AccountId) -> CreateAssetV1 {
    CreateAssetV1 {
        asset_id: hub_fin::validation::derive_asset_id("X", issuer, "X"),
        name: "X".to_string(),
        symbol: "X".to_string(),
        issuer: issuer.clone(),
        decimals: 6,
        metadata_uri: None,
        actor: Some(actor.clone()),
        mint_policy: MintPolicyV1::IssuerOnly,
        transfer_policy: TransferPolicyV1::Free,
    }
}

#[test]
fn compliance_denylist_blocks_actions_when_enabled() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let receipts = tmp.path().join("receipts");
    let fin_db = tmp.path().join("fin_db");

    let l1 = Arc::new(MockL1Client::default());
    let fin_store = FinStore::open(&fin_db).unwrap();

    let policy_store = PolicyStore::open_temporary().unwrap();
    policy_store.deny_add("acc-bad").unwrap();

    let policy = PolicyRuntime {
        mode: PolicyMode::Permissive,
        admins: vec![],
        compliance: ComplianceConfig {
            enabled: true,
            strategy: ComplianceStrategy::GlobalDenylist,
        },
        store: Some(policy_store),
    };

    let api = FinApi::new_with_policy(l1, fin_store, receipts, policy);
    let err = api
        .submit_action_obj(FinActionV1::CreateAssetV1(mk_asset(
            &AccountId::new("acc-bad"),
            &AccountId::new("acc-bad"),
        )))
        .unwrap_err()
        .to_string();
    assert!(err.contains("ComplianceDenied"), "{err}");
}

#[test]
fn compliance_toggle_allows_when_disabled() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let receipts = tmp.path().join("receipts");
    let fin_db = tmp.path().join("fin_db");

    let l1 = Arc::new(MockL1Client::default());
    let fin_store = FinStore::open(&fin_db).unwrap();

    let policy_store = PolicyStore::open_temporary().unwrap();
    policy_store.deny_add("acc-bad").unwrap();

    let policy = PolicyRuntime {
        mode: PolicyMode::Permissive,
        admins: vec![],
        compliance: ComplianceConfig {
            enabled: false,
            strategy: ComplianceStrategy::GlobalDenylist,
        },
        store: Some(policy_store),
    };

    let api = FinApi::new_with_policy(l1, fin_store, receipts, policy);
    api.submit_action_obj(FinActionV1::CreateAssetV1(mk_asset(
        &AccountId::new("acc-bad"),
        &AccountId::new("acc-bad"),
    )))
    .unwrap();
}
