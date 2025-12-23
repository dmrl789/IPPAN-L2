use hub_data::canonical::canonical_json_bytes;
use hub_data::{
    apply, ApplyOutcome, DataActionV1, DataEnvelopeV1, DataStore, Hex32, LicenseRightsV1,
    RegisterDatasetV1,
};
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
fn golden_register_dataset_v1_action_and_envelope_bytes_are_stable() {
    let action_json = fixture("register_dataset_v1.action.canon.json");
    let env_json = fixture("register_dataset_v1.envelope.canon.json");
    let expected_id = fixture("register_dataset_v1.action_id.hex");

    let action: DataActionV1 = serde_json::from_str(&action_json).expect("parse action");
    let action_bytes = canonical_json_bytes(&action).expect("canonical bytes");
    assert_eq!(action_bytes, action_json.as_bytes());

    let got_id = hex::encode(blake3::hash(&action_bytes).as_bytes());
    assert_eq!(got_id, expected_id);

    let env = DataEnvelopeV1::new(action).expect("env");
    assert_eq!(env.action_id.to_hex(), expected_id);
    let env_bytes = env.canonical_bytes().expect("env bytes");
    assert_eq!(env_bytes, env_json.as_bytes());
}

#[test]
fn golden_issue_license_v1_action_and_envelope_bytes_are_stable() {
    let action_json = fixture("issue_license_v1.action.canon.json");
    let env_json = fixture("issue_license_v1.envelope.canon.json");
    let expected_id = fixture("issue_license_v1.action_id.hex");

    let action: DataActionV1 = serde_json::from_str(&action_json).expect("parse action");
    let action_bytes = canonical_json_bytes(&action).expect("canonical bytes");
    assert_eq!(action_bytes, action_json.as_bytes());

    let got_id = hex::encode(blake3::hash(&action_bytes).as_bytes());
    assert_eq!(got_id, expected_id);

    let env = DataEnvelopeV1::new(action).expect("env");
    assert_eq!(env.action_id.to_hex(), expected_id);
    let env_bytes = env.canonical_bytes().expect("env bytes");
    assert_eq!(env_bytes, env_json.as_bytes());
}

#[test]
fn golden_append_attestation_v1_action_and_envelope_bytes_are_stable() {
    let action_json = fixture("append_attestation_v1.action.canon.json");
    let env_json = fixture("append_attestation_v1.envelope.canon.json");
    let expected_id = fixture("append_attestation_v1.action_id.hex");

    let action: DataActionV1 = serde_json::from_str(&action_json).expect("parse action");
    let action_bytes = canonical_json_bytes(&action).expect("canonical bytes");
    assert_eq!(action_bytes, action_json.as_bytes());

    let got_id = hex::encode(blake3::hash(&action_bytes).as_bytes());
    assert_eq!(got_id, expected_id);

    let env = DataEnvelopeV1::new(action).expect("env");
    assert_eq!(env.action_id.to_hex(), expected_id);
    let env_bytes = env.canonical_bytes().expect("env bytes");
    assert_eq!(env_bytes, env_json.as_bytes());
}

#[test]
fn golden_create_listing_v1_action_and_envelope_bytes_are_stable() {
    let action_json = fixture("create_listing_v1.action.canon.json");
    let env_json = fixture("create_listing_v1.envelope.canon.json");
    let expected_id = fixture("create_listing_v1.action_id.hex");

    let action: DataActionV1 = serde_json::from_str(&action_json).expect("parse action");
    let action_bytes = canonical_json_bytes(&action).expect("canonical bytes");
    assert_eq!(action_bytes, action_json.as_bytes());

    let got_id = hex::encode(blake3::hash(&action_bytes).as_bytes());
    assert_eq!(got_id, expected_id);

    let env = DataEnvelopeV1::new(action).expect("env");
    assert_eq!(env.action_id.to_hex(), expected_id);
    let env_bytes = env.canonical_bytes().expect("env bytes");
    assert_eq!(env_bytes, env_json.as_bytes());
}

#[test]
fn golden_grant_entitlement_v1_action_and_envelope_bytes_are_stable() {
    let action_json = fixture("grant_entitlement_v1.action.canon.json");
    let env_json = fixture("grant_entitlement_v1.envelope.canon.json");
    let expected_id = fixture("grant_entitlement_v1.action_id.hex");

    let action: DataActionV1 = serde_json::from_str(&action_json).expect("parse action");
    let action_bytes = canonical_json_bytes(&action).expect("canonical bytes");
    assert_eq!(action_bytes, action_json.as_bytes());

    let got_id = hex::encode(blake3::hash(&action_bytes).as_bytes());
    assert_eq!(got_id, expected_id);

    let env = DataEnvelopeV1::new(action).expect("env");
    assert_eq!(env.action_id.to_hex(), expected_id);
    let env_bytes = env.canonical_bytes().expect("env bytes");
    assert_eq!(env_bytes, env_json.as_bytes());
}

#[test]
fn apply_is_idempotent_and_indexes_are_queryable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = DataStore::open(tmp.path()).expect("open store");

    // Apply REGISTER_DATASET
    let create_action: DataActionV1 =
        serde_json::from_str(&fixture("register_dataset_v1.action.canon.json")).unwrap();
    let create_env = DataEnvelopeV1::new(create_action).unwrap();
    let r1 = apply(&create_env, &store).expect("apply register");
    assert_eq!(r1.outcome, ApplyOutcome::Applied);
    let dataset_id = r1.dataset_id.unwrap();

    let r2 = apply(&create_env, &store).expect("replay register");
    assert_eq!(r2.outcome, ApplyOutcome::AlreadyApplied);

    // Apply ISSUE_LICENSE
    let lic_action: DataActionV1 =
        serde_json::from_str(&fixture("issue_license_v1.action.canon.json")).unwrap();
    let lic_env = DataEnvelopeV1::new(lic_action).unwrap();
    let r3 = apply(&lic_env, &store).expect("apply license");
    assert_eq!(r3.outcome, ApplyOutcome::Applied);
    let license_id = r3.license_id.unwrap();

    // Apply APPEND_ATTESTATION
    let att_action: DataActionV1 =
        serde_json::from_str(&fixture("append_attestation_v1.action.canon.json")).unwrap();
    let att_env = DataEnvelopeV1::new(att_action).unwrap();
    let r4 = apply(&att_env, &store).expect("apply attestation");
    assert_eq!(r4.outcome, ApplyOutcome::Applied);

    // Queries
    assert!(store.get_dataset(dataset_id).unwrap().is_some());
    assert!(store.get_license(license_id).unwrap().is_some());
    let licenses = store.list_licenses_by_dataset(dataset_id).unwrap();
    assert_eq!(licenses.len(), 1);
    let atts = store.list_attestations_by_dataset(dataset_id).unwrap();
    assert_eq!(atts.len(), 1);

    // Apply CREATE_LISTING
    let listing_action: DataActionV1 =
        serde_json::from_str(&fixture("create_listing_v1.action.canon.json")).unwrap();
    let listing_env = DataEnvelopeV1::new(listing_action).unwrap();
    let r7 = apply(&listing_env, &store).expect("apply listing");
    assert_eq!(r7.outcome, ApplyOutcome::Applied);

    let listing_id = r7.listing_id.unwrap();
    assert!(store.get_listing(listing_id).unwrap().is_some());
    let listings = store.list_listings_by_dataset(dataset_id).unwrap();
    assert_eq!(listings.len(), 1);

    // Apply GRANT_ENTITLEMENT
    let ent_action: DataActionV1 =
        serde_json::from_str(&fixture("grant_entitlement_v1.action.canon.json")).unwrap();
    let ent_env = DataEnvelopeV1::new(ent_action).unwrap();
    let r8 = apply(&ent_env, &store).expect("apply entitlement");
    assert_eq!(r8.outcome, ApplyOutcome::Applied);
    let ent_license_id = r8.license_id.unwrap();
    let purchase_id = match &ent_env.action {
        DataActionV1::GrantEntitlementV1(x) => x.purchase_id,
        _ => panic!("expected grant entitlement action"),
    };
    let ent = store.get_entitlement(purchase_id).unwrap();
    assert!(ent.is_some());

    let ents_by_dataset = store.list_entitlements_by_dataset(dataset_id).unwrap();
    assert_eq!(ents_by_dataset.len(), 1);
    assert_eq!(ents_by_dataset[0].license_id, ent_license_id);

    let ents_by_licensee = store.list_entitlements_by_licensee("acc-bob").unwrap();
    assert_eq!(ents_by_licensee.len(), 1);
    assert_eq!(ents_by_licensee[0].purchase_id, purchase_id);

    // Replays are idempotent
    let r5 = apply(&lic_env, &store).expect("replay license");
    assert_eq!(r5.outcome, ApplyOutcome::AlreadyApplied);
    let r6 = apply(&att_env, &store).expect("replay att");
    assert_eq!(r6.outcome, ApplyOutcome::AlreadyApplied);

    let r9 = apply(&listing_env, &store).expect("replay listing");
    assert_eq!(r9.outcome, ApplyOutcome::AlreadyApplied);
    let r10 = apply(&ent_env, &store).expect("replay entitlement");
    assert_eq!(r10.outcome, ApplyOutcome::AlreadyApplied);
}

#[test]
fn dataset_id_uniqueness_is_enforced() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = DataStore::open(tmp.path()).expect("open store");

    let action: DataActionV1 =
        serde_json::from_str(&fixture("register_dataset_v1.action.canon.json")).unwrap();
    let env = DataEnvelopeV1::new(action.clone()).unwrap();
    apply(&env, &store).unwrap();

    // Same dataset_id but different action_id (change a field not in dataset_id derivation).
    let DataActionV1::RegisterDatasetV1(mut ds) = action else {
        panic!("expected register dataset action");
    };
    ds.description = Some("changed description".to_string());
    let env2 = DataEnvelopeV1::new(DataActionV1::RegisterDatasetV1(ds)).unwrap();
    let err = apply(&env2, &store).unwrap_err().to_string();
    assert!(err.contains("dataset_id already exists"), "{err}");
    assert!(!store.is_applied(env2.action_id).unwrap());
}

#[test]
fn license_issuer_must_be_dataset_owner() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = DataStore::open(tmp.path()).expect("open store");

    // Register dataset.
    let create_action: DataActionV1 =
        serde_json::from_str(&fixture("register_dataset_v1.action.canon.json")).unwrap();
    let create_env = DataEnvelopeV1::new(create_action).unwrap();
    apply(&create_env, &store).unwrap();

    // Build a license with wrong licensor.
    let DataActionV1::IssueLicenseV1(mut lic) =
        serde_json::from_str::<DataActionV1>(&fixture("issue_license_v1.action.canon.json"))
            .unwrap()
    else {
        panic!("expected issue license action");
    };
    lic.licensor = AccountId::new("acc-mallory");
    // license_id derivation does not include licensor, so keep it unchanged.
    let env = DataEnvelopeV1::new(DataActionV1::IssueLicenseV1(lic)).unwrap();
    let err = apply(&env, &store).unwrap_err().to_string();
    assert!(err.contains("licensor not permitted for dataset"), "{err}");
    assert!(!store.is_applied(env.action_id).unwrap());
}

#[test]
fn tags_must_be_normalized_sorted_and_deduped() {
    let owner = AccountId::new("acc-alice");
    let content_hash =
        Hex32::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();

    let dataset_id = hub_data::validation::derive_dataset_id(&owner, "X", &content_hash, 1);
    let ds = RegisterDatasetV1 {
        dataset_id,
        owner,
        name: "X".to_string(),
        description: None,
        content_hash,
        pointer_uri: None,
        mime_type: None,
        tags: vec!["b".to_string(), "A".to_string(), "b".to_string()], // not normalized
        schema_version: 1,
        attestation_policy: hub_data::AttestationPolicyV1::Anyone,
    };
    let env = DataEnvelopeV1::new(DataActionV1::RegisterDatasetV1(ds)).unwrap();

    let tmp = tempfile::tempdir().expect("tempdir");
    let store = DataStore::open(tmp.path()).expect("open store");
    let err = apply(&env, &store).unwrap_err().to_string();
    assert!(err.contains("tags must be normalized"), "{err}");
}

#[test]
fn bounds_are_enforced() {
    let owner = AccountId::new("acc-alice");
    let content_hash =
        Hex32::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
    let name = "x".repeat(97);
    let dataset_id = hub_data::validation::derive_dataset_id(&owner, &name, &content_hash, 1);
    let ds = RegisterDatasetV1 {
        dataset_id,
        owner,
        name,
        description: None,
        content_hash,
        pointer_uri: None,
        mime_type: None,
        tags: vec![],
        schema_version: 1,
        attestation_policy: hub_data::AttestationPolicyV1::Anyone,
    };
    let env = DataEnvelopeV1::new(DataActionV1::RegisterDatasetV1(ds)).unwrap();

    let tmp = tempfile::tempdir().expect("tempdir");
    let store = DataStore::open(tmp.path()).expect("open store");
    let err = apply(&env, &store).unwrap_err().to_string();
    assert!(err.contains("name exceeds max length"), "{err}");
}

#[test]
fn license_id_duplicates_are_idempotent_success() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = DataStore::open(tmp.path()).expect("open store");

    // Register dataset.
    let create_action: DataActionV1 =
        serde_json::from_str(&fixture("register_dataset_v1.action.canon.json")).unwrap();
    let create_env = DataEnvelopeV1::new(create_action).unwrap();
    apply(&create_env, &store).unwrap();

    let DataActionV1::IssueLicenseV1(mut lic) =
        serde_json::from_str::<DataActionV1>(&fixture("issue_license_v1.action.canon.json"))
            .unwrap()
    else {
        panic!("expected issue license action");
    };
    // First apply.
    let env1 = DataEnvelopeV1::new(DataActionV1::IssueLicenseV1(lic.clone())).unwrap();
    let r1 = apply(&env1, &store).unwrap();
    assert_eq!(r1.outcome, ApplyOutcome::Applied);

    // Second apply with the same license_id but different terms_uri (not part of license_id derivation).
    lic.terms_uri = Some("https://example.com/terms/v1?variant=2".to_string());
    let env2 = DataEnvelopeV1::new(DataActionV1::IssueLicenseV1(lic)).unwrap();
    let r2 = apply(&env2, &store).unwrap();
    assert_eq!(r2.outcome, ApplyOutcome::AlreadyApplied);
}

#[test]
fn attestation_id_duplicates_are_idempotent_success() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = DataStore::open(tmp.path()).expect("open store");

    // Register dataset.
    let create_action: DataActionV1 =
        serde_json::from_str(&fixture("register_dataset_v1.action.canon.json")).unwrap();
    let create_env = DataEnvelopeV1::new(create_action).unwrap();
    apply(&create_env, &store).unwrap();

    let DataActionV1::AppendAttestationV1(mut att) =
        serde_json::from_str::<DataActionV1>(&fixture("append_attestation_v1.action.canon.json"))
            .unwrap()
    else {
        panic!("expected append attestation action");
    };
    let env1 = DataEnvelopeV1::new(DataActionV1::AppendAttestationV1(att.clone())).unwrap();
    let r1 = apply(&env1, &store).unwrap();
    assert_eq!(r1.outcome, ApplyOutcome::Applied);

    // Same attestation_id (because statement_hash is unchanged) but different statement text.
    att.statement = Some("quality:good (updated UX text)".to_string());
    let env2 = DataEnvelopeV1::new(DataActionV1::AppendAttestationV1(att)).unwrap();
    let r2 = apply(&env2, &store).unwrap();
    assert_eq!(r2.outcome, ApplyOutcome::AlreadyApplied);
}

#[test]
fn listing_is_deterministically_ordered_by_key() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = DataStore::open(tmp.path()).expect("open store");

    // Register dataset.
    let create_action: DataActionV1 =
        serde_json::from_str(&fixture("register_dataset_v1.action.canon.json")).unwrap();
    let create_env = DataEnvelopeV1::new(create_action).unwrap();
    let dataset_id = apply(&create_env, &store).unwrap().dataset_id.unwrap();

    // Apply two licenses in reverse order of their license_id hex to ensure store ordering is key-based.
    let base: DataActionV1 =
        serde_json::from_str(&fixture("issue_license_v1.action.canon.json")).unwrap();
    let DataActionV1::IssueLicenseV1(a) = base else {
        panic!("expected issue license action");
    };
    let mut b = a.clone();
    // Change nonce so the derived license_id changes deterministically.
    b.nonce = "lic-002".to_string();
    b.license_id = hub_data::validation::derive_license_id(
        b.dataset_id,
        &b.licensee,
        b.rights,
        b.terms_hash.as_ref(),
        b.expires_at,
        &b.nonce,
    );

    // Apply in whichever order, then assert returned list is sorted by key.
    let env_a = DataEnvelopeV1::new(DataActionV1::IssueLicenseV1(a.clone())).unwrap();
    let env_b = DataEnvelopeV1::new(DataActionV1::IssueLicenseV1(b.clone())).unwrap();
    apply(&env_b, &store).unwrap();
    apply(&env_a, &store).unwrap();

    let ids = store.list_license_ids_by_dataset(dataset_id).unwrap();
    assert_eq!(ids.len(), 2);
    assert!(ids[0].to_hex() <= ids[1].to_hex());
}

#[test]
fn export_snapshot_is_deterministic_and_sorted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = DataStore::open(tmp.path()).expect("open store");

    // Register dataset.
    let create_action: DataActionV1 =
        serde_json::from_str(&fixture("register_dataset_v1.action.canon.json")).unwrap();
    let create_env = DataEnvelopeV1::new(create_action).unwrap();
    let dataset_id = apply(&create_env, &store).unwrap().dataset_id.unwrap();

    // Two licenses, applied in non-sorted order.
    let base: DataActionV1 =
        serde_json::from_str(&fixture("issue_license_v1.action.canon.json")).unwrap();
    let DataActionV1::IssueLicenseV1(a) = base else {
        panic!("expected issue license action");
    };
    let mut b = a.clone();
    b.nonce = "lic-002".to_string();
    b.license_id = hub_data::validation::derive_license_id(
        b.dataset_id,
        &b.licensee,
        b.rights,
        b.terms_hash.as_ref(),
        b.expires_at,
        &b.nonce,
    );
    apply(
        &DataEnvelopeV1::new(DataActionV1::IssueLicenseV1(b.clone())).unwrap(),
        &store,
    )
    .unwrap();
    apply(
        &DataEnvelopeV1::new(DataActionV1::IssueLicenseV1(a.clone())).unwrap(),
        &store,
    )
    .unwrap();

    let snap1 = store.export_snapshot_v1().unwrap();
    let snap2 = store.export_snapshot_v1().unwrap();
    let j1 = serde_json::to_string_pretty(&snap1).unwrap();
    let j2 = serde_json::to_string_pretty(&snap2).unwrap();
    assert_eq!(j1, j2);

    assert_eq!(snap1.schema_version, 1);
    assert_eq!(snap1.datasets.len(), 1);
    assert_eq!(snap1.datasets[0].dataset.dataset_id, dataset_id);
    assert_eq!(snap1.datasets[0].licenses.len(), 2);
    assert!(
        snap1.datasets[0].licenses[0].license_id.to_hex()
            <= snap1.datasets[0].licenses[1].license_id.to_hex()
    );
}

#[allow(dead_code)]
fn _use_rights_enum_for_clippy(_r: LicenseRightsV1) {}
