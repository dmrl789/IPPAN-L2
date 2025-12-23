use hub_data::{
    apply_with_policy, AddAttestorV1, AddLicensorV1, AppendAttestationV1, AttestationPolicyV1,
    CreateListingV1, DataActionV1, DataEnvelopeV1, DataStore, GrantEntitlementV1, Hex32,
    LicenseRightsV1, PriceMicrounitsU128, RegisterDatasetV1,
};
use l2_core::hub_linkage::{PaymentRef, PurchaseId};
use l2_core::policy::PolicyMode;
use l2_core::AccountId;

fn mk_dataset(owner: &AccountId, att_policy: AttestationPolicyV1) -> RegisterDatasetV1 {
    let content_hash =
        Hex32::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
    let dataset_id = hub_data::validation::derive_dataset_id(owner, "D", &content_hash, 1);
    RegisterDatasetV1 {
        dataset_id,
        owner: owner.clone(),
        name: "D".to_string(),
        description: None,
        content_hash,
        pointer_uri: None,
        mime_type: None,
        tags: vec![],
        schema_version: 1,
        attestation_policy: att_policy,
    }
}

#[test]
fn strict_listing_requires_owner_or_allowlisted_licensor() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = DataStore::open(tmp.path()).expect("open store");

    let owner = AccountId::new("acc-owner");
    let licensor = AccountId::new("acc-licensor");

    // register dataset
    let ds = mk_dataset(&owner, AttestationPolicyV1::Anyone);
    let env = DataEnvelopeV1::new(DataActionV1::RegisterDatasetV1(ds.clone())).unwrap();
    apply_with_policy(&env, &store, PolicyMode::Strict, &[]).unwrap();

    // attempt listing by non-owner (not allowlisted)
    let listing = CreateListingV1 {
        dataset_id: ds.dataset_id,
        listing_id: hub_data::validation::derive_listing_id_v1(
            ds.dataset_id,
            &licensor,
            PriceMicrounitsU128(1),
            &Hex32::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap(),
            LicenseRightsV1::Use,
            None,
        ),
        licensor: licensor.clone(),
        rights: LicenseRightsV1::Use,
        price_microunits: PriceMicrounitsU128(1),
        currency_asset_id: Hex32::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap(),
        terms_uri: None,
        terms_hash: None,
    };
    let env = DataEnvelopeV1::new(DataActionV1::CreateListingV1(listing.clone())).unwrap();
    let err = apply_with_policy(&env, &store, PolicyMode::Strict, &[])
        .unwrap_err()
        .to_string();
    assert!(err.contains("policy:unauthorized"), "{err}");

    // allowlist licensor (by owner)
    let add = AddLicensorV1 {
        dataset_id: ds.dataset_id,
        licensor: licensor.clone(),
        actor: owner.clone(),
    };
    let env = DataEnvelopeV1::new(DataActionV1::AddLicensorV1(add)).unwrap();
    apply_with_policy(&env, &store, PolicyMode::Strict, &[]).unwrap();

    // listing now allowed
    let env = DataEnvelopeV1::new(DataActionV1::CreateListingV1(listing)).unwrap();
    let r = apply_with_policy(&env, &store, PolicyMode::Strict, &[]).unwrap();
    assert_eq!(r.outcome, hub_data::ApplyOutcome::Applied);
}

#[test]
fn strict_attestation_allowlist_is_enforced() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = DataStore::open(tmp.path()).expect("open store");

    let owner = AccountId::new("acc-owner");
    let attestor = AccountId::new("acc-attestor");
    let ds = mk_dataset(&owner, AttestationPolicyV1::AllowlistOnly);
    let env = DataEnvelopeV1::new(DataActionV1::RegisterDatasetV1(ds.clone())).unwrap();
    apply_with_policy(&env, &store, PolicyMode::Strict, &[]).unwrap();

    let att = AppendAttestationV1 {
        dataset_id: ds.dataset_id,
        attestation_id: hub_data::validation::derive_attestation_id(
            ds.dataset_id,
            &attestor,
            &Hex32::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap(),
            None,
            "n1",
        ),
        attestor: attestor.clone(),
        statement: None,
        statement_hash: Hex32::from_hex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap(),
        ref_hash: None,
        ref_uri: None,
        nonce: "n1".to_string(),
    };
    let env = DataEnvelopeV1::new(DataActionV1::AppendAttestationV1(att.clone())).unwrap();
    let err = apply_with_policy(&env, &store, PolicyMode::Strict, &[])
        .unwrap_err()
        .to_string();
    assert!(err.contains("policy:unauthorized"), "{err}");

    // allowlist attestor and retry
    let add = AddAttestorV1 {
        dataset_id: ds.dataset_id,
        attestor: attestor.clone(),
        actor: owner,
    };
    let env = DataEnvelopeV1::new(DataActionV1::AddAttestorV1(add)).unwrap();
    apply_with_policy(&env, &store, PolicyMode::Strict, &[]).unwrap();

    let env = DataEnvelopeV1::new(DataActionV1::AppendAttestationV1(att)).unwrap();
    let r = apply_with_policy(&env, &store, PolicyMode::Strict, &[]).unwrap();
    assert_eq!(r.outcome, hub_data::ApplyOutcome::Applied);
}

#[test]
fn strict_grant_entitlement_requires_actor() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = DataStore::open(tmp.path()).expect("open store");
    let owner = AccountId::new("acc-owner");
    let ds = mk_dataset(&owner, AttestationPolicyV1::Anyone);
    apply_with_policy(
        &DataEnvelopeV1::new(DataActionV1::RegisterDatasetV1(ds.clone())).unwrap(),
        &store,
        PolicyMode::Strict,
        &[],
    )
    .unwrap();

    // Seed a listing (by owner).
    let listing = CreateListingV1 {
        dataset_id: ds.dataset_id,
        listing_id: hub_data::validation::derive_listing_id_v1(
            ds.dataset_id,
            &owner,
            PriceMicrounitsU128(1),
            &Hex32::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap(),
            LicenseRightsV1::Use,
            None,
        ),
        licensor: owner.clone(),
        rights: LicenseRightsV1::Use,
        price_microunits: PriceMicrounitsU128(1),
        currency_asset_id: Hex32::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap(),
        terms_uri: None,
        terms_hash: None,
    };
    apply_with_policy(
        &DataEnvelopeV1::new(DataActionV1::CreateListingV1(listing.clone())).unwrap(),
        &store,
        PolicyMode::Strict,
        &[],
    )
    .unwrap();

    let purchase_id =
        PurchaseId::from_hex("ca5c1349b612332d1faa80dde1f8b2b0c59bf447ff3688c48a9d438ed9d0918c")
            .unwrap();
    let ent = GrantEntitlementV1 {
        purchase_id,
        listing_id: listing.listing_id,
        dataset_id: ds.dataset_id,
        licensee: AccountId::new("acc-buyer"),
        payment_ref: PaymentRef {
            fin_action_id: l2_core::hub_linkage::Hex32::from_hex(
                "2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
            fin_receipt_hash: l2_core::hub_linkage::Hex32::from_hex(
                "3333333333333333333333333333333333333333333333333333333333333333",
            )
            .unwrap(),
        },
        license_id: hub_data::validation::derive_entitlement_license_id_v1(
            ds.dataset_id,
            listing.listing_id,
            &AccountId::new("acc-buyer"),
            &purchase_id,
        ),
        actor: None,
    };
    let env = DataEnvelopeV1::new(DataActionV1::GrantEntitlementV1(ent)).unwrap();
    let err = apply_with_policy(&env, &store, PolicyMode::Strict, &[])
        .unwrap_err()
        .to_string();
    assert!(err.contains("policy:missing_actor"), "{err}");
}
