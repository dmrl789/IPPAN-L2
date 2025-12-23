use hub_data::canonical::canonical_json_bytes;
use hub_data::{
    CreateListingV1, DataActionV1, DataEnvelopeV1, GrantEntitlementV1, Hex32, PriceMicrounitsU128,
};
use hub_data::{IssueLicenseV1, LicenseRightsV1, RegisterDatasetV1};
use l2_core::AccountId;

// Helper test to print canonical bytes + hashes for fixtures.
// Run with: `cargo test -p hub-data --test gen_goldens -- --ignored --nocapture`
#[test]
#[ignore]
fn print_goldens() {
    let dataset = RegisterDatasetV1 {
        dataset_id: hub_data::validation::derive_dataset_id(
            &AccountId::new("acc-alice"),
            "Example Dataset v1",
            &Hex32::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap(),
            1,
        ),
        owner: AccountId::new("acc-alice"),
        name: "Example Dataset v1".to_string(),
        description: Some("A small example dataset for HUB-DATA MVP v1 fixtures.".to_string()),
        content_hash: Hex32::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap(),
        pointer_uri: Some("ipfs://bafybeigdyrztl5example".to_string()),
        mime_type: Some("application/json".to_string()),
        tags: vec![
            "ai".to_string(),
            "dataset".to_string(),
            "example".to_string(),
        ],
        schema_version: 1,
    };

    let register_action = DataActionV1::RegisterDatasetV1(dataset.clone());
    let register_env = DataEnvelopeV1::new(register_action.clone()).unwrap();

    let license = IssueLicenseV1 {
        dataset_id: dataset.dataset_id,
        license_id: hub_data::validation::derive_license_id(
            dataset.dataset_id,
            &AccountId::new("acc-bob"),
            LicenseRightsV1::Use,
            Some(
                &Hex32::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
            ),
            Some(2_000_000_000),
            "lic-001",
        ),
        licensor: AccountId::new("acc-alice"),
        licensee: AccountId::new("acc-bob"),
        rights: LicenseRightsV1::Use,
        terms_uri: Some("https://example.com/terms/v1".to_string()),
        terms_hash: Some(
            Hex32::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap(),
        ),
        expires_at: Some(2_000_000_000),
        price_microunits: Some(PriceMicrounitsU128(1_000_000)),
        nonce: "lic-001".to_string(),
    };

    let license_action = DataActionV1::IssueLicenseV1(license.clone());
    let license_env = DataEnvelopeV1::new(license_action.clone()).unwrap();

    let statement = "quality:good".to_string();
    let mut statement_hash_bytes = [0u8; 32];
    statement_hash_bytes.copy_from_slice(blake3::hash(statement.as_bytes()).as_bytes());
    let att = hub_data::AppendAttestationV1 {
        dataset_id: dataset.dataset_id,
        attestation_id: hub_data::validation::derive_attestation_id(
            dataset.dataset_id,
            &AccountId::new("acc-carol"),
            &Hex32(statement_hash_bytes),
            None,
            "att-001",
        ),
        attestor: AccountId::new("acc-carol"),
        statement: Some(statement),
        statement_hash: Hex32(statement_hash_bytes),
        ref_hash: None,
        ref_uri: Some("https://example.com/eval/001".to_string()),
        nonce: "att-001".to_string(),
    };
    let att_action = DataActionV1::AppendAttestationV1(att.clone());
    let att_env = DataEnvelopeV1::new(att_action.clone()).unwrap();

    let listing = CreateListingV1 {
        dataset_id: dataset.dataset_id,
        listing_id: hub_data::validation::derive_listing_id_v1(
            dataset.dataset_id,
            &AccountId::new("acc-alice"),
            PriceMicrounitsU128(1_000_000),
            &Hex32::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap(),
            LicenseRightsV1::Use,
            Some(
                &Hex32::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
            ),
        ),
        licensor: AccountId::new("acc-alice"),
        rights: LicenseRightsV1::Use,
        price_microunits: PriceMicrounitsU128(1_000_000),
        currency_asset_id: Hex32::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap(),
        terms_uri: Some("https://example.com/terms/v1".to_string()),
        terms_hash: Some(
            Hex32::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap(),
        ),
    };
    let listing_action = DataActionV1::CreateListingV1(listing.clone());
    let listing_env = DataEnvelopeV1::new(listing_action.clone()).unwrap();

    let purchase_id = l2_core::hub_linkage::derive_purchase_id_v1(
        &l2_core::hub_linkage::Hex32(dataset.dataset_id.0),
        &AccountId::new("acc-bob"),
        1_000_000,
        &l2_core::hub_linkage::Hex32(listing.currency_asset_id.0),
        Some(&l2_core::hub_linkage::Hex32(
            listing.terms_hash.as_ref().unwrap().0,
        )),
        "nonce-001",
    );
    let ent = GrantEntitlementV1 {
        purchase_id,
        listing_id: listing.listing_id,
        dataset_id: dataset.dataset_id,
        licensee: AccountId::new("acc-bob"),
        payment_ref: l2_core::hub_linkage::PaymentRef {
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
            dataset.dataset_id,
            listing.listing_id,
            &AccountId::new("acc-bob"),
            &purchase_id,
        ),
    };
    let ent_action = DataActionV1::GrantEntitlementV1(ent.clone());
    let ent_env = DataEnvelopeV1::new(ent_action.clone()).unwrap();

    for (label, action, env) in [
        ("register_dataset_v1", register_action, register_env),
        ("issue_license_v1", license_action, license_env),
        ("append_attestation_v1", att_action, att_env),
        ("create_listing_v1", listing_action, listing_env),
        ("grant_entitlement_v1", ent_action, ent_env),
    ] {
        let action_bytes = canonical_json_bytes(&action).unwrap();
        let action_hash = blake3::hash(&action_bytes);
        let env_bytes = env.canonical_bytes().unwrap();

        println!("== {label} ==");
        println!("action_id_hex={}", hex::encode(action_hash.as_bytes()));
        println!("envelope_action_id_hex={}", env.action_id.to_hex());
        println!(
            "action_canonical_json={}",
            String::from_utf8(action_bytes).unwrap()
        );
        println!(
            "envelope_canonical_json={}",
            String::from_utf8(env_bytes).unwrap()
        );
        println!();
    }
}
