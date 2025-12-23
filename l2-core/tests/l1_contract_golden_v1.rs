//! Golden fixtures for the L1 ↔ L2 contract v1.

use base64::Engine as _;
use l2_core::l1_contract::{derive_idempotency_key_v1, HubPayloadEnvelopeV1, L2BatchEnvelopeV1};

const HUB_PAYLOAD_V1: &str = include_str!("fixtures/l1_contract/v1/hub_payload_envelope_v1.json");
const L2_BATCH_V1: &str = include_str!("fixtures/l1_contract/v1/l2_batch_envelope_v1.json");
const EXPECTED: &str = include_str!("fixtures/l1_contract/v1/expected_hashes.json");

#[derive(Debug, serde::Deserialize)]
struct Expected {
    hub_payload_envelope_v1_canonical_blake3_b64url: String,
    l2_batch_envelope_v1_canonical_blake3_b64url: String,
    l2_batch_envelope_v1_idempotency_key_b64url: String,
}

fn b64url32(bytes: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[test]
fn test_fixture_roundtrip_v1() {
    let hub: HubPayloadEnvelopeV1 = serde_json::from_str(HUB_PAYLOAD_V1).expect("deserialize hub payload v1");
    let hub_json = serde_json::to_string(&hub).expect("serialize hub payload v1");
    let hub2: HubPayloadEnvelopeV1 = serde_json::from_str(&hub_json).expect("roundtrip hub payload v1");
    assert_eq!(hub, hub2);

    let batch: L2BatchEnvelopeV1 = serde_json::from_str(L2_BATCH_V1).expect("deserialize batch v1");
    let batch_json = serde_json::to_string(&batch).expect("serialize batch v1");
    let batch2: L2BatchEnvelopeV1 = serde_json::from_str(&batch_json).expect("roundtrip batch v1");
    assert_eq!(batch, batch2);
}

#[test]
fn test_idempotency_key_stable_v1() {
    let batch: L2BatchEnvelopeV1 = serde_json::from_str(L2_BATCH_V1).expect("deserialize batch v1");
    let payload_hash = batch.payload.canonical_hash_blake3().expect("payload canonical hash");
    let expected = derive_idempotency_key_v1(
        batch.contract_version,
        batch.hub,
        &batch.batch_id,
        batch.sequence,
        &payload_hash,
    );
    assert_eq!(batch.idempotency_key, expected);
}

#[test]
fn test_canonical_hash_matches_golden_v1() {
    let expected: Expected = serde_json::from_str(EXPECTED).expect("deserialize expected hashes");

    let hub: HubPayloadEnvelopeV1 = serde_json::from_str(HUB_PAYLOAD_V1).expect("deserialize hub payload v1");
    let hub_hash = hub.canonical_hash_blake3().expect("hub canonical hash");
    assert_eq!(
        b64url32(&hub_hash),
        expected.hub_payload_envelope_v1_canonical_blake3_b64url
    );

    let batch: L2BatchEnvelopeV1 = serde_json::from_str(L2_BATCH_V1).expect("deserialize batch v1");
    let batch_hash = batch.canonical_hash_blake3().expect("batch canonical hash");
    assert_eq!(
        b64url32(&batch_hash),
        expected.l2_batch_envelope_v1_canonical_blake3_b64url
    );

    assert_eq!(
        b64url32(batch.idempotency_key.as_bytes()),
        expected.l2_batch_envelope_v1_idempotency_key_b64url
    );
}

