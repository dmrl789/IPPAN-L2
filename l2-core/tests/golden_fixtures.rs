//! Golden fixture tests for API stability.
//!
//! These tests ensure that serialization format remains stable
//! across versions, preventing accidental breaking changes.

use l2_core::{FixedAmount, L2Batch, L2BatchId, L2HubId, SettlementRequest};

const L2_BATCH_FIXTURE: &str = include_str!("fixtures/l2_batch.json");
const SETTLEMENT_REQUEST_FIXTURE: &str = include_str!("fixtures/settlement_request.json");

#[test]
fn deserialize_l2_batch_fixture() {
    let batch: L2Batch =
        serde_json::from_str(L2_BATCH_FIXTURE).expect("Failed to deserialize L2Batch fixture");

    assert_eq!(batch.hub, L2HubId::Fin);
    assert_eq!(batch.batch_id.0, "batch-golden-001");
    assert_eq!(batch.tx_count, 42);
    assert_eq!(batch.commitment, Some("0xdeadbeef".to_string()));
}

#[test]
fn roundtrip_l2_batch_fixture() {
    let batch: L2Batch =
        serde_json::from_str(L2_BATCH_FIXTURE).expect("Failed to deserialize L2Batch fixture");

    let reserialized = serde_json::to_string(&batch).expect("Failed to reserialize");
    let batch2: L2Batch =
        serde_json::from_str(&reserialized).expect("Failed to deserialize reserialized");

    assert_eq!(batch.hub, batch2.hub);
    assert_eq!(batch.batch_id.0, batch2.batch_id.0);
    assert_eq!(batch.tx_count, batch2.tx_count);
    assert_eq!(batch.commitment, batch2.commitment);
}

#[test]
fn deserialize_settlement_request_fixture() {
    let request: SettlementRequest = serde_json::from_str(SETTLEMENT_REQUEST_FIXTURE)
        .expect("Failed to deserialize SettlementRequest fixture");

    assert_eq!(request.hub, L2HubId::Fin);
    assert_eq!(request.batch.batch_id.0, "batch-golden-002");
    assert_eq!(request.batch.tx_count, 10);
    assert_eq!(request.fee.into_scaled(), 1_000_000);
}

#[test]
fn roundtrip_settlement_request_fixture() {
    let request: SettlementRequest = serde_json::from_str(SETTLEMENT_REQUEST_FIXTURE)
        .expect("Failed to deserialize SettlementRequest fixture");

    let reserialized = serde_json::to_string(&request).expect("Failed to reserialize");
    let request2: SettlementRequest =
        serde_json::from_str(&reserialized).expect("Failed to deserialize reserialized");

    assert_eq!(request.hub, request2.hub);
    assert_eq!(request.batch.batch_id.0, request2.batch.batch_id.0);
    assert_eq!(request.fee.into_scaled(), request2.fee.into_scaled());
}

#[test]
fn hub_id_serialization_is_string() {
    // Ensure hub IDs serialize as readable strings, not numbers
    let fin = L2HubId::Fin;
    let json = serde_json::to_string(&fin).unwrap();
    assert_eq!(json, "\"Fin\"");

    let data = L2HubId::Data;
    let json = serde_json::to_string(&data).unwrap();
    assert_eq!(json, "\"Data\"");
}

#[test]
fn batch_id_serialization_is_string() {
    let id = L2BatchId("test-batch".to_string());
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, "\"test-batch\"");
}

#[test]
fn fixed_amount_serialization() {
    let amount = FixedAmount::from_scaled(1_234_567);
    let json = serde_json::to_string(&amount).unwrap();

    // Should serialize the inner value
    assert!(json.contains("1234567"));

    // Roundtrip
    let amount2: FixedAmount = serde_json::from_str(&json).unwrap();
    assert_eq!(amount.into_scaled(), amount2.into_scaled());
}
