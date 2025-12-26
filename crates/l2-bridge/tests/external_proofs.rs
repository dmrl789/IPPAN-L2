//! Integration tests for external chain proofs and proof-carrying intents.
//!
//! These tests verify the full lifecycle of external proofs including:
//! - Proof submission and storage
//! - Proof verification status updates
//! - Intent gating based on proof verification status
//! - API endpoint behavior

use l2_bridge::{
    eth_adapter::MockVerifier,
    external_proof_api::{ExternalProofApi, ListProofsQuery, SubmitProofRequest},
    external_proof_reconciler::StorageExternalProofChecker,
    intents::{
        ExternalProofChecker, IntentPolicy, IntentRouter, IntentRouterError, MockFinalityChecker,
        MockHubExecutor,
    },
};
use l2_core::{
    canonical_encode, EthReceiptAttestationV1, ExternalChainId, ExternalEventProofV1,
    ExternalProofState, Hash32, Intent, IntentId, IntentKind, L2HubId,
};
use l2_storage::{ExternalProofStorage, IntentStorage};
use std::sync::Arc;
use tempfile::tempdir;

// ============== Test Helpers ==============

fn test_db() -> sled::Db {
    let dir = tempdir().expect("tmpdir");
    sled::open(dir.path()).expect("open")
}

fn test_attestation(suffix: u8) -> ExternalEventProofV1 {
    ExternalEventProofV1::EthReceiptAttestationV1(EthReceiptAttestationV1 {
        chain: ExternalChainId::EthereumMainnet,
        tx_hash: [suffix; 32],
        log_index: 0,
        contract: [0xBB; 20],
        topic0: [0xCC; 32],
        data_hash: [0xDD; 32],
        block_number: 18_000_000,
        block_hash: [0xEE; 32],
        confirmations: 15, // Above default mainnet threshold
        attestor_pubkey: [0x11; 32],
        signature: [0x22; 64],
    })
}

fn test_external_intent(suffix: u8) -> (Intent, IntentId) {
    let payload = serde_json::json!({
        "external_chain": "ethereum_mainnet",
        "external_asset": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "amount": 1000000,
        "recipient": "alice_l2",
        "wrapped_asset_id": "wUSDC",
        "proof_id": hex::encode([suffix; 32])
    });
    let payload_bytes = canonical_encode(&payload).unwrap();
    let intent = Intent {
        kind: IntentKind::ExternalLockAndMint,
        created_ms: 1000,
        expires_ms: 1_700_000_600_000, // Far in the future
        from_hub: L2HubId::Bridge,
        to_hub: L2HubId::Fin,
        initiator: format!("user_{}", suffix),
        payload: payload_bytes,
    };
    let intent_id = intent.compute_id().unwrap();
    (intent, intent_id)
}

fn test_regular_intent(suffix: u8) -> (Intent, IntentId) {
    let payload = serde_json::json!({
        "asset": "IPN",
        "amount": 1000,
        "from": "alice",
        "to": "bob"
    });
    let payload_bytes = canonical_encode(&payload).unwrap();
    let intent = Intent {
        kind: IntentKind::CrossHubTransfer,
        created_ms: 1000,
        expires_ms: 1_700_000_600_000, // Far in the future
        from_hub: L2HubId::Fin,
        to_hub: L2HubId::Data,
        initiator: format!("user_{}", suffix),
        payload: payload_bytes,
    };
    let intent_id = intent.compute_id().unwrap();
    (intent, intent_id)
}

fn test_submit_request(suffix: u8) -> SubmitProofRequest {
    SubmitProofRequest {
        proof_type: "eth_receipt_attestation_v1".to_string(),
        chain: "ethereum_mainnet".to_string(),
        tx_hash: hex::encode([suffix; 32]),
        log_index: 0,
        contract: hex::encode([0xBB; 20]),
        topic0: hex::encode([0xCC; 32]),
        data_hash: hex::encode([0xDD; 32]),
        block_number: 18_000_000,
        block_hash: hex::encode([0xEE; 32]),
        confirmations: Some(15),
        attestor_pubkey: Some(hex::encode([0x11; 32])),
        signature: Some(hex::encode([0x22; 64])),
    }
}

fn setup_router(db: &sled::Db) -> IntentRouter {
    let intent_storage = IntentStorage::new(db).unwrap();
    let policy = IntentPolicy::default();
    let finality_checker = Arc::new(MockFinalityChecker { is_finalised: true });
    let mut router = IntentRouter::new(intent_storage, policy, finality_checker);

    // Register mock executors for all hubs
    router.register_executor(L2HubId::Fin, Arc::new(MockHubExecutor::new(L2HubId::Fin)));
    router.register_executor(L2HubId::Data, Arc::new(MockHubExecutor::new(L2HubId::Data)));
    router.register_executor(
        L2HubId::World,
        Arc::new(MockHubExecutor::new(L2HubId::World)),
    );
    router.register_executor(L2HubId::M2m, Arc::new(MockHubExecutor::new(L2HubId::M2m)));
    router.register_executor(
        L2HubId::Bridge,
        Arc::new(MockHubExecutor::new(L2HubId::Bridge)),
    );

    router
}

// ============== Test: Proof Storage Lifecycle ==============

#[test]
fn proof_storage_lifecycle() {
    let db = test_db();
    let storage = ExternalProofStorage::new(&db).unwrap();

    let proof = test_attestation(0x01);
    let proof_id = proof.proof_id().unwrap();

    // Store proof
    let was_new = storage.put_proof_if_absent(&proof, 1000).unwrap();
    assert!(was_new);

    // Should not be new on second insert
    let was_new2 = storage.put_proof_if_absent(&proof, 2000).unwrap();
    assert!(!was_new2);

    // Check state is Unverified
    let state = storage.get_proof_state(&proof_id).unwrap().unwrap();
    assert!(matches!(state, ExternalProofState::Unverified));

    // Update to Verified
    storage
        .set_proof_state(&proof_id, ExternalProofState::verified(3000))
        .unwrap();

    let state2 = storage.get_proof_state(&proof_id).unwrap().unwrap();
    assert!(matches!(state2, ExternalProofState::Verified { .. }));

    // Cannot transition from Verified to Rejected
    let result = storage.set_proof_state(
        &proof_id,
        ExternalProofState::rejected("test".to_string(), 4000),
    );
    assert!(result.is_err());
}

// ============== Test: Proof-Intent Binding ==============

#[test]
fn proof_intent_binding() {
    let db = test_db();
    let storage = ExternalProofStorage::new(&db).unwrap();

    let proof = test_attestation(0x02);
    let proof_id = proof.proof_id().unwrap();
    let intent_id = IntentId(Hash32([0x99; 32]));

    // Store proof
    storage.put_proof_if_absent(&proof, 1000).unwrap();

    // Bind to intent
    storage
        .bind_proof_to_intent(&proof_id, &intent_id, 2000)
        .unwrap();

    // List proofs for intent
    let proofs = storage.list_proofs_for_intent(&intent_id, 100).unwrap();
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].proof_id, proof_id);

    // Check all_proofs_verified (should be false, proof is Unverified)
    let all_verified = storage.all_proofs_verified_for_intent(&intent_id).unwrap();
    assert!(!all_verified);

    // Verify the proof
    storage
        .set_proof_state(&proof_id, ExternalProofState::verified(3000))
        .unwrap();

    // Now all_proofs_verified should be true
    let all_verified2 = storage.all_proofs_verified_for_intent(&intent_id).unwrap();
    assert!(all_verified2);
}

// ============== Test: Multiple Proofs Per Intent ==============

#[test]
fn multiple_proofs_per_intent() {
    let db = test_db();
    let storage = ExternalProofStorage::new(&db).unwrap();
    let intent_id = IntentId(Hash32([0x88; 32]));

    // Submit and bind 3 proofs
    let mut proof_ids = Vec::new();
    for i in 1u8..4 {
        let proof = test_attestation(i);
        let proof_id = proof.proof_id().unwrap();
        storage.put_proof_if_absent(&proof, 1000).unwrap();
        storage
            .bind_proof_to_intent(&proof_id, &intent_id, 2000)
            .unwrap();
        proof_ids.push(proof_id);
    }

    // All unverified = not ready
    assert!(!storage.all_proofs_verified_for_intent(&intent_id).unwrap());

    // Verify first two
    for proof_id in &proof_ids[0..2] {
        storage
            .set_proof_state(proof_id, ExternalProofState::verified(3000))
            .unwrap();
    }

    // Still not all verified
    assert!(!storage.all_proofs_verified_for_intent(&intent_id).unwrap());

    // Verify the third
    storage
        .set_proof_state(&proof_ids[2], ExternalProofState::verified(4000))
        .unwrap();

    // Now all verified
    assert!(storage.all_proofs_verified_for_intent(&intent_id).unwrap());
}

// ============== Test: External Proof Checker Trait ==============

#[test]
fn storage_external_proof_checker() {
    let db = test_db();
    let storage = Arc::new(ExternalProofStorage::new(&db).unwrap());
    let checker = StorageExternalProofChecker::new(storage.clone());

    let (external_intent, external_intent_id) = test_external_intent(0x10);
    let (regular_intent, _) = test_regular_intent(0x10);

    // External intent requires proof
    assert!(checker.requires_proof(&external_intent));
    // Regular intent does not
    assert!(!checker.requires_proof(&regular_intent));

    // No proofs bound = not verified
    assert!(!checker.all_proofs_verified(&external_intent_id).unwrap());

    // Submit and bind a proof
    let proof = test_attestation(0x10);
    let proof_id = proof.proof_id().unwrap();
    storage.put_proof_if_absent(&proof, 1000).unwrap();
    storage
        .bind_proof_to_intent(&proof_id, &external_intent_id, 2000)
        .unwrap();

    // Still not verified (proof is Unverified)
    assert!(!checker.all_proofs_verified(&external_intent_id).unwrap());

    // Verify the proof
    storage
        .set_proof_state(&proof_id, ExternalProofState::verified(3000))
        .unwrap();

    // Now verified
    assert!(checker.all_proofs_verified(&external_intent_id).unwrap());
}

// ============== Test: Intent Gating at Prepare ==============

#[tokio::test]
async fn intent_router_external_proof_gating() {
    let db = test_db();
    let proof_storage = Arc::new(ExternalProofStorage::new(&db).unwrap());
    let checker = Arc::new(StorageExternalProofChecker::new(proof_storage.clone()));

    let mut router = setup_router(&db);
    router.set_external_proof_checker(checker);

    let (intent, intent_id) = test_external_intent(0x20);
    let current_ms = 1_700_000_100_000;

    // Create the intent
    let create_result = router.create_intent(intent.clone(), current_ms).unwrap();
    assert_eq!(create_result.intent_id, intent_id);

    // Try to prepare - should fail (no proof bound)
    let prepare_result = router.prepare_intent(&intent_id, &intent, current_ms).await;
    assert!(matches!(
        prepare_result,
        Err(IntentRouterError::ExternalProofNotVerified { .. })
    ));

    // Submit and bind a proof (unverified)
    let proof = test_attestation(0x20);
    let proof_id = proof.proof_id().unwrap();
    proof_storage.put_proof_if_absent(&proof, 3000).unwrap();
    proof_storage
        .bind_proof_to_intent(&proof_id, &intent_id, 3000)
        .unwrap();

    // Try to prepare - should still fail (proof not verified)
    let prepare_result2 = router.prepare_intent(&intent_id, &intent, current_ms).await;
    assert!(matches!(
        prepare_result2,
        Err(IntentRouterError::ExternalProofNotVerified { .. })
    ));

    // Verify the proof
    proof_storage
        .set_proof_state(&proof_id, ExternalProofState::verified(5000))
        .unwrap();

    // Now prepare should succeed
    let prepare_result3 = router.prepare_intent(&intent_id, &intent, current_ms).await;
    assert!(prepare_result3.is_ok());
}

// ============== Test: Regular Intents Not Gated ==============

#[tokio::test]
async fn regular_intents_not_gated() {
    let db = test_db();
    let proof_storage = Arc::new(ExternalProofStorage::new(&db).unwrap());
    let checker = Arc::new(StorageExternalProofChecker::new(proof_storage.clone()));

    let mut router = setup_router(&db);
    router.set_external_proof_checker(checker);

    let (intent, intent_id) = test_regular_intent(0x30);
    let current_ms = 1_700_000_100_000;

    // Create the intent
    let create_result = router.create_intent(intent.clone(), current_ms).unwrap();
    assert_eq!(create_result.intent_id, intent_id);

    // Prepare should succeed without any proofs
    let prepare_result = router.prepare_intent(&intent_id, &intent, current_ms).await;
    assert!(prepare_result.is_ok());
}

// ============== Test: API Proof Submission ==============

#[test]
fn api_proof_submission_and_query() {
    let db = test_db();
    let storage = Arc::new(ExternalProofStorage::new(&db).unwrap());
    let api = ExternalProofApi::new(storage.clone());

    // Submit a proof
    let request = test_submit_request(0x40);
    let response = api.submit_proof(request.clone()).unwrap();

    assert!(response.was_new);
    assert!(!response.proof_id.is_empty());
    assert_eq!(response.chain, "ethereum:1");
    assert_eq!(response.proof_type, "eth_receipt_attestation_v1");

    // Query the proof
    let status = api.get_proof(&response.proof_id).unwrap();
    assert_eq!(status.proof_id, response.proof_id);
    assert_eq!(status.state, "unverified");
    assert!(!status.is_verified);

    // List unverified proofs
    let list = api
        .list_proofs(ListProofsQuery {
            state: Some("unverified".to_string()),
            limit: Some(10),
        })
        .unwrap();
    assert_eq!(list.total, 1);

    // Get counts
    let counts = api.get_counts().unwrap();
    assert_eq!(counts.unverified, 1);
    assert_eq!(counts.verified, 0);
    assert_eq!(counts.total, 1);
}

// ============== Test: API Proof Binding ==============

#[test]
fn api_proof_binding_to_intent() {
    let db = test_db();
    let storage = Arc::new(ExternalProofStorage::new(&db).unwrap());
    let api = ExternalProofApi::new(storage.clone());

    // Submit a proof
    let request = test_submit_request(0x50);
    let proof_response = api.submit_proof(request).unwrap();

    // Create an intent ID
    let intent_id = hex::encode([0x50; 32]);

    // Bind proof to intent
    let bind_response = api
        .bind_proof_to_intent(&proof_response.proof_id, &intent_id)
        .unwrap();
    assert_eq!(bind_response.proof_id, proof_response.proof_id);
    assert_eq!(bind_response.intent_id, intent_id);

    // List proofs for intent
    let proofs = api.list_proofs_for_intent(&intent_id, None).unwrap();
    assert_eq!(proofs.total, 1);

    // Check intent proofs verified (should be false)
    let verified = api.check_intent_proofs_verified(&intent_id).unwrap();
    assert!(!verified.all_verified);
    assert_eq!(verified.total_proofs, 1);
    assert_eq!(verified.unverified_count, 1);
}

// ============== Test: Full Workflow ==============

#[tokio::test]
async fn full_external_proof_workflow() {
    let db = test_db();
    let proof_storage = Arc::new(ExternalProofStorage::new(&db).unwrap());

    // Setup API and router
    let api = ExternalProofApi::new(proof_storage.clone());
    let checker = Arc::new(StorageExternalProofChecker::new(proof_storage.clone()));

    let mut router = setup_router(&db);
    router.set_external_proof_checker(checker);

    let current_ms = 1_700_000_100_000;

    // 1. User submits proof via API
    let proof_request = test_submit_request(0x60);
    let proof_response = api.submit_proof(proof_request).unwrap();
    assert!(proof_response.was_new);

    // 2. User creates external intent
    let (intent, intent_id) = test_external_intent(0x60);

    let create_result = router.create_intent(intent.clone(), current_ms).unwrap();
    assert_eq!(create_result.intent_id, intent_id);

    // 3. Bind proof to intent via API
    let intent_id_hex = intent_id.to_hex();
    api.bind_proof_to_intent(&proof_response.proof_id, &intent_id_hex)
        .unwrap();

    // 4. Try to prepare - fails (proof not verified)
    let prepare_result = router.prepare_intent(&intent_id, &intent, current_ms).await;
    assert!(matches!(
        prepare_result,
        Err(IntentRouterError::ExternalProofNotVerified { .. })
    ));

    // 5. Simulate reconciler verifying the proof
    let proof_id = l2_core::ExternalProofId::from_hex(&proof_response.proof_id).unwrap();
    proof_storage
        .set_proof_state(&proof_id, ExternalProofState::verified(3000))
        .unwrap();

    // 6. Check intent proofs verified status via API
    let verified_status = api.check_intent_proofs_verified(&intent_id_hex).unwrap();
    assert!(verified_status.all_verified);

    // 7. Now prepare succeeds
    let prepare_result2 = router.prepare_intent(&intent_id, &intent, current_ms).await;
    assert!(prepare_result2.is_ok());
}

// ============== Test: Chain ID Parsing ==============

#[test]
fn chain_id_parsing() {
    let db = test_db();
    let storage = Arc::new(ExternalProofStorage::new(&db).unwrap());
    let api = ExternalProofApi::new(storage.clone());

    // Mainnet
    let mut request = test_submit_request(0x70);
    request.chain = "ethereum_mainnet".to_string();
    let response = api.submit_proof(request).unwrap();
    assert_eq!(response.chain, "ethereum:1");

    // Sepolia
    let mut request = test_submit_request(0x71);
    request.chain = "sepolia".to_string();
    let response = api.submit_proof(request).unwrap();
    assert_eq!(response.chain, "sepolia:11155111");

    // Holesky
    let mut request = test_submit_request(0x72);
    request.chain = "holesky".to_string();
    let response = api.submit_proof(request).unwrap();
    assert_eq!(response.chain, "holesky:17000");

    // Custom chain
    let mut request = test_submit_request(0x73);
    request.chain = "42161:arbitrum".to_string();
    let response = api.submit_proof(request).unwrap();
    assert_eq!(response.chain, "arbitrum:42161");
}

// ============== Test: Idempotent Proof Submission ==============

#[test]
fn idempotent_proof_submission() {
    let db = test_db();
    let storage = Arc::new(ExternalProofStorage::new(&db).unwrap());
    let api = ExternalProofApi::new(storage.clone());

    let request = test_submit_request(0x80);

    // First submission
    let response1 = api.submit_proof(request.clone()).unwrap();
    assert!(response1.was_new);

    // Second submission (same proof)
    let response2 = api.submit_proof(request).unwrap();
    assert!(!response2.was_new);
    assert_eq!(response1.proof_id, response2.proof_id);

    // Count should still be 1
    let counts = api.get_counts().unwrap();
    assert_eq!(counts.total, 1);
}

// ============== Test: Rejected Proof Blocks Intent ==============

#[tokio::test]
async fn rejected_proof_blocks_intent() {
    let db = test_db();
    let proof_storage = Arc::new(ExternalProofStorage::new(&db).unwrap());
    let checker = Arc::new(StorageExternalProofChecker::new(proof_storage.clone()));

    let mut router = setup_router(&db);
    router.set_external_proof_checker(checker);

    let (intent, intent_id) = test_external_intent(0x90);
    let current_ms = 1_700_000_100_000;

    // Create intent
    router.create_intent(intent.clone(), current_ms).unwrap();

    // Submit and bind a proof, then reject it
    let proof = test_attestation(0x90);
    let proof_id = proof.proof_id().unwrap();
    proof_storage.put_proof_if_absent(&proof, 2000).unwrap();
    proof_storage
        .bind_proof_to_intent(&proof_id, &intent_id, 2000)
        .unwrap();

    // Reject the proof
    proof_storage
        .set_proof_state(
            &proof_id,
            ExternalProofState::rejected("invalid signature".to_string(), 3000),
        )
        .unwrap();

    // Prepare should still fail (rejected != verified)
    let prepare_result = router.prepare_intent(&intent_id, &intent, current_ms).await;
    assert!(matches!(
        prepare_result,
        Err(IntentRouterError::ExternalProofNotVerified { .. })
    ));
}

// ============== Test: Empty Intent Has No Proofs ==============

#[test]
fn empty_intent_no_proofs() {
    let db = test_db();
    let storage = Arc::new(ExternalProofStorage::new(&db).unwrap());
    let checker = StorageExternalProofChecker::new(storage.clone());

    let intent_id = IntentId(Hash32([0xAA; 32]));

    // No proofs bound = all_proofs_verified returns false
    // (intent with no proofs is not considered ready)
    assert!(!checker.all_proofs_verified(&intent_id).unwrap());
}

// ============== Test: Proof Counts ==============

#[test]
fn proof_counts() {
    let db = test_db();
    let storage = ExternalProofStorage::new(&db).unwrap();

    // Initial counts
    let counts = storage.count_proofs().unwrap();
    assert_eq!(counts.total(), 0);

    // Add some proofs
    for i in 1u8..6 {
        let proof = test_attestation(i);
        storage.put_proof_if_absent(&proof, 1000).unwrap();
    }

    // Verify one, reject one
    let proof1 = test_attestation(1);
    let proof2 = test_attestation(2);
    let id1 = proof1.proof_id().unwrap();
    let id2 = proof2.proof_id().unwrap();

    storage
        .set_proof_state(&id1, ExternalProofState::verified(2000))
        .unwrap();

    storage
        .set_proof_state(&id2, ExternalProofState::rejected("test".to_string(), 2000))
        .unwrap();

    let counts = storage.count_proofs().unwrap();
    assert_eq!(counts.total(), 5);
    assert_eq!(counts.unverified, 3);
    assert_eq!(counts.verified, 1);
    assert_eq!(counts.rejected, 1);
}

// ============== Test: Mock Verifier ==============

#[test]
fn mock_verifier_accepts_all() {
    use l2_bridge::eth_adapter::ExternalVerifier;

    let verifier = MockVerifier::accepting();
    let proof = test_attestation(0xAA);

    let result = verifier.verify(&proof, None);
    assert!(result.is_ok());
}

#[test]
fn mock_verifier_rejects_all() {
    use l2_bridge::eth_adapter::ExternalVerifier;

    let verifier = MockVerifier::rejecting();
    let proof = test_attestation(0xBB);

    let result = verifier.verify(&proof, None);
    assert!(result.is_err());
}
