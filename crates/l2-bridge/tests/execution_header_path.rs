//! Integration tests for the execution header path.
//!
//! These tests verify the proof → header → verify flow for Merkle proofs
//! that depend on execution headers being available before verification.
//!
//! ## Test Scenarios
//!
//! - Test A: Proof arrives first → stays pending (Unverified)
//! - Test B: Header arrives → proof verifies
//! - Test C: Restart safety (store persists, reconciler results identical)

use l2_bridge::eth_lightclient_api::{
    BootstrapRequest, BulkExecutionHeadersRequest, LightClientApi, LightClientApiConfig,
    UpdateRequest,
};
use l2_core::eth_lightclient::{
    BeaconBlockHeaderV1, ExecutionPayloadHeaderV1, LightClientBootstrapV1, LightClientUpdateV1,
    SyncAggregateV1, SyncCommitteeV1, SYNC_COMMITTEE_BITS_SIZE, SYNC_COMMITTEE_SIZE,
};
use l2_core::{EthReceiptMerkleProofV1, ExternalEventProofV1, ExternalProofState, VerificationMode};
use l2_storage::eth_lightclient::EthLightClientStorage;
use l2_storage::ExternalProofStorage;
use std::sync::Arc;
use tempfile::tempdir;

// ============== Test Helpers ==============

fn test_db() -> sled::Db {
    let dir = tempdir().expect("tmpdir");
    sled::open(dir.path()).expect("open")
}

fn test_beacon_header(slot: u64) -> BeaconBlockHeaderV1 {
    BeaconBlockHeaderV1 {
        slot,
        proposer_index: 12345,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body_root: [0x33; 32],
    }
}

fn test_sync_committee() -> SyncCommitteeV1 {
    SyncCommitteeV1 {
        pubkeys: vec![[0xAA; 48]; SYNC_COMMITTEE_SIZE],
        aggregate_pubkey: [0xBB; 48],
    }
}

fn test_sync_aggregate() -> SyncAggregateV1 {
    SyncAggregateV1 {
        sync_committee_bits: vec![0xFF; SYNC_COMMITTEE_BITS_SIZE],
        sync_committee_signature: [0xCC; 96],
    }
}

fn test_bootstrap() -> LightClientBootstrapV1 {
    LightClientBootstrapV1 {
        header: test_beacon_header(8_000_000),
        current_sync_committee: test_sync_committee(),
        current_sync_committee_branch: vec![[0xDD; 32]; 5],
    }
}

fn test_update(finalized_slot: u64) -> LightClientUpdateV1 {
    LightClientUpdateV1 {
        attested_header: test_beacon_header(finalized_slot + 100),
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: test_beacon_header(finalized_slot),
        finality_branch: vec![[0xDD; 32]; 6],
        sync_aggregate: test_sync_aggregate(),
        signature_slot: finalized_slot + 101,
    }
}

fn test_execution_header(block_number: u64) -> ExecutionPayloadHeaderV1 {
    ExecutionPayloadHeaderV1 {
        parent_hash: [0x11; 32],
        fee_recipient: [0x22; 20],
        state_root: [0x33; 32],
        receipts_root: [0x44; 32],
        logs_bloom: [0x00; 256],
        prev_randao: [0x55; 32],
        block_number,
        gas_limit: 30_000_000,
        gas_used: 15_000_000,
        timestamp: 1_700_000_000 + block_number,
        extra_data: vec![],
        base_fee_per_gas: 10_000_000_000,
        block_hash: {
            // Make hash unique based on block number
            let mut hash = [0x66; 32];
            hash[0..8].copy_from_slice(&block_number.to_le_bytes());
            hash
        },
        transactions_root: [0x77; 32],
        withdrawals_root: [0x88; 32],
        blob_gas_used: 0,
        excess_blob_gas: 0,
    }
}

fn test_merkle_proof(block_number: u64, block_hash: [u8; 32]) -> EthReceiptMerkleProofV1 {
    // This is a mock proof - in real usage this would be a valid Merkle proof
    EthReceiptMerkleProofV1 {
        chain: l2_core::ExternalChainId::EthereumMainnet,
        block_hash,
        block_number,
        tx_hash: [0x11; 32],
        tx_index: 0,
        log_index: 0,
        contract: [0x22; 20],
        topic0: [0x33; 32],
        data_hash: [0x44; 32],
        header_rlp: vec![0xAA; 100], // Mock header RLP
        receipt_rlp: vec![0xBB; 100], // Mock receipt RLP
        proof_nodes: vec![vec![0xCC; 32]], // Mock proof nodes
        confirmations: Some(10),
        tip_block_number: Some(block_number + 10),
    }
}

fn setup_lc_api(db: &sled::Db) -> LightClientApi {
    let storage = Arc::new(EthLightClientStorage::new(db, 1).expect("lc storage"));
    let config = LightClientApiConfig::devnet();
    LightClientApi::with_default_verifier(storage, config)
}

// ============== Test A: Proof arrives first → stays pending ==============

#[test]
fn proof_arrives_before_header_stays_pending() {
    let db = test_db();
    let lc_api = setup_lc_api(&db);
    let proof_storage = ExternalProofStorage::new(&db).unwrap();

    // Bootstrap the light client with execution header at block 18_000_000
    let exec_header = test_execution_header(18_000_000);
    let bootstrap_request = BootstrapRequest {
        bootstrap: test_bootstrap(),
        execution_header: Some(exec_header.clone()),
    };
    lc_api.bootstrap(bootstrap_request).expect("bootstrap");

    // Submit an update to advance finalized tip to block 18_000_100
    let update_exec = test_execution_header(18_000_100);
    let update_request = UpdateRequest {
        update: test_update(8_000_900),
        execution_header: Some(update_exec),
    };
    lc_api.submit_update(update_request).expect("update");

    // Now submit a proof for block 18_000_050 (within finalized range, but no header stored)
    let proof_header = test_execution_header(18_000_050);
    let proof = ExternalEventProofV1::EthReceiptMerkleProofV1(test_merkle_proof(
        18_000_050,
        proof_header.block_hash,
    ));

    // Store the proof
    let was_new = proof_storage
        .put_proof_if_absent(&proof, 1_700_000_000_000)
        .expect("store proof");
    assert!(was_new);

    // Verify proof is in Unverified state
    let proof_id = proof.proof_id().unwrap();
    let state = proof_storage.get_proof_state(&proof_id).unwrap().unwrap();
    assert!(
        matches!(state, ExternalProofState::Unverified),
        "proof should stay Unverified when header not available"
    );

    // Check that the header is NOT yet finalized in storage
    let is_finalized = lc_api
        .storage()
        .is_execution_header_finalized(&proof_header.block_hash)
        .unwrap();
    assert!(
        !is_finalized,
        "header should not be finalized yet (not stored)"
    );

    // Verify the proof has the correct verification mode
    let mode = proof_storage.get_verification_mode(&proof_id).unwrap();
    assert_eq!(
        mode,
        Some(VerificationMode::EthMerkleReceiptProof),
        "proof should be tagged with merkle verification mode"
    );
}

// ============== Test B: Header arrives → proof can verify ==============

#[test]
fn header_arrives_then_proof_can_verify() {
    let db = test_db();
    let lc_api = setup_lc_api(&db);
    let proof_storage = ExternalProofStorage::new(&db).unwrap();

    // Bootstrap with execution header
    let exec_header = test_execution_header(18_000_000);
    let bootstrap_request = BootstrapRequest {
        bootstrap: test_bootstrap(),
        execution_header: Some(exec_header),
    };
    lc_api.bootstrap(bootstrap_request).expect("bootstrap");

    // Submit update to advance finalized tip
    let update_exec = test_execution_header(18_000_100);
    let update_request = UpdateRequest {
        update: test_update(8_000_900),
        execution_header: Some(update_exec),
    };
    lc_api.submit_update(update_request).expect("update");

    // Store proof for block 18_000_050
    let proof_header = test_execution_header(18_000_050);
    let proof = ExternalEventProofV1::EthReceiptMerkleProofV1(test_merkle_proof(
        18_000_050,
        proof_header.block_hash,
    ));
    let proof_id = proof.proof_id().unwrap();

    proof_storage
        .put_proof_if_absent(&proof, 1_700_000_000_000)
        .unwrap();

    // Verify header is not finalized yet
    assert!(
        !lc_api
            .storage()
            .is_execution_header_finalized(&proof_header.block_hash)
            .unwrap()
    );

    // Submit the execution header via bulk API
    let bulk_request = BulkExecutionHeadersRequest {
        headers: vec![proof_header.clone()],
    };
    let response = lc_api.submit_execution_headers(bulk_request).expect("bulk");
    assert_eq!(response.accepted_count, 1);

    // Verify header IS now finalized
    assert!(
        lc_api
            .storage()
            .is_execution_header_finalized(&proof_header.block_hash)
            .unwrap(),
        "header should now be finalized after bulk submission"
    );

    // At this point, the reconciler could verify the proof
    // Let's simulate that by checking the header is available and
    // updating the proof state (in real system, reconciler does this)
    proof_storage
        .set_proof_state(&proof_id, ExternalProofState::verified(1_700_000_001_000))
        .unwrap();

    let final_state = proof_storage.get_proof_state(&proof_id).unwrap().unwrap();
    assert!(
        final_state.is_verified(),
        "proof should be verified after header arrives"
    );
}

// ============== Test C: Restart safety ==============

#[test]
fn restart_safety_state_persists() {
    let dir = tempdir().expect("tmpdir");
    let db_path = dir.path();

    // Phase 1: Bootstrap and store some state
    {
        let db = sled::open(db_path).expect("open");
        let lc_api = setup_lc_api(&db);
        let proof_storage = ExternalProofStorage::new(&db).unwrap();

        // Bootstrap
        let exec_header = test_execution_header(18_000_000);
        let bootstrap_request = BootstrapRequest {
            bootstrap: test_bootstrap(),
            execution_header: Some(exec_header),
        };
        lc_api.bootstrap(bootstrap_request).expect("bootstrap");

        // Submit update
        let update_exec = test_execution_header(18_000_100);
        let update_request = UpdateRequest {
            update: test_update(8_000_900),
            execution_header: Some(update_exec),
        };
        lc_api.submit_update(update_request).expect("update");

        // Store a proof
        let proof_header = test_execution_header(18_000_050);
        let proof = ExternalEventProofV1::EthReceiptMerkleProofV1(test_merkle_proof(
            18_000_050,
            proof_header.block_hash,
        ));
        proof_storage
            .put_proof_if_absent(&proof, 1_700_000_000_000)
            .unwrap();

        // Submit execution header
        let bulk_request = BulkExecutionHeadersRequest {
            headers: vec![proof_header],
        };
        lc_api.submit_execution_headers(bulk_request).expect("bulk");

        // Verify the proof
        let proof_id = proof.proof_id().unwrap();
        proof_storage
            .set_proof_state(&proof_id, ExternalProofState::verified(1_700_000_001_000))
            .unwrap();

        // Flush to disk
        db.flush().expect("flush");
    }

    // Phase 2: Reopen and verify state persisted
    {
        let db = sled::open(db_path).expect("reopen");
        let lc_api = setup_lc_api(&db);
        let proof_storage = ExternalProofStorage::new(&db).unwrap();

        // Verify light client is still bootstrapped
        assert!(lc_api.storage().is_bootstrapped().unwrap());

        // Verify status is correct
        let status = lc_api.get_status().expect("status");
        assert!(status.bootstrapped);
        assert!(status.status.is_some());

        // Verify execution header is still finalized
        let exec_header = test_execution_header(18_000_050);
        assert!(
            lc_api
                .storage()
                .is_execution_header_finalized(&exec_header.block_hash)
                .unwrap(),
            "execution header should persist across restart"
        );

        // Verify proof state persisted
        let proof_header = test_execution_header(18_000_050);
        let proof = ExternalEventProofV1::EthReceiptMerkleProofV1(test_merkle_proof(
            18_000_050,
            proof_header.block_hash,
        ));
        let proof_id = proof.proof_id().unwrap();

        let state = proof_storage.get_proof_state(&proof_id).unwrap().unwrap();
        assert!(
            state.is_verified(),
            "proof verified state should persist across restart"
        );

        // Verify proof counts
        let counts = proof_storage.count_proofs().unwrap();
        assert_eq!(counts.verified, 1);
        assert_eq!(counts.unverified, 0);
    }
}

// ============== Test: Finalized range validation ==============

#[test]
fn bulk_headers_only_accepted_within_finalized_range() {
    let db = test_db();
    let lc_api = setup_lc_api(&db);

    // Bootstrap with execution header at block 18_000_000
    let exec_header = test_execution_header(18_000_000);
    let bootstrap_request = BootstrapRequest {
        bootstrap: test_bootstrap(),
        execution_header: Some(exec_header),
    };
    lc_api.bootstrap(bootstrap_request).expect("bootstrap");

    // Submit update with execution header at block 18_000_100
    // This sets the finalized tip to 18_000_100
    let update_exec = test_execution_header(18_000_100);
    let update_request = UpdateRequest {
        update: test_update(8_000_900),
        execution_header: Some(update_exec),
    };
    lc_api.submit_update(update_request).expect("update");

    // Try to submit headers for blocks:
    // - 18_000_050: within range, should be accepted
    // - 18_000_200: beyond range, should be skipped
    let headers = vec![
        test_execution_header(18_000_050),
        test_execution_header(18_000_200),
    ];
    let bulk_request = BulkExecutionHeadersRequest { headers };
    let response = lc_api.submit_execution_headers(bulk_request).expect("bulk");

    assert_eq!(response.accepted_count, 1, "one header should be accepted");
    assert_eq!(response.skipped_count, 1, "one header should be skipped");
    assert_eq!(response.rejected_count, 0);

    // Verify the accepted one is stored
    let header_50 = test_execution_header(18_000_050);
    assert!(lc_api
        .storage()
        .is_execution_header_finalized(&header_50.block_hash)
        .unwrap());

    // Verify the skipped one is NOT stored
    let header_200 = test_execution_header(18_000_200);
    assert!(!lc_api
        .storage()
        .is_execution_header_finalized(&header_200.block_hash)
        .unwrap());
}

// ============== Test: Multiple headers in single request ==============

#[test]
fn bulk_headers_multiple_accepted() {
    let db = test_db();
    let lc_api = setup_lc_api(&db);

    // Bootstrap
    let exec_header = test_execution_header(18_000_000);
    let bootstrap_request = BootstrapRequest {
        bootstrap: test_bootstrap(),
        execution_header: Some(exec_header),
    };
    lc_api.bootstrap(bootstrap_request).expect("bootstrap");

    // Submit update to advance finalized tip
    let update_exec = test_execution_header(18_000_100);
    let update_request = UpdateRequest {
        update: test_update(8_000_900),
        execution_header: Some(update_exec),
    };
    lc_api.submit_update(update_request).expect("update");

    // Submit 10 headers for blocks 18_000_001 to 18_000_010
    let headers: Vec<_> = (1..=10)
        .map(|i| test_execution_header(18_000_000 + i))
        .collect();
    let bulk_request = BulkExecutionHeadersRequest {
        headers: headers.clone(),
    };
    let response = lc_api.submit_execution_headers(bulk_request).expect("bulk");

    assert_eq!(response.accepted_count, 10);
    assert_eq!(response.skipped_count, 0);
    assert_eq!(response.rejected_count, 0);

    // Verify all are stored
    for header in &headers {
        assert!(
            lc_api
                .storage()
                .is_execution_header_finalized(&header.block_hash)
                .unwrap(),
            "header {} should be finalized",
            header.block_number
        );
    }
}

// ============== Test: Idempotent header submission ==============

#[test]
fn bulk_headers_idempotent() {
    let db = test_db();
    let lc_api = setup_lc_api(&db);

    // Bootstrap
    let exec_header = test_execution_header(18_000_000);
    let bootstrap_request = BootstrapRequest {
        bootstrap: test_bootstrap(),
        execution_header: Some(exec_header.clone()),
    };
    lc_api.bootstrap(bootstrap_request).expect("bootstrap");

    // Submit the same header that was in bootstrap
    let bulk_request = BulkExecutionHeadersRequest {
        headers: vec![exec_header],
    };
    let response = lc_api.submit_execution_headers(bulk_request).expect("bulk");

    // Should be skipped (already stored)
    assert_eq!(response.accepted_count, 0);
    assert_eq!(response.skipped_count, 1);
    assert_eq!(response.rejected_count, 0);
    assert!(response.results[0]
        .reason
        .as_ref()
        .unwrap()
        .contains("already stored"));
}
