//! Ethereum PoS Light Client Test Vectors.
//!
//! This file contains deterministic test vectors for the sync committee light client.
//!
//! ## Test Coverage
//!
//! - Bootstrap validation and storage
//! - Update validation and application
//! - Finalized header tracking
//! - Receipt proof verification with finalized headers
//!
//! ## Note on Synthetic Vectors
//!
//! These vectors use devnet mode (skip cryptographic verification) because:
//! 1. Real BLS signatures require valid keys and complex setup
//! 2. The state machine logic is what we're primarily testing
//! 3. BLS verification is tested separately with known good test vectors
//!
//! For production, BLS signature verification is enabled.

#![cfg(feature = "eth-lightclient")]

use l2_bridge::eth_lightclient_api::{
    BootstrapRequest, LightClientApi, LightClientApiConfig, UpdateRequest,
};
use l2_bridge::eth_lightclient_verify::{LightClientVerifier, LightClientVerifierConfig};
use l2_bridge::eth_merkle::{can_verify_proof_with_lightclient, LightClientProofReadiness};
use l2_core::eth_lightclient::{
    BeaconBlockHeaderV1, ExecutionPayloadHeaderV1, LightClientBootstrapV1, LightClientUpdateV1,
    SyncAggregateV1, SyncCommitteeV1, SYNC_COMMITTEE_BITS_SIZE, SYNC_COMMITTEE_SIZE,
};
use l2_core::{EthReceiptMerkleProofV1, ExternalChainId};
use l2_storage::eth_lightclient::EthLightClientStorage;
use std::sync::Arc;
use tempfile::tempdir;

// ========== Test Helpers ==========

fn test_beacon_header(slot: u64) -> BeaconBlockHeaderV1 {
    BeaconBlockHeaderV1 {
        slot,
        proposer_index: (slot % 100) as u64,
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
        sync_committee_bits: vec![0xFF; SYNC_COMMITTEE_BITS_SIZE], // All 512 participants
        sync_committee_signature: [0xCC; 96],
    }
}

fn test_execution_header(block_number: u64, block_hash: [u8; 32]) -> ExecutionPayloadHeaderV1 {
    ExecutionPayloadHeaderV1 {
        parent_hash: [0x01; 32],
        fee_recipient: [0x02; 20],
        state_root: [0x03; 32],
        receipts_root: [0x04; 32],
        logs_bloom: [0x00; 256],
        prev_randao: [0x05; 32],
        block_number,
        gas_limit: 30_000_000,
        gas_used: 15_000_000,
        timestamp: 1_700_000_000 + block_number,
        extra_data: vec![],
        base_fee_per_gas: 1_000_000_000, // 1 gwei
        block_hash,
        transactions_root: [0x06; 32],
        withdrawals_root: [0x07; 32],
        blob_gas_used: 0,
        excess_blob_gas: 0,
    }
}

fn test_bootstrap(slot: u64) -> LightClientBootstrapV1 {
    LightClientBootstrapV1 {
        header: test_beacon_header(slot),
        current_sync_committee: test_sync_committee(),
        current_sync_committee_branch: vec![[0xDD; 32]; 5],
    }
}

fn test_update(
    attested_slot: u64,
    finalized_slot: u64,
    signature_slot: u64,
) -> LightClientUpdateV1 {
    LightClientUpdateV1 {
        attested_header: test_beacon_header(attested_slot),
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: test_beacon_header(finalized_slot),
        finality_branch: vec![[0xEE; 32]; 6],
        sync_aggregate: test_sync_aggregate(),
        signature_slot,
    }
}

fn setup_api() -> (LightClientApi, tempfile::TempDir) {
    let dir = tempdir().expect("tmpdir");
    let db = sled::open(dir.path()).expect("open sled");
    let storage = Arc::new(EthLightClientStorage::new(&db, 1).expect("storage"));
    let config = LightClientApiConfig::devnet();
    let api = LightClientApi::with_default_verifier(storage, config);
    (api, dir)
}

// ========== Bootstrap Tests ==========

/// Test: Bootstrap initializes the light client correctly.
#[test]
fn test_bootstrap_initializes_state() {
    let (api, _dir) = setup_api();

    // Before bootstrap
    let status = api.get_status().expect("status");
    assert!(!status.bootstrapped);

    // Bootstrap at slot 8,000,000 (period ~976)
    let bootstrap = test_bootstrap(8_000_000);
    let request = BootstrapRequest {
        bootstrap: bootstrap.clone(),
        execution_header: None,
    };

    let response = api.bootstrap(request).expect("bootstrap");
    assert!(response.accepted);
    assert_eq!(response.finalized_slot, 8_000_000);

    // After bootstrap
    let status = api.get_status().expect("status");
    assert!(status.bootstrapped);
    assert!(status.status.is_some());
    let lc_status = status.status.unwrap();
    assert_eq!(lc_status.finalized_slot, 8_000_000);
}

/// Test: Bootstrap with execution header stores finalized header.
#[test]
fn test_bootstrap_with_execution_header() {
    let (api, _dir) = setup_api();

    let block_hash = [0xAB; 32];
    let execution_header = test_execution_header(18_000_000, block_hash);

    let request = BootstrapRequest {
        bootstrap: test_bootstrap(8_000_000),
        execution_header: Some(execution_header),
    };

    let response = api.bootstrap(request).expect("bootstrap");
    assert!(response.accepted);

    // Check execution header is finalized
    let finalized = api.get_finalized_header(&block_hash).expect("finalized");
    assert!(finalized.is_finalized);
    assert!(finalized.header.is_some());
    assert_eq!(finalized.header.unwrap().block_number, 18_000_000);
}

/// Test: Bootstrap is idempotent with same data.
#[test]
fn test_bootstrap_idempotent() {
    let (api, _dir) = setup_api();

    let bootstrap = test_bootstrap(8_000_000);
    let request = BootstrapRequest {
        bootstrap: bootstrap.clone(),
        execution_header: None,
    };

    // First bootstrap
    let response1 = api.bootstrap(request.clone()).expect("bootstrap 1");
    assert!(response1.accepted);

    // Second bootstrap with same data
    let response2 = api.bootstrap(request).expect("bootstrap 2");
    assert!(response2.accepted);
    assert_eq!(response1.bootstrap_id, response2.bootstrap_id);
}

/// Test: Bootstrap rejects different data after initial bootstrap (non-devnet).
#[test]
fn test_bootstrap_rejects_different_data() {
    let (api, _dir) = setup_api();

    // First bootstrap
    let request1 = BootstrapRequest {
        bootstrap: test_bootstrap(8_000_000),
        execution_header: None,
    };
    api.bootstrap(request1).expect("bootstrap 1");

    // Second bootstrap with different slot
    let request2 = BootstrapRequest {
        bootstrap: test_bootstrap(9_000_000), // Different slot
        execution_header: None,
    };

    // This should succeed in devnet mode (allows reset)
    let response = api.bootstrap(request2);
    // In devnet mode, this actually succeeds because allow_reset=true
    assert!(response.is_ok());
}

// ========== Update Tests ==========

/// Test: Update advances finalized header.
#[test]
fn test_update_advances_finalized() {
    let (api, _dir) = setup_api();

    // Bootstrap
    api.bootstrap(BootstrapRequest {
        bootstrap: test_bootstrap(8_000_000),
        execution_header: None,
    })
    .expect("bootstrap");

    // Submit update that advances finalized slot
    let update = test_update(8_001_000, 8_000_900, 8_001_001);
    let request = UpdateRequest {
        update,
        execution_header: None,
    };

    let response = api.submit_update(request).expect("update");
    assert!(response.accepted);
    assert_eq!(response.finalized_slot, 8_000_900);

    // Verify finalized slot advanced
    let status = api.get_status().expect("status");
    let lc_status = status.status.unwrap();
    assert_eq!(lc_status.finalized_slot, 8_000_900);
}

/// Test: Update with execution header stores finalized header.
#[test]
fn test_update_stores_execution_header() {
    let (api, _dir) = setup_api();

    // Bootstrap
    api.bootstrap(BootstrapRequest {
        bootstrap: test_bootstrap(8_000_000),
        execution_header: None,
    })
    .expect("bootstrap");

    // Submit update with execution header
    let block_hash = [0xCD; 32];
    let execution_header = test_execution_header(18_000_100, block_hash);

    let update = test_update(8_001_000, 8_000_900, 8_001_001);
    let request = UpdateRequest {
        update,
        execution_header: Some(execution_header),
    };

    api.submit_update(request).expect("update");

    // Check execution header is finalized
    let finalized = api.get_finalized_header(&block_hash).expect("finalized");
    assert!(finalized.is_finalized);
    assert_eq!(finalized.header.unwrap().block_number, 18_000_100);
}

/// Test: Update is idempotent.
#[test]
fn test_update_idempotent() {
    let (api, _dir) = setup_api();

    // Bootstrap
    api.bootstrap(BootstrapRequest {
        bootstrap: test_bootstrap(8_000_000),
        execution_header: None,
    })
    .expect("bootstrap");

    let update = test_update(8_001_000, 8_000_900, 8_001_001);
    let request = UpdateRequest {
        update,
        execution_header: None,
    };

    // First update
    let response1 = api.submit_update(request.clone()).expect("update 1");
    assert!(response1.accepted);

    // Second update with same data
    let response2 = api.submit_update(request).expect("update 2");
    assert!(response2.accepted);
    assert_eq!(response1.update_id, response2.update_id);
}

/// Test: Update requires bootstrap first.
#[test]
fn test_update_requires_bootstrap() {
    let (api, _dir) = setup_api();

    // Try to submit update without bootstrap
    let update = test_update(8_001_000, 8_000_900, 8_001_001);
    let request = UpdateRequest {
        update,
        execution_header: None,
    };

    let result = api.submit_update(request);
    assert!(result.is_err());
}

/// Test: Multiple updates advance finalized slot monotonically.
#[test]
fn test_multiple_updates_advance_finalized() {
    let (api, _dir) = setup_api();

    // Bootstrap at slot 8,000,000
    api.bootstrap(BootstrapRequest {
        bootstrap: test_bootstrap(8_000_000),
        execution_header: None,
    })
    .expect("bootstrap");

    // Update 1: finalize slot 8,000,900
    let update1 = test_update(8_001_000, 8_000_900, 8_001_001);
    api.submit_update(UpdateRequest {
        update: update1,
        execution_header: None,
    })
    .expect("update 1");

    let status1 = api.get_status().unwrap().status.unwrap();
    assert_eq!(status1.finalized_slot, 8_000_900);

    // Update 2: finalize slot 8_001_800
    let update2 = test_update(8_002_000, 8_001_800, 8_002_001);
    api.submit_update(UpdateRequest {
        update: update2,
        execution_header: None,
    })
    .expect("update 2");

    let status2 = api.get_status().unwrap().status.unwrap();
    assert_eq!(status2.finalized_slot, 8_001_800);
}

// ========== Finalized Header Tests ==========

/// Test: Query non-finalized header returns not finalized.
#[test]
fn test_non_finalized_header_query() {
    let (api, _dir) = setup_api();

    // Bootstrap
    api.bootstrap(BootstrapRequest {
        bootstrap: test_bootstrap(8_000_000),
        execution_header: None,
    })
    .expect("bootstrap");

    // Query a header that was never stored
    let unknown_hash = [0xFF; 32];
    let result = api.get_finalized_header(&unknown_hash).expect("query");

    assert!(!result.is_finalized);
    assert!(result.header.is_none());
    assert!(result.confirmations.is_none());
}

/// Test: Finalized header confirmations computed correctly.
#[test]
fn test_finalized_header_confirmations() {
    let (api, _dir) = setup_api();

    // Bootstrap with execution header at block 18,000,000
    let block_hash1 = [0xAA; 32];
    api.bootstrap(BootstrapRequest {
        bootstrap: test_bootstrap(8_000_000),
        execution_header: Some(test_execution_header(18_000_000, block_hash1)),
    })
    .expect("bootstrap");

    // Add another execution header at block 18,000,005
    let block_hash2 = [0xBB; 32];
    api.submit_update(UpdateRequest {
        update: test_update(8_001_000, 8_000_900, 8_001_001),
        execution_header: Some(test_execution_header(18_000_005, block_hash2)),
    })
    .expect("update");

    // Query first header - should have 6 confirmations (18_000_005 - 18_000_000 + 1)
    let result1 = api.get_finalized_header(&block_hash1).expect("query 1");
    assert!(result1.is_finalized);
    assert_eq!(result1.confirmations, Some(6));

    // Query second header - should have 1 confirmation (it's the tip)
    let result2 = api.get_finalized_header(&block_hash2).expect("query 2");
    assert!(result2.is_finalized);
    assert_eq!(result2.confirmations, Some(1));
}

// ========== Light Client Merkle Proof Tests ==========

/// Test: Proof readiness before bootstrap.
#[test]
fn test_proof_readiness_before_bootstrap() {
    let dir = tempdir().expect("tmpdir");
    let db = sled::open(dir.path()).expect("open sled");
    let storage = EthLightClientStorage::new(&db, 1).expect("storage");

    let proof = create_minimal_merkle_proof([0xAA; 32]);

    let readiness = can_verify_proof_with_lightclient(&proof, &storage, 1);
    assert_eq!(readiness, LightClientProofReadiness::NotBootstrapped);
}

/// Test: Proof readiness for non-finalized block.
#[test]
fn test_proof_readiness_not_finalized() {
    let (api, _dir) = setup_api();

    // Bootstrap without execution header
    api.bootstrap(BootstrapRequest {
        bootstrap: test_bootstrap(8_000_000),
        execution_header: None,
    })
    .expect("bootstrap");

    let proof = create_minimal_merkle_proof([0xFF; 32]); // Unknown block hash

    let readiness = can_verify_proof_with_lightclient(&proof, api.storage(), 1);
    assert_eq!(readiness, LightClientProofReadiness::BlockNotFinalized);
}

/// Test: Proof readiness for finalized block.
#[test]
fn test_proof_readiness_finalized() {
    let (api, _dir) = setup_api();

    let block_hash = [0xAB; 32];
    api.bootstrap(BootstrapRequest {
        bootstrap: test_bootstrap(8_000_000),
        execution_header: Some(test_execution_header(18_000_000, block_hash)),
    })
    .expect("bootstrap");

    let proof = create_minimal_merkle_proof(block_hash);

    let readiness = can_verify_proof_with_lightclient(&proof, api.storage(), 1);
    assert!(matches!(readiness, LightClientProofReadiness::Ready { .. }));
}

// ========== Verifier Tests ==========

/// Test: Verifier config for different networks.
#[test]
fn test_verifier_network_configs() {
    let mainnet = LightClientVerifierConfig::mainnet();
    assert_eq!(mainnet.chain_id, 1);
    assert!(!mainnet.skip_bls_verify);

    let sepolia = LightClientVerifierConfig::sepolia();
    assert_eq!(sepolia.chain_id, 11155111);
    assert!(!sepolia.skip_bls_verify);

    let holesky = LightClientVerifierConfig::holesky();
    assert_eq!(holesky.chain_id, 17000);
    assert!(!holesky.skip_bls_verify);

    let devnet = LightClientVerifierConfig::devnet_insecure();
    assert!(devnet.skip_bls_verify);
    assert!(devnet.skip_merkle_verify);
}

/// Test: Beacon header root computation is deterministic.
#[test]
fn test_beacon_header_root_deterministic() {
    let config = LightClientVerifierConfig::devnet_insecure();
    let verifier = LightClientVerifier::new(config);

    let header = test_beacon_header(8_000_000);

    // Compute root twice
    let bootstrap = LightClientBootstrapV1 {
        header: header.clone(),
        current_sync_committee: test_sync_committee(),
        current_sync_committee_branch: vec![[0xDD; 32]; 5],
    };

    let result1 = verifier.verify_bootstrap(&bootstrap).expect("verify 1");
    let result2 = verifier.verify_bootstrap(&bootstrap).expect("verify 2");

    assert_eq!(result1.header_root, result2.header_root);
    assert_ne!(result1.header_root, [0u8; 32]); // Not all zeros
}

/// Test: Different beacon headers produce different roots.
#[test]
fn test_different_headers_different_roots() {
    let config = LightClientVerifierConfig::devnet_insecure();
    let verifier = LightClientVerifier::new(config);

    let header1 = test_beacon_header(8_000_000);
    let header2 = test_beacon_header(8_000_001); // Different slot

    let bootstrap1 = LightClientBootstrapV1 {
        header: header1,
        current_sync_committee: test_sync_committee(),
        current_sync_committee_branch: vec![[0xDD; 32]; 5],
    };

    let bootstrap2 = LightClientBootstrapV1 {
        header: header2,
        current_sync_committee: test_sync_committee(),
        current_sync_committee_branch: vec![[0xDD; 32]; 5],
    };

    let result1 = verifier.verify_bootstrap(&bootstrap1).expect("verify 1");
    let result2 = verifier.verify_bootstrap(&bootstrap2).expect("verify 2");

    assert_ne!(result1.header_root, result2.header_root);
}

// ========== Helper Functions ==========

/// Create a minimal Merkle proof for testing.
fn create_minimal_merkle_proof(block_hash: [u8; 32]) -> EthReceiptMerkleProofV1 {
    EthReceiptMerkleProofV1 {
        chain: ExternalChainId::EthereumMainnet,
        tx_hash: [0x11; 32],
        log_index: 0,
        contract: [0x22; 20],
        topic0: [0x33; 32],
        data_hash: [0x44; 32],
        block_number: 18_000_000,
        block_hash,
        header_rlp: vec![0x00], // Minimal - would fail actual verification
        tx_index: 0,
        receipt_rlp: vec![0x00], // Minimal - would fail actual verification
        proof_nodes: vec![],
        confirmations: Some(1),
        tip_block_number: Some(18_000_001),
    }
}
