//! Atomicity Invariant Tests for Cross-Hub Intent Protocol.
//!
//! This module tests the fundamental atomicity properties of the 2PC intent protocol:
//!
//! 1. **State Monotonicity**: Once an intent reaches a terminal state, it cannot change.
//! 2. **Prepare-Before-Commit**: An intent must be prepared before it can be committed.
//! 3. **No Partial Execution**: Either both hubs execute or neither does.
//! 4. **Deterministic ID**: Intent ID is deterministic and immutable.
//! 5. **Expiry Enforcement**: Expired intents cannot commit, only abort.
//!
//! ## Test Categories
//!
//! - State transition invariants
//! - Concurrent operation safety
//! - Crash recovery scenarios
//! - Finality coupling

use l2_bridge::{
    FinalityChecker, IntentPolicy, IntentRouter, MockFinalityChecker, MockHubExecutor,
    PrepareFinality, DEFAULT_INTENT_EXPIRES_MS,
};
use l2_core::{Intent, IntentId, IntentKind, Hash32, L2HubId};
use l2_storage::{IntentState, IntentStorage};
use std::sync::Arc;
use tempfile::tempdir;

// ========== Test Helpers ==========

fn test_db() -> sled::Db {
    let dir = tempdir().expect("tmpdir");
    sled::open(dir.path()).expect("open")
}

fn make_intent(from_hub: L2HubId, to_hub: L2HubId, expires_ms: u64) -> Intent {
    Intent {
        kind: IntentKind::CrossHubTransfer,
        created_ms: 1_700_000_000_000,
        expires_ms,
        from_hub,
        to_hub,
        initiator: "test_user".to_string(),
        payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
    }
}

fn setup_router_with_finality(is_finalised: bool) -> (IntentRouter, Intent) {
    let db = test_db();
    let storage = IntentStorage::new(&db).unwrap();
    let policy = IntentPolicy::default();
    let finality_checker = Arc::new(MockFinalityChecker { is_finalised });

    let mut router = IntentRouter::new(storage, policy, finality_checker);

    // Register mock executors for all hubs
    for hub in l2_core::ALL_HUBS {
        router.register_executor(hub, Arc::new(MockHubExecutor::new(hub)));
    }

    let intent = make_intent(L2HubId::Fin, L2HubId::World, 1_700_000_600_000);
    (router, intent)
}

// ========== State Monotonicity Tests ==========

/// INVARIANT: Terminal states (Committed, Aborted) are permanent.
#[tokio::test]
async fn invariant_committed_is_terminal() {
    let (router, intent) = setup_router_with_finality(true);
    let current_ms = 1_700_000_100_000;

    // Progress to Committed
    let create_result = router.create_intent(intent.clone(), current_ms).unwrap();
    router
        .prepare_intent(&create_result.intent_id, &intent, current_ms)
        .await
        .unwrap();
    router
        .commit_intent(&create_result.intent_id, &intent, current_ms)
        .await
        .unwrap();

    // Verify state
    let state = router.get_state(&create_result.intent_id).unwrap();
    assert!(state.is_terminal(), "Committed should be terminal");
    assert!(state.is_committed(), "Should be in Committed state");

    // Try to abort - should fail
    let abort_result = router
        .abort_intent(
            &create_result.intent_id,
            "test abort".to_string(),
            Some(&intent),
            current_ms,
        )
        .await;
    assert!(
        abort_result.is_err(),
        "Should not be able to abort a committed intent"
    );

    // State should still be Committed
    let state = router.get_state(&create_result.intent_id).unwrap();
    assert!(state.is_committed(), "State should remain Committed");
}

/// INVARIANT: Aborted state is terminal.
#[tokio::test]
async fn invariant_aborted_is_terminal() {
    let (router, intent) = setup_router_with_finality(true);
    let current_ms = 1_700_000_100_000;

    // Create and abort
    let create_result = router.create_intent(intent.clone(), current_ms).unwrap();
    router
        .abort_intent(
            &create_result.intent_id,
            "cancelled".to_string(),
            Some(&intent),
            current_ms,
        )
        .await
        .unwrap();

    // Verify state
    let state = router.get_state(&create_result.intent_id).unwrap();
    assert!(state.is_terminal(), "Aborted should be terminal");
    assert!(state.is_aborted(), "Should be in Aborted state");

    // Try to prepare - should fail (simulated by checking state)
    let prepare_result = router
        .prepare_intent(&create_result.intent_id, &intent, current_ms)
        .await;
    assert!(
        prepare_result.is_err(),
        "Should not be able to prepare an aborted intent"
    );
}

// ========== Prepare-Before-Commit Tests ==========

/// INVARIANT: Cannot commit without first preparing.
#[tokio::test]
async fn invariant_must_prepare_before_commit() {
    let (router, intent) = setup_router_with_finality(true);
    let current_ms = 1_700_000_100_000;

    // Create intent
    let create_result = router.create_intent(intent.clone(), current_ms).unwrap();

    // Try to commit directly - should fail
    let commit_result = router
        .commit_intent(&create_result.intent_id, &intent, current_ms)
        .await;
    assert!(
        commit_result.is_err(),
        "Should not be able to commit without prepare"
    );

    // State should still be Created
    let state = router.get_state(&create_result.intent_id).unwrap();
    assert!(state.is_created(), "State should remain Created");
}

/// INVARIANT: Cannot skip Prepared state to reach Committed.
#[tokio::test]
async fn invariant_no_state_skipping() {
    let db = test_db();
    let storage = IntentStorage::new(&db).unwrap();

    let intent_id = IntentId(Hash32([0xAA; 32]));

    // Create in Created state
    let created = IntentState::created(
        1_700_000_000_000,
        1_700_000_600_000,
        L2HubId::Fin,
        L2HubId::World,
    );
    storage.create(&intent_id, &created).unwrap();

    // Try to transition directly to Committed - should fail
    let committed = IntentState::committed(1_700_000_200_000, vec![Hash32([0xBB; 32])]);
    let result = storage.update(&intent_id, &committed);
    assert!(
        result.is_err(),
        "Should not be able to skip from Created to Committed"
    );
}

// ========== Deterministic ID Tests ==========

/// INVARIANT: Intent ID is deterministic - same input always produces same ID.
#[test]
fn invariant_intent_id_is_deterministic() {
    let intent1 = make_intent(L2HubId::Fin, L2HubId::World, 1_700_000_600_000);
    let intent2 = make_intent(L2HubId::Fin, L2HubId::World, 1_700_000_600_000);

    let id1 = intent1.compute_id().unwrap();
    let id2 = intent2.compute_id().unwrap();

    assert_eq!(id1, id2, "Same intent data should produce same ID");
}

/// INVARIANT: Different intents produce different IDs.
#[test]
fn invariant_different_intents_different_ids() {
    let intent1 = make_intent(L2HubId::Fin, L2HubId::World, 1_700_000_600_000);
    let intent2 = make_intent(L2HubId::Data, L2HubId::M2m, 1_700_000_700_000);

    let id1 = intent1.compute_id().unwrap();
    let id2 = intent2.compute_id().unwrap();

    assert_ne!(id1, id2, "Different intents should produce different IDs");
}

// ========== Expiry Enforcement Tests ==========

/// INVARIANT: Expired intents cannot be created.
#[test]
fn invariant_cannot_create_expired_intent() {
    let (router, _) = setup_router_with_finality(true);

    let intent = Intent {
        kind: IntentKind::CrossHubTransfer,
        created_ms: 1_700_000_000_000,
        expires_ms: 1_700_000_100_000, // Already expired
        from_hub: L2HubId::Fin,
        to_hub: L2HubId::World,
        initiator: "test".to_string(),
        payload: vec![],
    };

    let current_ms = 1_700_000_200_000; // After expiry
    let result = router.create_intent(intent, current_ms);

    assert!(result.is_err(), "Should not create an already-expired intent");
}

/// INVARIANT: Cannot prepare an expired intent.
#[tokio::test]
async fn invariant_cannot_prepare_expired_intent() {
    let (router, intent) = setup_router_with_finality(true);

    // Create at time before expiry
    let create_ms = 1_700_000_100_000;
    let create_result = router.create_intent(intent.clone(), create_ms).unwrap();

    // Try to prepare after expiry
    let expired_ms = 1_700_000_700_000; // After expires_ms (1_700_000_600_000)
    let prepare_result = router
        .prepare_intent(&create_result.intent_id, &intent, expired_ms)
        .await;

    assert!(
        prepare_result.is_err(),
        "Should not prepare an expired intent"
    );
}

// ========== Finality Coupling Tests ==========

/// INVARIANT: When require_prep_finality is true, cannot commit without finality.
#[tokio::test]
async fn invariant_commit_requires_finality_when_enabled() {
    let db = test_db();
    let storage = IntentStorage::new(&db).unwrap();
    let policy = IntentPolicy {
        require_prep_finality: true,
        ..Default::default()
    };
    let finality_checker = Arc::new(MockFinalityChecker { is_finalised: false });

    let mut router = IntentRouter::new(storage, policy, finality_checker);
    router.register_executor(L2HubId::Fin, Arc::new(MockHubExecutor::new(L2HubId::Fin)));
    router.register_executor(L2HubId::World, Arc::new(MockHubExecutor::new(L2HubId::World)));

    let intent = make_intent(L2HubId::Fin, L2HubId::World, 1_700_000_600_000);
    let current_ms = 1_700_000_100_000;

    // Create and prepare
    let create_result = router.create_intent(intent.clone(), current_ms).unwrap();
    router
        .prepare_intent(&create_result.intent_id, &intent, current_ms)
        .await
        .unwrap();

    // Try to commit without finality
    let commit_result = router
        .commit_intent(&create_result.intent_id, &intent, current_ms)
        .await;

    assert!(
        commit_result.is_err(),
        "Should not commit without prepare finality"
    );
}

/// INVARIANT: Can commit when finality is achieved.
#[tokio::test]
async fn invariant_commit_succeeds_with_finality() {
    let db = test_db();
    let storage = IntentStorage::new(&db).unwrap();
    let policy = IntentPolicy {
        require_prep_finality: true,
        ..Default::default()
    };
    let finality_checker = Arc::new(MockFinalityChecker { is_finalised: true });

    let mut router = IntentRouter::new(storage, policy, finality_checker);
    router.register_executor(L2HubId::Fin, Arc::new(MockHubExecutor::new(L2HubId::Fin)));
    router.register_executor(L2HubId::World, Arc::new(MockHubExecutor::new(L2HubId::World)));

    let intent = make_intent(L2HubId::Fin, L2HubId::World, 1_700_000_600_000);
    let current_ms = 1_700_000_100_000;

    // Full lifecycle
    let create_result = router.create_intent(intent.clone(), current_ms).unwrap();
    router
        .prepare_intent(&create_result.intent_id, &intent, current_ms)
        .await
        .unwrap();
    let commit_result = router
        .commit_intent(&create_result.intent_id, &intent, current_ms)
        .await;

    assert!(
        commit_result.is_ok(),
        "Should commit when finality is achieved"
    );
}

// ========== No Partial Execution Tests ==========

/// INVARIANT: Both hubs are called during prepare.
#[tokio::test]
async fn invariant_prepare_calls_both_hubs() {
    let (router, intent) = setup_router_with_finality(true);
    let current_ms = 1_700_000_100_000;

    let create_result = router.create_intent(intent.clone(), current_ms).unwrap();
    let prepare_result = router
        .prepare_intent(&create_result.intent_id, &intent, current_ms)
        .await
        .unwrap();

    // Should have 2 receipts (one per hub)
    assert_eq!(
        prepare_result.receipts.len(),
        2,
        "Prepare should produce receipts from both hubs"
    );

    // Verify receipts are from the correct hubs
    let hub_names: Vec<_> = prepare_result.receipts.iter().map(|r| r.hub).collect();
    assert!(hub_names.contains(&L2HubId::Fin));
    assert!(hub_names.contains(&L2HubId::World));
}

/// INVARIANT: Both hubs are called during commit.
#[tokio::test]
async fn invariant_commit_calls_both_hubs() {
    let (router, intent) = setup_router_with_finality(true);
    let current_ms = 1_700_000_100_000;

    let create_result = router.create_intent(intent.clone(), current_ms).unwrap();
    router
        .prepare_intent(&create_result.intent_id, &intent, current_ms)
        .await
        .unwrap();
    let commit_result = router
        .commit_intent(&create_result.intent_id, &intent, current_ms)
        .await
        .unwrap();

    // Should have 2 receipts (one per hub)
    assert_eq!(
        commit_result.receipts.len(),
        2,
        "Commit should produce receipts from both hubs"
    );

    // Verify receipts are from the correct hubs
    let hub_names: Vec<_> = commit_result.receipts.iter().map(|r| r.hub).collect();
    assert!(hub_names.contains(&L2HubId::Fin));
    assert!(hub_names.contains(&L2HubId::World));
}

// ========== State Consistency Tests ==========

/// INVARIANT: Storage state matches router-reported state.
#[tokio::test]
async fn invariant_storage_state_consistency() {
    let (router, intent) = setup_router_with_finality(true);
    let current_ms = 1_700_000_100_000;

    let create_result = router.create_intent(intent.clone(), current_ms).unwrap();

    // Check Created state
    let state = router.get_state(&create_result.intent_id).unwrap();
    let status = router.get_status(&create_result.intent_id).unwrap();
    assert!(state.is_created());
    assert_eq!(status.state_name, "created");

    // After prepare
    router
        .prepare_intent(&create_result.intent_id, &intent, current_ms)
        .await
        .unwrap();
    let state = router.get_state(&create_result.intent_id).unwrap();
    let status = router.get_status(&create_result.intent_id).unwrap();
    assert!(state.is_prepared());
    assert_eq!(status.state_name, "prepared");

    // After commit
    router
        .commit_intent(&create_result.intent_id, &intent, current_ms)
        .await
        .unwrap();
    let state = router.get_state(&create_result.intent_id).unwrap();
    let status = router.get_status(&create_result.intent_id).unwrap();
    assert!(state.is_committed());
    assert_eq!(status.state_name, "committed");
    assert!(status.is_terminal);
}

// ========== Idempotency Tests ==========

/// INVARIANT: Re-creating same intent produces same ID.
#[test]
fn invariant_intent_creation_idempotent_id() {
    let intent = make_intent(L2HubId::Fin, L2HubId::World, 1_700_000_600_000);

    let id1 = intent.compute_id().unwrap();
    let id2 = intent.compute_id().unwrap();
    let id3 = intent.compute_id().unwrap();

    assert_eq!(id1, id2);
    assert_eq!(id2, id3);
}

/// Test multiple intents can coexist.
#[tokio::test]
async fn multiple_intents_coexist() {
    let (router, _) = setup_router_with_finality(true);
    let current_ms = 1_700_000_100_000;

    // Create multiple different intents
    let intents: Vec<Intent> = (0..5)
        .map(|i| Intent {
            kind: IntentKind::CrossHubTransfer,
            created_ms: 1_700_000_000_000 + i,
            expires_ms: 1_700_000_600_000,
            from_hub: L2HubId::Fin,
            to_hub: L2HubId::World,
            initiator: format!("user_{}", i),
            payload: vec![i as u8],
        })
        .collect();

    let mut ids = Vec::new();
    for intent in &intents {
        let result = router.create_intent(intent.clone(), current_ms).unwrap();
        ids.push(result.intent_id);
    }

    // All IDs should be unique
    let unique_ids: std::collections::HashSet<_> = ids.iter().map(|id| id.to_hex()).collect();
    assert_eq!(unique_ids.len(), ids.len(), "All intent IDs should be unique");

    // All intents should be in Created state
    for id in &ids {
        let state = router.get_state(id).unwrap();
        assert!(state.is_created());
    }

    // Counts should be correct
    let counts = router.count_states().unwrap();
    assert_eq!(counts.created, 5);
    assert_eq!(counts.pending(), 5);
}

// ========== Cross-Hub Validation Tests ==========

/// INVARIANT: Cannot create intent with same from_hub and to_hub.
#[test]
fn invariant_different_hubs_required() {
    let intent = Intent {
        kind: IntentKind::CrossHubTransfer,
        created_ms: 1_700_000_000_000,
        expires_ms: 1_700_000_600_000,
        from_hub: L2HubId::Fin,
        to_hub: L2HubId::Fin, // Same hub!
        initiator: "test".to_string(),
        payload: vec![],
    };

    let validation = intent.validate();
    assert!(
        validation.is_err(),
        "Should reject intent with same from_hub and to_hub"
    );
}

/// INVARIANT: Initiator must not be empty.
#[test]
fn invariant_initiator_required() {
    let intent = Intent {
        kind: IntentKind::CrossHubTransfer,
        created_ms: 1_700_000_000_000,
        expires_ms: 1_700_000_600_000,
        from_hub: L2HubId::Fin,
        to_hub: L2HubId::World,
        initiator: String::new(), // Empty!
        payload: vec![],
    };

    let validation = intent.validate();
    assert!(validation.is_err(), "Should reject intent with empty initiator");
}
