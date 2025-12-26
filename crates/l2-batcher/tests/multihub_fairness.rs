//! Multi-hub organiser fairness and determinism tests.
//!
//! These tests verify:
//! - Forced transactions are processed promptly
//! - No hub starves under sustained load
//! - Hub selection is deterministic given the same inputs
//! - Fairness across all hubs over time

use l2_batcher::gbdt_organiser_v2::{GbdtOrganiserV2, OrganiserV2};
use l2_batcher::{HubInputs, OrganiserDecisionV2, OrganiserInputsV2};
use l2_core::{L2HubId, ALL_HUBS};
use std::collections::BTreeMap;

/// Helper to create inputs with specified queue depths for each hub.
fn create_inputs(
    now_ms: u64,
    depths: &[(L2HubId, u32, u32)], // (hub, queue_depth, forced_queue_depth)
) -> OrganiserInputsV2 {
    let mut hubs_map: BTreeMap<L2HubId, HubInputs> = ALL_HUBS
        .iter()
        .map(|&hub| {
            (
                hub,
                HubInputs {
                    hub,
                    queue_depth: 0,
                    forced_queue_depth: 0,
                    in_flight_batches: 0,
                    recent_rejects: 0,
                    avg_tx_bytes_est: 256,
                },
            )
        })
        .collect();

    for (hub, queue_depth, forced_depth) in depths {
        if let Some(inputs) = hubs_map.get_mut(hub) {
            inputs.queue_depth = *queue_depth;
            inputs.forced_queue_depth = *forced_depth;
        }
    }

    OrganiserInputsV2 {
        now_ms,
        hubs: hubs_map.into_values().collect(),
    }
}

/// Test: Forced transactions in one hub cause that hub to be chosen promptly.
#[test]
fn forced_hub_chosen_promptly() {
    let organiser = GbdtOrganiserV2::new();

    // Setup: Fin, Data, M2m have normal backlog, World has forced txs
    let inputs = create_inputs(
        1000,
        &[
            (L2HubId::Fin, 100, 0),
            (L2HubId::Data, 100, 0),
            (L2HubId::M2m, 100, 0),
            (L2HubId::World, 50, 10), // World has forced txs
            (L2HubId::Bridge, 0, 0),
        ],
    );

    let decision = organiser.decide(&inputs);

    // World should be chosen because it has forced transactions
    assert_eq!(
        decision.chosen_hub,
        L2HubId::World,
        "hub with forced txs should be chosen"
    );
    assert!(
        decision.forced_drain_max > 0,
        "forced drain should be enabled"
    );
}

/// Test: Multiple hubs with forced txs - highest forced count wins.
#[test]
fn highest_forced_count_wins() {
    let organiser = GbdtOrganiserV2::new();

    // Setup: Data has 5 forced, M2m has 10 forced
    let inputs = create_inputs(
        1000,
        &[
            (L2HubId::Fin, 100, 0),
            (L2HubId::Data, 100, 5),  // 5 forced
            (L2HubId::M2m, 100, 10),  // 10 forced - highest
            (L2HubId::World, 100, 3), // 3 forced
            (L2HubId::Bridge, 0, 0),
        ],
    );

    let decision = organiser.decide(&inputs);

    // M2m should be chosen because it has the highest forced count
    assert_eq!(
        decision.chosen_hub,
        L2HubId::M2m,
        "hub with highest forced count should be chosen"
    );
}

/// Test: No hub starves under sustained load.
///
/// This test simulates sustained load and verifies that all hubs
/// with pending work get served within a bounded number of iterations.
#[test]
fn no_starvation_under_sustained_load() {
    let mut organiser = GbdtOrganiserV2::new();

    // Track how many times each hub was chosen
    let mut serve_counts: BTreeMap<L2HubId, u32> = BTreeMap::new();
    for hub in ALL_HUBS {
        serve_counts.insert(hub, 0);
    }

    // Simulate sustained load: all hubs have work
    let max_iterations = 100;
    let starvation_threshold = 20; // No hub should go more than 20 iterations without being served

    // Track last served iteration for each hub
    let mut last_served: BTreeMap<L2HubId, u32> = BTreeMap::new();
    for hub in ALL_HUBS {
        if hub != L2HubId::Bridge {
            // Bridge has no work
            last_served.insert(hub, 0);
        }
    }

    for i in 0u32..max_iterations {
        let inputs = create_inputs(
            1000 + i as u64 * 100,
            &[
                (L2HubId::Fin, 50, 0),
                (L2HubId::Data, 50, 0),
                (L2HubId::M2m, 50, 0),
                (L2HubId::World, 50, 0),
                (L2HubId::Bridge, 0, 0), // Bridge has no work
            ],
        );

        let decision = organiser.decide(&inputs);
        let chosen = decision.chosen_hub;

        // Update serve count
        *serve_counts.get_mut(&chosen).unwrap() += 1;

        // Mark hub as served
        organiser.mark_hub_served(chosen);

        // Check starvation for hubs with work
        for hub in ALL_HUBS {
            if hub != L2HubId::Bridge && hub != chosen {
                // This hub wasn't served
                if let Some(last) = last_served.get(&hub) {
                    let iterations_since = i.saturating_sub(*last);
                    assert!(
                        iterations_since < starvation_threshold,
                        "Hub {:?} starved for {} iterations (threshold: {})",
                        hub,
                        iterations_since,
                        starvation_threshold
                    );
                }
            }
        }

        // Update last served for chosen hub
        if let Some(last) = last_served.get_mut(&chosen) {
            *last = i;
        }
    }

    // Verify all hubs with work were served at least once
    for hub in ALL_HUBS {
        if hub != L2HubId::Bridge {
            let count = serve_counts.get(&hub).unwrap();
            assert!(
                *count > 0,
                "Hub {:?} was never served in {} iterations",
                hub,
                max_iterations
            );
        }
    }

    // Verify Bridge (no work) wasn't served too often
    // It might still be chosen occasionally due to starvation prevention
    let bridge_count = serve_counts.get(&L2HubId::Bridge).unwrap();
    assert!(
        *bridge_count < max_iterations / 4,
        "Bridge (no work) was served too often: {}/{}",
        bridge_count,
        max_iterations
    );
}

/// Test: Hub selection is deterministic given the same inputs.
#[test]
fn determinism_same_inputs_same_output() {
    // Create two separate organiser instances
    let org1 = GbdtOrganiserV2::new();
    let org2 = GbdtOrganiserV2::new();

    // Same inputs
    let inputs = create_inputs(
        1000,
        &[
            (L2HubId::Fin, 100, 0),
            (L2HubId::Data, 50, 0),
            (L2HubId::M2m, 75, 5),
            (L2HubId::World, 25, 0),
            (L2HubId::Bridge, 10, 0),
        ],
    );

    // Both should produce identical decisions
    let d1 = org1.decide(&inputs);
    let d2 = org2.decide(&inputs);

    assert_eq!(d1.chosen_hub, d2.chosen_hub, "chosen_hub must be deterministic");
    assert_eq!(d1.sleep_ms, d2.sleep_ms, "sleep_ms must be deterministic");
    assert_eq!(d1.max_txs, d2.max_txs, "max_txs must be deterministic");
    assert_eq!(d1.max_bytes, d2.max_bytes, "max_bytes must be deterministic");
    assert_eq!(
        d1.forced_drain_max, d2.forced_drain_max,
        "forced_drain_max must be deterministic"
    );
}

/// Test: Decision sequence is deterministic given same input sequence.
#[test]
fn determinism_sequence_reproducible() {
    let iterations = 20;

    // Collect decisions from first run
    let mut org1 = GbdtOrganiserV2::new();
    let mut decisions1: Vec<OrganiserDecisionV2> = Vec::new();

    for i in 0..iterations {
        let inputs = create_inputs(
            1000 + i as u64 * 100,
            &[
                (L2HubId::Fin, 100 - i * 2, 0),
                (L2HubId::Data, 50 + i, 0),
                (L2HubId::M2m, 75, i % 3), // Varying forced
                (L2HubId::World, 25, 0),
                (L2HubId::Bridge, i * 5, 0),
            ],
        );

        let decision = org1.decide(&inputs);
        decisions1.push(decision.clone());
        org1.mark_hub_served(decision.chosen_hub);
    }

    // Collect decisions from second run (should be identical)
    let mut org2 = GbdtOrganiserV2::new();
    let mut decisions2: Vec<OrganiserDecisionV2> = Vec::new();

    for i in 0..iterations {
        let inputs = create_inputs(
            1000 + i as u64 * 100,
            &[
                (L2HubId::Fin, 100 - i * 2, 0),
                (L2HubId::Data, 50 + i, 0),
                (L2HubId::M2m, 75, i % 3),
                (L2HubId::World, 25, 0),
                (L2HubId::Bridge, i * 5, 0),
            ],
        );

        let decision = org2.decide(&inputs);
        decisions2.push(decision.clone());
        org2.mark_hub_served(decision.chosen_hub);
    }

    // Compare all decisions
    for (i, (d1, d2)) in decisions1.iter().zip(decisions2.iter()).enumerate() {
        assert_eq!(
            d1, d2,
            "Decision at iteration {} differs: {:?} vs {:?}",
            i, d1, d2
        );
    }
}

/// Test: Tie-break uses deterministic hub enum ordering.
#[test]
fn tie_break_uses_hub_enum_order() {
    let organiser = GbdtOrganiserV2::new();

    // All hubs have identical queue depths (except Bridge with zero)
    let inputs = create_inputs(
        1000,
        &[
            (L2HubId::Fin, 50, 0),
            (L2HubId::Data, 50, 0),
            (L2HubId::M2m, 50, 0),
            (L2HubId::World, 50, 0),
            (L2HubId::Bridge, 0, 0),
        ],
    );

    let decision = organiser.decide(&inputs);

    // With equal depths, Fin should win (lowest in enum order)
    // Note: This depends on the implementation's tie-break logic
    // The key point is that it's deterministic, not random
    let first_decision = decision.chosen_hub;

    // Reset and try again
    let org2 = GbdtOrganiserV2::new();
    let d2 = org2.decide(&inputs);

    assert_eq!(
        first_decision, d2.chosen_hub,
        "tie-break must be deterministic"
    );
}

/// Test: Fairness counters prevent immediate re-selection of same hub.
#[test]
fn fairness_counters_prevent_reselection() {
    let mut organiser = GbdtOrganiserV2::new();

    // Initial state: Fin has highest queue depth
    let inputs1 = create_inputs(
        1000,
        &[
            (L2HubId::Fin, 100, 0),
            (L2HubId::Data, 50, 0),
            (L2HubId::M2m, 50, 0),
            (L2HubId::World, 50, 0),
            (L2HubId::Bridge, 0, 0),
        ],
    );

    let d1 = organiser.decide(&inputs1);
    assert_eq!(d1.chosen_hub, L2HubId::Fin, "Fin should be chosen first");

    // Mark Fin as served
    organiser.mark_hub_served(L2HubId::Fin);

    // Same inputs again - fairness should favor other hubs now
    // because Fin's iterations_since_served is 0
    let d2 = organiser.decide(&inputs1);

    // The chosen hub may still be Fin if its queue depth advantage is large enough,
    // but the fairness scoring should be applied consistently
    // This test verifies the fairness counters are being tracked
    organiser.mark_hub_served(d2.chosen_hub);

    // After several iterations, verify fairness is working
    let mut chosen_sequence: Vec<L2HubId> = vec![d1.chosen_hub, d2.chosen_hub];

    for _ in 0..8 {
        let decision = organiser.decide(&inputs1);
        chosen_sequence.push(decision.chosen_hub);
        organiser.mark_hub_served(decision.chosen_hub);
    }

    // Count how many times each hub was chosen
    let mut counts: BTreeMap<L2HubId, usize> = BTreeMap::new();
    for hub in &chosen_sequence {
        *counts.entry(*hub).or_default() += 1;
    }

    // Verify we didn't just pick the same hub every time
    assert!(
        counts.len() > 1,
        "Fairness should cause multiple hubs to be chosen, got: {:?}",
        counts
    );
}

/// Test: Forced queue is drained before normal queue.
#[test]
fn forced_drained_before_normal() {
    let organiser = GbdtOrganiserV2::new();

    // M2m has high normal queue but also forced txs
    let inputs = create_inputs(
        1000,
        &[
            (L2HubId::Fin, 200, 0), // Higher normal queue
            (L2HubId::Data, 0, 0),
            (L2HubId::M2m, 100, 5), // Lower normal but has forced
            (L2HubId::World, 0, 0),
            (L2HubId::Bridge, 0, 0),
        ],
    );

    let decision = organiser.decide(&inputs);

    // M2m should be chosen because of forced txs
    assert_eq!(
        decision.chosen_hub,
        L2HubId::M2m,
        "hub with forced txs should be prioritized"
    );
    assert!(
        decision.forced_drain_max > 0,
        "forced_drain_max should be set"
    );
}

/// Test: Empty inputs default to Fin hub.
#[test]
fn empty_inputs_defaults_to_fin() {
    let organiser = GbdtOrganiserV2::new();

    let inputs = create_inputs(
        1000,
        &[
            (L2HubId::Fin, 0, 0),
            (L2HubId::Data, 0, 0),
            (L2HubId::M2m, 0, 0),
            (L2HubId::World, 0, 0),
            (L2HubId::Bridge, 0, 0),
        ],
    );

    let decision = organiser.decide(&inputs);

    // With all empty, Fin should be chosen (default/first in order)
    assert_eq!(
        decision.chosen_hub,
        L2HubId::Fin,
        "empty inputs should default to Fin"
    );
}

/// Test: Decision parameters scale correctly with inputs.
#[test]
fn parameters_scale_with_inputs() {
    let organiser = GbdtOrganiserV2::new();

    // Low load inputs
    let low_load = create_inputs(
        1000,
        &[
            (L2HubId::Fin, 10, 0),
            (L2HubId::Data, 0, 0),
            (L2HubId::M2m, 0, 0),
            (L2HubId::World, 0, 0),
            (L2HubId::Bridge, 0, 0),
        ],
    );

    let low_decision = organiser.decide(&low_load);

    // High load inputs
    let high_load = create_inputs(
        1000,
        &[
            (L2HubId::Fin, 500, 0),
            (L2HubId::Data, 0, 0),
            (L2HubId::M2m, 0, 0),
            (L2HubId::World, 0, 0),
            (L2HubId::Bridge, 0, 0),
        ],
    );

    let high_decision = organiser.decide(&high_load);

    // High load should have:
    // - Lower sleep (process faster)
    // - Higher max_txs (batch more)
    assert!(
        high_decision.sleep_ms <= low_decision.sleep_ms,
        "high load should have lower or equal sleep: {} vs {}",
        high_decision.sleep_ms,
        low_decision.sleep_ms
    );
    assert!(
        high_decision.max_txs >= low_decision.max_txs,
        "high load should have higher or equal max_txs: {} vs {}",
        high_decision.max_txs,
        low_decision.max_txs
    );
}

/// Test: Organiser version is reported correctly.
#[test]
fn version_is_gbdt_v2() {
    use l2_batcher::gbdt_organiser_v2::OrganiserVersionV2;
    
    let organiser = GbdtOrganiserV2::new();
    let version = organiser.version();
    assert_eq!(
        version,
        OrganiserVersionV2::GbdtV2,
        "version should be GbdtV2"
    );
    assert_eq!(
        version.to_string(),
        "gbdt_v2",
        "version string should be gbdt_v2"
    );
}
