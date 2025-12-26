//! Determinism and bounds tests for the GBDT organiser.
//!
//! These tests verify that:
//! 1. Same inputs always produce identical decisions (bit-exact)
//! 2. Decisions are always within policy bounds
//! 3. Monotonic sanity: higher queue depth should not increase sleep_ms
//!    (unless capped by in-flight batches)
//! 4. Forced queue depth increases forced_drain_max (within cap)

use l2_batcher::{
    GbdtOrganiserV1, Organiser, OrganiserDecision, OrganiserInputs, OrganiserPolicyBounds,
    OrganiserVersion,
};

/// Create test inputs with given parameters.
fn make_inputs(queue_depth: u32, forced_queue_depth: u32, in_flight: u32) -> OrganiserInputs {
    OrganiserInputs {
        now_ms: 1_700_000_000_000,
        queue_depth,
        forced_queue_depth,
        in_flight_batches: in_flight,
        recent_quota_rejects: 0,
        recent_insufficient_balance: 0,
        recent_forced_used_bytes: 0,
        avg_tx_bytes_est: 256,
    }
}

// ============== Determinism Tests ==============

#[test]
fn determinism_same_inputs_same_output() {
    let organiser = GbdtOrganiserV1::new();

    // Test case 1: idle state
    let inputs = make_inputs(0, 0, 0);
    let d1 = organiser.decide(&inputs);
    let d2 = organiser.decide(&inputs);
    let d3 = organiser.decide(&inputs);

    assert_eq!(d1, d2, "same inputs must produce identical decision");
    assert_eq!(d2, d3, "same inputs must produce identical decision");

    // Test case 2: moderate load
    let inputs = make_inputs(100, 15, 1);
    let d1 = organiser.decide(&inputs);
    let d2 = organiser.decide(&inputs);

    assert_eq!(d1, d2, "same inputs must produce identical decision");

    // Test case 3: high load
    let inputs = make_inputs(600, 60, 2);
    let d1 = organiser.decide(&inputs);
    let d2 = organiser.decide(&inputs);

    assert_eq!(d1, d2, "same inputs must produce identical decision");
}

#[test]
fn determinism_across_instances() {
    // Different organiser instances with same config must produce same results
    let organiser1 = GbdtOrganiserV1::new();
    let organiser2 = GbdtOrganiserV1::new();

    let inputs = make_inputs(200, 30, 1);

    let d1 = organiser1.decide(&inputs);
    let d2 = organiser2.decide(&inputs);

    assert_eq!(
        d1, d2,
        "different instances must produce identical decisions"
    );
}

#[test]
fn determinism_timestamp_independent() {
    let organiser = GbdtOrganiserV1::new();

    // Same state, different timestamps -> same decision
    // (timestamp is not used in v1 decision logic)
    let inputs1 = OrganiserInputs {
        now_ms: 1_000_000,
        queue_depth: 50,
        forced_queue_depth: 5,
        in_flight_batches: 1,
        recent_quota_rejects: 0,
        recent_insufficient_balance: 0,
        recent_forced_used_bytes: 0,
        avg_tx_bytes_est: 256,
    };

    let inputs2 = OrganiserInputs {
        now_ms: 2_000_000_000_000, // Very different timestamp
        ..inputs1.clone()
    };

    let d1 = organiser.decide(&inputs1);
    let d2 = organiser.decide(&inputs2);

    assert_eq!(d1, d2, "timestamp should not affect decision in v1");
}

#[test]
fn determinism_bit_exact_golden() {
    // Golden test with known expected values
    let organiser = GbdtOrganiserV1::new();

    // Test case: moderate load
    let inputs = make_inputs(50, 15, 1);
    let decision = organiser.decide(&inputs);

    // These are the expected values from the v1 decision tree
    // queue_depth=50 -> 50% capacity
    // forced_queue_depth=15 -> 50% drain (> 10)
    assert_eq!(
        decision.sleep_ms, 500,
        "expected sleep_ms = 500 for queue_depth=50"
    );
    assert_eq!(decision.max_txs, 128, "expected max_txs = 128 (50% of 256)");
    assert_eq!(
        decision.max_bytes, 262144,
        "expected max_bytes = 262144 (50% of 512KB)"
    );
    assert_eq!(
        decision.forced_drain_max, 64,
        "expected forced_drain_max = 64 (50% of 128)"
    );
}

// ============== Bounds Tests ==============

#[test]
fn bounds_clamp_below_minimum() {
    let bounds = OrganiserPolicyBounds {
        sleep_ms_min: 100,
        sleep_ms_max: 10_000,
        max_txs_min: 10,
        max_txs_max: 1000,
        max_bytes_min: 1024,
        max_bytes_max: 1_000_000,
        forced_drain_min: 5,
        forced_drain_max: 100,
    };

    // Decision with values below minimum
    let decision = OrganiserDecision::new(10, 1, 100, 0);
    let clamped = bounds.clamp(decision);

    assert_eq!(clamped.sleep_ms, 100, "sleep_ms clamped to min");
    assert_eq!(clamped.max_txs, 10, "max_txs clamped to min");
    assert_eq!(clamped.max_bytes, 1024, "max_bytes clamped to min");
    assert_eq!(
        clamped.forced_drain_max, 5,
        "forced_drain_max clamped to min"
    );
}

#[test]
fn bounds_clamp_above_maximum() {
    let bounds = OrganiserPolicyBounds {
        sleep_ms_min: 100,
        sleep_ms_max: 10_000,
        max_txs_min: 10,
        max_txs_max: 1000,
        max_bytes_min: 1024,
        max_bytes_max: 1_000_000,
        forced_drain_min: 5,
        forced_drain_max: 100,
    };

    // Decision with values above maximum
    let decision = OrganiserDecision::new(100_000, 5000, 10_000_000, 500);
    let clamped = bounds.clamp(decision);

    assert_eq!(clamped.sleep_ms, 10_000, "sleep_ms clamped to max");
    assert_eq!(clamped.max_txs, 1000, "max_txs clamped to max");
    assert_eq!(clamped.max_bytes, 1_000_000, "max_bytes clamped to max");
    assert_eq!(
        clamped.forced_drain_max, 100,
        "forced_drain_max clamped to max"
    );
}

#[test]
fn bounds_within_range_unchanged() {
    let bounds = OrganiserPolicyBounds {
        sleep_ms_min: 100,
        sleep_ms_max: 10_000,
        max_txs_min: 10,
        max_txs_max: 1000,
        max_bytes_min: 1024,
        max_bytes_max: 1_000_000,
        forced_drain_min: 5,
        forced_drain_max: 100,
    };

    // Decision within bounds
    let decision = OrganiserDecision::new(500, 200, 50_000, 50);
    let clamped = bounds.clamp(decision.clone());

    assert_eq!(
        clamped, decision,
        "within-bounds decision should be unchanged"
    );
}

#[test]
fn bounds_all_decisions_within_default_bounds() {
    let organiser = GbdtOrganiserV1::new();
    let bounds = OrganiserPolicyBounds::default();

    // Test many different input combinations
    let test_cases = vec![
        make_inputs(0, 0, 0),      // Idle
        make_inputs(10, 5, 0),     // Low
        make_inputs(50, 15, 1),    // Moderate
        make_inputs(200, 30, 2),   // High
        make_inputs(600, 60, 3),   // Very high
        make_inputs(1000, 100, 5), // Extreme
        OrganiserInputs {
            now_ms: u64::MAX,
            queue_depth: u32::MAX,
            forced_queue_depth: u32::MAX,
            in_flight_batches: u32::MAX,
            recent_quota_rejects: u32::MAX,
            recent_insufficient_balance: u32::MAX,
            recent_forced_used_bytes: u64::MAX,
            avg_tx_bytes_est: u32::MAX,
        }, // Overflow test
    ];

    for inputs in test_cases {
        let decision = organiser.decide(&inputs);
        let clamped = bounds.clamp(decision.clone());

        // After clamping, values must be within bounds
        assert!(
            clamped.sleep_ms >= bounds.sleep_ms_min && clamped.sleep_ms <= bounds.sleep_ms_max,
            "sleep_ms {} out of bounds [{}, {}]",
            clamped.sleep_ms,
            bounds.sleep_ms_min,
            bounds.sleep_ms_max
        );
        assert!(
            clamped.max_txs >= bounds.max_txs_min && clamped.max_txs <= bounds.max_txs_max,
            "max_txs {} out of bounds [{}, {}]",
            clamped.max_txs,
            bounds.max_txs_min,
            bounds.max_txs_max
        );
        assert!(
            clamped.max_bytes >= bounds.max_bytes_min && clamped.max_bytes <= bounds.max_bytes_max,
            "max_bytes {} out of bounds [{}, {}]",
            clamped.max_bytes,
            bounds.max_bytes_min,
            bounds.max_bytes_max
        );
        assert!(
            clamped.forced_drain_max >= bounds.forced_drain_min
                && clamped.forced_drain_max <= bounds.forced_drain_max,
            "forced_drain_max {} out of bounds [{}, {}]",
            clamped.forced_drain_max,
            bounds.forced_drain_min,
            bounds.forced_drain_max
        );
    }
}

// ============== Monotonic Sanity Tests ==============

#[test]
fn monotonic_sleep_decreases_with_queue_depth() {
    let organiser = GbdtOrganiserV1::new();

    // Higher queue depth should not increase sleep_ms
    // (unless capped by in-flight batches)
    let inputs_idle = make_inputs(0, 0, 0);
    let inputs_low = make_inputs(10, 0, 0);
    let inputs_medium = make_inputs(50, 0, 0);
    let inputs_high = make_inputs(200, 0, 0);
    let inputs_very_high = make_inputs(600, 0, 0);

    let sleep_idle = organiser.decide(&inputs_idle).sleep_ms;
    let sleep_low = organiser.decide(&inputs_low).sleep_ms;
    let sleep_medium = organiser.decide(&inputs_medium).sleep_ms;
    let sleep_high = organiser.decide(&inputs_high).sleep_ms;
    let sleep_very_high = organiser.decide(&inputs_very_high).sleep_ms;

    // Sleep should be monotonically non-increasing as queue depth increases
    assert!(
        sleep_idle >= sleep_low,
        "sleep should not increase with queue depth: idle {} vs low {}",
        sleep_idle,
        sleep_low
    );
    assert!(
        sleep_low >= sleep_medium,
        "sleep should not increase with queue depth: low {} vs medium {}",
        sleep_low,
        sleep_medium
    );
    assert!(
        sleep_medium >= sleep_high,
        "sleep should not increase with queue depth: medium {} vs high {}",
        sleep_medium,
        sleep_high
    );
    assert!(
        sleep_high >= sleep_very_high,
        "sleep should not increase with queue depth: high {} vs very_high {}",
        sleep_high,
        sleep_very_high
    );
}

#[test]
fn monotonic_sleep_increases_with_in_flight_backpressure() {
    let organiser = GbdtOrganiserV1::new();

    // In-flight backpressure should increase sleep_ms
    let inputs_no_inflight = make_inputs(100, 0, 0);
    let inputs_some_inflight = make_inputs(100, 0, 3);
    let inputs_more_inflight = make_inputs(100, 0, 5);

    let sleep_none = organiser.decide(&inputs_no_inflight).sleep_ms;
    let sleep_some = organiser.decide(&inputs_some_inflight).sleep_ms;
    let sleep_more = organiser.decide(&inputs_more_inflight).sleep_ms;

    // With in-flight batches >= 3, backpressure kicks in
    assert!(
        sleep_some >= sleep_none,
        "backpressure should not decrease sleep: none {} vs some {}",
        sleep_none,
        sleep_some
    );
    assert!(
        sleep_more >= sleep_some,
        "more in-flight should not decrease sleep: some {} vs more {}",
        sleep_some,
        sleep_more
    );
}

#[test]
fn monotonic_forced_drain_increases_with_forced_queue() {
    let organiser = GbdtOrganiserV1::new();

    // Higher forced_queue_depth should increase forced_drain_max (up to cap)
    let inputs_low = make_inputs(0, 5, 0);
    let inputs_medium = make_inputs(0, 15, 0);
    let inputs_high = make_inputs(0, 60, 0);

    let drain_low = organiser.decide(&inputs_low).forced_drain_max;
    let drain_medium = organiser.decide(&inputs_medium).forced_drain_max;
    let drain_high = organiser.decide(&inputs_high).forced_drain_max;

    // Forced drain should be monotonically non-decreasing as forced queue increases
    assert!(
        drain_medium >= drain_low,
        "forced drain should not decrease with forced queue: low {} vs medium {}",
        drain_low,
        drain_medium
    );
    assert!(
        drain_high >= drain_medium,
        "forced drain should not decrease with forced queue: medium {} vs high {}",
        drain_medium,
        drain_high
    );
}

#[test]
fn monotonic_max_txs_increases_with_queue_depth() {
    let organiser = GbdtOrganiserV1::new();

    // Higher queue depth should increase max_txs (up to cap)
    let inputs_idle = make_inputs(0, 0, 0);
    let inputs_low = make_inputs(30, 0, 0);
    let inputs_high = make_inputs(200, 0, 0);
    let inputs_very_high = make_inputs(600, 0, 0);

    let max_txs_idle = organiser.decide(&inputs_idle).max_txs;
    let max_txs_low = organiser.decide(&inputs_low).max_txs;
    let max_txs_high = organiser.decide(&inputs_high).max_txs;
    let max_txs_very_high = organiser.decide(&inputs_very_high).max_txs;

    // max_txs should be monotonically non-decreasing as queue depth increases
    assert!(
        max_txs_low >= max_txs_idle,
        "max_txs should not decrease with queue depth: idle {} vs low {}",
        max_txs_idle,
        max_txs_low
    );
    assert!(
        max_txs_high >= max_txs_low,
        "max_txs should not decrease with queue depth: low {} vs high {}",
        max_txs_low,
        max_txs_high
    );
    assert!(
        max_txs_very_high >= max_txs_high,
        "max_txs should not decrease with queue depth: high {} vs very_high {}",
        max_txs_high,
        max_txs_very_high
    );
}

// ============== Version Tests ==============

#[test]
fn version_is_gbdt_v1() {
    let organiser = GbdtOrganiserV1::new();
    assert_eq!(organiser.version(), OrganiserVersion::GbdtV1);
}

// ============== No-Panic Tests ==============

#[test]
fn no_panic_on_extreme_inputs() {
    let organiser = GbdtOrganiserV1::new();

    // These should not panic
    let extreme_inputs = OrganiserInputs {
        now_ms: u64::MAX,
        queue_depth: u32::MAX,
        forced_queue_depth: u32::MAX,
        in_flight_batches: u32::MAX,
        recent_quota_rejects: u32::MAX,
        recent_insufficient_balance: u32::MAX,
        recent_forced_used_bytes: u64::MAX,
        avg_tx_bytes_est: u32::MAX,
    };

    let decision = organiser.decide(&extreme_inputs);

    // Values should be positive (not zero due to overflow)
    assert!(decision.sleep_ms > 0, "sleep_ms should be positive");
    assert!(decision.max_txs > 0, "max_txs should be positive");
    assert!(decision.max_bytes > 0, "max_bytes should be positive");
    assert!(
        decision.forced_drain_max > 0,
        "forced_drain_max should be positive"
    );
}

#[test]
fn no_panic_on_zero_inputs() {
    let organiser = GbdtOrganiserV1::new();

    let zero_inputs = OrganiserInputs {
        now_ms: 0,
        queue_depth: 0,
        forced_queue_depth: 0,
        in_flight_batches: 0,
        recent_quota_rejects: 0,
        recent_insufficient_balance: 0,
        recent_forced_used_bytes: 0,
        avg_tx_bytes_est: 0,
    };

    let decision = organiser.decide(&zero_inputs);

    // Values should be positive (base values)
    assert!(decision.sleep_ms > 0, "sleep_ms should be positive");
    assert!(decision.max_txs > 0, "max_txs should be positive");
    assert!(decision.max_bytes > 0, "max_bytes should be positive");
    assert!(
        decision.forced_drain_max > 0,
        "forced_drain_max should be positive"
    );
}

// ============== Serialization Tests ==============

#[test]
fn inputs_serialization_roundtrip() {
    let inputs = make_inputs(100, 20, 2);

    let json = serde_json::to_string(&inputs).expect("serialize");
    let parsed: OrganiserInputs = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(
        inputs, parsed,
        "serialization roundtrip should preserve data"
    );
}

#[test]
fn decision_serialization_roundtrip() {
    let organiser = GbdtOrganiserV1::new();
    let inputs = make_inputs(100, 20, 2);
    let decision = organiser.decide(&inputs);

    let json = serde_json::to_string(&decision).expect("serialize");
    let parsed: OrganiserDecision = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(
        decision, parsed,
        "serialization roundtrip should preserve data"
    );
}

#[test]
fn bounds_serialization_roundtrip() {
    let bounds = OrganiserPolicyBounds::default();

    let json = serde_json::to_string(&bounds).expect("serialize");
    let parsed: OrganiserPolicyBounds = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(
        bounds, parsed,
        "serialization roundtrip should preserve data"
    );
}
