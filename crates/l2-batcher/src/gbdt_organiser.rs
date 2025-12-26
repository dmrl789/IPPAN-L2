//! Deterministic GBDT-style organiser for L2 batch scheduling.
//!
//! This module implements a "compiled tree" decision function with integer
//! thresholds only. No floats, no external ML runtime, no randomness.
//!
//! ## Design
//!
//! The organiser uses a hardcoded decision tree (version v1) that:
//! - Reduces sleep when queue_depth is high
//! - Increases max_txs/max_bytes when backlog is high
//! - Caps forced_drain_max tightly
//! - Slows down when too many in-flight batches
//!
//! All decisions are deterministic and replayable for given inputs.
//!
//! ## Future Extensions
//!
//! In the future, we may support loading a static JSON model file with
//! integer nodes, hash-locked for integrity. The current implementation
//! is "compiled tree" style for simplicity and auditability.

use l2_core::organiser::{Organiser, OrganiserDecision, OrganiserInputs, OrganiserVersion};

/// GBDT organiser version 1 - compiled integer decision tree.
///
/// This is a policy-only organiser that influences scheduling decisions
/// without touching fee rates or settlement truth.
#[derive(Debug, Clone)]
pub struct GbdtOrganiserV1 {
    /// Base sleep duration when idle (ms).
    base_sleep_ms: u64,
    /// Base max txs per batch.
    base_max_txs: u32,
    /// Base max bytes per batch.
    base_max_bytes: u32,
    /// Base forced drain cap.
    base_forced_drain: u32,
}

impl Default for GbdtOrganiserV1 {
    fn default() -> Self {
        Self {
            base_sleep_ms: 1000,
            base_max_txs: 256,
            base_max_bytes: 512 * 1024,
            base_forced_drain: 128,
        }
    }
}

impl GbdtOrganiserV1 {
    /// Create a new GBDT organiser with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a GBDT organiser with custom base parameters.
    pub fn with_base_params(
        base_sleep_ms: u64,
        base_max_txs: u32,
        base_max_bytes: u32,
        base_forced_drain: u32,
    ) -> Self {
        Self {
            base_sleep_ms,
            base_max_txs,
            base_max_bytes,
            base_forced_drain,
        }
    }

    /// Compute sleep duration based on queue state.
    ///
    /// Decision tree:
    /// - If in_flight_batches >= 3, increase sleep (backpressure)
    /// - If queue_depth > 500, reduce sleep aggressively
    /// - If queue_depth > 100, reduce sleep moderately
    /// - If queue_depth > 20, reduce sleep slightly
    /// - Otherwise, use base sleep
    fn compute_sleep_ms(&self, inputs: &OrganiserInputs) -> u64 {
        // Backpressure: if too many batches in flight, slow down
        if inputs.in_flight_batches >= 3 {
            // Increase sleep proportionally to in-flight count
            // Use saturating mul to avoid overflow
            let multiplier = u64::from(inputs.in_flight_batches);
            return self.base_sleep_ms.saturating_mul(multiplier);
        }

        // Queue depth decision tree (integer thresholds)
        if inputs.queue_depth > 500 {
            // Very high backlog - drain fast
            // sleep_ms = base / 10 (minimum 10ms)
            self.base_sleep_ms.saturating_div(10).max(10)
        } else if inputs.queue_depth > 100 {
            // High backlog - drain moderately
            // sleep_ms = base / 4
            self.base_sleep_ms.saturating_div(4).max(10)
        } else if inputs.queue_depth > 20 {
            // Moderate backlog - slightly faster
            // sleep_ms = base / 2
            self.base_sleep_ms.saturating_div(2).max(10)
        } else {
            // Normal operation - use base sleep
            self.base_sleep_ms
        }
    }

    /// Compute max_txs based on queue state.
    ///
    /// Decision tree:
    /// - If queue_depth > 500, use full capacity
    /// - If queue_depth > 100, use 75% capacity
    /// - If queue_depth > 20, use 50% capacity
    /// - Otherwise, use 25% capacity (smaller batches when idle)
    fn compute_max_txs(&self, inputs: &OrganiserInputs) -> u32 {
        if inputs.queue_depth > 500 {
            // Full capacity
            self.base_max_txs
        } else if inputs.queue_depth > 100 {
            // 75% capacity - use integer math: (base * 3) / 4
            self.base_max_txs.saturating_mul(3).saturating_div(4).max(1)
        } else if inputs.queue_depth > 20 {
            // 50% capacity
            self.base_max_txs.saturating_div(2).max(1)
        } else {
            // 25% capacity for smaller batches when idle
            self.base_max_txs.saturating_div(4).max(1)
        }
    }

    /// Compute max_bytes based on queue state and avg tx size.
    ///
    /// Uses estimated tx bytes to compute expected batch size.
    fn compute_max_bytes(&self, inputs: &OrganiserInputs) -> u32 {
        // Scale similarly to max_txs
        if inputs.queue_depth > 500 {
            self.base_max_bytes
        } else if inputs.queue_depth > 100 {
            self.base_max_bytes
                .saturating_mul(3)
                .saturating_div(4)
                .max(1024)
        } else if inputs.queue_depth > 20 {
            self.base_max_bytes.saturating_div(2).max(1024)
        } else {
            self.base_max_bytes.saturating_div(4).max(1024)
        }
    }

    /// Compute forced_drain_max based on forced queue state.
    ///
    /// Decision tree:
    /// - Base forced drain is capped tightly
    /// - If forced_queue_depth > 50, drain more aggressively
    /// - If forced_queue_depth > 10, drain moderately
    /// - Otherwise, drain conservatively
    ///
    /// Also considers recent_forced_used_bytes to avoid overwhelming
    /// batches with forced traffic.
    fn compute_forced_drain_max(&self, inputs: &OrganiserInputs) -> u32 {
        // If we've recently used a lot of forced bytes, be more conservative
        let recent_forced_kb = inputs.recent_forced_used_bytes.saturating_div(1024);

        // If recent forced traffic is high (> 100KB), reduce drain cap
        let reduction_factor = if recent_forced_kb > 100 {
            4u32
        } else if recent_forced_kb > 50 {
            2u32
        } else {
            1u32
        };

        // Base drain based on forced queue depth
        let base_drain = if inputs.forced_queue_depth > 50 {
            // High forced backlog - drain more
            self.base_forced_drain
        } else if inputs.forced_queue_depth > 10 {
            // Moderate forced backlog
            self.base_forced_drain.saturating_div(2).max(1)
        } else {
            // Low forced backlog - conservative drain
            self.base_forced_drain.saturating_div(4).max(1)
        };

        // Apply reduction factor
        base_drain.saturating_div(reduction_factor).max(1)
    }
}

impl Organiser for GbdtOrganiserV1 {
    fn version(&self) -> OrganiserVersion {
        OrganiserVersion::GbdtV1
    }

    fn decide(&self, inputs: &OrganiserInputs) -> OrganiserDecision {
        OrganiserDecision {
            sleep_ms: self.compute_sleep_ms(inputs),
            max_txs: self.compute_max_txs(inputs),
            max_bytes: self.compute_max_bytes(inputs),
            forced_drain_max: self.compute_forced_drain_max(inputs),
        }
    }
}

/// Configuration for the GBDT organiser.
#[derive(Debug, Clone)]
pub struct GbdtOrganiserConfig {
    /// Whether the organiser is enabled.
    pub enabled: bool,
    /// Base sleep duration when idle (ms).
    pub base_sleep_ms: u64,
    /// Base max txs per batch.
    pub base_max_txs: u32,
    /// Base max bytes per batch.
    pub base_max_bytes: u32,
    /// Base forced drain cap.
    pub base_forced_drain: u32,
}

impl Default for GbdtOrganiserConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_sleep_ms: 1000,
            base_max_txs: 256,
            base_max_bytes: 512 * 1024,
            base_forced_drain: 128,
        }
    }
}

impl GbdtOrganiserConfig {
    /// Create configuration from environment variables.
    pub fn from_env() -> Self {
        let default = Self::default();
        Self {
            enabled: std::env::var("L2_ORGANISER_ENABLED")
                .map(|s| s != "0" && s.to_lowercase() != "false")
                .unwrap_or(default.enabled),
            base_sleep_ms: std::env::var("L2_ORGANISER_BASE_SLEEP_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.base_sleep_ms),
            base_max_txs: std::env::var("L2_ORGANISER_BASE_MAX_TXS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.base_max_txs),
            base_max_bytes: std::env::var("L2_ORGANISER_BASE_MAX_BYTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.base_max_bytes),
            base_forced_drain: std::env::var("L2_ORGANISER_BASE_FORCED_DRAIN")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.base_forced_drain),
        }
    }

    /// Create a GBDT organiser from this configuration.
    pub fn build(&self) -> GbdtOrganiserV1 {
        GbdtOrganiserV1::with_base_params(
            self.base_sleep_ms,
            self.base_max_txs,
            self.base_max_bytes,
            self.base_forced_drain,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inputs() -> OrganiserInputs {
        OrganiserInputs::with_now(1_700_000_000_000)
    }

    #[test]
    fn gbdt_v1_version() {
        let organiser = GbdtOrganiserV1::new();
        assert_eq!(organiser.version(), OrganiserVersion::GbdtV1);
    }

    #[test]
    fn gbdt_v1_idle_state() {
        let organiser = GbdtOrganiserV1::new();
        let inputs = make_inputs();

        let decision = organiser.decide(&inputs);

        // Idle state: conservative parameters
        assert_eq!(decision.sleep_ms, 1000); // Base sleep
        assert_eq!(decision.max_txs, 64); // 25% of base (256)
        assert_eq!(decision.max_bytes, 131072); // 25% of base (512KB)
        assert_eq!(decision.forced_drain_max, 32); // 25% of base (128)
    }

    #[test]
    fn gbdt_v1_moderate_load() {
        let organiser = GbdtOrganiserV1::new();
        let inputs = make_inputs().queue_depth(50).forced_queue_depth(15);

        let decision = organiser.decide(&inputs);

        // Moderate load: 50% parameters
        assert_eq!(decision.sleep_ms, 500); // Half of base
        assert_eq!(decision.max_txs, 128); // 50% of base
        assert_eq!(decision.max_bytes, 262144); // 50% of base
        assert_eq!(decision.forced_drain_max, 64); // 50% due to forced_queue_depth > 10
    }

    #[test]
    fn gbdt_v1_high_load() {
        let organiser = GbdtOrganiserV1::new();
        let inputs = make_inputs().queue_depth(200).forced_queue_depth(60);

        let decision = organiser.decide(&inputs);

        // High load: 75% parameters
        assert_eq!(decision.sleep_ms, 250); // 25% of base (faster)
        assert_eq!(decision.max_txs, 192); // 75% of base
        assert_eq!(decision.max_bytes, 393216); // 75% of base
        assert_eq!(decision.forced_drain_max, 128); // Full due to forced_queue_depth > 50
    }

    #[test]
    fn gbdt_v1_very_high_load() {
        let organiser = GbdtOrganiserV1::new();
        let inputs = make_inputs().queue_depth(600).forced_queue_depth(100);

        let decision = organiser.decide(&inputs);

        // Very high load: full parameters
        assert_eq!(decision.sleep_ms, 100); // 10% of base (very fast)
        assert_eq!(decision.max_txs, 256); // Full base
        assert_eq!(decision.max_bytes, 524288); // Full base
        assert_eq!(decision.forced_drain_max, 128); // Full base
    }

    #[test]
    fn gbdt_v1_backpressure_from_in_flight() {
        let organiser = GbdtOrganiserV1::new();
        let inputs = make_inputs()
            .queue_depth(600) // High load
            .in_flight_batches(4); // Too many in-flight

        let decision = organiser.decide(&inputs);

        // Backpressure: sleep increases despite high queue
        assert_eq!(decision.sleep_ms, 4000); // base * 4 (in_flight_batches)
                                             // Other params still reflect queue depth
        assert_eq!(decision.max_txs, 256);
        assert_eq!(decision.max_bytes, 524288);
    }

    #[test]
    fn gbdt_v1_forced_traffic_reduction() {
        let organiser = GbdtOrganiserV1::new();
        let inputs = make_inputs()
            .forced_queue_depth(60)
            .recent_forced_used_bytes(150 * 1024); // 150KB

        let decision = organiser.decide(&inputs);

        // Forced traffic high: reduce drain cap
        // Base would be 128, but reduction factor 4 applies
        assert_eq!(decision.forced_drain_max, 32); // 128 / 4
    }

    #[test]
    fn gbdt_v1_determinism() {
        let organiser = GbdtOrganiserV1::new();

        // Same inputs must always produce same outputs
        let inputs = make_inputs()
            .queue_depth(100)
            .forced_queue_depth(20)
            .in_flight_batches(1);

        let decision1 = organiser.decide(&inputs);
        let decision2 = organiser.decide(&inputs);
        let decision3 = organiser.decide(&inputs);

        assert_eq!(decision1, decision2);
        assert_eq!(decision2, decision3);
    }

    #[test]
    fn gbdt_v1_determinism_different_timestamps() {
        let organiser = GbdtOrganiserV1::new();

        // Timestamp should not affect decision (it's not used in v1)
        let inputs1 = OrganiserInputs::with_now(1_000_000).queue_depth(50);
        let inputs2 = OrganiserInputs::with_now(2_000_000).queue_depth(50);

        let decision1 = organiser.decide(&inputs1);
        let decision2 = organiser.decide(&inputs2);

        // Same queue state, different timestamps -> same decision
        assert_eq!(decision1, decision2);
    }

    #[test]
    fn gbdt_v1_monotonic_sleep_vs_queue() {
        let organiser = GbdtOrganiserV1::new();

        // Higher queue depth should not increase sleep (unless capped by in-flight)
        let inputs_low = make_inputs().queue_depth(10);
        let inputs_medium = make_inputs().queue_depth(50);
        let inputs_high = make_inputs().queue_depth(200);
        let inputs_very_high = make_inputs().queue_depth(600);

        let sleep_low = organiser.decide(&inputs_low).sleep_ms;
        let sleep_medium = organiser.decide(&inputs_medium).sleep_ms;
        let sleep_high = organiser.decide(&inputs_high).sleep_ms;
        let sleep_very_high = organiser.decide(&inputs_very_high).sleep_ms;

        // Sleep should decrease (or stay same) as queue depth increases
        assert!(sleep_low >= sleep_medium);
        assert!(sleep_medium >= sleep_high);
        assert!(sleep_high >= sleep_very_high);
    }

    #[test]
    fn gbdt_v1_monotonic_forced_drain() {
        let organiser = GbdtOrganiserV1::new();

        // Higher forced_queue_depth should increase forced_drain_max (up to cap)
        let inputs_low = make_inputs().forced_queue_depth(5);
        let inputs_medium = make_inputs().forced_queue_depth(15);
        let inputs_high = make_inputs().forced_queue_depth(60);

        let drain_low = organiser.decide(&inputs_low).forced_drain_max;
        let drain_medium = organiser.decide(&inputs_medium).forced_drain_max;
        let drain_high = organiser.decide(&inputs_high).forced_drain_max;

        // Forced drain should increase (or stay same) as forced queue depth increases
        assert!(drain_low <= drain_medium);
        assert!(drain_medium <= drain_high);
    }

    #[test]
    fn gbdt_v1_overflow_safety() {
        let organiser = GbdtOrganiserV1::new();

        // Large values should not cause overflow
        let inputs = OrganiserInputs {
            now_ms: u64::MAX,
            queue_depth: u32::MAX,
            forced_queue_depth: u32::MAX,
            in_flight_batches: u32::MAX,
            recent_quota_rejects: u32::MAX,
            recent_insufficient_balance: u32::MAX,
            recent_forced_used_bytes: u64::MAX,
            avg_tx_bytes_est: u32::MAX,
        };

        // Should not panic
        let decision = organiser.decide(&inputs);

        // Values should be saturated, not overflowed
        assert!(decision.sleep_ms > 0);
        assert!(decision.max_txs > 0);
        assert!(decision.max_bytes > 0);
        assert!(decision.forced_drain_max > 0);
    }

    #[test]
    fn gbdt_config_from_env_defaults() {
        // Clear relevant env vars first
        std::env::remove_var("L2_ORGANISER_ENABLED");
        std::env::remove_var("L2_ORGANISER_BASE_SLEEP_MS");

        let config = GbdtOrganiserConfig::from_env();
        assert!(config.enabled);
        assert_eq!(config.base_sleep_ms, 1000);
        assert_eq!(config.base_max_txs, 256);
        assert_eq!(config.base_max_bytes, 512 * 1024);
        assert_eq!(config.base_forced_drain, 128);
    }

    #[test]
    fn gbdt_config_build() {
        let config = GbdtOrganiserConfig {
            enabled: true,
            base_sleep_ms: 500,
            base_max_txs: 100,
            base_max_bytes: 100_000,
            base_forced_drain: 50,
        };

        let organiser = config.build();

        // Verify the organiser uses the config values
        let inputs = make_inputs().queue_depth(600); // Max capacity
        let decision = organiser.decide(&inputs);

        assert_eq!(decision.max_txs, 100);
        assert_eq!(decision.max_bytes, 100_000);
    }

    #[test]
    fn gbdt_v1_with_custom_params() {
        let organiser = GbdtOrganiserV1::with_base_params(2000, 512, 1024 * 1024, 256);

        let inputs = make_inputs().queue_depth(600);
        let decision = organiser.decide(&inputs);

        // Custom base values
        assert_eq!(decision.sleep_ms, 200); // 2000 / 10
        assert_eq!(decision.max_txs, 512);
        assert_eq!(decision.max_bytes, 1024 * 1024);
        assert_eq!(decision.forced_drain_max, 64); // 256 / 4 (conservative with no forced queue)
    }
}
