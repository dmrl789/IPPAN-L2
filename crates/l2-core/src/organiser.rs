//! Deterministic organiser interface for L2 batch scheduling.
//!
//! The organiser is a **policy-only** component that influences *when* to build/submit
//! batches and *how much* to drain from queues. It **never** changes fee rates or
//! accepts unpaid transactions.
//!
//! ## Design Principles
//!
//! 1. **Deterministic**: All decisions use integer arithmetic only (no floats, no RNG)
//! 2. **Replayable**: Same inputs always produce the same outputs
//! 3. **Bounded**: All outputs are clamped to hard policy bounds
//! 4. **Auditable**: Decision inputs and outputs are logged for debugging
//!
//! ## Decision Flow
//!
//! ```text
//! OrganiserInputs (observable state)
//!         │
//!         ▼
//! ┌───────────────────┐
//! │ Organiser.decide  │ ← Policy-based decision tree
//! └───────────────────┘
//!         │
//!         ▼
//! ┌───────────────────┐
//! │ clamp(decision,   │ ← Hard bounds enforcement
//! │       bounds)     │
//! └───────────────────┘
//!         │
//!         ▼
//! OrganiserDecision (bounded outputs)
//! ```

use serde::{Deserialize, Serialize};

/// Version identifier for organiser implementations.
///
/// This allows tracking which version of the decision logic produced
/// a given decision, important for debugging and auditing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OrganiserVersion {
    /// No organiser (static config fallback).
    #[default]
    None,
    /// GBDT organiser v1 - compiled tree with integer thresholds.
    GbdtV1,
}

impl std::fmt::Display for OrganiserVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::GbdtV1 => write!(f, "gbdt_v1"),
        }
    }
}

/// Observable inputs for the organiser decision function.
///
/// These are safe, deterministic values that can be computed from the
/// current system state. All values are integers to ensure determinism.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganiserInputs {
    /// Current timestamp in milliseconds since epoch.
    pub now_ms: u64,
    /// Number of transactions waiting in the normal queue.
    pub queue_depth: u32,
    /// Number of transactions in the forced inclusion queue.
    pub forced_queue_depth: u32,
    /// Number of batches currently in-flight (submitted but not finalised).
    pub in_flight_batches: u32,
    /// Recent quota rejection count (rolling window).
    pub recent_quota_rejects: u32,
    /// Recent insufficient balance rejection count (rolling window).
    pub recent_insufficient_balance: u32,
    /// Recent bytes used by forced transactions (rolling window).
    pub recent_forced_used_bytes: u64,
    /// Estimated average transaction size in bytes.
    /// Computed as a deterministic integer EMA or bounded window average.
    pub avg_tx_bytes_est: u32,
}

impl Default for OrganiserInputs {
    fn default() -> Self {
        Self {
            now_ms: 0,
            queue_depth: 0,
            forced_queue_depth: 0,
            in_flight_batches: 0,
            recent_quota_rejects: 0,
            recent_insufficient_balance: 0,
            recent_forced_used_bytes: 0,
            avg_tx_bytes_est: 256, // Default estimate
        }
    }
}

impl OrganiserInputs {
    /// Create inputs with only the timestamp set.
    pub fn with_now(now_ms: u64) -> Self {
        Self {
            now_ms,
            ..Default::default()
        }
    }

    /// Builder: set queue depth.
    pub fn queue_depth(mut self, depth: u32) -> Self {
        self.queue_depth = depth;
        self
    }

    /// Builder: set forced queue depth.
    pub fn forced_queue_depth(mut self, depth: u32) -> Self {
        self.forced_queue_depth = depth;
        self
    }

    /// Builder: set in-flight batches count.
    pub fn in_flight_batches(mut self, count: u32) -> Self {
        self.in_flight_batches = count;
        self
    }

    /// Builder: set recent quota rejects.
    pub fn recent_quota_rejects(mut self, count: u32) -> Self {
        self.recent_quota_rejects = count;
        self
    }

    /// Builder: set recent insufficient balance count.
    pub fn recent_insufficient_balance(mut self, count: u32) -> Self {
        self.recent_insufficient_balance = count;
        self
    }

    /// Builder: set recent forced bytes used.
    pub fn recent_forced_used_bytes(mut self, bytes: u64) -> Self {
        self.recent_forced_used_bytes = bytes;
        self
    }

    /// Builder: set average tx bytes estimate.
    pub fn avg_tx_bytes_est(mut self, bytes: u32) -> Self {
        self.avg_tx_bytes_est = bytes;
        self
    }
}

/// Decision output from the organiser.
///
/// These values control batch scheduling behavior. All values are
/// subject to hard bounds enforcement via `OrganiserPolicyBounds::clamp`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganiserDecision {
    /// Sleep duration before building next batch (milliseconds).
    pub sleep_ms: u64,
    /// Maximum number of transactions to include in the batch.
    pub max_txs: u32,
    /// Maximum bytes to include in the batch.
    pub max_bytes: u32,
    /// Maximum number of forced queue transactions to drain.
    pub forced_drain_max: u32,
}

impl Default for OrganiserDecision {
    fn default() -> Self {
        Self {
            sleep_ms: 1000,
            max_txs: 256,
            max_bytes: 512 * 1024,
            forced_drain_max: 128,
        }
    }
}

impl OrganiserDecision {
    /// Create a decision with the given values.
    pub fn new(sleep_ms: u64, max_txs: u32, max_bytes: u32, forced_drain_max: u32) -> Self {
        Self {
            sleep_ms,
            max_txs,
            max_bytes,
            forced_drain_max,
        }
    }
}

/// Hard policy bounds that constrain organiser decisions.
///
/// These bounds ensure that even a misconfigured or buggy organiser
/// cannot produce decisions outside of safe operational limits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganiserPolicyBounds {
    /// Minimum sleep duration (ms).
    pub sleep_ms_min: u64,
    /// Maximum sleep duration (ms).
    pub sleep_ms_max: u64,
    /// Minimum max_txs per batch.
    pub max_txs_min: u32,
    /// Maximum max_txs per batch.
    pub max_txs_max: u32,
    /// Minimum max_bytes per batch.
    pub max_bytes_min: u32,
    /// Maximum max_bytes per batch.
    pub max_bytes_max: u32,
    /// Minimum forced drain cap.
    pub forced_drain_min: u32,
    /// Maximum forced drain cap.
    pub forced_drain_max: u32,
}

impl Default for OrganiserPolicyBounds {
    fn default() -> Self {
        Self {
            // Sleep: 10ms to 60 seconds
            sleep_ms_min: 10,
            sleep_ms_max: 60_000,
            // Txs: 1 to 1024
            max_txs_min: 1,
            max_txs_max: 1024,
            // Bytes: 1KB to 4MB
            max_bytes_min: 1024,
            max_bytes_max: 4 * 1024 * 1024,
            // Forced drain: 0 to 256
            forced_drain_min: 0,
            forced_drain_max: 256,
        }
    }
}

impl OrganiserPolicyBounds {
    /// Validate the bounds configuration.
    ///
    /// Returns an error message if bounds are invalid (min > max).
    pub fn validate(&self) -> Result<(), String> {
        if self.sleep_ms_min > self.sleep_ms_max {
            return Err(format!(
                "sleep_ms_min ({}) > sleep_ms_max ({})",
                self.sleep_ms_min, self.sleep_ms_max
            ));
        }
        if self.max_txs_min > self.max_txs_max {
            return Err(format!(
                "max_txs_min ({}) > max_txs_max ({})",
                self.max_txs_min, self.max_txs_max
            ));
        }
        if self.max_bytes_min > self.max_bytes_max {
            return Err(format!(
                "max_bytes_min ({}) > max_bytes_max ({})",
                self.max_bytes_min, self.max_bytes_max
            ));
        }
        if self.forced_drain_min > self.forced_drain_max {
            return Err(format!(
                "forced_drain_min ({}) > forced_drain_max ({})",
                self.forced_drain_min, self.forced_drain_max
            ));
        }
        Ok(())
    }

    /// Clamp a decision to be within these bounds.
    ///
    /// This is the primary safety mechanism: regardless of what the
    /// organiser decides, the output is always within safe limits.
    pub fn clamp(&self, decision: OrganiserDecision) -> OrganiserDecision {
        OrganiserDecision {
            sleep_ms: decision
                .sleep_ms
                .clamp(self.sleep_ms_min, self.sleep_ms_max),
            max_txs: decision.max_txs.clamp(self.max_txs_min, self.max_txs_max),
            max_bytes: decision
                .max_bytes
                .clamp(self.max_bytes_min, self.max_bytes_max),
            forced_drain_max: decision
                .forced_drain_max
                .clamp(self.forced_drain_min, self.forced_drain_max),
        }
    }

    /// Create bounds with tighter limits for testing.
    pub fn test_bounds() -> Self {
        Self {
            sleep_ms_min: 10,
            sleep_ms_max: 5_000,
            max_txs_min: 1,
            max_txs_max: 100,
            max_bytes_min: 1024,
            max_bytes_max: 100 * 1024,
            forced_drain_min: 0,
            forced_drain_max: 50,
        }
    }

    /// Create bounds from environment variables with fallback to defaults.
    pub fn from_env() -> Self {
        let default = Self::default();
        Self {
            sleep_ms_min: std::env::var("L2_ORGANISER_SLEEP_MS_MIN")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.sleep_ms_min),
            sleep_ms_max: std::env::var("L2_ORGANISER_SLEEP_MS_MAX")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.sleep_ms_max),
            max_txs_min: std::env::var("L2_ORGANISER_MAX_TXS_MIN")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.max_txs_min),
            max_txs_max: std::env::var("L2_ORGANISER_MAX_TXS_MAX")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.max_txs_max),
            max_bytes_min: std::env::var("L2_ORGANISER_MAX_BYTES_MIN")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.max_bytes_min),
            max_bytes_max: std::env::var("L2_ORGANISER_MAX_BYTES_MAX")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.max_bytes_max),
            forced_drain_min: std::env::var("L2_ORGANISER_FORCED_DRAIN_MIN")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.forced_drain_min),
            forced_drain_max: std::env::var("L2_ORGANISER_FORCED_DRAIN_MAX")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.forced_drain_max),
        }
    }
}

/// Trait for organiser implementations.
///
/// All organiser implementations must be:
/// - Deterministic: same inputs → same outputs
/// - Bounded: outputs subject to policy bounds
/// - No floats/RNG: integer arithmetic only
pub trait Organiser: Send + Sync {
    /// Return the version identifier for this organiser.
    fn version(&self) -> OrganiserVersion;

    /// Compute a scheduling decision from the given inputs.
    ///
    /// The returned decision may be outside of bounds; callers should
    /// use `OrganiserPolicyBounds::clamp` to enforce safety limits.
    fn decide(&self, inputs: &OrganiserInputs) -> OrganiserDecision;
}

/// Snapshot of organiser state for the /status endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrganiserStatus {
    /// Whether the organiser is enabled.
    pub enabled: bool,
    /// The organiser version.
    pub version: String,
    /// The last inputs used for a decision.
    pub last_inputs: Option<OrganiserInputs>,
    /// The last decision produced.
    pub last_decision: Option<OrganiserDecision>,
    /// The policy bounds in effect.
    pub bounds: OrganiserPolicyBounds,
}

impl Default for OrganiserStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            version: OrganiserVersion::None.to_string(),
            last_inputs: None,
            last_decision: None,
            bounds: OrganiserPolicyBounds::default(),
        }
    }
}

/// A no-op organiser that returns static defaults.
///
/// Used as a fallback when the organiser is disabled.
#[derive(Debug, Clone, Default)]
pub struct NoopOrganiser {
    /// Default decision to return.
    default_decision: OrganiserDecision,
}

impl NoopOrganiser {
    /// Create a new no-op organiser with the given default decision.
    pub fn new(default_decision: OrganiserDecision) -> Self {
        Self { default_decision }
    }
}

impl Organiser for NoopOrganiser {
    fn version(&self) -> OrganiserVersion {
        OrganiserVersion::None
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip(self, _inputs), level = "debug", name = "organiser_decide")
    )]
    fn decide(&self, _inputs: &OrganiserInputs) -> OrganiserDecision {
        self.default_decision.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organiser_inputs_default() {
        let inputs = OrganiserInputs::default();
        assert_eq!(inputs.queue_depth, 0);
        assert_eq!(inputs.forced_queue_depth, 0);
        assert_eq!(inputs.in_flight_batches, 0);
        assert_eq!(inputs.avg_tx_bytes_est, 256);
    }

    #[test]
    fn organiser_inputs_builder() {
        let inputs = OrganiserInputs::with_now(1_700_000_000_000)
            .queue_depth(100)
            .forced_queue_depth(5)
            .in_flight_batches(2)
            .recent_quota_rejects(10)
            .avg_tx_bytes_est(512);

        assert_eq!(inputs.now_ms, 1_700_000_000_000);
        assert_eq!(inputs.queue_depth, 100);
        assert_eq!(inputs.forced_queue_depth, 5);
        assert_eq!(inputs.in_flight_batches, 2);
        assert_eq!(inputs.recent_quota_rejects, 10);
        assert_eq!(inputs.avg_tx_bytes_est, 512);
    }

    #[test]
    fn organiser_decision_default() {
        let decision = OrganiserDecision::default();
        assert_eq!(decision.sleep_ms, 1000);
        assert_eq!(decision.max_txs, 256);
        assert_eq!(decision.max_bytes, 512 * 1024);
        assert_eq!(decision.forced_drain_max, 128);
    }

    #[test]
    fn policy_bounds_default() {
        let bounds = OrganiserPolicyBounds::default();
        assert!(bounds.validate().is_ok());
        assert_eq!(bounds.sleep_ms_min, 10);
        assert_eq!(bounds.sleep_ms_max, 60_000);
        assert_eq!(bounds.max_txs_min, 1);
        assert_eq!(bounds.max_txs_max, 1024);
    }

    #[test]
    fn policy_bounds_validation() {
        let mut bounds = OrganiserPolicyBounds::default();
        assert!(bounds.validate().is_ok());

        // Invalid: min > max for sleep
        bounds.sleep_ms_min = 10_000;
        bounds.sleep_ms_max = 1_000;
        assert!(bounds.validate().is_err());
    }

    #[test]
    fn policy_bounds_clamp() {
        let bounds = OrganiserPolicyBounds {
            sleep_ms_min: 100,
            sleep_ms_max: 5_000,
            max_txs_min: 10,
            max_txs_max: 500,
            max_bytes_min: 1024,
            max_bytes_max: 100_000,
            forced_drain_min: 1,
            forced_drain_max: 50,
        };

        // Decision within bounds - should be unchanged
        let decision = OrganiserDecision::new(1000, 100, 50_000, 25);
        let clamped = bounds.clamp(decision.clone());
        assert_eq!(clamped, decision);

        // Decision below bounds - should be raised to min
        let decision = OrganiserDecision::new(10, 5, 500, 0);
        let clamped = bounds.clamp(decision);
        assert_eq!(clamped.sleep_ms, 100); // Clamped to min
        assert_eq!(clamped.max_txs, 10); // Clamped to min
        assert_eq!(clamped.max_bytes, 1024); // Clamped to min
        assert_eq!(clamped.forced_drain_max, 1); // Clamped to min

        // Decision above bounds - should be reduced to max
        let decision = OrganiserDecision::new(100_000, 2000, 1_000_000, 200);
        let clamped = bounds.clamp(decision);
        assert_eq!(clamped.sleep_ms, 5_000); // Clamped to max
        assert_eq!(clamped.max_txs, 500); // Clamped to max
        assert_eq!(clamped.max_bytes, 100_000); // Clamped to max
        assert_eq!(clamped.forced_drain_max, 50); // Clamped to max
    }

    #[test]
    fn noop_organiser_returns_defaults() {
        let default_decision = OrganiserDecision::new(500, 128, 256_000, 64);
        let organiser = NoopOrganiser::new(default_decision.clone());

        assert_eq!(organiser.version(), OrganiserVersion::None);

        // Same inputs, always same output
        let inputs = OrganiserInputs::with_now(1_000);
        let decision = organiser.decide(&inputs);
        assert_eq!(decision, default_decision);

        // Different inputs, still same output
        let inputs = OrganiserInputs::with_now(2_000).queue_depth(100);
        let decision = organiser.decide(&inputs);
        assert_eq!(decision, default_decision);
    }

    #[test]
    fn organiser_version_display() {
        assert_eq!(OrganiserVersion::None.to_string(), "none");
        assert_eq!(OrganiserVersion::GbdtV1.to_string(), "gbdt_v1");
    }

    #[test]
    fn organiser_inputs_serialization() {
        let inputs = OrganiserInputs::with_now(1_700_000_000_000)
            .queue_depth(42)
            .forced_queue_depth(3);

        let json = serde_json::to_string(&inputs).unwrap();
        let parsed: OrganiserInputs = serde_json::from_str(&json).unwrap();
        assert_eq!(inputs, parsed);
    }

    #[test]
    fn organiser_decision_serialization() {
        let decision = OrganiserDecision::new(500, 128, 256_000, 64);

        let json = serde_json::to_string(&decision).unwrap();
        let parsed: OrganiserDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, parsed);
    }

    #[test]
    fn policy_bounds_serialization() {
        let bounds = OrganiserPolicyBounds::test_bounds();

        let json = serde_json::to_string(&bounds).unwrap();
        let parsed: OrganiserPolicyBounds = serde_json::from_str(&json).unwrap();
        assert_eq!(bounds, parsed);
    }
}
