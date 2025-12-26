//! Deterministic GBDT-style organiser V2 with multi-hub fairness.
//!
//! This module implements hub-aware scheduling with:
//! - Deterministic hub selection (no randomness)
//! - Weighted fairness based on queue depths
//! - Starvation prevention via bounded iteration counts
//! - Priority for forced queue processing
//!
//! ## Hub Selection Algorithm
//!
//! 1. **Forced Priority**: If any hub has forced queue items, serve the hub
//!    with the highest forced queue depth first (tie-break by hub order).
//!
//! 2. **Weighted Fairness**: Otherwise, select hub proportional to queue depth
//!    using deterministic integer arithmetic. Uses a "virtual time" concept
//!    to ensure fairness over time.
//!
//! 3. **Starvation Prevention**: Track iterations since last served for each hub.
//!    If any hub exceeds a threshold, prioritize it.
//!
//! 4. **Tie-Breaking**: When scores are equal, use hub enum order (Fin < Data < M2m < World < Bridge).

use l2_core::organiser::OrganiserPolicyBounds;
use l2_core::{L2HubId, ALL_HUBS};
use serde::{Deserialize, Serialize};

use crate::{HubInputs, OrganiserDecisionV2, OrganiserInputsV2};

/// OrganiserV2 version identifier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OrganiserVersionV2 {
    /// No organiser (static config fallback).
    #[default]
    None,
    /// GBDT organiser v2 - compiled tree with hub selection.
    GbdtV2,
}

impl std::fmt::Display for OrganiserVersionV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::GbdtV2 => write!(f, "gbdt_v2"),
        }
    }
}

/// Trait for V2 organisers with multi-hub support.
pub trait OrganiserV2: Send + Sync {
    /// Return the version identifier.
    fn version(&self) -> OrganiserVersionV2;

    /// Compute a scheduling decision from the given inputs.
    fn decide(&self, inputs: &OrganiserInputsV2) -> OrganiserDecisionV2;
}

/// GBDT organiser V2 - multi-hub scheduling with deterministic fairness.
///
/// This organiser selects which hub to serve based on:
/// 1. Forced queue priority (highest forced depth wins)
/// 2. Weighted queue depth with starvation prevention
/// 3. Deterministic tie-breaking via hub enum order
#[derive(Debug, Clone)]
pub struct GbdtOrganiserV2 {
    /// Base sleep duration when idle (ms).
    base_sleep_ms: u64,
    /// Base max txs per batch.
    base_max_txs: u32,
    /// Base max bytes per batch.
    base_max_bytes: u32,
    /// Base forced drain cap.
    base_forced_drain: u32,
    /// Starvation threshold: max iterations without serving a hub.
    starvation_threshold: u32,
    /// Policy bounds for clamping decisions.
    bounds: OrganiserPolicyBounds,
    /// Internal fairness state (iterations since last served per hub).
    /// Stored as array indexed by hub for determinism.
    iterations_since_served: [u32; 5],
}

impl Default for GbdtOrganiserV2 {
    fn default() -> Self {
        Self {
            base_sleep_ms: 1000,
            base_max_txs: 256,
            base_max_bytes: 512 * 1024,
            base_forced_drain: 128,
            starvation_threshold: 10,
            bounds: OrganiserPolicyBounds::default(),
            iterations_since_served: [0; 5],
        }
    }
}

impl GbdtOrganiserV2 {
    /// Create a new GBDT organiser V2 with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom parameters.
    pub fn with_params(
        base_sleep_ms: u64,
        base_max_txs: u32,
        base_max_bytes: u32,
        base_forced_drain: u32,
        starvation_threshold: u32,
        bounds: OrganiserPolicyBounds,
    ) -> Self {
        Self {
            base_sleep_ms,
            base_max_txs,
            base_max_bytes,
            base_forced_drain,
            starvation_threshold,
            bounds,
            iterations_since_served: [0; 5],
        }
    }

    /// Select which hub to serve based on current state.
    ///
    /// Returns the chosen hub using deterministic fairness algorithm.
    fn select_hub(&self, inputs: &OrganiserInputsV2) -> L2HubId {
        // Phase 1: Check for starving hubs (highest priority)
        let starving_hub = self.find_starving_hub(inputs);
        if let Some(hub) = starving_hub {
            return hub;
        }

        // Phase 2: Check for forced queue priority
        let forced_hub = self.find_forced_priority_hub(inputs);
        if let Some(hub) = forced_hub {
            return hub;
        }

        // Phase 3: Weighted fairness by queue depth
        self.select_by_weighted_depth(inputs)
    }

    /// Find a hub that has exceeded the starvation threshold.
    fn find_starving_hub(&self, inputs: &OrganiserInputsV2) -> Option<L2HubId> {
        let mut best_hub: Option<L2HubId> = None;
        let mut best_starvation: u32 = 0;

        for (idx, &hub) in ALL_HUBS.iter().enumerate() {
            // Only consider hubs with work to do
            let hub_inputs = inputs.get_hub(hub)?;
            if hub_inputs.queue_depth == 0 && hub_inputs.forced_queue_depth == 0 {
                continue;
            }

            let starvation = self.iterations_since_served[idx];
            if starvation >= self.starvation_threshold && starvation > best_starvation {
                best_starvation = starvation;
                best_hub = Some(hub);
            }
        }

        best_hub
    }

    /// Find the hub with highest forced queue depth (forced priority).
    fn find_forced_priority_hub(&self, inputs: &OrganiserInputsV2) -> Option<L2HubId> {
        let mut best_hub: Option<L2HubId> = None;
        let mut best_forced: u32 = 0;

        for &hub in ALL_HUBS.iter() {
            let hub_inputs = match inputs.get_hub(hub) {
                Some(h) => h,
                None => continue,
            };

            // Only consider hubs with forced items
            if hub_inputs.forced_queue_depth > best_forced {
                best_forced = hub_inputs.forced_queue_depth;
                best_hub = Some(hub);
            }
        }

        best_hub
    }

    /// Select hub proportional to queue depth with tie-breaking.
    fn select_by_weighted_depth(&self, inputs: &OrganiserInputsV2) -> L2HubId {
        let mut best_hub = L2HubId::Fin; // Default fallback
        let mut best_score: u64 = 0;

        for &hub in ALL_HUBS.iter() {
            let hub_inputs = match inputs.get_hub(hub) {
                Some(h) => h,
                None => continue,
            };

            // Skip empty hubs
            if hub_inputs.queue_depth == 0 {
                continue;
            }

            // Score = queue_depth * (iterations_since_served + 1)
            // This gives preference to both deeper queues and starving hubs
            let idx = hub.index();
            let starvation_boost = u64::from(self.iterations_since_served[idx].saturating_add(1));
            let score = u64::from(hub_inputs.queue_depth).saturating_mul(starvation_boost);

            // Use > for tie-breaking (first hub wins due to enum order)
            if score > best_score {
                best_score = score;
                best_hub = hub;
            }
        }

        best_hub
    }

    /// Compute sleep duration based on chosen hub's queue state.
    fn compute_sleep_ms(&self, hub_inputs: &HubInputs) -> u64 {
        // Backpressure: if too many batches in flight, slow down
        if hub_inputs.in_flight_batches >= 3 {
            let multiplier = u64::from(hub_inputs.in_flight_batches);
            return self.base_sleep_ms.saturating_mul(multiplier);
        }

        // Queue depth decision tree (same as V1)
        if hub_inputs.queue_depth > 500 {
            self.base_sleep_ms.saturating_div(10).max(10)
        } else if hub_inputs.queue_depth > 100 {
            self.base_sleep_ms.saturating_div(4).max(10)
        } else if hub_inputs.queue_depth > 20 {
            self.base_sleep_ms.saturating_div(2).max(10)
        } else {
            self.base_sleep_ms
        }
    }

    /// Compute max_txs based on chosen hub's queue state.
    fn compute_max_txs(&self, hub_inputs: &HubInputs) -> u32 {
        if hub_inputs.queue_depth > 500 {
            self.base_max_txs
        } else if hub_inputs.queue_depth > 100 {
            self.base_max_txs.saturating_mul(3).saturating_div(4).max(1)
        } else if hub_inputs.queue_depth > 20 {
            self.base_max_txs.saturating_div(2).max(1)
        } else {
            self.base_max_txs.saturating_div(4).max(1)
        }
    }

    /// Compute max_bytes based on chosen hub's queue state.
    fn compute_max_bytes(&self, hub_inputs: &HubInputs) -> u32 {
        if hub_inputs.queue_depth > 500 {
            self.base_max_bytes
        } else if hub_inputs.queue_depth > 100 {
            self.base_max_bytes
                .saturating_mul(3)
                .saturating_div(4)
                .max(1024)
        } else if hub_inputs.queue_depth > 20 {
            self.base_max_bytes.saturating_div(2).max(1024)
        } else {
            self.base_max_bytes.saturating_div(4).max(1024)
        }
    }

    /// Compute forced_drain_max based on chosen hub's forced queue state.
    fn compute_forced_drain_max(&self, hub_inputs: &HubInputs) -> u32 {
        if hub_inputs.forced_queue_depth > 50 {
            self.base_forced_drain
        } else if hub_inputs.forced_queue_depth > 10 {
            self.base_forced_drain.saturating_div(2).max(1)
        } else {
            self.base_forced_drain.saturating_div(4).max(1)
        }
    }

    /// Update internal state after serving a hub.
    /// 
    /// This should be called by the batcher after processing a batch.
    pub fn mark_hub_served(&mut self, hub: L2HubId) {
        let idx = hub.index();
        self.iterations_since_served[idx] = 0;

        // Increment all other hubs
        for (i, count) in self.iterations_since_served.iter_mut().enumerate() {
            if i != idx {
                *count = count.saturating_add(1);
            }
        }
    }

    /// Get the number of iterations since a hub was served.
    pub fn iterations_since_served(&self, hub: L2HubId) -> u32 {
        self.iterations_since_served[hub.index()]
    }

    /// Reset all fairness counters.
    pub fn reset_fairness_counters(&mut self) {
        self.iterations_since_served = [0; 5];
    }
}

impl OrganiserV2 for GbdtOrganiserV2 {
    fn version(&self) -> OrganiserVersionV2 {
        OrganiserVersionV2::GbdtV2
    }

    fn decide(&self, inputs: &OrganiserInputsV2) -> OrganiserDecisionV2 {
        // Select which hub to serve
        let chosen_hub = self.select_hub(inputs);

        // Get inputs for the chosen hub
        let hub_inputs = inputs
            .get_hub(chosen_hub)
            .cloned()
            .unwrap_or_default();

        // Compute parameters for the chosen hub
        let raw_decision = OrganiserDecisionV2 {
            chosen_hub,
            sleep_ms: self.compute_sleep_ms(&hub_inputs),
            max_txs: self.compute_max_txs(&hub_inputs),
            max_bytes: self.compute_max_bytes(&hub_inputs),
            forced_drain_max: self.compute_forced_drain_max(&hub_inputs),
        };

        // Clamp to policy bounds
        OrganiserDecisionV2 {
            chosen_hub: raw_decision.chosen_hub,
            sleep_ms: raw_decision
                .sleep_ms
                .clamp(self.bounds.sleep_ms_min, self.bounds.sleep_ms_max),
            max_txs: raw_decision
                .max_txs
                .clamp(self.bounds.max_txs_min, self.bounds.max_txs_max),
            max_bytes: raw_decision
                .max_bytes
                .clamp(self.bounds.max_bytes_min, self.bounds.max_bytes_max),
            forced_drain_max: raw_decision
                .forced_drain_max
                .clamp(self.bounds.forced_drain_min, self.bounds.forced_drain_max),
        }
    }
}

/// No-op V2 organiser that always returns a fixed decision.
#[derive(Debug, Clone)]
pub struct NoopOrganiserV2 {
    default_decision: OrganiserDecisionV2,
}

impl NoopOrganiserV2 {
    /// Create a new no-op V2 organiser.
    pub fn new(default_decision: OrganiserDecisionV2) -> Self {
        Self { default_decision }
    }
}

impl OrganiserV2 for NoopOrganiserV2 {
    fn version(&self) -> OrganiserVersionV2 {
        OrganiserVersionV2::None
    }

    fn decide(&self, _inputs: &OrganiserInputsV2) -> OrganiserDecisionV2 {
        self.default_decision.clone()
    }
}

/// Configuration for GBDT organiser V2.
#[derive(Debug, Clone)]
pub struct GbdtOrganiserV2Config {
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
    /// Starvation threshold (max iterations without serving a hub).
    pub starvation_threshold: u32,
    /// Policy bounds.
    pub bounds: OrganiserPolicyBounds,
}

impl Default for GbdtOrganiserV2Config {
    fn default() -> Self {
        Self {
            enabled: true,
            base_sleep_ms: 1000,
            base_max_txs: 256,
            base_max_bytes: 512 * 1024,
            base_forced_drain: 128,
            starvation_threshold: 10,
            bounds: OrganiserPolicyBounds::default(),
        }
    }
}

impl GbdtOrganiserV2Config {
    /// Create configuration from environment variables.
    pub fn from_env() -> Self {
        let default = Self::default();
        Self {
            enabled: std::env::var("L2_ORGANISER_V2_ENABLED")
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
            starvation_threshold: std::env::var("L2_ORGANISER_STARVATION_THRESHOLD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.starvation_threshold),
            bounds: OrganiserPolicyBounds::from_env(),
        }
    }

    /// Build a GBDT organiser V2 from this configuration.
    pub fn build(&self) -> GbdtOrganiserV2 {
        GbdtOrganiserV2::with_params(
            self.base_sleep_ms,
            self.base_max_txs,
            self.base_max_bytes,
            self.base_forced_drain,
            self.starvation_threshold,
            self.bounds.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inputs(hub_depths: &[(L2HubId, u32, u32)]) -> OrganiserInputsV2 {
        let mut hubs: Vec<HubInputs> = ALL_HUBS
            .iter()
            .map(|&hub| HubInputs {
                hub,
                queue_depth: 0,
                forced_queue_depth: 0,
                in_flight_batches: 0,
                recent_rejects: 0,
                avg_tx_bytes_est: 256,
            })
            .collect();

        for (hub, queue_depth, forced_depth) in hub_depths {
            if let Some(h) = hubs.iter_mut().find(|h| h.hub == *hub) {
                h.queue_depth = *queue_depth;
                h.forced_queue_depth = *forced_depth;
            }
        }

        OrganiserInputsV2 {
            now_ms: 1_700_000_000_000,
            hubs,
        }
    }

    // ========== Version Tests ==========

    #[test]
    fn version_is_gbdt_v2() {
        let organiser = GbdtOrganiserV2::new();
        assert_eq!(organiser.version(), OrganiserVersionV2::GbdtV2);
    }

    #[test]
    fn noop_version_is_none() {
        let organiser = NoopOrganiserV2::new(OrganiserDecisionV2::default());
        assert_eq!(organiser.version(), OrganiserVersionV2::None);
    }

    // ========== Hub Selection Tests ==========

    #[test]
    fn select_hub_with_forced_priority() {
        let organiser = GbdtOrganiserV2::new();

        // DATA has more forced items than FIN
        let inputs = make_inputs(&[
            (L2HubId::Fin, 100, 5),
            (L2HubId::Data, 50, 20),
            (L2HubId::M2m, 200, 0),
        ]);

        let decision = organiser.decide(&inputs);
        // DATA should be chosen due to highest forced queue
        assert_eq!(decision.chosen_hub, L2HubId::Data);
    }

    #[test]
    fn select_hub_by_queue_depth_when_no_forced() {
        let organiser = GbdtOrganiserV2::new();

        // M2M has highest queue depth, no forced items anywhere
        let inputs = make_inputs(&[
            (L2HubId::Fin, 100, 0),
            (L2HubId::Data, 50, 0),
            (L2HubId::M2m, 200, 0),
        ]);

        let decision = organiser.decide(&inputs);
        // M2M should be chosen due to highest queue depth
        assert_eq!(decision.chosen_hub, L2HubId::M2m);
    }

    #[test]
    fn select_hub_tie_break_by_enum_order() {
        let organiser = GbdtOrganiserV2::new();

        // All hubs have equal queue depth
        let inputs = make_inputs(&[
            (L2HubId::Fin, 100, 0),
            (L2HubId::Data, 100, 0),
            (L2HubId::M2m, 100, 0),
        ]);

        let decision = organiser.decide(&inputs);
        // FIN should be chosen due to enum order (lowest)
        assert_eq!(decision.chosen_hub, L2HubId::Fin);
    }

    #[test]
    fn select_hub_starvation_prevention() {
        let mut organiser = GbdtOrganiserV2::with_params(
            1000,
            256,
            512 * 1024,
            128,
            3, // Low threshold for testing
            OrganiserPolicyBounds::default(),
        );

        // Set up starvation: WORLD hasn't been served for 5 iterations
        organiser.iterations_since_served[L2HubId::World.index()] = 5;

        // WORLD has low queue depth but should be served due to starvation
        let inputs = make_inputs(&[
            (L2HubId::Fin, 500, 0),    // High queue
            (L2HubId::World, 10, 0),   // Low queue but starving
        ]);

        let decision = organiser.decide(&inputs);
        // WORLD should be chosen due to starvation prevention
        assert_eq!(decision.chosen_hub, L2HubId::World);
    }

    #[test]
    fn select_hub_empty_inputs_returns_fin() {
        let organiser = GbdtOrganiserV2::new();
        let inputs = make_inputs(&[]);

        let decision = organiser.decide(&inputs);
        // FIN is default fallback
        assert_eq!(decision.chosen_hub, L2HubId::Fin);
    }

    // ========== Determinism Tests ==========

    #[test]
    fn decision_is_deterministic() {
        let organiser = GbdtOrganiserV2::new();

        let inputs = make_inputs(&[
            (L2HubId::Fin, 100, 5),
            (L2HubId::Data, 200, 10),
            (L2HubId::M2m, 150, 3),
        ]);

        let d1 = organiser.decide(&inputs);
        let d2 = organiser.decide(&inputs);
        let d3 = organiser.decide(&inputs);

        assert_eq!(d1, d2);
        assert_eq!(d2, d3);
    }

    #[test]
    fn decision_is_deterministic_across_instances() {
        let organiser1 = GbdtOrganiserV2::new();
        let organiser2 = GbdtOrganiserV2::new();

        let inputs = make_inputs(&[
            (L2HubId::Data, 200, 10),
            (L2HubId::M2m, 150, 3),
        ]);

        let d1 = organiser1.decide(&inputs);
        let d2 = organiser2.decide(&inputs);

        assert_eq!(d1, d2);
    }

    // ========== Fairness State Tests ==========

    #[test]
    fn mark_hub_served_updates_counters() {
        let mut organiser = GbdtOrganiserV2::new();

        // Initial state: all zeros
        assert_eq!(organiser.iterations_since_served(L2HubId::Fin), 0);
        assert_eq!(organiser.iterations_since_served(L2HubId::Data), 0);

        // Mark FIN as served
        organiser.mark_hub_served(L2HubId::Fin);

        // FIN should be 0, others should be 1
        assert_eq!(organiser.iterations_since_served(L2HubId::Fin), 0);
        assert_eq!(organiser.iterations_since_served(L2HubId::Data), 1);
        assert_eq!(organiser.iterations_since_served(L2HubId::M2m), 1);

        // Mark FIN again
        organiser.mark_hub_served(L2HubId::Fin);

        // FIN should be 0, others should be 2
        assert_eq!(organiser.iterations_since_served(L2HubId::Fin), 0);
        assert_eq!(organiser.iterations_since_served(L2HubId::Data), 2);
        assert_eq!(organiser.iterations_since_served(L2HubId::M2m), 2);

        // Mark DATA as served
        organiser.mark_hub_served(L2HubId::Data);

        // DATA should be 0, FIN should be 1, M2M should be 3
        assert_eq!(organiser.iterations_since_served(L2HubId::Fin), 1);
        assert_eq!(organiser.iterations_since_served(L2HubId::Data), 0);
        assert_eq!(organiser.iterations_since_served(L2HubId::M2m), 3);
    }

    #[test]
    fn reset_fairness_counters() {
        let mut organiser = GbdtOrganiserV2::new();

        // Build up some state
        organiser.mark_hub_served(L2HubId::Fin);
        organiser.mark_hub_served(L2HubId::Fin);
        organiser.mark_hub_served(L2HubId::Fin);

        // Reset
        organiser.reset_fairness_counters();

        // All should be zero
        for hub in ALL_HUBS {
            assert_eq!(organiser.iterations_since_served(hub), 0);
        }
    }

    // ========== Batch Parameter Tests ==========

    #[test]
    fn sleep_scales_with_queue_depth() {
        let organiser = GbdtOrganiserV2::new();

        let inputs_low = make_inputs(&[(L2HubId::Fin, 10, 0)]);
        let inputs_high = make_inputs(&[(L2HubId::Fin, 600, 0)]);

        let d_low = organiser.decide(&inputs_low);
        let d_high = organiser.decide(&inputs_high);

        // Higher queue depth should have lower sleep
        assert!(d_high.sleep_ms < d_low.sleep_ms);
    }

    #[test]
    fn max_txs_scales_with_queue_depth() {
        let organiser = GbdtOrganiserV2::new();

        let inputs_low = make_inputs(&[(L2HubId::Fin, 10, 0)]);
        let inputs_high = make_inputs(&[(L2HubId::Fin, 600, 0)]);

        let d_low = organiser.decide(&inputs_low);
        let d_high = organiser.decide(&inputs_high);

        // Higher queue depth should have higher max_txs
        assert!(d_high.max_txs > d_low.max_txs);
    }

    #[test]
    fn forced_drain_scales_with_forced_depth() {
        let organiser = GbdtOrganiserV2::new();

        let inputs_low = make_inputs(&[(L2HubId::Fin, 100, 5)]);
        let inputs_high = make_inputs(&[(L2HubId::Fin, 100, 60)]);

        let d_low = organiser.decide(&inputs_low);
        let d_high = organiser.decide(&inputs_high);

        // Higher forced depth should have higher forced_drain_max
        assert!(d_high.forced_drain_max > d_low.forced_drain_max);
    }

    // ========== Bounds Tests ==========

    #[test]
    fn decision_respects_bounds() {
        let bounds = OrganiserPolicyBounds {
            sleep_ms_min: 100,
            sleep_ms_max: 5000,
            max_txs_min: 10,
            max_txs_max: 500,
            max_bytes_min: 1024,
            max_bytes_max: 256 * 1024,
            forced_drain_min: 1,
            forced_drain_max: 50,
        };

        let organiser = GbdtOrganiserV2::with_params(
            1000,
            256,
            512 * 1024, // Above max
            128,        // Above max
            10,
            bounds,
        );

        let inputs = make_inputs(&[(L2HubId::Fin, 600, 60)]);
        let decision = organiser.decide(&inputs);

        // Should be clamped to bounds
        assert!(decision.sleep_ms >= 100 && decision.sleep_ms <= 5000);
        assert!(decision.max_txs >= 10 && decision.max_txs <= 500);
        assert!(decision.max_bytes >= 1024 && decision.max_bytes <= 256 * 1024);
        assert!(decision.forced_drain_max >= 1 && decision.forced_drain_max <= 50);
    }

    // ========== Config Tests ==========

    #[test]
    fn config_defaults() {
        let config = GbdtOrganiserV2Config::default();
        assert!(config.enabled);
        assert_eq!(config.base_sleep_ms, 1000);
        assert_eq!(config.base_max_txs, 256);
        assert_eq!(config.starvation_threshold, 10);
    }

    #[test]
    fn config_build() {
        let config = GbdtOrganiserV2Config {
            enabled: true,
            base_sleep_ms: 500,
            base_max_txs: 128,
            base_max_bytes: 256 * 1024,
            base_forced_drain: 64,
            starvation_threshold: 5,
            bounds: OrganiserPolicyBounds::default(),
        };

        let organiser = config.build();
        assert_eq!(organiser.base_sleep_ms, 500);
        assert_eq!(organiser.base_max_txs, 128);
        assert_eq!(organiser.starvation_threshold, 5);
    }

    // ========== Overflow Safety Tests ==========

    #[test]
    fn no_panic_on_extreme_inputs() {
        let organiser = GbdtOrganiserV2::new();

        let mut inputs = OrganiserInputsV2::default();
        inputs.now_ms = u64::MAX;
        for hub_input in &mut inputs.hubs {
            hub_input.queue_depth = u32::MAX;
            hub_input.forced_queue_depth = u32::MAX;
            hub_input.in_flight_batches = u32::MAX;
        }

        // Should not panic
        let decision = organiser.decide(&inputs);

        assert!(decision.sleep_ms > 0);
        assert!(decision.max_txs > 0);
        assert!(decision.max_bytes > 0);
        assert!(decision.forced_drain_max > 0);
    }

    // ========== Serialization Tests ==========

    #[test]
    fn version_display() {
        assert_eq!(OrganiserVersionV2::None.to_string(), "none");
        assert_eq!(OrganiserVersionV2::GbdtV2.to_string(), "gbdt_v2");
    }
}
