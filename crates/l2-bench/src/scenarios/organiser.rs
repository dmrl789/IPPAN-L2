//! Organiser overhead benchmark.
//!
//! Measures the performance of the organiser decide() function
//! under varying hub statistics.

use crate::{BenchConfig, BenchError, LatencyCollector};
use l2_batcher::gbdt_organiser::GbdtOrganiserV1;
use l2_core::bench::{CustomMetric, ScenarioConfig, ScenarioResult};
use l2_core::organiser::{Organiser, OrganiserInputs, OrganiserPolicyBounds};
use std::time::Instant;

/// Run the organiser overhead benchmark.
///
/// This measures:
/// 1. decide() call latency under various input conditions
/// 2. Impact of queue depth on decision time
/// 3. Bounds clamping overhead
pub fn run_organiser_overhead(config: &BenchConfig) -> Result<ScenarioResult, BenchError> {
    let mut result = ScenarioResult::new(
        "organiser_overhead",
        "Measures organiser decide() performance under varying conditions",
    );

    let scenario_config = ScenarioConfig::with_ops(config.ops_count)
        .iterations(config.measure_iterations)
        .param("seed", config.seed.to_string());

    result = result.with_config(scenario_config);

    let organiser = GbdtOrganiserV1::new();
    let bounds = OrganiserPolicyBounds::default();

    // Generate deterministic input variations
    let inputs = generate_input_variations(config.ops_count, config.seed);

    tracing::debug!(
        input_count = inputs.len(),
        "generated organiser input variations"
    );

    // Warmup
    for _ in 0..config.warmup_iterations {
        for input in &inputs {
            let decision = organiser.decide(input);
            let _ = bounds.clamp(decision);
        }
    }

    // Measurement
    let mut latencies = LatencyCollector::with_capacity(config.ops_count as usize);
    let mut total_decisions = 0u64;

    let overall_start = Instant::now();

    for _ in 0..config.measure_iterations {
        for input in &inputs {
            let iter_start = Instant::now();
            let decision = organiser.decide(input);
            let _ = bounds.clamp(decision);
            latencies.record_elapsed(iter_start);
            total_decisions = total_decisions.saturating_add(1);
        }
    }

    let total_duration_us = overall_start.elapsed().as_micros() as u64;

    result = result.with_timing(total_decisions, total_duration_us);
    result = result.with_latency(latencies.stats());

    // Add custom metrics
    result = result.add_metric(CustomMetric::new(
        "total_decisions",
        total_decisions as i64,
        "count",
    ));

    // Calculate decisions per second
    let decisions_per_sec = if total_duration_us > 0 {
        (total_decisions as u128 * 1_000_000 / total_duration_us as u128) as i64
    } else {
        0
    };
    result = result.add_metric(CustomMetric::new(
        "decisions_per_sec",
        decisions_per_sec,
        "decision/s",
    ));

    Ok(result)
}

/// Generate deterministic input variations for the organiser.
fn generate_input_variations(count: u64, seed: u64) -> Vec<OrganiserInputs> {
    let mut inputs = Vec::with_capacity(count as usize);
    let mut state = seed;

    for i in 0..count {
        // Simple LCG for determinism
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);

        // Generate varied inputs
        let queue_depth = ((state >> 32) % 1000) as u32;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);

        let forced_queue_depth = ((state >> 32) % 100) as u32;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);

        let in_flight_batches = ((state >> 32) % 10) as u32;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);

        let recent_forced_used_bytes = (state >> 16) % 500_000;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);

        let avg_tx_bytes_est = (128 + ((state >> 32) % 384)) as u32;

        inputs.push(OrganiserInputs {
            now_ms: 1_700_000_000_000 + i * 100,
            queue_depth,
            forced_queue_depth,
            in_flight_batches,
            recent_quota_rejects: 0,
            recent_insufficient_balance: 0,
            recent_forced_used_bytes,
            avg_tx_bytes_est,
        });
    }

    inputs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_variations_deterministic() {
        let inputs1 = generate_input_variations(100, 42);
        let inputs2 = generate_input_variations(100, 42);

        assert_eq!(inputs1.len(), inputs2.len());
        for (i1, i2) in inputs1.iter().zip(inputs2.iter()) {
            assert_eq!(i1.queue_depth, i2.queue_depth);
            assert_eq!(i1.forced_queue_depth, i2.forced_queue_depth);
            assert_eq!(i1.in_flight_batches, i2.in_flight_batches);
        }
    }

    #[test]
    fn input_variations_varied() {
        let inputs = generate_input_variations(100, 42);

        // Should have varied queue depths
        let unique_depths: std::collections::HashSet<_> =
            inputs.iter().map(|i| i.queue_depth).collect();
        assert!(unique_depths.len() > 10);
    }

    #[test]
    fn run_benchmark_small() {
        let config = BenchConfig {
            ops_count: 100,
            warmup_iterations: 1,
            measure_iterations: 2,
            ..Default::default()
        };

        let result = run_organiser_overhead(&config).unwrap();
        assert!(result.success);
        assert!(result.total_ops > 0);
    }
}
