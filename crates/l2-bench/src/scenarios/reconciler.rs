//! Reconciler scan benchmark.
//!
//! Measures the performance of scanning and advancing settlement states
//! for in-flight batches.

use crate::{BenchConfig, BenchError, LatencyCollector};
use l2_core::bench::{CustomMetric, ScenarioConfig, ScenarioResult};
use l2_core::canonical::Hash32;
use l2_storage::{SettlementState, Storage};
use std::time::Instant;
use tempfile::TempDir;

/// Run the reconciler scan benchmark.
///
/// This measures:
/// 1. Listing submitted batches
/// 2. Listing included batches
/// 3. State transition overhead
pub fn run_reconciler_scan(config: &BenchConfig) -> Result<ScenarioResult, BenchError> {
    let mut result = ScenarioResult::new(
        "reconciler_scan",
        "Measures reconciler batch scanning and state transitions",
    );

    let scenario_config = ScenarioConfig::with_ops(config.ops_count)
        .iterations(config.measure_iterations)
        .param("seed", config.seed.to_string());

    result = result.with_config(scenario_config);

    // Setup temp storage
    let temp_dir = TempDir::new().map_err(|e| BenchError::Storage(e.to_string()))?;
    let storage = Storage::open(temp_dir.path()).map_err(|e| BenchError::Storage(e.to_string()))?;

    // Generate batch hashes and populate storage
    let batch_hashes = generate_batch_hashes(config.ops_count, config.seed);
    let now_ms = 1_700_000_000_000u64;

    // Half submitted, half included
    let half = config.ops_count / 2;
    for (i, hash) in batch_hashes.iter().enumerate() {
        let state = if (i as u64) < half {
            SettlementState::submitted(
                format!("l1tx_{:08x}", i),
                now_ms.saturating_sub(1000 * i as u64),
                format!("key_{:08x}", i),
            )
        } else {
            SettlementState::included(
                format!("l1tx_{:08x}", i),
                100 + i as u64,
                now_ms.saturating_sub(500 * i as u64),
                now_ms.saturating_sub(1000 * i as u64),
            )
        };

        storage
            .set_settlement_state_unchecked(hash, &state)
            .map_err(|e| BenchError::Storage(e.to_string()))?;
    }

    tracing::debug!(
        submitted = half,
        included = config.ops_count - half,
        "populated settlement storage"
    );

    // Warmup: list operations
    for _ in 0..config.warmup_iterations {
        let _ = storage.list_settlement_submitted(100);
        let _ = storage.list_settlement_included(100);
    }

    // Measurement: Scan performance
    let mut list_submitted_latencies =
        LatencyCollector::with_capacity(config.measure_iterations as usize);
    let mut list_included_latencies =
        LatencyCollector::with_capacity(config.measure_iterations as usize);
    let mut transition_latencies = LatencyCollector::with_capacity(config.ops_count as usize);

    let overall_start = Instant::now();

    for iter in 0..config.measure_iterations {
        // List submitted
        let list_start = Instant::now();
        let submitted = storage
            .list_settlement_submitted(half as usize)
            .map_err(|e| BenchError::Storage(e.to_string()))?;
        list_submitted_latencies.record_elapsed(list_start);

        // List included
        let list_start = Instant::now();
        let included = storage
            .list_settlement_included((config.ops_count - half) as usize)
            .map_err(|e| BenchError::Storage(e.to_string()))?;
        list_included_latencies.record_elapsed(list_start);

        // State transitions (only on first iteration to avoid conflicts)
        if iter == 0 {
            // Transition submitted -> included
            for entry in submitted.iter().take(10) {
                let trans_start = Instant::now();
                let new_state = SettlementState::included(
                    entry.state.l1_tx_id().unwrap_or("").to_string(),
                    200,
                    now_ms,
                    now_ms,
                );
                let _ = storage.set_settlement_state(&entry.batch_hash, &new_state);
                transition_latencies.record_elapsed(trans_start);
            }

            // Transition included -> finalised
            for entry in included.iter().take(10) {
                let trans_start = Instant::now();
                let new_state = SettlementState::finalised(
                    entry.state.l1_tx_id().unwrap_or("").to_string(),
                    entry.state.l1_block().unwrap_or(0),
                    now_ms,
                    now_ms,
                );
                let _ = storage.set_settlement_state(&entry.batch_hash, &new_state);
                transition_latencies.record_elapsed(trans_start);
            }
        }
    }

    let total_duration_us = overall_start.elapsed().as_micros() as u64;

    // Calculate total ops: list_submitted + list_included per iteration + transitions
    let list_ops = config.measure_iterations as u64 * 2;
    let transition_ops = transition_latencies.samples().len() as u64;
    let total_ops = list_ops.saturating_add(transition_ops);

    result = result.with_timing(total_ops, total_duration_us);
    result = result.with_latency(list_submitted_latencies.stats());

    // Custom metrics
    let list_submitted_stats = list_submitted_latencies.stats();
    let list_included_stats = list_included_latencies.stats();
    let transition_stats = transition_latencies.stats();

    result = result.add_metric(CustomMetric::new(
        "list_submitted_p50_us",
        list_submitted_stats.p50_us as i64,
        "us",
    ));

    result = result.add_metric(CustomMetric::new(
        "list_submitted_p99_us",
        list_submitted_stats.p99_us as i64,
        "us",
    ));

    result = result.add_metric(CustomMetric::new(
        "list_included_p50_us",
        list_included_stats.p50_us as i64,
        "us",
    ));

    result = result.add_metric(CustomMetric::new(
        "list_included_p99_us",
        list_included_stats.p99_us as i64,
        "us",
    ));

    if transition_stats.sample_count > 0 {
        result = result.add_metric(CustomMetric::new(
            "transition_p50_us",
            transition_stats.p50_us as i64,
            "us",
        ));

        result = result.add_metric(CustomMetric::new(
            "transition_p99_us",
            transition_stats.p99_us as i64,
            "us",
        ));
    }

    result = result.add_metric(CustomMetric::new(
        "batches_scanned",
        config.ops_count as i64,
        "count",
    ));

    Ok(result)
}

/// Generate deterministic batch hashes.
fn generate_batch_hashes(count: u64, seed: u64) -> Vec<Hash32> {
    let mut hashes = Vec::with_capacity(count as usize);
    let mut state = seed;

    for i in 0..count {
        let mut hash = [0u8; 32];
        for byte in &mut hash {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (state >> 56) as u8;
        }
        // Encode index for uniqueness
        hash[0..8].copy_from_slice(&i.to_le_bytes());

        hashes.push(Hash32(hash));
    }

    hashes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_hashes_deterministic() {
        let hashes1 = generate_batch_hashes(100, 42);
        let hashes2 = generate_batch_hashes(100, 42);

        assert_eq!(hashes1, hashes2);
    }

    #[test]
    fn batch_hashes_unique() {
        let hashes = generate_batch_hashes(100, 42);

        let unique: std::collections::HashSet<_> = hashes.iter().map(|h| h.0).collect();
        assert_eq!(unique.len(), 100);
    }

    #[test]
    fn run_benchmark_small() {
        let config = BenchConfig {
            ops_count: 50,
            warmup_iterations: 1,
            measure_iterations: 2,
            ..Default::default()
        };

        let result = run_reconciler_scan(&config).unwrap();
        assert!(result.success);
        assert!(result.total_ops > 0);
    }
}
