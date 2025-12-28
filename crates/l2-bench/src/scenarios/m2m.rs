//! M2M fee accounting benchmark.
//!
//! Measures the performance of reserve/finalise operations
//! using the M2M ledger for crash-safe fee tracking.

use crate::{BenchConfig, BenchError, LatencyCollector};
use l2_core::bench::{CustomMetric, ScenarioConfig, ScenarioResult};
use l2_core::fees::{FeeAmount, FeeSchedule, M2mFeeBreakdown};
use l2_storage::m2m::M2mStorage;
use std::time::Instant;
use tempfile::TempDir;

/// Run the M2M accounting benchmark.
///
/// This measures:
/// 1. Fee reservation performance
/// 2. Fee finalization performance
/// 3. Ledger idempotency overhead
pub fn run_m2m_accounting(config: &BenchConfig) -> Result<ScenarioResult, BenchError> {
    let mut result = ScenarioResult::new(
        "m2m_accounting",
        "Measures M2M reserve/finalise performance with ledger",
    );

    let scenario_config = ScenarioConfig::with_ops(config.ops_count)
        .iterations(config.measure_iterations)
        .param("seed", config.seed.to_string());

    result = result.with_config(scenario_config);

    // Setup temp storage
    let temp_dir = TempDir::new().map_err(|e| BenchError::Storage(e.to_string()))?;
    let db = sled::open(temp_dir.path()).map_err(|e| BenchError::Storage(e.to_string()))?;
    let storage = M2mStorage::open(&db, FeeSchedule::default())
        .map_err(|e| BenchError::Storage(e.to_string()))?;

    // Generate deterministic transaction data
    let tx_data = generate_tx_data(config.ops_count, config.seed);
    let machine_id = "bench-machine-001";

    // Setup machine with sufficient balance
    let total_fees = config.ops_count.saturating_mul(100_000); // 100k per tx
    storage
        .topup(machine_id, total_fees, 1_700_000_000_000)
        .map_err(|e| BenchError::Storage(e.to_string()))?;

    tracing::debug!(
        tx_count = tx_data.len(),
        balance = total_fees,
        "setup M2M benchmark"
    );

    // Warmup with a subset
    let warmup_count = (config.ops_count / 10).max(1) as usize;
    for (i, (tx_hash, amount, breakdown)) in tx_data.iter().take(warmup_count).enumerate() {
        let warmup_hash = {
            let mut h = *tx_hash;
            h[0] = 0xFF; // Modify to not conflict
            h[1] = (i >> 8) as u8;
            h[2] = i as u8;
            h
        };
        let _ = storage.reserve_fee(
            machine_id,
            warmup_hash,
            *amount,
            breakdown.clone(),
            false,
            0,
        );
        let _ = storage.finalise_fee(machine_id, warmup_hash, *amount / 2, 1000);
    }

    // Measurement: Reserve phase
    let mut reserve_latencies = LatencyCollector::with_capacity(config.ops_count as usize);
    let reserve_start = Instant::now();

    for (i, (tx_hash, amount, breakdown)) in tx_data.iter().enumerate() {
        let iter_start = Instant::now();
        let result = storage.reserve_fee(
            machine_id,
            *tx_hash,
            *amount,
            breakdown.clone(),
            false,
            1_700_000_000_000 + i as u64,
        );
        reserve_latencies.record_elapsed(iter_start);

        if let Err(e) = result {
            tracing::warn!(error = %e, tx_idx = i, "reserve failed");
        }
    }

    let reserve_duration_us = reserve_start.elapsed().as_micros() as u64;

    // Measurement: Finalise phase
    let mut finalise_latencies = LatencyCollector::with_capacity(config.ops_count as usize);
    let finalise_start = Instant::now();

    for (i, (tx_hash, amount, _)) in tx_data.iter().enumerate() {
        let iter_start = Instant::now();
        let final_amount = amount / 2; // Half the reserved amount
        let result = storage.finalise_fee(
            machine_id,
            *tx_hash,
            final_amount,
            1_700_000_001_000 + i as u64,
        );
        finalise_latencies.record_elapsed(iter_start);

        if let Err(e) = result {
            tracing::warn!(error = %e, tx_idx = i, "finalise failed");
        }
    }

    let finalise_duration_us = finalise_start.elapsed().as_micros() as u64;

    // Combined metrics
    let total_duration_us = reserve_duration_us.saturating_add(finalise_duration_us);
    let total_ops = config.ops_count.saturating_mul(2); // reserve + finalise

    result = result.with_timing(total_ops, total_duration_us);
    result = result.with_latency(reserve_latencies.stats());

    // Add custom metrics
    result = result.add_metric(CustomMetric::new(
        "reserve_total_us",
        reserve_duration_us as i64,
        "us",
    ));

    result = result.add_metric(CustomMetric::new(
        "finalise_total_us",
        finalise_duration_us as i64,
        "us",
    ));

    let reserve_ops_per_sec = if reserve_duration_us > 0 {
        (config.ops_count as u128 * 1_000_000 / reserve_duration_us as u128) as i64
    } else {
        0
    };
    result = result.add_metric(CustomMetric::new(
        "reserve_ops_per_sec",
        reserve_ops_per_sec,
        "op/s",
    ));

    let finalise_ops_per_sec = if finalise_duration_us > 0 {
        (config.ops_count as u128 * 1_000_000 / finalise_duration_us as u128) as i64
    } else {
        0
    };
    result = result.add_metric(CustomMetric::new(
        "finalise_ops_per_sec",
        finalise_ops_per_sec,
        "op/s",
    ));

    // Add finalise latency stats
    let finalise_stats = finalise_latencies.stats();
    result = result.add_metric(CustomMetric::new(
        "finalise_p50_us",
        finalise_stats.p50_us as i64,
        "us",
    ));
    result = result.add_metric(CustomMetric::new(
        "finalise_p99_us",
        finalise_stats.p99_us as i64,
        "us",
    ));

    Ok(result)
}

/// Generate deterministic transaction data for benchmarking.
fn generate_tx_data(count: u64, seed: u64) -> Vec<([u8; 32], u64, M2mFeeBreakdown)> {
    let mut data = Vec::with_capacity(count as usize);
    let mut state = seed;

    for i in 0..count {
        // Generate deterministic tx hash
        let mut tx_hash = [0u8; 32];
        for byte in &mut tx_hash {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (state >> 56) as u8;
        }
        // Ensure uniqueness by encoding index
        tx_hash[0..8].copy_from_slice(&i.to_le_bytes());

        // Generate fee amount (50k - 150k scaled)
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let amount = 50_000 + ((state >> 32) % 100_000);

        // Generate breakdown
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let exec_units = 100 + ((state >> 32) % 500);
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let data_bytes = 64 + ((state >> 32) % 256);
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let storage_writes = ((state >> 32) % 5) as u32;

        let breakdown = M2mFeeBreakdown::new(
            exec_units,
            data_bytes,
            storage_writes,
            FeeAmount::from_scaled(amount),
        );

        data.push((tx_hash, amount, breakdown));
    }

    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_data_deterministic() {
        let data1 = generate_tx_data(100, 42);
        let data2 = generate_tx_data(100, 42);

        assert_eq!(data1.len(), data2.len());
        for ((h1, a1, b1), (h2, a2, b2)) in data1.iter().zip(data2.iter()) {
            assert_eq!(h1, h2);
            assert_eq!(a1, a2);
            assert_eq!(b1.exec_units, b2.exec_units);
        }
    }

    #[test]
    fn tx_data_unique_hashes() {
        let data = generate_tx_data(100, 42);

        let hashes: std::collections::HashSet<_> = data.iter().map(|(h, _, _)| *h).collect();
        assert_eq!(hashes.len(), 100); // All unique
    }

    #[test]
    fn run_benchmark_small() {
        let config = BenchConfig {
            ops_count: 50,
            warmup_iterations: 0,
            measure_iterations: 1,
            ..Default::default()
        };

        let result = run_m2m_accounting(&config).unwrap();
        assert!(result.success);
        assert!(result.total_ops > 0);
    }
}
