//! Batcher throughput benchmark.
//!
//! Measures the performance of building batches from synthetic transactions.

use crate::{BenchConfig, BenchError, LatencyCollector};
use l2_core::bench::{CustomMetric, ScenarioConfig, ScenarioResult};
use l2_core::canonical::{canonical_encode, canonical_hash, Batch, ChainId, Hash32, Tx};
use l2_core::batch_envelope::{compute_tx_root, BatchEnvelope, BatchPayload};
use std::time::Instant;

/// Run the batcher throughput benchmark.
///
/// This measures:
/// 1. Synthetic transaction generation
/// 2. Batch building (grouping txs)
/// 3. Envelope creation (hashing, signing)
pub fn run_batcher_throughput(config: &BenchConfig) -> Result<ScenarioResult, BenchError> {
    let mut result = ScenarioResult::new(
        "batcher_throughput",
        "Measures batch building from synthetic transactions",
    );

    let scenario_config = ScenarioConfig::with_ops(config.ops_count)
        .batch_size(config.batch_size)
        .iterations(config.measure_iterations)
        .param("seed", config.seed.to_string());

    result = result.with_config(scenario_config);

    // Generate synthetic transactions deterministically
    let txs = generate_synthetic_txs(config.ops_count, config.seed);
    let tx_count = txs.len();

    tracing::debug!(tx_count = tx_count, "generated synthetic transactions");

    // Warmup iterations
    for _ in 0..config.warmup_iterations {
        let _ = build_batches(&txs, config.batch_size);
    }

    // Measurement iterations
    let mut latencies = LatencyCollector::with_capacity(config.measure_iterations as usize);
    let mut total_batches = 0u64;

    let overall_start = Instant::now();

    for _ in 0..config.measure_iterations {
        let iter_start = Instant::now();
        let batches = build_batches(&txs, config.batch_size);
        latencies.record_elapsed(iter_start);
        total_batches = total_batches.saturating_add(batches.len() as u64);
    }

    let total_duration_us = overall_start.elapsed().as_micros() as u64;
    let total_ops = config.ops_count.saturating_mul(config.measure_iterations as u64);

    result = result.with_timing(total_ops, total_duration_us);
    result = result.with_latency(latencies.stats());

    // Add custom metrics
    let batches_per_iter = total_batches / config.measure_iterations as u64;
    result = result.add_metric(CustomMetric::new(
        "batches_per_iteration",
        batches_per_iter as i64,
        "count",
    ));

    let txs_per_batch = if batches_per_iter > 0 {
        config.ops_count as i64 / batches_per_iter as i64
    } else {
        0
    };
    result = result.add_metric(CustomMetric::new("txs_per_batch", txs_per_batch, "count"));

    // Calculate throughput
    let throughput_per_sec = if total_duration_us > 0 {
        (total_ops as u128 * 1_000_000 / total_duration_us as u128) as i64
    } else {
        0
    };
    result = result.add_metric(CustomMetric::new(
        "throughput_txs_per_sec",
        throughput_per_sec,
        "tx/s",
    ));

    Ok(result)
}

/// Generate synthetic transactions deterministically.
fn generate_synthetic_txs(count: u64, seed: u64) -> Vec<Tx> {
    let mut txs = Vec::with_capacity(count as usize);
    
    // Deterministic PRNG using seed
    let mut state = seed;
    
    for i in 0..count {
        // Simple LCG for determinism
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        
        let nonce = i;
        let from = format!("user-{:08x}", (state >> 32) as u32);
        
        // Variable payload size (deterministic)
        let payload_size = 64 + ((state >> 40) as usize % 192); // 64-256 bytes
        let mut payload = vec![0u8; payload_size];
        
        // Fill payload deterministically
        for byte in payload.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (state >> 56) as u8;
        }
        
        txs.push(Tx {
            chain_id: ChainId(1337),
            nonce,
            from,
            payload,
        });
    }
    
    txs
}

/// Build batches from transactions.
fn build_batches(txs: &[Tx], batch_size: u32) -> Vec<BatchEnvelope> {
    let mut batches = Vec::new();
    let batch_size = batch_size as usize;
    let mut prev_hash = Hash32([0u8; 32]);
    
    for (batch_number, chunk) in txs.chunks(batch_size).enumerate() {
        let batch_number = batch_number as u64;
        let batch = Batch {
            chain_id: ChainId(1337),
            batch_number,
            txs: chunk.to_vec(),
            created_ms: 1_700_000_000_000 + batch_number * 1000,
        };
        
        // Compute tx hashes for root
        let tx_hashes: Vec<Hash32> = chunk
            .iter()
            .filter_map(|tx| canonical_hash(tx).ok())
            .collect();
        let tx_root = compute_tx_root(&tx_hashes);
        
        // Compute batch hash
        let batch_hash = canonical_hash(&batch).unwrap_or(Hash32([0u8; 32]));
        
        // Create payload
        let payload_bytes = canonical_encode(&batch).unwrap_or_default();
        let tx_bytes = payload_bytes.len() as u64;
        
        let payload = BatchPayload::new(
            ChainId(1337),
            batch_hash,
            prev_hash,
            batch.created_ms,
            chunk.len() as u32,
            tx_bytes,
            tx_root,
            payload_bytes,
        );
        
        // Create envelope
        if let Ok(envelope) = BatchEnvelope::new_unsigned(payload) {
            batches.push(envelope);
        }
        
        prev_hash = batch_hash;
    }
    
    batches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_txs_deterministic() {
        let txs1 = generate_synthetic_txs(100, 42);
        let txs2 = generate_synthetic_txs(100, 42);
        
        assert_eq!(txs1.len(), txs2.len());
        for (t1, t2) in txs1.iter().zip(txs2.iter()) {
            assert_eq!(t1.nonce, t2.nonce);
            assert_eq!(t1.from, t2.from);
            assert_eq!(t1.payload, t2.payload);
        }
    }

    #[test]
    fn synthetic_txs_different_seeds() {
        let txs1 = generate_synthetic_txs(10, 42);
        let txs2 = generate_synthetic_txs(10, 43);
        
        // Different seeds should produce different txs
        assert_ne!(txs1[0].from, txs2[0].from);
    }

    #[test]
    fn build_batches_correct_count() {
        let txs = generate_synthetic_txs(100, 42);
        let batches = build_batches(&txs, 25);
        
        assert_eq!(batches.len(), 4); // 100 / 25 = 4 batches
    }

    #[test]
    fn run_benchmark_small() {
        let config = BenchConfig {
            ops_count: 100,
            batch_size: 10,
            warmup_iterations: 1,
            measure_iterations: 2,
            ..Default::default()
        };

        let result = run_batcher_throughput(&config).unwrap();
        assert!(result.success);
        assert!(result.total_ops > 0);
        assert!(result.ops_per_sec > 0);
    }
}
