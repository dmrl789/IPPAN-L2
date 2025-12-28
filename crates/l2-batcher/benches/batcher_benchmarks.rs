//! Criterion microbenchmarks for l2-batcher hot functions.
//!
//! Run with: `cargo bench -p l2-batcher`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use l2_batcher::gbdt_organiser::GbdtOrganiserV1;
use l2_core::organiser::{Organiser, OrganiserInputs, OrganiserPolicyBounds};

/// Generate deterministic input variations.
fn generate_inputs(count: usize, seed: u64) -> Vec<OrganiserInputs> {
    let mut inputs = Vec::with_capacity(count);
    let mut state = seed;

    for i in 0..count {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let queue_depth = ((state >> 32) % 1000) as u32;

        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let forced_queue_depth = ((state >> 32) % 100) as u32;

        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let in_flight_batches = ((state >> 32) % 10) as u32;

        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let recent_forced_used_bytes = ((state >> 16) % 500_000) as u64;

        inputs.push(OrganiserInputs {
            now_ms: 1_700_000_000_000 + i as u64 * 100,
            queue_depth,
            forced_queue_depth,
            in_flight_batches,
            recent_quota_rejects: 0,
            recent_insufficient_balance: 0,
            recent_forced_used_bytes,
            avg_tx_bytes_est: 256,
        });
    }

    inputs
}

/// Benchmark GBDT organiser decide().
fn bench_gbdt_organiser_decide(c: &mut Criterion) {
    let organiser = GbdtOrganiserV1::new();
    let _bounds = OrganiserPolicyBounds::default();

    // Single decision benchmarks
    let mut group = c.benchmark_group("gbdt_organiser_decide");

    // Idle state
    let inputs_idle = OrganiserInputs::default();
    group.bench_function("idle", |b| {
        b.iter(|| organiser.decide(black_box(&inputs_idle)));
    });

    // Low queue depth
    let inputs_low = OrganiserInputs::default().queue_depth(10);
    group.bench_function("queue_10", |b| {
        b.iter(|| organiser.decide(black_box(&inputs_low)));
    });

    // Medium queue depth
    let inputs_medium = OrganiserInputs::default().queue_depth(100);
    group.bench_function("queue_100", |b| {
        b.iter(|| organiser.decide(black_box(&inputs_medium)));
    });

    // High queue depth
    let inputs_high = OrganiserInputs::default().queue_depth(600);
    group.bench_function("queue_600", |b| {
        b.iter(|| organiser.decide(black_box(&inputs_high)));
    });

    // With backpressure
    let inputs_backpressure = OrganiserInputs::default()
        .queue_depth(600)
        .in_flight_batches(5);
    group.bench_function("backpressure", |b| {
        b.iter(|| organiser.decide(black_box(&inputs_backpressure)));
    });

    group.finish();
}

/// Benchmark GBDT organiser decide() with bounds clamping.
fn bench_gbdt_organiser_with_clamp(c: &mut Criterion) {
    let organiser = GbdtOrganiserV1::new();
    let bounds = OrganiserPolicyBounds::default();

    let inputs_busy = OrganiserInputs {
        now_ms: 1_700_000_000_000,
        queue_depth: 500,
        forced_queue_depth: 50,
        in_flight_batches: 2,
        recent_quota_rejects: 10,
        recent_insufficient_balance: 5,
        recent_forced_used_bytes: 100_000,
        avg_tx_bytes_est: 512,
    };

    let mut group = c.benchmark_group("gbdt_organiser_with_clamp");

    group.bench_function("decide_and_clamp", |b| {
        b.iter(|| {
            let decision = organiser.decide(black_box(&inputs_busy));
            bounds.clamp(decision)
        });
    });

    group.finish();
}

/// Benchmark organiser throughput (decisions per second).
fn bench_gbdt_organiser_throughput(c: &mut Criterion) {
    let organiser = GbdtOrganiserV1::new();
    let bounds = OrganiserPolicyBounds::default();

    let mut group = c.benchmark_group("gbdt_organiser_throughput");

    for batch_size in [100u64, 1000, 10000] {
        let inputs = generate_inputs(batch_size as usize, 42);

        group.throughput(Throughput::Elements(batch_size));
        group.bench_with_input(
            BenchmarkId::new("batch_decide", batch_size),
            &inputs,
            |b, inputs| {
                b.iter(|| {
                    for input in inputs {
                        let decision = organiser.decide(black_box(input));
                        let _ = bounds.clamp(decision);
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark bounds validation.
fn bench_policy_bounds(c: &mut Criterion) {
    let bounds = OrganiserPolicyBounds::default();

    let mut group = c.benchmark_group("policy_bounds");

    // Validate bounds
    group.bench_function("validate", |b| {
        b.iter(|| bounds.validate());
    });

    // Clamp decision
    let decision = l2_core::organiser::OrganiserDecision {
        sleep_ms: 5, // Below min
        max_txs: 2000, // Above max
        max_bytes: 100, // Below min
        forced_drain_max: 500, // Above max
    };
    group.bench_function("clamp_out_of_bounds", |b| {
        b.iter(|| bounds.clamp(black_box(decision.clone())));
    });

    // Clamp in-bounds decision
    let decision_ok = l2_core::organiser::OrganiserDecision {
        sleep_ms: 1000,
        max_txs: 256,
        max_bytes: 512 * 1024,
        forced_drain_max: 128,
    };
    group.bench_function("clamp_in_bounds", |b| {
        b.iter(|| bounds.clamp(black_box(decision_ok.clone())));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_gbdt_organiser_decide,
    bench_gbdt_organiser_with_clamp,
    bench_gbdt_organiser_throughput,
    bench_policy_bounds,
);

criterion_main!(benches);
