//! Criterion microbenchmarks for l2-core hot functions.
//!
//! Run with: `cargo bench -p l2-core`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use l2_core::batch_envelope::{compute_tx_root, BatchEnvelope, BatchPayload};
use l2_core::canonical::{
    canonical_decode, canonical_encode, canonical_hash, Batch, ChainId, Hash32, Tx,
};
use l2_core::fees::{compute_m2m_fee, FeeSchedule};
use l2_core::organiser::{NoopOrganiser, Organiser, OrganiserInputs};

/// Benchmark `compute_m2m_fee` with various input sizes.
fn bench_compute_m2m_fee(c: &mut Criterion) {
    let schedule = FeeSchedule::default();

    let mut group = c.benchmark_group("compute_m2m_fee");

    // Various workload sizes
    let cases = [
        ("small", 100u64, 64u64, 1u32),
        ("medium", 1000, 512, 3),
        ("large", 10000, 4096, 10),
        ("xlarge", 100000, 32768, 100),
    ];

    for (name, exec_units, data_bytes, writes) in cases {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("fee_calc", name),
            &(exec_units, data_bytes, writes),
            |b, &(eu, db, w)| {
                b.iter(|| {
                    compute_m2m_fee(
                        black_box(&schedule),
                        black_box(eu),
                        black_box(db),
                        black_box(w),
                    )
                });
            },
        );
    }

    group.finish();
}

/// Benchmark canonical encoding/decoding.
fn bench_canonical_encode_decode(c: &mut Criterion) {
    // Create a sample batch payload
    let tx = Tx {
        chain_id: ChainId(1337),
        nonce: 42,
        from: "user-benchtest".to_string(),
        payload: vec![0xAA; 256],
    };

    let batch = Batch {
        chain_id: ChainId(1337),
        batch_number: 100,
        txs: vec![tx.clone(); 10],
        created_ms: 1_700_000_000_000,
    };

    let encoded = canonical_encode(&batch).expect("encode");

    let mut group = c.benchmark_group("canonical");

    // Encode benchmark
    group.throughput(Throughput::Bytes(encoded.len() as u64));
    group.bench_function("encode_batch_10tx", |b| {
        b.iter(|| canonical_encode(black_box(&batch)));
    });

    // Decode benchmark
    group.bench_function("decode_batch_10tx", |b| {
        b.iter(|| canonical_decode::<Batch>(black_box(&encoded)));
    });

    // Hash benchmark
    group.bench_function("hash_batch_10tx", |b| {
        b.iter(|| canonical_hash(black_box(&batch)));
    });

    // Single tx encode
    let tx_encoded = canonical_encode(&tx).expect("encode");
    group.throughput(Throughput::Bytes(tx_encoded.len() as u64));
    group.bench_function("encode_single_tx", |b| {
        b.iter(|| canonical_encode(black_box(&tx)));
    });

    group.finish();
}

/// Benchmark BatchEnvelope operations.
#[allow(clippy::cast_possible_truncation)]
fn bench_batch_envelope(c: &mut Criterion) {
    let tx_count: u32 = 100;
    let payload_bytes: Vec<u8> = (0..tx_count * 256).map(|i| (i % 256) as u8).collect();

    let payload = BatchPayload::new(
        ChainId(1337),
        Hash32([0xAA; 32]),
        Hash32([0x00; 32]),
        1_700_000_000_000,
        tx_count,
        payload_bytes.len() as u64,
        Hash32([0xBB; 32]),
        payload_bytes,
    );

    let mut group = c.benchmark_group("batch_envelope");

    // Create unsigned envelope
    group.bench_function("new_unsigned_100tx", |b| {
        b.iter(|| BatchEnvelope::new_unsigned(black_box(payload.clone())));
    });

    // Payload hash
    group.bench_function("payload_hash", |b| {
        b.iter(|| payload.hash());
    });

    // Signing bytes
    let envelope = BatchEnvelope::new_unsigned(payload.clone()).expect("envelope");
    group.bench_function("signing_bytes", |b| {
        b.iter(|| envelope.signing_bytes());
    });

    group.finish();
}

/// Benchmark compute_tx_root with various tx counts.
fn bench_compute_tx_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("compute_tx_root");

    for tx_count in [10u64, 100, 500, 1000] {
        let hashes: Vec<Hash32> = (0..tx_count)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                Hash32(h)
            })
            .collect();

        group.throughput(Throughput::Elements(tx_count));
        group.bench_with_input(
            BenchmarkId::new("tx_root", tx_count),
            &hashes,
            |b, hashes| {
                b.iter(|| compute_tx_root(black_box(hashes)));
            },
        );
    }

    group.finish();
}

/// Benchmark organiser decide() function.
fn bench_organiser_decide(c: &mut Criterion) {
    let organiser = NoopOrganiser::default();

    let inputs_idle = OrganiserInputs::default();
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

    let mut group = c.benchmark_group("organiser_decide");

    group.bench_function("noop_idle", |b| {
        b.iter(|| organiser.decide(black_box(&inputs_idle)));
    });

    group.bench_function("noop_busy", |b| {
        b.iter(|| organiser.decide(black_box(&inputs_busy)));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_compute_m2m_fee,
    bench_canonical_encode_decode,
    bench_batch_envelope,
    bench_compute_tx_root,
    bench_organiser_decide,
);

criterion_main!(benches);
