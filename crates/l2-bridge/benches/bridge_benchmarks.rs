//! Criterion microbenchmarks for l2-bridge hot functions.
//!
//! Run with: `cargo bench -p l2-bridge --features merkle-proofs`
//!
//! Note: Many benchmarks require the `merkle-proofs` feature to be enabled.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// Generate deterministic 32-byte hash.
fn generate_hash(seed: u64) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let mut state = seed;
    for chunk in hash.chunks_mut(8) {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let bytes = state.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    hash
}

/// Generate deterministic 20-byte address.
#[cfg(feature = "merkle-proofs")]
fn generate_address(seed: u64) -> [u8; 20] {
    let hash = generate_hash(seed);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[..20]);
    addr
}

/// Benchmark proof limit validation.
#[cfg(feature = "merkle-proofs")]
fn bench_validate_proof_limits(c: &mut Criterion) {
    use l2_bridge::{validate_proof_limits, VerificationLimits};
    use l2_core::{EthReceiptMerkleProofV1, ExternalChainId};

    let mut group = c.benchmark_group("validate_proof_limits");

    let limits = VerificationLimits::default();

    // Small proof
    let small_proof = EthReceiptMerkleProofV1 {
        chain: ExternalChainId::EthereumMainnet,
        block_hash: generate_hash(1),
        block_number: 19000000,
        tx_hash: generate_hash(2),
        tx_index: 42,
        log_index: 0,
        contract: generate_address(3),
        topic0: generate_hash(4),
        data_hash: generate_hash(5),
        header_rlp: vec![0; 512], // Small header
        receipt_rlp: vec![0; 256], // Small receipt
        proof_nodes: (0..4).map(|i| vec![0; 200 + i * 10]).collect(),
        confirmations: Some(12),
        tip_block_number: Some(19000012),
    };

    group.bench_function("small_proof", |b| {
        b.iter(|| validate_proof_limits(black_box(&small_proof), black_box(&limits)));
    });

    // Large proof (near limits)
    let large_proof = EthReceiptMerkleProofV1 {
        chain: ExternalChainId::EthereumMainnet,
        block_hash: generate_hash(1),
        block_number: 19000000,
        tx_hash: generate_hash(2),
        tx_index: 42,
        log_index: 0,
        contract: generate_address(3),
        topic0: generate_hash(4),
        data_hash: generate_hash(5),
        header_rlp: vec![0; 7000], // Near max header
        receipt_rlp: vec![0; 30000], // Near max receipt
        proof_nodes: (0..30).map(|i| vec![0; 2000 + i * 10]).collect(), // Many nodes
        confirmations: Some(100),
        tip_block_number: Some(19000100),
    };

    group.bench_function("large_proof", |b| {
        b.iter(|| validate_proof_limits(black_box(&large_proof), black_box(&limits)));
    });

    group.finish();
}

/// Benchmark verification limits default construction.
#[cfg(feature = "merkle-proofs")]
fn bench_verification_limits(c: &mut Criterion) {
    use l2_bridge::VerificationLimits;

    let mut group = c.benchmark_group("verification_limits");

    group.bench_function("default", |b| {
        b.iter(|| VerificationLimits::default());
    });

    group.finish();
}

/// Benchmark attestation verification (signed envelope style).
fn bench_attestation_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("attestation_verification");

    // Simulate computing attestation hash (BLAKE3)
    let attestation_data = vec![0u8; 256]; // Typical attestation size
    group.bench_function("compute_hash_256b", |b| {
        b.iter(|| {
            let hash = blake3::hash(black_box(&attestation_data));
            black_box(hash)
        });
    });

    // Larger attestation
    let large_attestation_data = vec![0u8; 1024];
    group.bench_function("compute_hash_1kb", |b| {
        b.iter(|| {
            let hash = blake3::hash(black_box(&large_attestation_data));
            black_box(hash)
        });
    });

    group.finish();
}

/// Benchmark throughput of attestation hash computation.
fn bench_attestation_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("attestation_throughput");

    for batch_size in [10u64, 100, 1000] {
        // Generate batch of attestation data
        let attestations: Vec<Vec<u8>> = (0..batch_size)
            .map(|i| {
                let mut data = vec![0u8; 256];
                let seed = generate_hash(i);
                data[..32].copy_from_slice(&seed);
                data
            })
            .collect();

        group.throughput(Throughput::Elements(batch_size));
        group.bench_with_input(
            BenchmarkId::new("batch_hash", batch_size),
            &attestations,
            |b, attestations| {
                b.iter(|| {
                    for att in attestations {
                        let _ = blake3::hash(black_box(att));
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark deposit event ID generation.
fn bench_deposit_id_generation(c: &mut Criterion) {
    use l2_bridge::DepositEvent;
    use l2_core::ChainId;

    let mut group = c.benchmark_group("deposit_event");

    let deposit = DepositEvent {
        l1_tx_hash: "0xabc123def456789012345678901234567890123456789012345678901234567890".to_string(),
        from_l1: "0x1234567890123456789012345678901234567890".to_string(),
        to_l2: "alice".to_string(),
        asset: "IPN".to_string(),
        amount: 1000000,
        memo: Some("l2_to=alice".to_string()),
        seen_at_ms: 1700000000000,
        status: l2_bridge::DepositStatus::Pending,
        chain_id: ChainId(1),
        nonce: 42,
    };

    group.bench_function("deposit_id", |b| {
        b.iter(|| deposit.deposit_id());
    });

    group.finish();
}

/// Benchmark memo parsing for deposit events.
fn bench_memo_parsing(c: &mut Criterion) {
    use l2_bridge::DepositEvent;

    let mut group = c.benchmark_group("memo_parsing");

    // Simple memo
    let simple_memo = "l2_to=alice";
    group.bench_function("simple", |b| {
        b.iter(|| DepositEvent::parse_to_l2_from_memo(black_box(simple_memo)));
    });

    // Complex memo with multiple fields
    let complex_memo = "foo=bar,l2_to=alice_address,baz=qux";
    group.bench_function("complex", |b| {
        b.iter(|| DepositEvent::parse_to_l2_from_memo(black_box(complex_memo)));
    });

    // Memo with no match
    let no_match_memo = "foo=bar,baz=qux,something=else";
    group.bench_function("no_match", |b| {
        b.iter(|| DepositEvent::parse_to_l2_from_memo(black_box(no_match_memo)));
    });

    group.finish();
}

/// Benchmark withdrawal ID generation.
fn bench_withdraw_id_generation(c: &mut Criterion) {
    use l2_bridge::WithdrawRequest;

    let mut group = c.benchmark_group("withdraw_request");

    group.bench_function("generate_id", |b| {
        b.iter(|| {
            WithdrawRequest::generate_id(black_box("alice_l2_address"), black_box(12345));
        });
    });

    // Throughput for batch ID generation
    group.throughput(Throughput::Elements(1000));
    group.bench_function("batch_generate_id_1000", |b| {
        b.iter(|| {
            for i in 0u64..1000 {
                let _ = WithdrawRequest::generate_id(black_box("alice_l2_address"), black_box(i));
            }
        });
    });

    group.finish();
}

// Conditional benchmark groups based on features
#[cfg(feature = "merkle-proofs")]
criterion_group!(
    merkle_benches,
    bench_validate_proof_limits,
    bench_verification_limits,
);

criterion_group!(
    common_benches,
    bench_attestation_verification,
    bench_attestation_throughput,
    bench_deposit_id_generation,
    bench_memo_parsing,
    bench_withdraw_id_generation,
);

#[cfg(feature = "merkle-proofs")]
criterion_main!(merkle_benches, common_benches);

#[cfg(not(feature = "merkle-proofs"))]
criterion_main!(common_benches);
