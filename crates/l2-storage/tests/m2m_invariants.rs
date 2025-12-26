//! M2M Accounting Invariant Tests
//!
//! This test suite verifies critical invariants for M2M fee accounting:
//!
//! 1. TotalBalance = sum(accounts) remains >= 0
//! 2. Reserved cannot exceed balance
//! 3. Finalised entries are immutable
//! 4. Batch totals equal sum(charged) within batch
//! 5. Idempotency: repeated operations produce same result
//! 6. Crash-safety: no double-charge or double-refund on restart

use l2_core::fees::{FeeAmount, FeeSchedule, M2mFeeBreakdown};
use l2_storage::m2m::{
    ForcedClass, ForcedInclusionLimits, LedgerEntry, M2mStorage, M2mStorageError,
};
use tempfile::tempdir;

fn test_storage() -> (sled::Db, M2mStorage) {
    let dir = tempdir().expect("tmpdir");
    let db = sled::open(dir.path()).expect("open db");
    let storage = M2mStorage::open(&db, FeeSchedule::default()).expect("open m2m");
    (db, storage)
}

// ========== Invariant 1: TotalBalance >= 0 ==========

#[test]
fn invariant_total_balance_non_negative() {
    let (_db, storage) = test_storage();

    // Add multiple machines
    storage.topup("machine-a", 1_000_000, 1000).unwrap();
    storage.topup("machine-b", 2_000_000, 1000).unwrap();
    storage.topup("machine-c", 500_000, 1000).unwrap();

    // Reserve and finalize some fees
    let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));

    storage
        .reserve_fee(
            "machine-a",
            [0x01; 32],
            50_000,
            breakdown.clone(),
            false,
            2000,
        )
        .unwrap();
    storage
        .finalise_fee("machine-a", [0x01; 32], 30_000, 3000)
        .unwrap();

    storage
        .reserve_fee(
            "machine-b",
            [0x02; 32],
            100_000,
            breakdown.clone(),
            false,
            2000,
        )
        .unwrap();
    storage
        .finalise_fee("machine-b", [0x02; 32], 80_000, 3000)
        .unwrap();

    // Verify invariant: total balance >= 0
    let stats = storage.get_stats().unwrap();
    assert!(stats.total_balance_scaled >= stats.total_reserved_scaled);

    // Individual accounts should also satisfy invariant
    let account_a = storage.get_account("machine-a").unwrap().unwrap();
    assert!(account_a.balance_scaled >= account_a.reserved_scaled);

    let account_b = storage.get_account("machine-b").unwrap().unwrap();
    assert!(account_b.balance_scaled >= account_b.reserved_scaled);
}

// ========== Invariant 2: Reserved cannot exceed balance ==========

#[test]
fn invariant_reserved_cannot_exceed_balance() {
    let (_db, storage) = test_storage();

    storage.topup("device-001", 100_000, 1000).unwrap();

    let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(100_000));

    // Try to reserve more than balance
    let result = storage.reserve_fee(
        "device-001",
        [0x01; 32],
        150_000,
        breakdown.clone(),
        false,
        2000,
    );
    assert!(matches!(
        result,
        Err(M2mStorageError::InsufficientBalance { .. })
    ));

    // Exactly equal should work
    storage
        .reserve_fee(
            "device-001",
            [0x02; 32],
            100_000,
            breakdown.clone(),
            false,
            2000,
        )
        .unwrap();

    // Now trying to reserve more should fail
    let result = storage.reserve_fee("device-001", [0x03; 32], 1, breakdown, false, 2000);
    assert!(matches!(
        result,
        Err(M2mStorageError::InsufficientBalance { .. })
    ));

    // Verify account state
    let account = storage.get_account("device-001").unwrap().unwrap();
    assert_eq!(account.balance_scaled, 100_000);
    assert_eq!(account.reserved_scaled, 100_000);
    assert_eq!(account.available_balance(), 0);
}

// ========== Invariant 3: Finalised entries are immutable ==========

#[test]
fn invariant_finalised_entries_immutable() {
    let (_db, storage) = test_storage();

    storage.topup("device-002", 1_000_000, 1000).unwrap();

    let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));
    let tx_hash = [0xAA; 32];

    // Reserve and finalize
    storage
        .reserve_fee(
            "device-002",
            tx_hash,
            50_000,
            breakdown.clone(),
            false,
            2000,
        )
        .unwrap();
    storage
        .finalise_fee_with_batch("device-002", tx_hash, 30_000, 3000, "batch1")
        .unwrap();

    // Verify entry is finalised
    let entry = storage.get_ledger_entry_by_hash(&tx_hash).unwrap().unwrap();
    assert!(entry.is_finalised());

    // Try to reserve again - should fail with LedgerConflict
    let result = storage.reserve_fee("device-002", tx_hash, 50_000, breakdown, false, 4000);
    assert!(matches!(
        result,
        Err(M2mStorageError::LedgerConflict { .. })
    ));

    // Finalize again should be idempotent (not error)
    let result = storage.finalise_fee_with_batch("device-002", tx_hash, 30_000, 5000, "batch2");
    assert!(result.is_ok());
    assert!(!result.unwrap().is_new()); // Should indicate already finalised

    // Entry should still be the same
    let entry2 = storage.get_ledger_entry_by_hash(&tx_hash).unwrap().unwrap();
    match entry2 {
        LedgerEntry::Finalised { batch_hash_hex, .. } => {
            // Should retain original batch hash
            assert_eq!(batch_hash_hex, "batch1");
        }
        _ => panic!("expected Finalised"),
    }
}

// ========== Invariant 4: Batch totals equal sum(charged) ==========

#[test]
fn invariant_batch_totals_equal_sum_charged() {
    let (_db, storage) = test_storage();

    // Setup multiple machines
    storage.topup("machine-x", 1_000_000, 1000).unwrap();
    storage.topup("machine-y", 1_000_000, 1000).unwrap();

    let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));

    // Create reservations for a batch
    let tx1 = [0x01; 32];
    let tx2 = [0x02; 32];
    let tx3 = [0x03; 32];

    storage
        .reserve_fee("machine-x", tx1, 50_000, breakdown.clone(), false, 2000)
        .unwrap();
    storage
        .reserve_fee("machine-x", tx2, 30_000, breakdown.clone(), false, 2000)
        .unwrap();
    storage
        .reserve_fee("machine-y", tx3, 40_000, breakdown.clone(), false, 2000)
        .unwrap();

    // Finalize with actual fees
    let batch_hash = [0xFF; 32];
    let batch_hash_hex = hex::encode(batch_hash);

    let mut total_charged: u64 = 0;
    let mut total_refunded: u64 = 0;

    // Tx1: charged 40_000, refund 10_000
    let r1 = storage
        .finalise_fee_with_batch("machine-x", tx1, 40_000, 3000, &batch_hash_hex)
        .unwrap();
    if r1.is_new() {
        total_charged += 40_000;
        total_refunded += r1.refund_scaled();
    }

    // Tx2: charged 25_000, refund 5_000
    let r2 = storage
        .finalise_fee_with_batch("machine-x", tx2, 25_000, 3000, &batch_hash_hex)
        .unwrap();
    if r2.is_new() {
        total_charged += 25_000;
        total_refunded += r2.refund_scaled();
    }

    // Tx3: charged 35_000, refund 5_000
    let r3 = storage
        .finalise_fee_with_batch("machine-y", tx3, 35_000, 3000, &batch_hash_hex)
        .unwrap();
    if r3.is_new() {
        total_charged += 35_000;
        total_refunded += r3.refund_scaled();
    }

    // Record batch totals
    let totals = l2_storage::m2m::BatchFeeTotals {
        batch_hash,
        total_fees_scaled: total_charged,
        tx_count: 3,
        total_refunds_scaled: total_refunded,
        created_at_ms: 3000,
    };
    storage.record_batch_fees(&totals).unwrap();

    // Verify batch totals
    let loaded = storage.get_batch_fees(&batch_hash).unwrap().unwrap();
    assert_eq!(loaded.total_fees_scaled, total_charged);
    assert_eq!(loaded.total_refunds_scaled, total_refunded);
    assert_eq!(loaded.tx_count, 3);

    // Expected: 40_000 + 25_000 + 35_000 = 100_000 charged
    // Refunds: 10_000 + 5_000 + 5_000 = 20_000
    assert_eq!(total_charged, 100_000);
    assert_eq!(total_refunded, 20_000);
}

// ========== Invariant 5: Idempotency ==========

#[test]
fn invariant_reserve_idempotent() {
    let (_db, storage) = test_storage();

    storage.topup("device-idem", 1_000_000, 1000).unwrap();

    let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));
    let tx_hash = [0xAB; 32];

    // Reserve multiple times with same params
    storage
        .reserve_fee(
            "device-idem",
            tx_hash,
            50_000,
            breakdown.clone(),
            false,
            2000,
        )
        .unwrap();
    storage
        .reserve_fee(
            "device-idem",
            tx_hash,
            50_000,
            breakdown.clone(),
            false,
            3000,
        )
        .unwrap();
    storage
        .reserve_fee("device-idem", tx_hash, 50_000, breakdown, false, 4000)
        .unwrap();

    // Should only reserve once
    let account = storage.get_account("device-idem").unwrap().unwrap();
    assert_eq!(account.reserved_scaled, 50_000);
    assert_eq!(account.balance_scaled, 1_000_000);
}

#[test]
fn invariant_finalise_idempotent() {
    let (_db, storage) = test_storage();

    storage.topup("device-fin", 1_000_000, 1000).unwrap();

    let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));
    let tx_hash = [0xCD; 32];

    storage
        .reserve_fee("device-fin", tx_hash, 50_000, breakdown, false, 2000)
        .unwrap();

    // Finalize multiple times
    let r1 = storage
        .finalise_fee("device-fin", tx_hash, 30_000, 3000)
        .unwrap();
    let r2 = storage
        .finalise_fee("device-fin", tx_hash, 30_000, 4000)
        .unwrap();
    let r3 = storage
        .finalise_fee("device-fin", tx_hash, 30_000, 5000)
        .unwrap();

    // First should have a refund, subsequent should return same value
    assert_eq!(r1, 20_000);
    assert_eq!(r2, 20_000);
    assert_eq!(r3, 20_000);

    // Balance should only be deducted once
    let account = storage.get_account("device-fin").unwrap().unwrap();
    assert_eq!(account.balance_scaled, 970_000);
    assert_eq!(account.reserved_scaled, 0);
    assert_eq!(account.total_fees_paid_scaled, 30_000);
    assert_eq!(account.total_tx_count, 1);
}

// ========== Invariant 6: Crash-safety ==========

#[test]
fn crash_safety_no_double_charge() {
    let (_db, storage) = test_storage();

    storage.topup("device-crash", 1_000_000, 1000).unwrap();

    let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));
    let tx_hash = [0xEF; 32];

    // Reserve
    storage
        .reserve_fee("device-crash", tx_hash, 50_000, breakdown, false, 2000)
        .unwrap();

    // Finalize
    storage
        .finalise_fee_with_batch("device-crash", tx_hash, 30_000, 3000, "batch1")
        .unwrap();

    // Simulate crash/restart by finalizing again
    // This should NOT double-charge
    let result = storage.finalise_fee_with_batch("device-crash", tx_hash, 30_000, 4000, "batch2");
    assert!(result.is_ok());
    assert!(!result.unwrap().is_new());

    // Verify account - should only be charged once
    let account = storage.get_account("device-crash").unwrap().unwrap();
    assert_eq!(account.balance_scaled, 970_000); // 1_000_000 - 30_000
    assert_eq!(account.total_fees_paid_scaled, 30_000);
}

#[test]
fn crash_safety_no_double_refund() {
    let (_db, storage) = test_storage();

    storage.topup("device-refund", 1_000_000, 1000).unwrap();

    let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));
    let tx_hash = [0xDE; 32];

    // Reserve
    storage
        .reserve_fee("device-refund", tx_hash, 50_000, breakdown, false, 2000)
        .unwrap();

    // Finalize with partial charge (refund expected)
    let r1 = storage
        .finalise_fee_with_batch("device-refund", tx_hash, 20_000, 3000, "batch1")
        .unwrap();
    assert!(r1.is_new());
    assert_eq!(r1.refund_scaled(), 30_000);

    // Try again - should not give another refund
    let r2 = storage
        .finalise_fee_with_batch("device-refund", tx_hash, 20_000, 4000, "batch2")
        .unwrap();
    assert!(!r2.is_new());
    assert_eq!(r2.refund_scaled(), 30_000); // Reports the same refund

    // But balance should only reflect one refund
    let account = storage.get_account("device-refund").unwrap().unwrap();
    // Final balance: 1_000_000 - 20_000 = 980_000 (refund is release of reserved, not addition)
    assert_eq!(account.balance_scaled, 980_000);
}

// ========== Forced Inclusion Invariants ==========

#[test]
fn invariant_forced_caps_unbypassable() {
    let (_db, storage) = test_storage();

    storage.topup("forced-device", 10_000_000, 1000).unwrap();
    storage
        .set_forced_class("forced-device", ForcedClass::ForcedInclusion, 1000)
        .unwrap();

    // Set strict limits
    let limits = ForcedInclusionLimits {
        max_tx_per_day: 2,
        max_bytes_per_day: 1000,
        day_start_ms: 0,
        used_tx_today: 0,
        used_bytes_today: 0,
    };
    storage.set_forced_limits("forced-device", limits).unwrap();

    // Use up tx limit
    storage
        .apply_forced_usage("forced-device", 100, 1000)
        .unwrap();
    storage
        .apply_forced_usage("forced-device", 100, 2000)
        .unwrap();

    // Third should fail (tx limit)
    let result = storage.apply_forced_usage("forced-device", 100, 3000);
    assert!(matches!(result, Err(M2mStorageError::QuotaExceeded { .. })));

    // Reset and test bytes limit
    let limits2 = ForcedInclusionLimits {
        max_tx_per_day: 100,
        max_bytes_per_day: 500,
        day_start_ms: 0,
        used_tx_today: 0,
        used_bytes_today: 0,
    };
    storage.set_forced_limits("forced-device", limits2).unwrap();

    storage
        .apply_forced_usage("forced-device", 400, 1000)
        .unwrap();

    // Next 200 bytes would exceed 500 limit
    let result = storage.apply_forced_usage("forced-device", 200, 2000);
    assert!(matches!(result, Err(M2mStorageError::QuotaExceeded { .. })));
}

// ========== Stats Invariants ==========

#[test]
fn invariant_stats_consistent() {
    let (_db, storage) = test_storage();

    // Create a mix of states
    storage.topup("m1", 1_000_000, 1000).unwrap();
    storage.topup("m2", 2_000_000, 1000).unwrap();
    storage
        .set_forced_class("m2", ForcedClass::ForcedInclusion, 1000)
        .unwrap();

    let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));

    // m1: reserve 100k
    storage
        .reserve_fee("m1", [0x01; 32], 100_000, breakdown.clone(), false, 2000)
        .unwrap();

    // m1: finalize 80k (reserve 2)
    storage
        .reserve_fee("m1", [0x02; 32], 80_000, breakdown.clone(), false, 2000)
        .unwrap();
    storage
        .finalise_fee("m1", [0x02; 32], 60_000, 3000)
        .unwrap();

    // m2: reserve 200k
    storage
        .reserve_fee("m2", [0x03; 32], 200_000, breakdown.clone(), false, 2000)
        .unwrap();

    let stats = storage.get_stats().unwrap();

    // Verify counts
    assert_eq!(stats.total_machines, 2);
    assert_eq!(stats.forced_machines, 1);

    // Verify balances
    // m1: 1_000_000 - 60_000 = 940_000
    // m2: 2_000_000
    // Total: 2_940_000
    assert_eq!(stats.total_balance_scaled, 2_940_000);

    // Reserved: m1 has 100k, m2 has 200k = 300k
    assert_eq!(stats.total_reserved_scaled, 300_000);

    // Fees paid: m1 paid 60_000
    assert_eq!(stats.total_fees_paid_scaled, 60_000);

    // Ledger counts
    assert_eq!(stats.ledger_reserved_count, 2); // [0x01] and [0x03]
    assert_eq!(stats.ledger_finalised_count, 1); // [0x02]
}
