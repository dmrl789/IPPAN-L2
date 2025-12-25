//! Deterministic Machine-to-Machine (M2M) fee infrastructure.
//!
//! This module provides deterministic, integer-only fee calculations for IPPAN L2.
//! No auctions, no dynamic pricing - just predictable costs that machines can rely on.
//!
//! ## Design Principles
//!
//! 1. **Determinism**: All calculations use integer arithmetic only
//! 2. **Predictability**: Machines can calculate exact costs in advance
//! 3. **Transparency**: Clear breakdown of what costs what
//! 4. **No speculation**: Fees are policy-based, not market-based
//!
//! ## Fee Flow
//!
//! ```text
//! Transaction Submission
//!         │
//!         ▼
//! ┌───────────────────┐
//! │ Reserve Fee       │ ← Pre-calculate max fee for tx
//! └───────────────────┘
//!         │
//!         ▼
//! ┌───────────────────┐
//! │ Include in Batch  │ ← Add to batch with fee reservation
//! └───────────────────┘
//!         │
//!         ▼
//! ┌───────────────────┐
//! │ Finalise Fee      │ ← Actual fee based on execution
//! └───────────────────┘
//!         │
//!         ▼
//! ┌───────────────────┐
//! │ Aggregate in      │ ← Total M2M fees in batch
//! │ Settlement        │    settlement metadata
//! └───────────────────┘
//! ```

use serde::{Deserialize, Serialize};

/// Scale factor for fixed-point fee amounts (6 decimals).
pub const FEE_SCALE: u64 = 1_000_000;

/// Fixed-point fee amount with 6 decimal places.
///
/// This is a simple wrapper around u64 that represents fees scaled by 10^6.
/// For example, 1.5 IPN would be represented as 1_500_000.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FeeAmount(pub u64);

impl FeeAmount {
    /// Zero fee.
    pub const ZERO: Self = Self(0);

    /// Create a fee from scaled units (already multiplied by FEE_SCALE).
    pub const fn from_scaled(scaled: u64) -> Self {
        Self(scaled)
    }

    /// Create a fee from whole units (e.g., 1 IPN).
    pub const fn from_units(units: u64) -> Self {
        Self(units.saturating_mul(FEE_SCALE))
    }

    /// Get the scaled value.
    pub const fn scaled(self) -> u64 {
        self.0
    }

    /// Add two fees, saturating on overflow.
    pub const fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Subtract two fees, saturating at zero.
    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// Multiply by a u64 factor, saturating on overflow.
    pub const fn saturating_mul(self, factor: u64) -> Self {
        Self(self.0.saturating_mul(factor))
    }

    /// Divide by a u64 divisor, returning zero if divisor is zero.
    pub const fn checked_div(self, divisor: u64) -> Option<Self> {
        if divisor == 0 {
            None
        } else {
            Some(Self(self.0 / divisor))
        }
    }

    /// Check if the fee is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl Default for FeeAmount {
    fn default() -> Self {
        Self::ZERO
    }
}

impl std::fmt::Display for FeeAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let whole = self.0 / FEE_SCALE;
        let frac = self.0 % FEE_SCALE;
        if frac == 0 {
            write!(f, "{}", whole)
        } else {
            write!(f, "{}.{:06}", whole, frac)
        }
    }
}

/// Breakdown of M2M fee components for a single transaction.
///
/// This provides a transparent view of what each resource costs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct M2mFeeBreakdown {
    /// Number of execution units consumed (compute).
    pub exec_units: u64,
    /// Number of data bytes in the transaction payload.
    pub data_bytes: u64,
    /// Number of storage writes performed.
    pub storage_writes: u32,
    /// Total fee calculated from the breakdown.
    pub total_fee: FeeAmount,
}

impl M2mFeeBreakdown {
    /// Create a new fee breakdown with the given resource usage.
    pub fn new(
        exec_units: u64,
        data_bytes: u64,
        storage_writes: u32,
        total_fee: FeeAmount,
    ) -> Self {
        Self {
            exec_units,
            data_bytes,
            storage_writes,
            total_fee,
        }
    }

    /// Create a zero fee breakdown (no resources used).
    pub fn zero() -> Self {
        Self {
            exec_units: 0,
            data_bytes: 0,
            storage_writes: 0,
            total_fee: FeeAmount::ZERO,
        }
    }

    /// Combine two fee breakdowns (e.g., for aggregating multiple txs).
    pub fn combine(&self, other: &Self) -> Self {
        Self {
            exec_units: self.exec_units.saturating_add(other.exec_units),
            data_bytes: self.data_bytes.saturating_add(other.data_bytes),
            storage_writes: self.storage_writes.saturating_add(other.storage_writes),
            total_fee: self.total_fee.saturating_add(other.total_fee),
        }
    }
}

impl Default for M2mFeeBreakdown {
    fn default() -> Self {
        Self::zero()
    }
}

/// Fee policy for deterministic fee calculation.
///
/// This defines the per-unit costs for each resource type.
/// All costs are in scaled FeeAmount units (6 decimal places).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct M2mFeePolicy {
    /// Cost per execution unit.
    pub cost_per_exec_unit: FeeAmount,
    /// Cost per byte of transaction data.
    pub cost_per_data_byte: FeeAmount,
    /// Cost per storage write operation.
    pub cost_per_storage_write: FeeAmount,
    /// Base fee per transaction (fixed overhead).
    pub base_fee: FeeAmount,
}

impl M2mFeePolicy {
    /// Default fee policy with conservative costs.
    ///
    /// These are placeholder values that should be tuned based on
    /// operational costs and network requirements.
    pub fn default_policy() -> Self {
        Self {
            // 0.000001 IPN per exec unit
            cost_per_exec_unit: FeeAmount::from_scaled(1),
            // 0.00001 IPN per byte (10 scaled units)
            cost_per_data_byte: FeeAmount::from_scaled(10),
            // 0.001 IPN per storage write (1000 scaled units)
            cost_per_storage_write: FeeAmount::from_scaled(1000),
            // 0.01 IPN base fee (10000 scaled units)
            base_fee: FeeAmount::from_scaled(10_000),
        }
    }

    /// Calculate the fee for a given resource usage.
    pub fn calculate_fee(
        &self,
        exec_units: u64,
        data_bytes: u64,
        storage_writes: u32,
    ) -> M2mFeeBreakdown {
        let exec_fee = self.cost_per_exec_unit.saturating_mul(exec_units);
        let data_fee = self.cost_per_data_byte.saturating_mul(data_bytes);
        let storage_fee = self
            .cost_per_storage_write
            .saturating_mul(u64::from(storage_writes));

        let total = self
            .base_fee
            .saturating_add(exec_fee)
            .saturating_add(data_fee)
            .saturating_add(storage_fee);

        M2mFeeBreakdown::new(exec_units, data_bytes, storage_writes, total)
    }

    /// Calculate the maximum fee for a given data size (for reservations).
    ///
    /// This assumes worst-case execution and storage usage for a given payload size.
    pub fn calculate_max_fee(&self, data_bytes: u64) -> FeeAmount {
        // Conservative estimates for worst-case usage
        let max_exec_units = data_bytes.saturating_mul(100); // 100 exec units per byte
        let max_storage_writes = 10u32; // Maximum storage writes per tx

        let breakdown = self.calculate_fee(max_exec_units, data_bytes, max_storage_writes);
        breakdown.total_fee
    }
}

impl Default for M2mFeePolicy {
    fn default() -> Self {
        Self::default_policy()
    }
}

/// Fee reservation for a transaction before it's included in a batch.
///
/// This represents the maximum fee that will be charged, allowing
/// the actual fee to be calculated after execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeReservation {
    /// Transaction hash this reservation is for.
    pub tx_hash: [u8; 32],
    /// Maximum fee reserved.
    pub max_fee: FeeAmount,
    /// Data bytes in the transaction (used for fee calculation).
    pub data_bytes: u64,
    /// Timestamp when the reservation was created (ms since epoch).
    pub created_at_ms: u64,
}

impl FeeReservation {
    /// Create a new fee reservation.
    pub fn new(tx_hash: [u8; 32], max_fee: FeeAmount, data_bytes: u64, created_at_ms: u64) -> Self {
        Self {
            tx_hash,
            max_fee,
            data_bytes,
            created_at_ms,
        }
    }

    /// Finalise the reservation with the actual fee breakdown.
    ///
    /// Returns the fee breakdown if the actual fee is within the reservation,
    /// or None if the actual fee exceeds the reservation.
    pub fn finalise(&self, actual: M2mFeeBreakdown) -> Option<FinalizedFee> {
        if actual.total_fee.0 <= self.max_fee.0 {
            let refund = self.max_fee.saturating_sub(actual.total_fee);
            Some(FinalizedFee {
                tx_hash: self.tx_hash,
                breakdown: actual,
                refund,
            })
        } else {
            None
        }
    }
}

/// Finalized fee after transaction execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedFee {
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Actual fee breakdown.
    pub breakdown: M2mFeeBreakdown,
    /// Refund amount (reserved - actual).
    pub refund: FeeAmount,
}

/// Aggregated M2M fees for a batch.
///
/// This is included in batch settlement metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchFeeAggregate {
    /// Number of transactions in the batch.
    pub tx_count: u64,
    /// Total execution units across all txs.
    pub total_exec_units: u64,
    /// Total data bytes across all txs.
    pub total_data_bytes: u64,
    /// Total storage writes across all txs.
    pub total_storage_writes: u64,
    /// Total fees collected.
    pub total_fees: FeeAmount,
    /// Total refunds issued.
    pub total_refunds: FeeAmount,
}

impl BatchFeeAggregate {
    /// Create an empty aggregate.
    pub fn empty() -> Self {
        Self {
            tx_count: 0,
            total_exec_units: 0,
            total_data_bytes: 0,
            total_storage_writes: 0,
            total_fees: FeeAmount::ZERO,
            total_refunds: FeeAmount::ZERO,
        }
    }

    /// Add a finalized fee to the aggregate.
    pub fn add_fee(&mut self, fee: &FinalizedFee) {
        self.tx_count = self.tx_count.saturating_add(1);
        self.total_exec_units = self
            .total_exec_units
            .saturating_add(fee.breakdown.exec_units);
        self.total_data_bytes = self
            .total_data_bytes
            .saturating_add(fee.breakdown.data_bytes);
        self.total_storage_writes = self
            .total_storage_writes
            .saturating_add(u64::from(fee.breakdown.storage_writes));
        self.total_fees = self.total_fees.saturating_add(fee.breakdown.total_fee);
        self.total_refunds = self.total_refunds.saturating_add(fee.refund);
    }

    /// Net fees after refunds.
    pub fn net_fees(&self) -> FeeAmount {
        self.total_fees.saturating_sub(self.total_refunds)
    }
}

impl Default for BatchFeeAggregate {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_amount_arithmetic() {
        let a = FeeAmount::from_units(1); // 1_000_000
        let b = FeeAmount::from_scaled(500_000); // 0.5

        assert_eq!(a.scaled(), 1_000_000);
        assert_eq!(b.scaled(), 500_000);

        let sum = a.saturating_add(b);
        assert_eq!(sum.scaled(), 1_500_000);

        let diff = a.saturating_sub(b);
        assert_eq!(diff.scaled(), 500_000);
    }

    #[test]
    fn fee_amount_display() {
        assert_eq!(FeeAmount::from_units(1).to_string(), "1");
        assert_eq!(FeeAmount::from_scaled(1_500_000).to_string(), "1.500000");
        assert_eq!(FeeAmount::from_scaled(500_000).to_string(), "0.500000");
        assert_eq!(FeeAmount::ZERO.to_string(), "0");
    }

    #[test]
    fn fee_policy_calculation() {
        let policy = M2mFeePolicy::default_policy();

        // Calculate fee for 1000 exec units, 100 bytes, 2 storage writes
        let breakdown = policy.calculate_fee(1000, 100, 2);

        // Expected:
        // - Base fee: 10_000
        // - Exec: 1000 * 1 = 1_000
        // - Data: 100 * 10 = 1_000
        // - Storage: 2 * 1000 = 2_000
        // Total: 14_000
        assert_eq!(breakdown.exec_units, 1000);
        assert_eq!(breakdown.data_bytes, 100);
        assert_eq!(breakdown.storage_writes, 2);
        assert_eq!(breakdown.total_fee.scaled(), 14_000);
    }

    #[test]
    fn fee_reservation_finalise() {
        let policy = M2mFeePolicy::default_policy();
        let max_fee = policy.calculate_max_fee(100);

        let reservation = FeeReservation::new([0x42; 32], max_fee, 100, 1_700_000_000_000);

        // Actual fee is less than reserved
        let actual = policy.calculate_fee(500, 100, 1);
        let finalized = reservation.finalise(actual).unwrap();

        assert_eq!(finalized.tx_hash, [0x42; 32]);
        assert!(finalized.refund.scaled() > 0);
    }

    #[test]
    fn fee_breakdown_combine() {
        let a = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(1000));
        let b = M2mFeeBreakdown::new(200, 100, 2, FeeAmount::from_scaled(2000));

        let combined = a.combine(&b);

        assert_eq!(combined.exec_units, 300);
        assert_eq!(combined.data_bytes, 150);
        assert_eq!(combined.storage_writes, 3);
        assert_eq!(combined.total_fee.scaled(), 3000);
    }

    #[test]
    fn batch_fee_aggregate() {
        let mut aggregate = BatchFeeAggregate::empty();

        let fee1 = FinalizedFee {
            tx_hash: [0x01; 32],
            breakdown: M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(1000)),
            refund: FeeAmount::from_scaled(200),
        };
        let fee2 = FinalizedFee {
            tx_hash: [0x02; 32],
            breakdown: M2mFeeBreakdown::new(200, 100, 2, FeeAmount::from_scaled(2000)),
            refund: FeeAmount::from_scaled(300),
        };

        aggregate.add_fee(&fee1);
        aggregate.add_fee(&fee2);

        assert_eq!(aggregate.tx_count, 2);
        assert_eq!(aggregate.total_exec_units, 300);
        assert_eq!(aggregate.total_data_bytes, 150);
        assert_eq!(aggregate.total_storage_writes, 3);
        assert_eq!(aggregate.total_fees.scaled(), 3000);
        assert_eq!(aggregate.total_refunds.scaled(), 500);
        assert_eq!(aggregate.net_fees().scaled(), 2500);
    }

    #[test]
    fn fee_serialization() {
        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(1000));
        let json = serde_json::to_string(&breakdown).unwrap();
        let parsed: M2mFeeBreakdown = serde_json::from_str(&json).unwrap();
        assert_eq!(breakdown, parsed);
    }
}
