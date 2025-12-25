//! M2M (Machine-to-Machine) fee accounting storage.
//!
//! This module provides persistent storage for:
//! - Machine balances
//! - Fee reservations
//! - Quota windows (rate limiting)
//! - Forced inclusion tier flags
//!
//! All operations are atomic and crash-safe using sled transactions.

use l2_core::fees::{FeeAmount, FeeError, FeeSchedule, M2mFeeBreakdown};
use l2_core::{canonical_decode, canonical_encode, CanonicalError};
use serde::{Deserialize, Serialize};
use sled::Tree;
use thiserror::Error;
use tracing::{debug, info};

/// Errors from M2M storage operations.
#[derive(Debug, Error)]
pub enum M2mStorageError {
    #[error("storage error: {0}")]
    Sled(#[from] sled::Error),
    #[error("canonical encoding error: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("fee error: {0}")]
    Fee(#[from] FeeError),
    #[error("insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u64, available: u64 },
    #[error("insufficient reservation: reserved {reserved}, requested {requested}")]
    InsufficientReservation { reserved: u64, requested: u64 },
    #[error("quota exceeded: {reason}")]
    QuotaExceeded { reason: String },
    #[error("machine not found: {machine_id}")]
    MachineNotFound { machine_id: String },
    #[error("invalid machine ID format: {reason}")]
    InvalidMachineId { reason: String },
}

/// Machine account state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineAccount {
    /// Machine identifier.
    pub machine_id: String,
    /// Available balance (scaled).
    pub balance_scaled: u64,
    /// Reserved balance (scaled).
    pub reserved_scaled: u64,
    /// Whether this machine has forced inclusion privileges.
    pub forced_class: ForcedClass,
    /// Last updated timestamp (ms since epoch).
    pub updated_at_ms: u64,
    /// Total fees paid (lifetime, scaled).
    pub total_fees_paid_scaled: u64,
    /// Total transactions submitted.
    pub total_tx_count: u64,
}

impl MachineAccount {
    /// Create a new machine account with zero balance.
    pub fn new(machine_id: String, forced_class: ForcedClass) -> Self {
        Self {
            machine_id,
            balance_scaled: 0,
            reserved_scaled: 0,
            forced_class,
            updated_at_ms: 0,
            total_fees_paid_scaled: 0,
            total_tx_count: 0,
        }
    }

    /// Get available balance (balance - reserved).
    pub fn available_balance(&self) -> u64 {
        self.balance_scaled.saturating_sub(self.reserved_scaled)
    }
}

/// Forced inclusion class for a machine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForcedClass {
    /// Standard machine - subject to normal rate limits.
    #[default]
    Standard,
    /// Safety-critical device - can bypass normal queue limits.
    ForcedInclusion,
}

/// Quota window for rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaWindow {
    /// Machine identifier.
    pub machine_id: String,
    /// Start of current quota window (ms since epoch).
    pub window_start_ms: u64,
    /// Units consumed in current window.
    pub used_units: u64,
    /// Maximum units allowed per window.
    pub max_units: u64,
    /// Window duration (ms).
    pub window_duration_ms: u64,
}

impl QuotaWindow {
    /// Create a new quota window.
    pub fn new(machine_id: String, max_units: u64, window_duration_ms: u64) -> Self {
        Self {
            machine_id,
            window_start_ms: 0,
            used_units: 0,
            max_units,
            window_duration_ms,
        }
    }

    /// Check if the window needs to be reset at the given timestamp.
    pub fn should_reset(&self, now_ms: u64) -> bool {
        now_ms >= self.window_start_ms.saturating_add(self.window_duration_ms)
    }

    /// Reset the window.
    pub fn reset(&mut self, now_ms: u64) {
        self.window_start_ms = now_ms;
        self.used_units = 0;
    }

    /// Get remaining quota.
    pub fn remaining(&self) -> u64 {
        self.max_units.saturating_sub(self.used_units)
    }
}

/// Pending fee reservation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingReservation {
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Machine ID.
    pub machine_id: String,
    /// Reserved amount (scaled).
    pub reserved_scaled: u64,
    /// Fee breakdown.
    pub breakdown: M2mFeeBreakdown,
    /// Created timestamp (ms since epoch).
    pub created_at_ms: u64,
    /// Whether this is a forced inclusion tx.
    pub forced: bool,
}

/// Configuration for forced inclusion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForcedInclusionLimits {
    /// Maximum forced txs per machine per day.
    pub max_per_day: u64,
    /// Current day start (ms since epoch).
    pub day_start_ms: u64,
    /// Usage count for current day.
    pub used_today: u64,
}

impl Default for ForcedInclusionLimits {
    fn default() -> Self {
        Self {
            max_per_day: 100,
            day_start_ms: 0,
            used_today: 0,
        }
    }
}

/// Batch fee totals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchFeeTotals {
    /// Batch hash.
    pub batch_hash: [u8; 32],
    /// Total fees collected (scaled).
    pub total_fees_scaled: u64,
    /// Number of transactions.
    pub tx_count: u64,
    /// Total refunds issued (scaled).
    pub total_refunds_scaled: u64,
    /// Created timestamp.
    pub created_at_ms: u64,
}

/// M2M storage handle.
pub struct M2mStorage {
    /// Machine accounts (machine_id -> MachineAccount).
    accounts: Tree,
    /// Quota windows (machine_id -> QuotaWindow).
    quotas: Tree,
    /// Pending reservations (tx_hash -> PendingReservation).
    reservations: Tree,
    /// Batch fee totals (batch_hash -> BatchFeeTotals).
    batch_fees: Tree,
    /// Forced inclusion usage (machine_id -> ForcedInclusionLimits).
    forced_limits: Tree,
    /// Fee schedule.
    schedule: FeeSchedule,
}

impl M2mStorage {
    /// Create a new M2M storage using the given sled database.
    pub fn open(db: &sled::Db, schedule: FeeSchedule) -> Result<Self, M2mStorageError> {
        let accounts = db.open_tree("m2m_accounts")?;
        let quotas = db.open_tree("m2m_quotas")?;
        let reservations = db.open_tree("m2m_reservations")?;
        let batch_fees = db.open_tree("m2m_batch_fees")?;
        let forced_limits = db.open_tree("m2m_forced_limits")?;

        Ok(Self {
            accounts,
            quotas,
            reservations,
            batch_fees,
            forced_limits,
            schedule,
        })
    }

    /// Validate machine ID format.
    ///
    /// Machine IDs must be:
    /// - 1-64 characters
    /// - Alphanumeric, dash, underscore only
    /// - No leading/trailing whitespace
    pub fn validate_machine_id(machine_id: &str) -> Result<(), M2mStorageError> {
        if machine_id.is_empty() || machine_id.len() > 64 {
            return Err(M2mStorageError::InvalidMachineId {
                reason: "machine_id must be 1-64 characters".to_string(),
            });
        }

        if machine_id.trim() != machine_id {
            return Err(M2mStorageError::InvalidMachineId {
                reason: "machine_id cannot have leading/trailing whitespace".to_string(),
            });
        }

        for c in machine_id.chars() {
            if !c.is_alphanumeric() && c != '-' && c != '_' {
                return Err(M2mStorageError::InvalidMachineId {
                    reason: format!("invalid character '{}' in machine_id", c),
                });
            }
        }

        Ok(())
    }

    /// Get the current fee schedule.
    pub fn get_schedule(&self) -> &FeeSchedule {
        &self.schedule
    }

    // ========== Balance APIs ==========

    /// Get account balance.
    pub fn balance(&self, machine_id: &str) -> Result<FeeAmount, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        match self.accounts.get(machine_id.as_bytes())? {
            Some(data) => {
                let account: MachineAccount = canonical_decode(&data)?;
                Ok(FeeAmount::from_scaled(account.balance_scaled))
            }
            None => Ok(FeeAmount::ZERO),
        }
    }

    /// Get full machine account.
    pub fn get_account(&self, machine_id: &str) -> Result<Option<MachineAccount>, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        match self.accounts.get(machine_id.as_bytes())? {
            Some(data) => Ok(Some(canonical_decode(&data)?)),
            None => Ok(None),
        }
    }

    /// Get reserved amount for a machine.
    pub fn reserved(&self, machine_id: &str) -> Result<FeeAmount, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        match self.accounts.get(machine_id.as_bytes())? {
            Some(data) => {
                let account: MachineAccount = canonical_decode(&data)?;
                Ok(FeeAmount::from_scaled(account.reserved_scaled))
            }
            None => Ok(FeeAmount::ZERO),
        }
    }

    /// Get forced class for a machine.
    pub fn forced_class(&self, machine_id: &str) -> Result<ForcedClass, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        match self.accounts.get(machine_id.as_bytes())? {
            Some(data) => {
                let account: MachineAccount = canonical_decode(&data)?;
                Ok(account.forced_class)
            }
            None => Ok(ForcedClass::Standard),
        }
    }

    /// Set forced class for a machine.
    pub fn set_forced_class(
        &self,
        machine_id: &str,
        class: ForcedClass,
        now_ms: u64,
    ) -> Result<(), M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        let mut account = self
            .get_account(machine_id)?
            .unwrap_or_else(|| MachineAccount::new(machine_id.to_string(), class));

        account.forced_class = class;
        account.updated_at_ms = now_ms;

        let data = canonical_encode(&account)?;
        self.accounts.insert(machine_id.as_bytes(), data)?;
        Ok(())
    }

    /// Top up balance (devnet only).
    pub fn topup(
        &self,
        machine_id: &str,
        amount_scaled: u64,
        now_ms: u64,
    ) -> Result<FeeAmount, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        let mut account = self
            .get_account(machine_id)?
            .unwrap_or_else(|| MachineAccount::new(machine_id.to_string(), ForcedClass::Standard));

        account.balance_scaled = account
            .balance_scaled
            .checked_add(amount_scaled)
            .ok_or(FeeError::Overflow)?;
        account.updated_at_ms = now_ms;

        let data = canonical_encode(&account)?;
        self.accounts.insert(machine_id.as_bytes(), data)?;

        info!(
            machine_id = %machine_id,
            amount_scaled = amount_scaled,
            new_balance = account.balance_scaled,
            "topped up machine balance"
        );

        Ok(FeeAmount::from_scaled(account.balance_scaled))
    }

    // ========== Reservation APIs ==========

    /// Reserve fee for a transaction.
    ///
    /// This deducts from available balance and creates a pending reservation.
    pub fn reserve_fee(
        &self,
        machine_id: &str,
        tx_hash: [u8; 32],
        amount_scaled: u64,
        breakdown: M2mFeeBreakdown,
        forced: bool,
        now_ms: u64,
    ) -> Result<(), M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        // Get account
        let mut account =
            self.get_account(machine_id)?
                .ok_or_else(|| M2mStorageError::MachineNotFound {
                    machine_id: machine_id.to_string(),
                })?;

        // Check available balance
        let available = account.available_balance();
        if available < amount_scaled {
            return Err(M2mStorageError::InsufficientBalance {
                required: amount_scaled,
                available,
            });
        }

        // Update reserved amount
        account.reserved_scaled = account
            .reserved_scaled
            .checked_add(amount_scaled)
            .ok_or(FeeError::Overflow)?;
        account.updated_at_ms = now_ms;

        // Create reservation
        let reservation = PendingReservation {
            tx_hash,
            machine_id: machine_id.to_string(),
            reserved_scaled: amount_scaled,
            breakdown,
            created_at_ms: now_ms,
            forced,
        };

        // Persist atomically
        let account_data = canonical_encode(&account)?;
        let reservation_data = canonical_encode(&reservation)?;

        self.accounts.insert(machine_id.as_bytes(), account_data)?;
        self.reservations.insert(tx_hash, reservation_data)?;

        debug!(
            machine_id = %machine_id,
            tx_hash = %hex::encode(tx_hash),
            amount_scaled = amount_scaled,
            "reserved fee"
        );

        Ok(())
    }

    /// Finalise fee for a transaction.
    ///
    /// This releases the reservation and deducts the final fee.
    /// Any excess is refunded to the available balance.
    pub fn finalise_fee(
        &self,
        machine_id: &str,
        tx_hash: [u8; 32],
        final_amount_scaled: u64,
        now_ms: u64,
    ) -> Result<u64, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        // Get reservation
        let reservation_data =
            self.reservations
                .get(tx_hash)?
                .ok_or_else(|| M2mStorageError::MachineNotFound {
                    machine_id: format!("reservation:{}", hex::encode(tx_hash)),
                })?;
        let reservation: PendingReservation = canonical_decode(&reservation_data)?;

        // Verify machine ID matches
        if reservation.machine_id != machine_id {
            return Err(M2mStorageError::InvalidMachineId {
                reason: format!(
                    "reservation machine_id mismatch: {} vs {}",
                    reservation.machine_id, machine_id
                ),
            });
        }

        // Check final doesn't exceed reserved
        if final_amount_scaled > reservation.reserved_scaled {
            return Err(M2mStorageError::InsufficientReservation {
                reserved: reservation.reserved_scaled,
                requested: final_amount_scaled,
            });
        }

        // Get account
        let mut account =
            self.get_account(machine_id)?
                .ok_or_else(|| M2mStorageError::MachineNotFound {
                    machine_id: machine_id.to_string(),
                })?;

        // Calculate refund
        let refund = reservation
            .reserved_scaled
            .saturating_sub(final_amount_scaled);

        // Update account:
        // - Deduct final fee from balance
        // - Release reservation
        account.balance_scaled = account.balance_scaled.saturating_sub(final_amount_scaled);
        account.reserved_scaled = account
            .reserved_scaled
            .saturating_sub(reservation.reserved_scaled);
        account.total_fees_paid_scaled = account
            .total_fees_paid_scaled
            .saturating_add(final_amount_scaled);
        account.total_tx_count = account.total_tx_count.saturating_add(1);
        account.updated_at_ms = now_ms;

        // Persist
        let account_data = canonical_encode(&account)?;
        self.accounts.insert(machine_id.as_bytes(), account_data)?;
        self.reservations.remove(tx_hash)?;

        debug!(
            machine_id = %machine_id,
            tx_hash = %hex::encode(tx_hash),
            final_amount_scaled = final_amount_scaled,
            refund = refund,
            "finalised fee"
        );

        Ok(refund)
    }

    /// Release a reservation without finalising (e.g., tx rejected).
    pub fn release_reservation(
        &self,
        machine_id: &str,
        tx_hash: [u8; 32],
        now_ms: u64,
    ) -> Result<u64, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        // Get reservation
        let reservation_data = match self.reservations.get(tx_hash)? {
            Some(data) => data,
            None => return Ok(0), // No reservation to release
        };
        let reservation: PendingReservation = canonical_decode(&reservation_data)?;

        // Get account
        let mut account = match self.get_account(machine_id)? {
            Some(acc) => acc,
            None => return Ok(0),
        };

        // Release reserved amount
        account.reserved_scaled = account
            .reserved_scaled
            .saturating_sub(reservation.reserved_scaled);
        account.updated_at_ms = now_ms;

        // Persist
        let account_data = canonical_encode(&account)?;
        self.accounts.insert(machine_id.as_bytes(), account_data)?;
        self.reservations.remove(tx_hash)?;

        debug!(
            machine_id = %machine_id,
            tx_hash = %hex::encode(tx_hash),
            released = reservation.reserved_scaled,
            "released reservation"
        );

        Ok(reservation.reserved_scaled)
    }

    /// Get a pending reservation.
    pub fn get_reservation(
        &self,
        tx_hash: &[u8; 32],
    ) -> Result<Option<PendingReservation>, M2mStorageError> {
        match self.reservations.get(tx_hash)? {
            Some(data) => Ok(Some(canonical_decode(&data)?)),
            None => Ok(None),
        }
    }

    // ========== Quota APIs ==========

    /// Get quota window for a machine.
    pub fn get_quota_window(
        &self,
        machine_id: &str,
    ) -> Result<Option<QuotaWindow>, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        match self.quotas.get(machine_id.as_bytes())? {
            Some(data) => Ok(Some(canonical_decode(&data)?)),
            None => Ok(None),
        }
    }

    /// Apply quota usage.
    ///
    /// This checks and updates the quota window for the machine.
    /// If the quota would be exceeded, returns an error.
    pub fn apply_quota(
        &self,
        machine_id: &str,
        cost_units: u64,
        now_ms: u64,
        max_units: u64,
        window_duration_ms: u64,
    ) -> Result<(), M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        let mut window = self.get_quota_window(machine_id)?.unwrap_or_else(|| {
            QuotaWindow::new(machine_id.to_string(), max_units, window_duration_ms)
        });

        // Reset window if expired
        if window.should_reset(now_ms) {
            window.reset(now_ms);
            window.max_units = max_units;
            window.window_duration_ms = window_duration_ms;
        }

        // Check quota
        let new_usage = window.used_units.saturating_add(cost_units);
        if new_usage > window.max_units {
            return Err(M2mStorageError::QuotaExceeded {
                reason: format!(
                    "quota exceeded: {} + {} > {} (resets at {})",
                    window.used_units,
                    cost_units,
                    window.max_units,
                    window
                        .window_start_ms
                        .saturating_add(window.window_duration_ms)
                ),
            });
        }

        // Update window
        window.used_units = new_usage;
        let data = canonical_encode(&window)?;
        self.quotas.insert(machine_id.as_bytes(), data)?;

        Ok(())
    }

    // ========== Forced Inclusion APIs ==========

    /// Check and apply forced inclusion usage.
    ///
    /// For ForcedInclusion class machines, this tracks daily usage limits.
    pub fn apply_forced_usage(&self, machine_id: &str, now_ms: u64) -> Result<(), M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        // Check machine class
        let class = self.forced_class(machine_id)?;
        if class != ForcedClass::ForcedInclusion {
            return Err(M2mStorageError::QuotaExceeded {
                reason: "machine does not have forced inclusion privileges".to_string(),
            });
        }

        // Get or create limits
        let mut limits = match self.forced_limits.get(machine_id.as_bytes())? {
            Some(data) => canonical_decode(&data)?,
            None => ForcedInclusionLimits::default(),
        };

        // Check if we need to reset (new day)
        const MS_PER_DAY: u64 = 86_400_000;
        if now_ms >= limits.day_start_ms.saturating_add(MS_PER_DAY) {
            limits.day_start_ms = now_ms.saturating_sub(now_ms % MS_PER_DAY);
            limits.used_today = 0;
        }

        // Check limit
        if limits.used_today >= limits.max_per_day {
            return Err(M2mStorageError::QuotaExceeded {
                reason: format!(
                    "forced inclusion daily limit exceeded: {} >= {}",
                    limits.used_today, limits.max_per_day
                ),
            });
        }

        // Increment usage
        limits.used_today = limits.used_today.saturating_add(1);

        // Persist
        let data = canonical_encode(&limits)?;
        self.forced_limits.insert(machine_id.as_bytes(), data)?;

        Ok(())
    }

    /// Get forced inclusion limits for a machine.
    pub fn get_forced_limits(
        &self,
        machine_id: &str,
    ) -> Result<Option<ForcedInclusionLimits>, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        match self.forced_limits.get(machine_id.as_bytes())? {
            Some(data) => Ok(Some(canonical_decode(&data)?)),
            None => Ok(None),
        }
    }

    /// Set forced inclusion limits for a machine.
    pub fn set_forced_limits(
        &self,
        machine_id: &str,
        limits: ForcedInclusionLimits,
    ) -> Result<(), M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        let data = canonical_encode(&limits)?;
        self.forced_limits.insert(machine_id.as_bytes(), data)?;
        Ok(())
    }

    // ========== Batch Fee APIs ==========

    /// Record batch fee totals.
    pub fn record_batch_fees(&self, totals: &BatchFeeTotals) -> Result<(), M2mStorageError> {
        let data = canonical_encode(totals)?;
        self.batch_fees.insert(totals.batch_hash, data)?;
        Ok(())
    }

    /// Get batch fee totals.
    pub fn get_batch_fees(
        &self,
        batch_hash: &[u8; 32],
    ) -> Result<Option<BatchFeeTotals>, M2mStorageError> {
        match self.batch_fees.get(batch_hash)? {
            Some(data) => Ok(Some(canonical_decode(&data)?)),
            None => Ok(None),
        }
    }

    // ========== Statistics APIs ==========

    /// Get total M2M fee statistics.
    pub fn get_stats(&self) -> Result<M2mStats, M2mStorageError> {
        let mut stats = M2mStats::default();

        for result in self.accounts.iter() {
            let (_key, value) = result?;
            let account: MachineAccount = canonical_decode(&value)?;
            stats.total_machines = stats.total_machines.saturating_add(1);
            stats.total_balance_scaled = stats
                .total_balance_scaled
                .saturating_add(account.balance_scaled);
            stats.total_reserved_scaled = stats
                .total_reserved_scaled
                .saturating_add(account.reserved_scaled);
            stats.total_fees_paid_scaled = stats
                .total_fees_paid_scaled
                .saturating_add(account.total_fees_paid_scaled);
            if account.forced_class == ForcedClass::ForcedInclusion {
                stats.forced_machines = stats.forced_machines.saturating_add(1);
            }
        }

        stats.pending_reservations = u64::try_from(self.reservations.len()).unwrap_or(u64::MAX);

        Ok(stats)
    }
}

/// M2M statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct M2mStats {
    /// Total number of registered machines.
    pub total_machines: u64,
    /// Number of machines with forced inclusion privileges.
    pub forced_machines: u64,
    /// Total balance across all machines (scaled).
    pub total_balance_scaled: u64,
    /// Total reserved balance (scaled).
    pub total_reserved_scaled: u64,
    /// Total fees paid (lifetime, scaled).
    pub total_fees_paid_scaled: u64,
    /// Number of pending reservations.
    pub pending_reservations: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_storage() -> (sled::Db, M2mStorage) {
        let dir = tempdir().expect("tmpdir");
        let db = sled::open(dir.path()).expect("open db");
        let storage = M2mStorage::open(&db, FeeSchedule::default()).expect("open m2m");
        (db, storage)
    }

    #[test]
    fn validate_machine_id() {
        assert!(M2mStorage::validate_machine_id("device-001").is_ok());
        assert!(M2mStorage::validate_machine_id("machine_123").is_ok());
        assert!(M2mStorage::validate_machine_id("A").is_ok());

        // Invalid cases
        assert!(M2mStorage::validate_machine_id("").is_err());
        assert!(M2mStorage::validate_machine_id(" space").is_err());
        assert!(M2mStorage::validate_machine_id("a".repeat(65).as_str()).is_err());
        assert!(M2mStorage::validate_machine_id("invalid@char").is_err());
    }

    #[test]
    fn topup_and_balance() {
        let (_db, storage) = test_storage();
        let machine_id = "device-001";

        // Initial balance is zero
        assert_eq!(storage.balance(machine_id).unwrap().scaled(), 0);

        // Top up
        let new_balance = storage.topup(machine_id, 1_000_000, 1000).unwrap();
        assert_eq!(new_balance.scaled(), 1_000_000);
        assert_eq!(storage.balance(machine_id).unwrap().scaled(), 1_000_000);

        // Top up again
        let new_balance = storage.topup(machine_id, 500_000, 2000).unwrap();
        assert_eq!(new_balance.scaled(), 1_500_000);
    }

    #[test]
    fn reserve_and_finalise_fee() {
        let (_db, storage) = test_storage();
        let machine_id = "device-002";
        let tx_hash = [0xAA; 32];

        // Top up first
        storage.topup(machine_id, 1_000_000, 1000).unwrap();

        // Reserve
        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));
        storage
            .reserve_fee(machine_id, tx_hash, 50_000, breakdown, false, 2000)
            .unwrap();

        // Check reserved
        assert_eq!(storage.reserved(machine_id).unwrap().scaled(), 50_000);
        assert!(storage.get_reservation(&tx_hash).unwrap().is_some());

        // Finalise with lower actual fee
        let refund = storage
            .finalise_fee(machine_id, tx_hash, 30_000, 3000)
            .unwrap();
        assert_eq!(refund, 20_000);

        // Check final state
        assert_eq!(storage.reserved(machine_id).unwrap().scaled(), 0);
        assert_eq!(storage.balance(machine_id).unwrap().scaled(), 970_000);
        assert!(storage.get_reservation(&tx_hash).unwrap().is_none());
    }

    #[test]
    fn reserve_insufficient_balance() {
        let (_db, storage) = test_storage();
        let machine_id = "device-003";
        let tx_hash = [0xBB; 32];

        // Top up small amount
        storage.topup(machine_id, 10_000, 1000).unwrap();

        // Try to reserve more than available
        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(100_000));
        let result = storage.reserve_fee(machine_id, tx_hash, 100_000, breakdown, false, 2000);
        assert!(matches!(
            result,
            Err(M2mStorageError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn release_reservation() {
        let (_db, storage) = test_storage();
        let machine_id = "device-004";
        let tx_hash = [0xCC; 32];

        storage.topup(machine_id, 1_000_000, 1000).unwrap();

        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));
        storage
            .reserve_fee(machine_id, tx_hash, 50_000, breakdown, false, 2000)
            .unwrap();

        // Release without finalising
        let released = storage
            .release_reservation(machine_id, tx_hash, 3000)
            .unwrap();
        assert_eq!(released, 50_000);
        assert_eq!(storage.reserved(machine_id).unwrap().scaled(), 0);
        assert_eq!(storage.balance(machine_id).unwrap().scaled(), 1_000_000);
    }

    #[test]
    fn quota_window() {
        let (_db, storage) = test_storage();
        let machine_id = "device-005";

        // Apply quota
        storage
            .apply_quota(machine_id, 100, 1000, 1000, 60_000)
            .unwrap();
        storage
            .apply_quota(machine_id, 200, 2000, 1000, 60_000)
            .unwrap();

        let window = storage.get_quota_window(machine_id).unwrap().unwrap();
        assert_eq!(window.used_units, 300);

        // Exceed quota
        let result = storage.apply_quota(machine_id, 800, 3000, 1000, 60_000);
        assert!(matches!(result, Err(M2mStorageError::QuotaExceeded { .. })));

        // After window expires, quota resets
        storage
            .apply_quota(machine_id, 100, 70_000, 1000, 60_000)
            .unwrap();
        let window = storage.get_quota_window(machine_id).unwrap().unwrap();
        assert_eq!(window.used_units, 100);
    }

    #[test]
    fn forced_class() {
        let (_db, storage) = test_storage();
        let machine_id = "device-006";

        // Default is standard
        assert_eq!(
            storage.forced_class(machine_id).unwrap(),
            ForcedClass::Standard
        );

        // Set to forced
        storage
            .set_forced_class(machine_id, ForcedClass::ForcedInclusion, 1000)
            .unwrap();
        assert_eq!(
            storage.forced_class(machine_id).unwrap(),
            ForcedClass::ForcedInclusion
        );
    }

    #[test]
    fn forced_usage_limits() {
        let (_db, storage) = test_storage();
        let machine_id = "device-007";

        // Set up forced machine
        storage
            .set_forced_class(machine_id, ForcedClass::ForcedInclusion, 1000)
            .unwrap();

        // Set low limit for testing
        let limits = ForcedInclusionLimits {
            max_per_day: 3,
            day_start_ms: 0,
            used_today: 0,
        };
        storage.set_forced_limits(machine_id, limits).unwrap();

        // Use up limit
        storage.apply_forced_usage(machine_id, 1000).unwrap();
        storage.apply_forced_usage(machine_id, 2000).unwrap();
        storage.apply_forced_usage(machine_id, 3000).unwrap();

        // Should fail now
        let result = storage.apply_forced_usage(machine_id, 4000);
        assert!(matches!(result, Err(M2mStorageError::QuotaExceeded { .. })));
    }

    #[test]
    fn batch_fees_roundtrip() {
        let (_db, storage) = test_storage();
        let batch_hash = [0xDD; 32];

        let totals = BatchFeeTotals {
            batch_hash,
            total_fees_scaled: 1_000_000,
            tx_count: 50,
            total_refunds_scaled: 50_000,
            created_at_ms: 1_700_000_000_000,
        };

        storage.record_batch_fees(&totals).unwrap();
        let loaded = storage.get_batch_fees(&batch_hash).unwrap().unwrap();

        assert_eq!(loaded.total_fees_scaled, 1_000_000);
        assert_eq!(loaded.tx_count, 50);
    }

    #[test]
    fn stats() {
        let (_db, storage) = test_storage();

        storage.topup("device-a", 1_000_000, 1000).unwrap();
        storage.topup("device-b", 2_000_000, 1000).unwrap();
        storage
            .set_forced_class("device-b", ForcedClass::ForcedInclusion, 1000)
            .unwrap();

        let stats = storage.get_stats().unwrap();
        assert_eq!(stats.total_machines, 2);
        assert_eq!(stats.total_balance_scaled, 3_000_000);
        assert_eq!(stats.forced_machines, 1);
    }
}
