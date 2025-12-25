//! Settlement State Machine for L2 batch lifecycle.
//!
//! This module provides an explicit, persistent settlement state machine that tracks
//! batches through their full lifecycle from creation to L1 finality.
//!
//! ## State Transitions
//!
//! ```text
//! Created -> Submitted -> Included -> Finalised
//!    |           |           |
//!    +-----------+-----------+---> Failed
//! ```
//!
//! State transitions are **monotonic**: once a batch reaches a terminal state
//! (Finalised or Failed), it cannot transition to any other state.
//!
//! ## Crash Safety
//!
//! All state transitions are persisted to disk before returning. On restart,
//! the reconciler will pick up from where it left off and resume processing.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Settlement lifecycle states for a batch.
///
/// States progress monotonically: `Created -> Submitted -> Included -> Finalised`.
/// Any state can transition to `Failed` as a terminal state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementState {
    /// Batch has been created and stored locally.
    /// Ready for submission to L1.
    Created {
        /// Timestamp when batch was created (ms since epoch).
        created_at_ms: u64,
    },

    /// Batch has been submitted to L1.
    /// Awaiting inclusion in an L1 block.
    Submitted {
        /// L1 transaction ID/hash.
        l1_tx_id: String,
        /// Timestamp when the batch was submitted (ms since epoch).
        submitted_at_ms: u64,
        /// Idempotency key used for this submission (hex).
        idempotency_key: String,
    },

    /// Batch has been included in an L1 block.
    /// Awaiting finality confirmation.
    Included {
        /// L1 transaction ID/hash.
        l1_tx_id: String,
        /// L1 block number where the batch was included.
        l1_block: u64,
        /// IPPAN timestamp (network-wide logical time).
        ippan_time: u64,
        /// Timestamp when inclusion was detected (ms since epoch).
        included_at_ms: u64,
    },

    /// Batch has reached finality on L1.
    /// This is a terminal state.
    Finalised {
        /// L1 transaction ID/hash.
        l1_tx_id: String,
        /// L1 block number where the batch was included.
        l1_block: u64,
        /// IPPAN timestamp (network-wide logical time).
        ippan_time: u64,
        /// Timestamp when finality was confirmed (ms since epoch).
        finalised_at_ms: u64,
    },

    /// Settlement failed.
    /// This is a terminal state.
    Failed {
        /// Reason for failure.
        reason: String,
        /// Timestamp when failure occurred (ms since epoch).
        failed_at_ms: u64,
        /// Number of retry attempts made before failure.
        retry_count: u32,
        /// Last known state before failure.
        last_state: Option<Box<SettlementState>>,
    },
}

impl SettlementState {
    // ========== Constructors ==========

    /// Create a new `Created` state.
    pub fn created(created_at_ms: u64) -> Self {
        Self::Created { created_at_ms }
    }

    /// Create a new `Submitted` state.
    pub fn submitted(l1_tx_id: String, submitted_at_ms: u64, idempotency_key: String) -> Self {
        Self::Submitted {
            l1_tx_id,
            submitted_at_ms,
            idempotency_key,
        }
    }

    /// Create a new `Included` state.
    pub fn included(l1_tx_id: String, l1_block: u64, ippan_time: u64, included_at_ms: u64) -> Self {
        Self::Included {
            l1_tx_id,
            l1_block,
            ippan_time,
            included_at_ms,
        }
    }

    /// Create a new `Finalised` state.
    pub fn finalised(
        l1_tx_id: String,
        l1_block: u64,
        ippan_time: u64,
        finalised_at_ms: u64,
    ) -> Self {
        Self::Finalised {
            l1_tx_id,
            l1_block,
            ippan_time,
            finalised_at_ms,
        }
    }

    /// Create a new `Failed` state.
    pub fn failed(
        reason: String,
        failed_at_ms: u64,
        retry_count: u32,
        last_state: Option<SettlementState>,
    ) -> Self {
        Self::Failed {
            reason,
            failed_at_ms,
            retry_count,
            last_state: last_state.map(Box::new),
        }
    }

    // ========== State Queries ==========

    /// Check if this is a terminal state (Finalised or Failed).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Finalised { .. } | Self::Failed { .. })
    }

    /// Check if this batch is in Created state.
    pub fn is_created(&self) -> bool {
        matches!(self, Self::Created { .. })
    }

    /// Check if this batch is in Submitted state.
    pub fn is_submitted(&self) -> bool {
        matches!(self, Self::Submitted { .. })
    }

    /// Check if this batch is in Included state.
    pub fn is_included(&self) -> bool {
        matches!(self, Self::Included { .. })
    }

    /// Check if this batch is finalised.
    pub fn is_finalised(&self) -> bool {
        matches!(self, Self::Finalised { .. })
    }

    /// Check if this batch failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// Check if this batch needs reconciliation (in-flight but not terminal).
    pub fn needs_reconciliation(&self) -> bool {
        matches!(self, Self::Submitted { .. } | Self::Included { .. })
    }

    /// Get the L1 tx ID if available.
    pub fn l1_tx_id(&self) -> Option<&str> {
        match self {
            Self::Submitted { l1_tx_id, .. }
            | Self::Included { l1_tx_id, .. }
            | Self::Finalised { l1_tx_id, .. } => Some(l1_tx_id),
            _ => None,
        }
    }

    /// Get the idempotency key if available.
    pub fn idempotency_key(&self) -> Option<&str> {
        match self {
            Self::Submitted {
                idempotency_key, ..
            } => Some(idempotency_key),
            _ => None,
        }
    }

    /// Get the L1 block number if available.
    pub fn l1_block(&self) -> Option<u64> {
        match self {
            Self::Included { l1_block, .. } | Self::Finalised { l1_block, .. } => Some(*l1_block),
            _ => None,
        }
    }

    /// Get the IPPAN time if available.
    pub fn ippan_time(&self) -> Option<u64> {
        match self {
            Self::Included { ippan_time, .. } | Self::Finalised { ippan_time, .. } => {
                Some(*ippan_time)
            }
            _ => None,
        }
    }

    /// Get the ordinal value for state ordering (used in monotonic checks).
    fn ordinal(&self) -> u8 {
        match self {
            Self::Created { .. } => 0,
            Self::Submitted { .. } => 1,
            Self::Included { .. } => 2,
            Self::Finalised { .. } => 3,
            Self::Failed { .. } => 4,
        }
    }

    /// Get a short name for the state.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Created { .. } => "created",
            Self::Submitted { .. } => "submitted",
            Self::Included { .. } => "included",
            Self::Finalised { .. } => "finalised",
            Self::Failed { .. } => "failed",
        }
    }
}

impl fmt::Display for SettlementState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created { created_at_ms } => {
                write!(f, "Created(at={})", created_at_ms)
            }
            Self::Submitted {
                l1_tx_id,
                submitted_at_ms,
                ..
            } => {
                write!(f, "Submitted(tx={}, at={})", l1_tx_id, submitted_at_ms)
            }
            Self::Included {
                l1_tx_id, l1_block, ..
            } => {
                write!(f, "Included(tx={}, block={})", l1_tx_id, l1_block)
            }
            Self::Finalised {
                l1_tx_id, l1_block, ..
            } => {
                write!(f, "Finalised(tx={}, block={})", l1_tx_id, l1_block)
            }
            Self::Failed {
                reason,
                retry_count,
                ..
            } => {
                write!(f, "Failed(reason={}, retries={})", reason, retry_count)
            }
        }
    }
}

/// Error type for invalid state transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementTransitionError {
    /// Cannot transition from a terminal state.
    TerminalState { from: String, to: String },
    /// Invalid state transition (non-monotonic).
    InvalidTransition {
        from: String,
        to: String,
        reason: String,
    },
    /// Cannot skip states in the settlement lifecycle.
    SkippedState {
        from: String,
        to: String,
        skipped: String,
    },
}

impl fmt::Display for SettlementTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TerminalState { from, to } => {
                write!(
                    f,
                    "cannot transition from terminal state {} to {}",
                    from, to
                )
            }
            Self::InvalidTransition { from, to, reason } => {
                write!(f, "invalid transition from {} to {}: {}", from, to, reason)
            }
            Self::SkippedState { from, to, skipped } => {
                write!(
                    f,
                    "cannot transition from {} to {}: skipped {}",
                    from, to, skipped
                )
            }
        }
    }
}

impl std::error::Error for SettlementTransitionError {}

/// Validate a state transition.
///
/// Returns `Ok(())` if the transition is valid, or an error describing why not.
///
/// # Rules
///
/// 1. Terminal states (Finalised, Failed) cannot transition to any state.
/// 2. States must progress in order: Created -> Submitted -> Included -> Finalised.
/// 3. Any state can transition to Failed (except terminal states).
/// 4. Cannot skip states (e.g., Created cannot go directly to Included).
pub fn validate_transition(
    from: &SettlementState,
    to: &SettlementState,
) -> Result<(), SettlementTransitionError> {
    // Rule 1: Cannot transition from terminal states
    if from.is_terminal() {
        return Err(SettlementTransitionError::TerminalState {
            from: from.name().to_string(),
            to: to.name().to_string(),
        });
    }

    // Rule 3: Any non-terminal state can transition to Failed
    if to.is_failed() {
        return Ok(());
    }

    // Rule 2 & 4: Check monotonic progression
    let from_ord = from.ordinal();
    let to_ord = to.ordinal();

    // Cannot go backwards
    if to_ord < from_ord {
        return Err(SettlementTransitionError::InvalidTransition {
            from: from.name().to_string(),
            to: to.name().to_string(),
            reason: "cannot go backwards in settlement lifecycle".to_string(),
        });
    }

    // Cannot skip states (must increment by exactly 1)
    if to_ord > from_ord + 1 && !to.is_failed() {
        let skipped = match from_ord + 1 {
            1 => "Submitted",
            2 => "Included",
            3 => "Finalised",
            _ => "unknown",
        };
        return Err(SettlementTransitionError::SkippedState {
            from: from.name().to_string(),
            to: to.name().to_string(),
            skipped: skipped.to_string(),
        });
    }

    Ok(())
}

/// Entry in the settlement state index for listing.
#[derive(Debug, Clone)]
pub struct SettlementStateEntry {
    /// The batch hash.
    pub batch_hash: l2_core::Hash32,
    /// The current settlement state.
    pub state: SettlementState,
}

/// Counts of batches by settlement state.
#[derive(Debug, Clone, Default)]
pub struct SettlementStateCounts {
    pub created: u64,
    pub submitted: u64,
    pub included: u64,
    pub finalised: u64,
    pub failed: u64,
}

impl SettlementStateCounts {
    /// Total number of batches tracked.
    pub fn total(&self) -> u64 {
        self.created
            .saturating_add(self.submitted)
            .saturating_add(self.included)
            .saturating_add(self.finalised)
            .saturating_add(self.failed)
    }

    /// Number of in-flight batches (not terminal).
    pub fn in_flight(&self) -> u64 {
        self.created
            .saturating_add(self.submitted)
            .saturating_add(self.included)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_constructors() {
        let created = SettlementState::created(1000);
        assert!(created.is_created());
        assert!(!created.is_terminal());

        let submitted = SettlementState::submitted("l1tx".to_string(), 2000, "key".to_string());
        assert!(submitted.is_submitted());
        assert!(!submitted.is_terminal());
        assert_eq!(submitted.l1_tx_id(), Some("l1tx"));
        assert_eq!(submitted.idempotency_key(), Some("key"));

        let included = SettlementState::included("l1tx".to_string(), 100, 3000, 3001);
        assert!(included.is_included());
        assert!(!included.is_terminal());
        assert_eq!(included.l1_block(), Some(100));
        assert_eq!(included.ippan_time(), Some(3000));

        let finalised = SettlementState::finalised("l1tx".to_string(), 100, 3000, 4000);
        assert!(finalised.is_finalised());
        assert!(finalised.is_terminal());

        let failed = SettlementState::failed("error".to_string(), 5000, 3, None);
        assert!(failed.is_failed());
        assert!(failed.is_terminal());
    }

    #[test]
    fn valid_forward_transitions() {
        let created = SettlementState::created(1000);
        let submitted = SettlementState::submitted("l1tx".to_string(), 2000, "key".to_string());
        let included = SettlementState::included("l1tx".to_string(), 100, 3000, 3001);
        let finalised = SettlementState::finalised("l1tx".to_string(), 100, 3000, 4000);

        // Valid forward transitions
        assert!(validate_transition(&created, &submitted).is_ok());
        assert!(validate_transition(&submitted, &included).is_ok());
        assert!(validate_transition(&included, &finalised).is_ok());
    }

    #[test]
    fn any_state_can_fail() {
        let created = SettlementState::created(1000);
        let submitted = SettlementState::submitted("l1tx".to_string(), 2000, "key".to_string());
        let included = SettlementState::included("l1tx".to_string(), 100, 3000, 3001);
        let failed = SettlementState::failed("error".to_string(), 5000, 0, None);

        assert!(validate_transition(&created, &failed).is_ok());
        assert!(validate_transition(&submitted, &failed).is_ok());
        assert!(validate_transition(&included, &failed).is_ok());
    }

    #[test]
    fn cannot_transition_from_terminal() {
        let finalised = SettlementState::finalised("l1tx".to_string(), 100, 3000, 4000);
        let failed = SettlementState::failed("error".to_string(), 5000, 0, None);
        let created = SettlementState::created(1000);

        let err1 = validate_transition(&finalised, &created).unwrap_err();
        assert!(matches!(
            err1,
            SettlementTransitionError::TerminalState { .. }
        ));

        let err2 = validate_transition(&failed, &created).unwrap_err();
        assert!(matches!(
            err2,
            SettlementTransitionError::TerminalState { .. }
        ));
    }

    #[test]
    fn cannot_go_backwards() {
        let submitted = SettlementState::submitted("l1tx".to_string(), 2000, "key".to_string());
        let created = SettlementState::created(1000);

        let err = validate_transition(&submitted, &created).unwrap_err();
        assert!(matches!(
            err,
            SettlementTransitionError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn cannot_skip_states() {
        let created = SettlementState::created(1000);
        let included = SettlementState::included("l1tx".to_string(), 100, 3000, 3001);
        let finalised = SettlementState::finalised("l1tx".to_string(), 100, 3000, 4000);

        let err1 = validate_transition(&created, &included).unwrap_err();
        assert!(matches!(
            err1,
            SettlementTransitionError::SkippedState { skipped, .. } if skipped == "Submitted"
        ));

        let err2 = validate_transition(&created, &finalised).unwrap_err();
        assert!(matches!(
            err2,
            SettlementTransitionError::SkippedState { .. }
        ));
    }

    #[test]
    fn needs_reconciliation() {
        let created = SettlementState::created(1000);
        let submitted = SettlementState::submitted("l1tx".to_string(), 2000, "key".to_string());
        let included = SettlementState::included("l1tx".to_string(), 100, 3000, 3001);
        let finalised = SettlementState::finalised("l1tx".to_string(), 100, 3000, 4000);
        let failed = SettlementState::failed("error".to_string(), 5000, 0, None);

        assert!(!created.needs_reconciliation());
        assert!(submitted.needs_reconciliation());
        assert!(included.needs_reconciliation());
        assert!(!finalised.needs_reconciliation());
        assert!(!failed.needs_reconciliation());
    }

    #[test]
    fn state_display() {
        let created = SettlementState::created(1000);
        assert!(created.to_string().contains("Created"));

        let submitted = SettlementState::submitted("l1tx123".to_string(), 2000, "key".to_string());
        let s = submitted.to_string();
        assert!(s.contains("Submitted"));
        assert!(s.contains("l1tx123"));
    }

    #[test]
    fn settlement_counts() {
        let mut counts = SettlementStateCounts::default();
        counts.created = 5;
        counts.submitted = 3;
        counts.included = 2;
        counts.finalised = 10;
        counts.failed = 1;

        assert_eq!(counts.total(), 21);
        assert_eq!(counts.in_flight(), 10);
    }
}
