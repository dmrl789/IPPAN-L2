//! Persistent Intent State Machine for Cross-Hub Operations.
//!
//! This module provides crash-safe, persistent storage for cross-hub intents
//! with monotonic state transitions and per-hub indexing.
//!
//! ## State Transitions
//!
//! ```text
//! Created -> Prepared -> Committed
//!    |          |
//!    +----------+---> Aborted
//! ```
//!
//! State transitions are **monotonic**: once an intent reaches a terminal state
//! (Committed or Aborted), it cannot transition to any other state.
//!
//! ## Idempotency
//!
//! All state updates are idempotent - replaying the same transition has no effect.
//! This ensures crash safety and allows deterministic replay.

use l2_core::{canonical_decode, canonical_encode, Hash32, IntentId, L2HubId};
use serde::{Deserialize, Serialize};
use sled::Tree;
use std::fmt;
use thiserror::Error;

/// Persistent state of an intent in the 2PC protocol.
///
/// Unlike the `IntentPhase` enum in l2-core which represents phases,
/// this enum contains the full state including timestamps and receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentState {
    /// Intent has been created and stored.
    Created {
        /// Timestamp when intent was created (ms since epoch).
        created_ms: u64,
        /// Expiry timestamp (ms since epoch).
        expires_ms: u64,
        /// Source hub.
        from_hub: L2HubId,
        /// Destination hub.
        to_hub: L2HubId,
    },

    /// Intent has been prepared (locks acquired).
    Prepared {
        /// Timestamp when prepare was completed (ms since epoch).
        prepared_ms: u64,
        /// Hashes of the prepare receipts from each hub.
        prep_receipts: Vec<Hash32>,
    },

    /// Intent has been committed (finalized).
    Committed {
        /// Timestamp when commit was completed (ms since epoch).
        committed_ms: u64,
        /// Hashes of the commit receipts from each hub.
        commit_receipts: Vec<Hash32>,
    },

    /// Intent has been aborted (rolled back).
    Aborted {
        /// Timestamp when abort was executed (ms since epoch).
        aborted_ms: u64,
        /// Human-readable reason for abort.
        reason: String,
    },
}

impl IntentState {
    // ========== Constructors ==========

    /// Create a new `Created` state.
    pub fn created(created_ms: u64, expires_ms: u64, from_hub: L2HubId, to_hub: L2HubId) -> Self {
        Self::Created {
            created_ms,
            expires_ms,
            from_hub,
            to_hub,
        }
    }

    /// Create a new `Prepared` state.
    pub fn prepared(prepared_ms: u64, prep_receipts: Vec<Hash32>) -> Self {
        Self::Prepared {
            prepared_ms,
            prep_receipts,
        }
    }

    /// Create a new `Committed` state.
    pub fn committed(committed_ms: u64, commit_receipts: Vec<Hash32>) -> Self {
        Self::Committed {
            committed_ms,
            commit_receipts,
        }
    }

    /// Create a new `Aborted` state.
    pub fn aborted(aborted_ms: u64, reason: String) -> Self {
        Self::Aborted { aborted_ms, reason }
    }

    // ========== State Queries ==========

    /// Check if this is a terminal state (Committed or Aborted).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Committed { .. } | Self::Aborted { .. })
    }

    /// Check if this intent is in Created state.
    pub fn is_created(&self) -> bool {
        matches!(self, Self::Created { .. })
    }

    /// Check if this intent is in Prepared state.
    pub fn is_prepared(&self) -> bool {
        matches!(self, Self::Prepared { .. })
    }

    /// Check if this intent is committed.
    pub fn is_committed(&self) -> bool {
        matches!(self, Self::Committed { .. })
    }

    /// Check if this intent is aborted.
    pub fn is_aborted(&self) -> bool {
        matches!(self, Self::Aborted { .. })
    }

    /// Get the ordinal value for state ordering (used in monotonic checks).
    fn ordinal(&self) -> u8 {
        match self {
            Self::Created { .. } => 0,
            Self::Prepared { .. } => 1,
            Self::Committed { .. } => 2,
            Self::Aborted { .. } => 3,
        }
    }

    /// Get a short name for the state.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Created { .. } => "created",
            Self::Prepared { .. } => "prepared",
            Self::Committed { .. } => "committed",
            Self::Aborted { .. } => "aborted",
        }
    }

    /// Get the from_hub if in Created state.
    pub fn from_hub(&self) -> Option<L2HubId> {
        match self {
            Self::Created { from_hub, .. } => Some(*from_hub),
            _ => None,
        }
    }

    /// Get the to_hub if in Created state.
    pub fn to_hub(&self) -> Option<L2HubId> {
        match self {
            Self::Created { to_hub, .. } => Some(*to_hub),
            _ => None,
        }
    }

    /// Get the expires_ms if in Created state.
    pub fn expires_ms(&self) -> Option<u64> {
        match self {
            Self::Created { expires_ms, .. } => Some(*expires_ms),
            _ => None,
        }
    }

    /// Check if the intent has expired.
    pub fn is_expired(&self, current_ms: u64) -> bool {
        match self {
            Self::Created { expires_ms, .. } => current_ms >= *expires_ms,
            _ => false, // Only Created intents can expire
        }
    }
}

impl fmt::Display for IntentState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created {
                created_ms,
                expires_ms,
                from_hub,
                to_hub,
            } => {
                write!(
                    f,
                    "Created(at={}, expires={}, {}->{})",
                    created_ms, expires_ms, from_hub, to_hub
                )
            }
            Self::Prepared {
                prepared_ms,
                prep_receipts,
            } => {
                write!(
                    f,
                    "Prepared(at={}, receipts={})",
                    prepared_ms,
                    prep_receipts.len()
                )
            }
            Self::Committed {
                committed_ms,
                commit_receipts,
            } => {
                write!(
                    f,
                    "Committed(at={}, receipts={})",
                    committed_ms,
                    commit_receipts.len()
                )
            }
            Self::Aborted { aborted_ms, reason } => {
                write!(f, "Aborted(at={}, reason={})", aborted_ms, reason)
            }
        }
    }
}

/// Error type for invalid intent state transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentTransitionError {
    /// Cannot transition from a terminal state.
    TerminalState { from: String, to: String },
    /// Invalid state transition (non-monotonic).
    InvalidTransition {
        from: String,
        to: String,
        reason: String,
    },
    /// Cannot skip states in the intent lifecycle.
    SkippedState {
        from: String,
        to: String,
        skipped: String,
    },
    /// Idempotent transition (same state).
    Idempotent { state: String },
}

impl fmt::Display for IntentTransitionError {
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
            Self::Idempotent { state } => {
                write!(f, "idempotent transition to same state: {}", state)
            }
        }
    }
}

impl std::error::Error for IntentTransitionError {}

/// Validate an intent state transition.
///
/// Returns `Ok(())` if the transition is valid, `Err(Idempotent)` if it's a no-op,
/// or another error if the transition is invalid.
///
/// # Rules
///
/// 1. Terminal states (Committed, Aborted) cannot transition to any state.
/// 2. States must progress in order: Created -> Prepared -> Committed.
/// 3. Created and Prepared can transition to Aborted.
/// 4. Cannot skip states (e.g., Created cannot go directly to Committed).
pub fn validate_intent_transition(
    from: &IntentState,
    to: &IntentState,
) -> Result<(), IntentTransitionError> {
    // Check for idempotent transition (same state type)
    if from.ordinal() == to.ordinal() {
        return Err(IntentTransitionError::Idempotent {
            state: from.name().to_string(),
        });
    }

    // Rule 1: Cannot transition from terminal states
    if from.is_terminal() {
        return Err(IntentTransitionError::TerminalState {
            from: from.name().to_string(),
            to: to.name().to_string(),
        });
    }

    // Rule 3: Any non-terminal state can transition to Aborted
    if to.is_aborted() {
        return Ok(());
    }

    // Rule 2 & 4: Check monotonic progression
    let from_ord = from.ordinal();
    let to_ord = to.ordinal();

    // Cannot go backwards
    if to_ord < from_ord {
        return Err(IntentTransitionError::InvalidTransition {
            from: from.name().to_string(),
            to: to.name().to_string(),
            reason: "cannot go backwards in intent lifecycle".to_string(),
        });
    }

    // Cannot skip states (must increment by exactly 1 for non-abort transitions)
    if to_ord > from_ord + 1 && !to.is_aborted() {
        let skipped = match from_ord + 1 {
            1 => "Prepared",
            2 => "Committed",
            _ => "unknown",
        };
        return Err(IntentTransitionError::SkippedState {
            from: from.name().to_string(),
            to: to.name().to_string(),
            skipped: skipped.to_string(),
        });
    }

    Ok(())
}

/// Entry in the intent state index for listing.
#[derive(Debug, Clone)]
pub struct IntentStateEntry {
    /// The intent ID.
    pub intent_id: IntentId,
    /// The current intent state.
    pub state: IntentState,
}

/// Counts of intents by state.
#[derive(Debug, Clone, Default)]
pub struct IntentStateCounts {
    pub created: u64,
    pub prepared: u64,
    pub committed: u64,
    pub aborted: u64,
}

impl IntentStateCounts {
    /// Total number of intents tracked.
    pub fn total(&self) -> u64 {
        self.created
            .saturating_add(self.prepared)
            .saturating_add(self.committed)
            .saturating_add(self.aborted)
    }

    /// Number of pending intents (not terminal).
    pub fn pending(&self) -> u64 {
        self.created.saturating_add(self.prepared)
    }
}

/// Storage error types.
#[derive(Debug, Error)]
pub enum IntentStorageError {
    #[error("storage error: {0}")]
    Sled(#[from] sled::Error),
    #[error("canonical encoding error: {0}")]
    Canonical(#[from] l2_core::CanonicalError),
    #[error("invalid transition: {0}")]
    InvalidTransition(#[from] IntentTransitionError),
    #[error("intent not found: {0}")]
    NotFound(String),
}

/// Persistent storage for cross-hub intents.
///
/// Provides crash-safe storage with monotonic state transitions and per-hub indexing.
pub struct IntentStorage {
    /// Main intent state tree (intent_id_hex -> IntentState).
    intents: Tree,
    /// Per-hub index for from_hub (hub:intent_id_hex -> "").
    from_hub_index: Tree,
    /// Per-hub index for to_hub (hub:intent_id_hex -> "").
    to_hub_index: Tree,
    /// State index (state:intent_id_hex -> "").
    state_index: Tree,
}

impl IntentStorage {
    /// Create a new IntentStorage from a sled database.
    pub fn new(db: &sled::Db) -> Result<Self, IntentStorageError> {
        Ok(Self {
            intents: db.open_tree("intents")?,
            from_hub_index: db.open_tree("intents_from_hub")?,
            to_hub_index: db.open_tree("intents_to_hub")?,
            state_index: db.open_tree("intents_state")?,
        })
    }

    /// Store a new intent (must be in Created state).
    pub fn create(
        &self,
        intent_id: &IntentId,
        state: &IntentState,
    ) -> Result<(), IntentStorageError> {
        let key = intent_id.to_hex();

        // Must be a new intent
        if self.intents.contains_key(key.as_bytes())? {
            return Err(IntentStorageError::InvalidTransition(
                IntentTransitionError::Idempotent {
                    state: "already exists".to_string(),
                },
            ));
        }

        // Must be in Created state
        if !state.is_created() {
            return Err(IntentStorageError::InvalidTransition(
                IntentTransitionError::InvalidTransition {
                    from: "none".to_string(),
                    to: state.name().to_string(),
                    reason: "new intents must be in Created state".to_string(),
                },
            ));
        }

        // Store the intent
        let bytes = canonical_encode(state)?;
        self.intents.insert(key.as_bytes(), bytes)?;

        // Update indexes
        self.update_indexes(intent_id, None, state)?;

        Ok(())
    }

    /// Get the current state of an intent.
    pub fn get(&self, intent_id: &IntentId) -> Result<Option<IntentState>, IntentStorageError> {
        let key = intent_id.to_hex();
        match self.intents.get(key.as_bytes())? {
            Some(bytes) => Ok(Some(canonical_decode(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Update an intent's state with validation.
    ///
    /// Returns `Ok(())` if the transition is valid.
    /// Returns `Err(Idempotent)` if the state is unchanged (safe to ignore).
    pub fn update(
        &self,
        intent_id: &IntentId,
        new_state: &IntentState,
    ) -> Result<(), IntentStorageError> {
        let key = intent_id.to_hex();

        // Get current state
        let current = self
            .get(intent_id)?
            .ok_or_else(|| IntentStorageError::NotFound(intent_id.to_hex()))?;

        // Validate transition
        validate_intent_transition(&current, new_state)?;

        // Store the new state
        let bytes = canonical_encode(new_state)?;
        self.intents.insert(key.as_bytes(), bytes)?;

        // Update indexes
        self.update_indexes(intent_id, Some(&current), new_state)?;

        Ok(())
    }

    /// Force-set an intent's state without validation.
    ///
    /// Use only for crash recovery or tests. Normal code should use `update`.
    pub fn set_unchecked(
        &self,
        intent_id: &IntentId,
        state: &IntentState,
    ) -> Result<(), IntentStorageError> {
        let key = intent_id.to_hex();
        let old_state = self.get(intent_id)?;
        let bytes = canonical_encode(state)?;
        self.intents.insert(key.as_bytes(), bytes)?;
        self.update_indexes(intent_id, old_state.as_ref(), state)?;
        Ok(())
    }

    /// Delete an intent (use only for cleanup/tests).
    pub fn delete(&self, intent_id: &IntentId) -> Result<bool, IntentStorageError> {
        let key = intent_id.to_hex();

        // Get current state for index cleanup
        if let Some(state) = self.get(intent_id)? {
            // Remove from indexes
            self.remove_from_indexes(intent_id, &state)?;
        }

        let existed = self.intents.remove(key.as_bytes())?.is_some();
        Ok(existed)
    }

    /// List intents in Created state.
    pub fn list_created(&self, limit: usize) -> Result<Vec<IntentStateEntry>, IntentStorageError> {
        self.list_by_state("created", limit)
    }

    /// List intents in Prepared state.
    pub fn list_prepared(&self, limit: usize) -> Result<Vec<IntentStateEntry>, IntentStorageError> {
        self.list_by_state("prepared", limit)
    }

    /// List intents in Committed state.
    pub fn list_committed(
        &self,
        limit: usize,
    ) -> Result<Vec<IntentStateEntry>, IntentStorageError> {
        self.list_by_state("committed", limit)
    }

    /// List intents in Aborted state.
    pub fn list_aborted(&self, limit: usize) -> Result<Vec<IntentStateEntry>, IntentStorageError> {
        self.list_by_state("aborted", limit)
    }

    /// List pending intents (Created or Prepared).
    pub fn list_pending(&self, limit: usize) -> Result<Vec<IntentStateEntry>, IntentStorageError> {
        let mut entries = Vec::new();
        entries.extend(self.list_created(limit)?);
        if entries.len() < limit {
            entries.extend(self.list_prepared(limit - entries.len())?);
        }
        Ok(entries)
    }

    /// List intents for a specific from_hub.
    pub fn list_by_from_hub(
        &self,
        hub: L2HubId,
        limit: usize,
    ) -> Result<Vec<IntentStateEntry>, IntentStorageError> {
        let prefix = format!("{}:", hub.as_str());
        self.list_by_index_prefix(&self.from_hub_index, &prefix, limit)
    }

    /// List intents for a specific to_hub.
    pub fn list_by_to_hub(
        &self,
        hub: L2HubId,
        limit: usize,
    ) -> Result<Vec<IntentStateEntry>, IntentStorageError> {
        let prefix = format!("{}:", hub.as_str());
        self.list_by_index_prefix(&self.to_hub_index, &prefix, limit)
    }

    /// List pending intents for a specific hub (either from or to).
    pub fn list_pending_for_hub(
        &self,
        hub: L2HubId,
        limit: usize,
    ) -> Result<Vec<IntentStateEntry>, IntentStorageError> {
        let mut entries = Vec::new();

        // Get from_hub intents
        for entry in self.list_by_from_hub(hub, limit)? {
            if !entry.state.is_terminal() {
                entries.push(entry);
            }
        }

        // Get to_hub intents
        if entries.len() < limit {
            for entry in self.list_by_to_hub(hub, limit - entries.len())? {
                if !entry.state.is_terminal() {
                    // Avoid duplicates if hub == hub
                    let id_hex = entry.intent_id.to_hex();
                    if !entries.iter().any(|e| e.intent_id.to_hex() == id_hex) {
                        entries.push(entry);
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Count intents by state.
    pub fn count_states(&self) -> Result<IntentStateCounts, IntentStorageError> {
        let mut counts = IntentStateCounts::default();
        for result in self.intents.iter() {
            let (_key, value) = result?;
            let state: IntentState = canonical_decode(&value)?;
            match state {
                IntentState::Created { .. } => counts.created += 1,
                IntentState::Prepared { .. } => counts.prepared += 1,
                IntentState::Committed { .. } => counts.committed += 1,
                IntentState::Aborted { .. } => counts.aborted += 1,
            }
        }
        Ok(counts)
    }

    /// Count pending intents by hub.
    pub fn count_pending_by_hub(&self, hub: L2HubId) -> Result<u64, IntentStorageError> {
        let entries = self.list_pending_for_hub(hub, usize::MAX)?;
        Ok(u64::try_from(entries.len()).unwrap_or(u64::MAX))
    }

    /// List expired intents (in Created state past their expires_ms).
    pub fn list_expired(
        &self,
        current_ms: u64,
        limit: usize,
    ) -> Result<Vec<IntentStateEntry>, IntentStorageError> {
        let mut entries = Vec::new();
        for result in self.intents.iter() {
            if entries.len() >= limit {
                break;
            }
            let (key, value) = result?;
            let state: IntentState = canonical_decode(&value)?;
            if state.is_expired(current_ms) {
                let id_hex = String::from_utf8_lossy(&key).to_string();
                if let Ok(intent_id) = IntentId::from_hex(&id_hex) {
                    entries.push(IntentStateEntry { intent_id, state });
                }
            }
        }
        Ok(entries)
    }

    // ========== Internal helpers ==========

    fn list_by_state(
        &self,
        state_name: &str,
        limit: usize,
    ) -> Result<Vec<IntentStateEntry>, IntentStorageError> {
        let prefix = format!("{}:", state_name);
        self.list_by_index_prefix(&self.state_index, &prefix, limit)
    }

    fn list_by_index_prefix(
        &self,
        index: &Tree,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<IntentStateEntry>, IntentStorageError> {
        let mut entries = Vec::new();
        for result in index.scan_prefix(prefix.as_bytes()) {
            if entries.len() >= limit {
                break;
            }
            let (key, _value) = result?;
            let key_str = String::from_utf8_lossy(&key);
            // Key format is "state:intent_id_hex" or "hub:intent_id_hex"
            if let Some(id_hex) = key_str.split(':').nth(1) {
                if let Ok(intent_id) = IntentId::from_hex(id_hex) {
                    if let Some(state) = self.get(&intent_id)? {
                        entries.push(IntentStateEntry { intent_id, state });
                    }
                }
            }
        }
        Ok(entries)
    }

    fn update_indexes(
        &self,
        intent_id: &IntentId,
        old_state: Option<&IntentState>,
        new_state: &IntentState,
    ) -> Result<(), IntentStorageError> {
        let id_hex = intent_id.to_hex();

        // Remove old index entries
        if let Some(old) = old_state {
            self.remove_from_indexes(intent_id, old)?;
        }

        // Add new state index
        let state_key = format!("{}:{}", new_state.name(), id_hex);
        self.state_index.insert(state_key.as_bytes(), &[])?;

        // Add hub indexes (only for Created state which has hub info)
        if let IntentState::Created {
            from_hub, to_hub, ..
        } = new_state
        {
            let from_key = format!("{}:{}", from_hub.as_str(), id_hex);
            let to_key = format!("{}:{}", to_hub.as_str(), id_hex);
            self.from_hub_index.insert(from_key.as_bytes(), &[])?;
            self.to_hub_index.insert(to_key.as_bytes(), &[])?;
        }

        Ok(())
    }

    fn remove_from_indexes(
        &self,
        intent_id: &IntentId,
        state: &IntentState,
    ) -> Result<(), IntentStorageError> {
        let id_hex = intent_id.to_hex();

        // Remove state index
        let state_key = format!("{}:{}", state.name(), id_hex);
        self.state_index.remove(state_key.as_bytes())?;

        // Remove hub indexes (only for Created state)
        if let IntentState::Created {
            from_hub, to_hub, ..
        } = state
        {
            let from_key = format!("{}:{}", from_hub.as_str(), id_hex);
            let to_key = format!("{}:{}", to_hub.as_str(), id_hex);
            self.from_hub_index.remove(from_key.as_bytes())?;
            self.to_hub_index.remove(to_key.as_bytes())?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_db() -> sled::Db {
        let dir = tempdir().expect("tmpdir");
        sled::open(dir.path()).expect("open")
    }

    fn test_intent_id(n: u8) -> IntentId {
        IntentId(Hash32([n; 32]))
    }

    // ========== State Constructor Tests ==========

    #[test]
    fn state_constructors() {
        let created = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);
        assert!(created.is_created());
        assert!(!created.is_terminal());
        assert_eq!(created.from_hub(), Some(L2HubId::Fin));
        assert_eq!(created.to_hub(), Some(L2HubId::World));
        assert_eq!(created.expires_ms(), Some(2000));

        let prepared = IntentState::prepared(1500, vec![Hash32([0xAA; 32])]);
        assert!(prepared.is_prepared());
        assert!(!prepared.is_terminal());

        let committed = IntentState::committed(2000, vec![Hash32([0xBB; 32])]);
        assert!(committed.is_committed());
        assert!(committed.is_terminal());

        let aborted = IntentState::aborted(1800, "expired".to_string());
        assert!(aborted.is_aborted());
        assert!(aborted.is_terminal());
    }

    // ========== Transition Validation Tests ==========

    #[test]
    fn valid_forward_transitions() {
        let created = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);
        let prepared = IntentState::prepared(1500, vec![Hash32([0xAA; 32])]);
        let committed = IntentState::committed(2000, vec![Hash32([0xBB; 32])]);

        assert!(validate_intent_transition(&created, &prepared).is_ok());
        assert!(validate_intent_transition(&prepared, &committed).is_ok());
    }

    #[test]
    fn any_state_can_abort() {
        let created = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);
        let prepared = IntentState::prepared(1500, vec![]);
        let aborted = IntentState::aborted(1800, "cancelled".to_string());

        assert!(validate_intent_transition(&created, &aborted).is_ok());
        assert!(validate_intent_transition(&prepared, &aborted).is_ok());
    }

    #[test]
    fn cannot_transition_from_terminal() {
        let committed = IntentState::committed(2000, vec![]);
        let aborted = IntentState::aborted(1800, "cancelled".to_string());
        let created = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);

        let err1 = validate_intent_transition(&committed, &created).unwrap_err();
        assert!(matches!(err1, IntentTransitionError::TerminalState { .. }));

        let err2 = validate_intent_transition(&aborted, &created).unwrap_err();
        assert!(matches!(err2, IntentTransitionError::TerminalState { .. }));
    }

    #[test]
    fn cannot_go_backwards() {
        let prepared = IntentState::prepared(1500, vec![]);
        let created = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);

        let err = validate_intent_transition(&prepared, &created).unwrap_err();
        assert!(matches!(
            err,
            IntentTransitionError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn cannot_skip_states() {
        let created = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);
        let committed = IntentState::committed(2000, vec![]);

        let err = validate_intent_transition(&created, &committed).unwrap_err();
        assert!(matches!(
            err,
            IntentTransitionError::SkippedState { skipped, .. } if skipped == "Prepared"
        ));
    }

    #[test]
    fn idempotent_transition_detected() {
        let created1 = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);
        let created2 = IntentState::created(1001, 2001, L2HubId::Data, L2HubId::M2m);

        let err = validate_intent_transition(&created1, &created2).unwrap_err();
        assert!(matches!(err, IntentTransitionError::Idempotent { .. }));
    }

    // ========== Storage Tests ==========

    #[test]
    fn create_and_get_intent() {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();

        let intent_id = test_intent_id(1);
        let state = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);

        storage.create(&intent_id, &state).unwrap();

        let loaded = storage.get(&intent_id).unwrap().unwrap();
        assert_eq!(loaded, state);
    }

    #[test]
    fn cannot_create_duplicate() {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();

        let intent_id = test_intent_id(1);
        let state = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);

        storage.create(&intent_id, &state).unwrap();

        let result = storage.create(&intent_id, &state);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_create_non_created_state() {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();

        let intent_id = test_intent_id(1);
        let state = IntentState::prepared(1500, vec![]);

        let result = storage.create(&intent_id, &state);
        assert!(result.is_err());
    }

    #[test]
    fn update_intent_state() {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();

        let intent_id = test_intent_id(1);
        let created = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);
        let prepared = IntentState::prepared(1500, vec![Hash32([0xAA; 32])]);

        storage.create(&intent_id, &created).unwrap();
        storage.update(&intent_id, &prepared).unwrap();

        let loaded = storage.get(&intent_id).unwrap().unwrap();
        assert!(loaded.is_prepared());
    }

    #[test]
    fn full_lifecycle_commit() {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();

        let intent_id = test_intent_id(1);
        let created = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);
        let prepared = IntentState::prepared(1500, vec![Hash32([0xAA; 32])]);
        let committed = IntentState::committed(2000, vec![Hash32([0xBB; 32])]);

        storage.create(&intent_id, &created).unwrap();
        storage.update(&intent_id, &prepared).unwrap();
        storage.update(&intent_id, &committed).unwrap();

        let loaded = storage.get(&intent_id).unwrap().unwrap();
        assert!(loaded.is_committed());
        assert!(loaded.is_terminal());
    }

    #[test]
    fn full_lifecycle_abort() {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();

        let intent_id = test_intent_id(1);
        let created = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);
        let aborted = IntentState::aborted(1500, "cancelled by user".to_string());

        storage.create(&intent_id, &created).unwrap();
        storage.update(&intent_id, &aborted).unwrap();

        let loaded = storage.get(&intent_id).unwrap().unwrap();
        assert!(loaded.is_aborted());
    }

    #[test]
    fn cannot_commit_from_created() {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();

        let intent_id = test_intent_id(1);
        let created = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);
        let committed = IntentState::committed(2000, vec![]);

        storage.create(&intent_id, &created).unwrap();
        let result = storage.update(&intent_id, &committed);
        assert!(result.is_err());
    }

    #[test]
    fn list_by_state() {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();

        // Create multiple intents in different states
        let id1 = test_intent_id(1);
        let id2 = test_intent_id(2);
        let id3 = test_intent_id(3);

        storage
            .create(
                &id1,
                &IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World),
            )
            .unwrap();
        storage
            .create(
                &id2,
                &IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::Data),
            )
            .unwrap();
        storage
            .create(
                &id3,
                &IntentState::created(1000, 2000, L2HubId::Data, L2HubId::World),
            )
            .unwrap();

        // Move id2 to prepared
        storage
            .update(&id2, &IntentState::prepared(1500, vec![]))
            .unwrap();

        // Move id3 to committed
        storage
            .update(&id3, &IntentState::prepared(1500, vec![]))
            .unwrap();
        storage
            .update(&id3, &IntentState::committed(2000, vec![]))
            .unwrap();

        let created = storage.list_created(10).unwrap();
        assert_eq!(created.len(), 1);

        let prepared = storage.list_prepared(10).unwrap();
        assert_eq!(prepared.len(), 1);

        let committed = storage.list_committed(10).unwrap();
        assert_eq!(committed.len(), 1);

        let pending = storage.list_pending(10).unwrap();
        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn list_by_hub() {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();

        let id1 = test_intent_id(1);
        let id2 = test_intent_id(2);

        storage
            .create(
                &id1,
                &IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World),
            )
            .unwrap();
        storage
            .create(
                &id2,
                &IntentState::created(1000, 2000, L2HubId::Data, L2HubId::World),
            )
            .unwrap();

        let from_fin = storage.list_by_from_hub(L2HubId::Fin, 10).unwrap();
        assert_eq!(from_fin.len(), 1);

        let to_world = storage.list_by_to_hub(L2HubId::World, 10).unwrap();
        assert_eq!(to_world.len(), 2);
    }

    #[test]
    fn count_states() {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();

        for i in 0u8..5 {
            let id = test_intent_id(i);
            storage
                .create(
                    &id,
                    &IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World),
                )
                .unwrap();
        }

        // Move some to prepared
        storage
            .update(&test_intent_id(0), &IntentState::prepared(1500, vec![]))
            .unwrap();
        storage
            .update(&test_intent_id(1), &IntentState::prepared(1500, vec![]))
            .unwrap();

        // Commit one
        storage
            .update(&test_intent_id(0), &IntentState::committed(2000, vec![]))
            .unwrap();

        // Abort one
        storage
            .update(
                &test_intent_id(2),
                &IntentState::aborted(1800, "test".to_string()),
            )
            .unwrap();

        let counts = storage.count_states().unwrap();
        assert_eq!(counts.created, 2);
        assert_eq!(counts.prepared, 1);
        assert_eq!(counts.committed, 1);
        assert_eq!(counts.aborted, 1);
        assert_eq!(counts.total(), 5);
        assert_eq!(counts.pending(), 3);
    }

    #[test]
    fn list_expired() {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();

        let id1 = test_intent_id(1);
        let id2 = test_intent_id(2);

        // Expired
        storage
            .create(
                &id1,
                &IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World),
            )
            .unwrap();

        // Not expired
        storage
            .create(
                &id2,
                &IntentState::created(1000, 5000, L2HubId::Fin, L2HubId::World),
            )
            .unwrap();

        let expired = storage.list_expired(3000, 10).unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].intent_id, id1);
    }

    #[test]
    fn delete_intent() {
        let db = test_db();
        let storage = IntentStorage::new(&db).unwrap();

        let intent_id = test_intent_id(1);
        let state = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);

        storage.create(&intent_id, &state).unwrap();
        assert!(storage.get(&intent_id).unwrap().is_some());

        let deleted = storage.delete(&intent_id).unwrap();
        assert!(deleted);
        assert!(storage.get(&intent_id).unwrap().is_none());

        // Deleting again returns false
        let deleted_again = storage.delete(&intent_id).unwrap();
        assert!(!deleted_again);
    }

    #[test]
    fn is_expired() {
        let created = IntentState::created(1000, 2000, L2HubId::Fin, L2HubId::World);
        let prepared = IntentState::prepared(1500, vec![]);

        assert!(!created.is_expired(1500));
        assert!(created.is_expired(2000));
        assert!(created.is_expired(3000));

        // Prepared intents don't expire
        assert!(!prepared.is_expired(3000));
    }
}
