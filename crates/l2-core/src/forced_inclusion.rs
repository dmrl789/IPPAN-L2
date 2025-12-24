//! Forced Inclusion Types
//!
//! This module provides types for forced transaction inclusion to mitigate
//! leader censorship. Users can submit a forced inclusion request that must
//! be included within a bounded number of epochs.

use serde::{Deserialize, Serialize};

use crate::{canonical_encode, canonical_hash, CanonicalError, Hash32};

/// Status of a forced inclusion ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForcedInclusionStatus {
    /// Ticket is queued, waiting to be included.
    Queued,
    /// Transaction has been included in a batch.
    Included,
    /// Ticket was rejected (invalid or duplicate).
    Rejected,
    /// Ticket expired without being included.
    Expired,
}

/// A forced inclusion ticket.
///
/// This ticket represents a commitment by a node to include a transaction
/// within a bounded number of epochs. The ticket is signed by the issuing node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionTicket {
    /// Hash of the transaction to be included.
    pub tx_hash: Hash32,
    /// Timestamp when the forced request was submitted (ms since epoch).
    pub submitted_at_ms: u64,
    /// Timestamp when this ticket expires (ms since epoch).
    pub expires_at_ms: u64,
    /// Account ID of the requester.
    pub requester: String,
    /// Current status of the ticket.
    pub status: ForcedInclusionStatus,
    /// Epoch index when the ticket was created.
    pub created_epoch: u64,
    /// Maximum epochs before this must be included (from config).
    pub max_epochs: u64,
    /// Node pubkey that issued this ticket (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_pubkey: Option<String>,
    /// Signature over the ticket data (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_sig: Option<String>,
    /// Batch hash where the tx was included (if status == Included).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub included_batch: Option<Hash32>,
}

impl InclusionTicket {
    /// Create a new inclusion ticket.
    pub fn new(
        tx_hash: Hash32,
        requester: String,
        submitted_at_ms: u64,
        epoch_ms: u64,
        max_epochs: u64,
        created_epoch: u64,
    ) -> Self {
        let expires_at_ms = submitted_at_ms.saturating_add(epoch_ms.saturating_mul(max_epochs));
        Self {
            tx_hash,
            submitted_at_ms,
            expires_at_ms,
            requester,
            status: ForcedInclusionStatus::Queued,
            created_epoch,
            max_epochs,
            issuer_pubkey: None,
            issuer_sig: None,
            included_batch: None,
        }
    }

    /// Check if the ticket has expired at a given timestamp.
    pub fn is_expired(&self, current_ms: u64) -> bool {
        current_ms >= self.expires_at_ms
    }

    /// Check if the ticket should be included by a given epoch.
    pub fn must_include_by_epoch(&self) -> u64 {
        self.created_epoch.saturating_add(self.max_epochs)
    }

    /// Mark the ticket as included.
    pub fn mark_included(&mut self, batch_hash: Hash32) {
        self.status = ForcedInclusionStatus::Included;
        self.included_batch = Some(batch_hash);
    }

    /// Mark the ticket as expired.
    pub fn mark_expired(&mut self) {
        self.status = ForcedInclusionStatus::Expired;
    }

    /// Mark the ticket as rejected.
    pub fn mark_rejected(&mut self) {
        self.status = ForcedInclusionStatus::Rejected;
    }

    /// Get the canonical bytes for signing.
    ///
    /// This returns the deterministic encoding of the ticket without
    /// signature fields.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        // Create a signable version without signature fields
        let signable = SignableTicket {
            tx_hash: self.tx_hash,
            submitted_at_ms: self.submitted_at_ms,
            expires_at_ms: self.expires_at_ms,
            requester: self.requester.clone(),
            created_epoch: self.created_epoch,
            max_epochs: self.max_epochs,
        };
        canonical_encode(&signable)
    }

    /// Compute the ticket ID (hash of signing bytes).
    pub fn ticket_id(&self) -> Result<Hash32, CanonicalError> {
        let signable = SignableTicket {
            tx_hash: self.tx_hash,
            submitted_at_ms: self.submitted_at_ms,
            expires_at_ms: self.expires_at_ms,
            requester: self.requester.clone(),
            created_epoch: self.created_epoch,
            max_epochs: self.max_epochs,
        };
        canonical_hash(&signable)
    }
}

/// Internal struct for signing (excludes signature fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignableTicket {
    tx_hash: Hash32,
    submitted_at_ms: u64,
    expires_at_ms: u64,
    requester: String,
    created_epoch: u64,
    max_epochs: u64,
}

/// Request to force include a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForceIncludeRequest {
    /// The transaction to force include.
    pub chain_id: u64,
    /// Sender address/identifier.
    pub from: String,
    /// Transaction nonce.
    pub nonce: u64,
    /// Transaction payload (hex encoded).
    pub payload: String,
    /// Optional signature from requester proving ownership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_sig: Option<String>,
}

/// Response to a force include request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForceIncludeResponse {
    /// Whether the request was accepted.
    pub accepted: bool,
    /// The hash of the transaction.
    pub tx_hash: String,
    /// The inclusion ticket (if accepted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<InclusionTicket>,
    /// Error message (if rejected).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Query response for a forced inclusion ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForceIncludeStatus {
    /// The transaction hash.
    pub tx_hash: String,
    /// Current status.
    pub status: ForcedInclusionStatus,
    /// The full ticket details.
    pub ticket: InclusionTicket,
}

/// Configuration for forced inclusion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForcedInclusionConfig {
    /// Maximum epochs before a forced tx must be included.
    pub max_epochs: u64,
    /// Maximum forced txs per account per epoch.
    pub max_per_account_per_epoch: u64,
    /// Whether to post L1 commitments for forced queue.
    pub post_l1_commitments: bool,
}

impl Default for ForcedInclusionConfig {
    fn default() -> Self {
        Self {
            max_epochs: 3,
            max_per_account_per_epoch: 5,
            post_l1_commitments: false,
        }
    }
}

impl ForcedInclusionConfig {
    /// Create from environment variables.
    pub fn from_env() -> Self {
        let max_epochs = std::env::var("L2_FORCE_INCLUDE_MAX_EPOCHS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);
        let max_per_account_per_epoch = std::env::var("L2_FORCE_MAX_PER_ACCOUNT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        let post_l1_commitments = std::env::var("L2_FORCE_L1_COMMITMENTS")
            .map(|s| s == "1" || s.to_lowercase() == "true")
            .unwrap_or(false);

        Self {
            max_epochs,
            max_per_account_per_epoch,
            post_l1_commitments,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_creation() {
        let tx_hash = Hash32([0xAB; 32]);
        let ticket = InclusionTicket::new(
            tx_hash,
            "alice".to_string(),
            1_000_000,
            10_000, // 10s epochs
            3,      // 3 epochs max
            5,      // created at epoch 5
        );

        assert_eq!(ticket.status, ForcedInclusionStatus::Queued);
        assert_eq!(ticket.expires_at_ms, 1_030_000);
        assert_eq!(ticket.must_include_by_epoch(), 8);
    }

    #[test]
    fn ticket_expiration() {
        let tx_hash = Hash32([0xAB; 32]);
        let ticket = InclusionTicket::new(tx_hash, "alice".to_string(), 1_000_000, 10_000, 3, 5);

        assert!(!ticket.is_expired(1_000_000));
        assert!(!ticket.is_expired(1_029_999));
        assert!(ticket.is_expired(1_030_000));
        assert!(ticket.is_expired(1_100_000));
    }

    #[test]
    fn ticket_mark_included() {
        let tx_hash = Hash32([0xAB; 32]);
        let mut ticket =
            InclusionTicket::new(tx_hash, "alice".to_string(), 1_000_000, 10_000, 3, 5);

        let batch_hash = Hash32([0xCD; 32]);
        ticket.mark_included(batch_hash);

        assert_eq!(ticket.status, ForcedInclusionStatus::Included);
        assert_eq!(ticket.included_batch, Some(batch_hash));
    }

    #[test]
    fn ticket_signing_bytes_deterministic() {
        let tx_hash = Hash32([0xAB; 32]);
        let ticket1 =
            InclusionTicket::new(tx_hash, "alice".to_string(), 1_000_000, 10_000, 3, 5);
        let ticket2 =
            InclusionTicket::new(tx_hash, "alice".to_string(), 1_000_000, 10_000, 3, 5);

        let bytes1 = ticket1.signing_bytes().unwrap();
        let bytes2 = ticket2.signing_bytes().unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn ticket_id_deterministic() {
        let tx_hash = Hash32([0xAB; 32]);
        let ticket1 =
            InclusionTicket::new(tx_hash, "alice".to_string(), 1_000_000, 10_000, 3, 5);
        let ticket2 =
            InclusionTicket::new(tx_hash, "alice".to_string(), 1_000_000, 10_000, 3, 5);

        let id1 = ticket1.ticket_id().unwrap();
        let id2 = ticket2.ticket_id().unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn forced_inclusion_config_defaults() {
        let config = ForcedInclusionConfig::default();
        assert_eq!(config.max_epochs, 3);
        assert_eq!(config.max_per_account_per_epoch, 5);
        assert!(!config.post_l1_commitments);
    }
}
