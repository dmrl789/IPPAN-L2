#![forbid(unsafe_code)]

use crate::actions::FinActionV1;
use crate::canonical::{canonical_json_bytes, CanonicalizeError};
use crate::types::{ActionId, Hex32};
use serde::{Deserialize, Serialize};

/// FIN action envelope (v1).
///
/// This is the payload that gets wrapped into `HubPayloadEnvelopeV1.payload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinEnvelopeV1 {
    /// L1/L2 contract version string for the FIN payload (not the L1 contract enum).
    pub contract_version: String,
    /// Hub identifier string ("fin").
    pub hub_id: String,
    /// FIN schema version (numeric).
    pub schema_version: u32,
    /// FIN action schema version (numeric).
    pub action_version: u32,
    pub action: FinActionV1,
    /// Canonical hash of `action` bytes: `blake3(canonical_bytes(action))`.
    pub action_id: ActionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

impl FinEnvelopeV1 {
    pub const fn schema_version() -> u32 {
        1
    }

    pub const fn action_version() -> u32 {
        1
    }

    pub fn new(action: FinActionV1) -> Result<Self, CanonicalizeError> {
        let action_bytes = canonical_json_bytes(&action)?;
        let mut id = [0u8; 32];
        id.copy_from_slice(blake3::hash(&action_bytes).as_bytes());
        Ok(Self {
            contract_version: "v1".to_string(),
            hub_id: "fin".to_string(),
            schema_version: Self::schema_version(),
            action_version: Self::action_version(),
            action,
            action_id: Hex32(id),
            created_at: None,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalizeError> {
        canonical_json_bytes(self)
    }
}
