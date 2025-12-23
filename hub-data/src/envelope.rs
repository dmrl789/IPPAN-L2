#![forbid(unsafe_code)]

use crate::actions::DataActionV1;
use crate::canonical::{canonical_json_bytes, CanonicalizeError};
use crate::types::{ActionId, DatasetId, Hex32};
use serde::{Deserialize, Serialize};

/// HUB-DATA action envelope (v1).
///
/// This is the payload that gets wrapped into `HubPayloadEnvelopeV1.payload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataEnvelopeV1 {
    /// L1/L2 contract version string for the DATA payload (not the L1 contract enum).
    pub contract_version: String,
    /// Hub identifier string ("data").
    pub hub_id: String,
    /// HUB-DATA schema version (numeric).
    pub schema_version: u32,
    /// HUB-DATA action schema version (numeric).
    pub action_version: u32,
    pub action: DataActionV1,
    /// Canonical hash of `action` bytes: `blake3(canonical_bytes(action))`.
    pub action_id: ActionId,
    /// Convenience dataset id extracted from action (if present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<DatasetId>,
}

impl DataEnvelopeV1 {
    pub const fn schema_version() -> u32 {
        1
    }

    pub const fn action_version() -> u32 {
        1
    }

    pub fn new(action: DataActionV1) -> Result<Self, CanonicalizeError> {
        let action_bytes = canonical_json_bytes(&action)?;
        let mut id = [0u8; 32];
        id.copy_from_slice(blake3::hash(&action_bytes).as_bytes());
        let dataset_id = dataset_id_from_action(&action);
        Ok(Self {
            contract_version: "v1".to_string(),
            hub_id: "data".to_string(),
            schema_version: Self::schema_version(),
            action_version: Self::action_version(),
            action,
            action_id: Hex32(id),
            dataset_id,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalizeError> {
        canonical_json_bytes(self)
    }
}

fn dataset_id_from_action(a: &DataActionV1) -> Option<DatasetId> {
    match a {
        DataActionV1::RegisterDatasetV1(x) => Some(x.dataset_id),
        DataActionV1::IssueLicenseV1(x) => Some(x.dataset_id),
        DataActionV1::AppendAttestationV1(x) => Some(x.dataset_id),
    }
}
