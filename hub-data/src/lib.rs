#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::disallowed_types)]

//! IPPAN DATA – Data & AI Hub (MVP v1)
//!
//! This crate implements a minimal, deterministic HUB-DATA:
//! - Exactly three actions: REGISTER_DATASET, ISSUE_LICENSE, APPEND_ATTESTATION
//! - Canonical encoding + stable hashes (BLAKE3)
//! - Deterministic state transitions with sled-backed storage
//! - Hub never calls L1; it only emits `HubPayloadEnvelopeV1` payload bytes

pub mod actions;
pub mod apply;
pub mod canonical;
pub mod envelope;
pub mod store;
pub mod types;
pub mod validation;

pub use actions::{
    AddAttestorRequestV1, AddAttestorV1, AddLicensorRequestV1, AddLicensorV1,
    AppendAttestationRequestV1, AppendAttestationV1, AttestationPolicyV1, CreateListingRequestV1,
    CreateListingV1, DataActionRequestV1, DataActionV1, GrantEntitlementRequestV1,
    GrantEntitlementV1, IssueLicenseRequestV1, IssueLicenseV1, LicenseRightsV1,
    RegisterDatasetRequestV1, RegisterDatasetV1,
};
pub use apply::{apply, apply_with_policy, ApplyOutcome, ApplyReceipt};
pub use envelope::DataEnvelopeV1;
pub use store::{DataStateSnapshotV1, DataStore, DatasetSnapshotV1};
pub use types::{
    ActionId, AttestationId, DatasetId, Hex32, LicenseId, ListingId, PriceMicrounitsU128,
};

use l2_core::l1_contract::{Base64Bytes, ContractVersion, HubPayloadEnvelopeV1};
use l2_core::L2HubId;

/// Logical identifier for the DATA hub.
pub const HUB_ID: L2HubId = L2HubId::Data;

/// Hub payload schema for DATA envelopes.
pub const DATA_HUB_PAYLOAD_SCHEMA_V1: &str = "hub-data.envelope.v1";

/// MIME-ish content type for DATA payload bytes.
pub const DATA_HUB_PAYLOAD_CONTENT_TYPE_V1: &str = "application/ippan.hub-data.v1";

/// Convert a DATA envelope into an L1-submittable hub payload envelope (v1).
///
/// `payload` bytes are the canonical JSON bytes of `DataEnvelopeV1`.
impl From<&DataEnvelopeV1> for HubPayloadEnvelopeV1 {
    fn from(env: &DataEnvelopeV1) -> Self {
        let payload_bytes = env
            .canonical_bytes()
            .expect("DataEnvelopeV1 canonicalization is infallible for valid serde values");
        HubPayloadEnvelopeV1 {
            contract_version: ContractVersion::V1,
            hub: HUB_ID,
            schema_version: DATA_HUB_PAYLOAD_SCHEMA_V1.to_string(),
            content_type: DATA_HUB_PAYLOAD_CONTENT_TYPE_V1.to_string(),
            payload: Base64Bytes(payload_bytes),
        }
    }
}
