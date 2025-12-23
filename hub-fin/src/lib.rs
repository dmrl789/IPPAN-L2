#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::disallowed_types)]

//! IPPAN FIN – Finance Hub (MVP v1)
//!
//! This crate implements a minimal, deterministic FIN hub:
//! - Exactly two actions: CREATE_ASSET and MINT_UNITS
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
    CreateAssetV1, FinActionRequestV1, FinActionV1, MintPolicyV1, MintUnitsV1, TransferPolicyV1,
    TransferUnitsV1,
};
pub use apply::{apply, apply_with_policy, ApplyOutcome, ApplyReceipt};
pub use envelope::FinEnvelopeV1;
pub use store::FinStore;
pub use types::{ActionId, AmountU128, AssetId32, Hex32};

use l2_core::l1_contract::{Base64Bytes, ContractVersion, HubPayloadEnvelopeV1};
use l2_core::L2HubId;

/// Logical identifier for the FIN hub.
pub const HUB_ID: L2HubId = L2HubId::Fin;

/// Hub payload schema for FIN action envelopes.
///
/// This string is part of the L1/L2 contract envelope (not the FIN action envelope).
pub const FIN_HUB_PAYLOAD_SCHEMA_V1: &str = "hub-fin.envelope.v1";

/// MIME-ish content type for the hub payload bytes.
pub const FIN_HUB_PAYLOAD_CONTENT_TYPE_V1: &str = "application/json";

/// Convert a FIN envelope into an L1-submittable hub payload envelope (v1).
///
/// `payload` bytes are the canonical JSON bytes of `FinEnvelopeV1`.
impl From<&FinEnvelopeV1> for HubPayloadEnvelopeV1 {
    fn from(env: &FinEnvelopeV1) -> Self {
        let payload_bytes = env
            .canonical_bytes()
            .expect("FinEnvelopeV1 canonicalization is infallible for valid serde values");
        HubPayloadEnvelopeV1 {
            contract_version: ContractVersion::V1,
            hub: HUB_ID,
            schema_version: FIN_HUB_PAYLOAD_SCHEMA_V1.to_string(),
            content_type: FIN_HUB_PAYLOAD_CONTENT_TYPE_V1.to_string(),
            payload: Base64Bytes(payload_bytes),
        }
    }
}
