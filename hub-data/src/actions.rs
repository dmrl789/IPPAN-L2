#![forbid(unsafe_code)]

use crate::types::{AttestationId, DatasetId, Hex32, LicenseId, ListingId, PriceMicrounitsU128};
use crate::validation::{
    derive_attestation_id, derive_dataset_id, derive_entitlement_license_id_v1, derive_license_id,
    derive_listing_id_v1,
};
use l2_core::hub_linkage::{PaymentRef, PurchaseId};
use l2_core::AccountId;
use serde::{Deserialize, Serialize};

/// Attestation policy for a dataset.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationPolicyV1 {
    #[default]
    Anyone,
    AllowlistOnly,
}

/// REGISTER_DATASET action (v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDatasetV1 {
    /// Deterministic id:
    /// `blake3(owner || name || content_hash || schema_version)` (32 bytes, hex in JSON).
    pub dataset_id: DatasetId,
    pub owner: AccountId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Immutable 32-byte content hash pointer (blake3/sha256/cid digest bytes).
    pub content_hash: Hex32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Dataset format schema version (not contract version).
    pub schema_version: u32,
    /// Who may append attestations for this dataset.
    #[serde(default)]
    pub attestation_policy: AttestationPolicyV1,
}

/// Request shape for registering a dataset (server derives `dataset_id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDatasetRequestV1 {
    pub owner: AccountId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub content_hash: Hex32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub schema_version: u32,
    #[serde(default)]
    pub attestation_policy: AttestationPolicyV1,
}

/// Rights granted by a license (MVP v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseRightsV1 {
    View,
    Use,
    CommercialUse,
    DerivativeUse,
}

impl LicenseRightsV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            LicenseRightsV1::View => "view",
            LicenseRightsV1::Use => "use",
            LicenseRightsV1::CommercialUse => "commercial_use",
            LicenseRightsV1::DerivativeUse => "derivative_use",
        }
    }
}

/// ISSUE_LICENSE action (v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueLicenseV1 {
    pub dataset_id: DatasetId,
    /// Deterministic id:
    /// `blake3(dataset_id || licensee || rights || terms_hash || expires_at || nonce)`.
    pub license_id: LicenseId,
    pub licensor: AccountId,
    pub licensee: AccountId,
    pub rights: LicenseRightsV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms_hash: Option<Hex32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Informational only (no settlement logic in HUB-DATA MVP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_microunits: Option<PriceMicrounitsU128>,
    /// Client nonce included in the deterministic `license_id`.
    pub nonce: String,
}

/// Request shape for issuing a license (server derives `license_id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueLicenseRequestV1 {
    pub dataset_id: DatasetId,
    pub licensor: AccountId,
    pub licensee: AccountId,
    pub rights: LicenseRightsV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms_hash: Option<Hex32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_microunits: Option<PriceMicrounitsU128>,
    pub nonce: String,
}

/// APPEND_ATTESTATION action (v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendAttestationV1 {
    pub dataset_id: DatasetId,
    /// Deterministic id:
    /// `blake3(dataset_id || attestor || statement_hash || ref_hash || nonce)`.
    pub attestation_id: AttestationId,
    pub attestor: AccountId,
    /// Optional short statement (<= 280) for operator UX (not privacy-preserving).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    /// Canonical statement hash (preferred for privacy).
    pub statement_hash: Hex32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_hash: Option<Hex32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_uri: Option<String>,
    /// Client nonce included in deterministic `attestation_id`.
    pub nonce: String,
}

/// Request shape for appending an attestation (server derives `statement_hash` and `attestation_id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendAttestationRequestV1 {
    pub dataset_id: DatasetId,
    pub attestor: AccountId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_hash: Option<Hex32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_hash: Option<Hex32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_uri: Option<String>,
    pub nonce: String,
}

/// CREATE_LISTING action (v1.1, contract_version remains "v1").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateListingV1 {
    pub dataset_id: DatasetId,
    /// Deterministic id:
    /// `blake3(dataset_id || licensor || price || currency_asset_id || rights || terms_hash)`.
    pub listing_id: ListingId,
    pub licensor: AccountId,
    pub rights: LicenseRightsV1,
    /// Integer microunits (u128) encoded as JSON string.
    pub price_microunits: PriceMicrounitsU128,
    /// References HUB-FIN asset id (32 bytes).
    pub currency_asset_id: Hex32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms_hash: Option<Hex32>,
}

/// Request shape for creating a listing (server derives `listing_id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateListingRequestV1 {
    pub dataset_id: DatasetId,
    pub licensor: AccountId,
    pub rights: LicenseRightsV1,
    pub price_microunits: PriceMicrounitsU128,
    pub currency_asset_id: Hex32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms_hash: Option<Hex32>,
}

/// GRANT_ENTITLEMENT action (v1.1, contract_version remains "v1").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantEntitlementV1 {
    pub purchase_id: PurchaseId,
    pub listing_id: ListingId,
    pub dataset_id: DatasetId,
    pub licensee: AccountId,
    pub payment_ref: PaymentRef,
    /// Deterministic entitlement license id (hub-defined).
    pub license_id: LicenseId,
    /// Actor granting the entitlement (required in strict mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<AccountId>,
}

/// Request shape for granting entitlement (server derives `license_id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantEntitlementRequestV1 {
    pub purchase_id: PurchaseId,
    pub listing_id: ListingId,
    pub dataset_id: DatasetId,
    pub licensee: AccountId,
    pub payment_ref: PaymentRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<AccountId>,
}

/// ADD_LICENSOR action (v1.2, contract_version remains "v1").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddLicensorV1 {
    pub dataset_id: DatasetId,
    pub licensor: AccountId,
    /// Actor performing the change (dataset owner in strict mode).
    pub actor: AccountId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddLicensorRequestV1 {
    pub dataset_id: DatasetId,
    pub licensor: AccountId,
    pub actor: AccountId,
}

/// ADD_ATTESTOR action (v1.2, contract_version remains "v1").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddAttestorV1 {
    pub dataset_id: DatasetId,
    pub attestor: AccountId,
    /// Actor performing the change (dataset owner in strict mode).
    pub actor: AccountId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddAttestorRequestV1 {
    pub dataset_id: DatasetId,
    pub attestor: AccountId,
    pub actor: AccountId,
}

/// HUB-DATA action enum (v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DataActionV1 {
    RegisterDatasetV1(RegisterDatasetV1),
    IssueLicenseV1(IssueLicenseV1),
    AppendAttestationV1(AppendAttestationV1),
    CreateListingV1(CreateListingV1),
    GrantEntitlementV1(GrantEntitlementV1),
    AddLicensorV1(AddLicensorV1),
    AddAttestorV1(AddAttestorV1),
}

/// fin-node request shape for submitting HUB-DATA actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DataActionRequestV1 {
    RegisterDatasetV1(RegisterDatasetRequestV1),
    IssueLicenseV1(IssueLicenseRequestV1),
    AppendAttestationV1(AppendAttestationRequestV1),
    CreateListingV1(CreateListingRequestV1),
    GrantEntitlementV1(GrantEntitlementRequestV1),
    AddLicensorV1(AddLicensorRequestV1),
    AddAttestorV1(AddAttestorRequestV1),
}

impl DataActionRequestV1 {
    pub fn into_action(self) -> DataActionV1 {
        match self {
            DataActionRequestV1::RegisterDatasetV1(req) => {
                // Determinism: normalize + sort tags before hashing/serialization.
                let mut tags = req.tags;
                for t in tags.iter_mut() {
                    *t = t.trim().to_ascii_lowercase();
                }
                tags.sort();
                tags.dedup();
                let dataset_id =
                    derive_dataset_id(&req.owner, &req.name, &req.content_hash, req.schema_version);
                DataActionV1::RegisterDatasetV1(RegisterDatasetV1 {
                    dataset_id,
                    owner: req.owner,
                    name: req.name,
                    description: req.description,
                    content_hash: req.content_hash,
                    pointer_uri: req.pointer_uri,
                    mime_type: req.mime_type,
                    tags,
                    schema_version: req.schema_version,
                    attestation_policy: req.attestation_policy,
                })
            }
            DataActionRequestV1::IssueLicenseV1(req) => {
                let license_id = derive_license_id(
                    req.dataset_id,
                    &req.licensee,
                    req.rights,
                    req.terms_hash.as_ref(),
                    req.expires_at,
                    &req.nonce,
                );
                DataActionV1::IssueLicenseV1(IssueLicenseV1 {
                    dataset_id: req.dataset_id,
                    license_id,
                    licensor: req.licensor,
                    licensee: req.licensee,
                    rights: req.rights,
                    terms_uri: req.terms_uri,
                    terms_hash: req.terms_hash,
                    expires_at: req.expires_at,
                    price_microunits: req.price_microunits,
                    nonce: req.nonce,
                })
            }
            DataActionRequestV1::AppendAttestationV1(req) => {
                let statement_hash = req.statement_hash.unwrap_or_else(|| {
                    let s = req.statement.as_deref().unwrap_or("");
                    let mut out = [0u8; 32];
                    out.copy_from_slice(blake3::hash(s.as_bytes()).as_bytes());
                    Hex32(out)
                });
                let attestation_id = derive_attestation_id(
                    req.dataset_id,
                    &req.attestor,
                    &statement_hash,
                    req.ref_hash.as_ref(),
                    &req.nonce,
                );
                DataActionV1::AppendAttestationV1(AppendAttestationV1 {
                    dataset_id: req.dataset_id,
                    attestation_id,
                    attestor: req.attestor,
                    statement: req.statement,
                    statement_hash,
                    ref_hash: req.ref_hash,
                    ref_uri: req.ref_uri,
                    nonce: req.nonce,
                })
            }
            DataActionRequestV1::CreateListingV1(req) => {
                let listing_id = derive_listing_id_v1(
                    req.dataset_id,
                    &req.licensor,
                    req.price_microunits,
                    &req.currency_asset_id,
                    req.rights,
                    req.terms_hash.as_ref(),
                );
                DataActionV1::CreateListingV1(CreateListingV1 {
                    dataset_id: req.dataset_id,
                    listing_id,
                    licensor: req.licensor,
                    rights: req.rights,
                    price_microunits: req.price_microunits,
                    currency_asset_id: req.currency_asset_id,
                    terms_uri: req.terms_uri,
                    terms_hash: req.terms_hash,
                })
            }
            DataActionRequestV1::GrantEntitlementV1(req) => {
                let license_id = derive_entitlement_license_id_v1(
                    req.dataset_id,
                    req.listing_id,
                    &req.licensee,
                    &req.purchase_id,
                );
                DataActionV1::GrantEntitlementV1(GrantEntitlementV1 {
                    purchase_id: req.purchase_id,
                    listing_id: req.listing_id,
                    dataset_id: req.dataset_id,
                    licensee: req.licensee,
                    payment_ref: req.payment_ref,
                    license_id,
                    actor: req.actor,
                })
            }
            DataActionRequestV1::AddLicensorV1(req) => DataActionV1::AddLicensorV1(AddLicensorV1 {
                dataset_id: req.dataset_id,
                licensor: req.licensor,
                actor: req.actor,
            }),
            DataActionRequestV1::AddAttestorV1(req) => DataActionV1::AddAttestorV1(AddAttestorV1 {
                dataset_id: req.dataset_id,
                attestor: req.attestor,
                actor: req.actor,
            }),
        }
    }
}
