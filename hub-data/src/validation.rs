#![forbid(unsafe_code)]

use crate::actions::{
    AppendAttestationV1, CreateListingV1, GrantEntitlementV1, IssueLicenseV1, LicenseRightsV1,
    RegisterDatasetV1,
};
use crate::types::{AttestationId, DatasetId, Hex32, LicenseId, ListingId, PriceMicrounitsU128};
use l2_core::AccountId;

pub const NAME_MIN_LEN: usize = 1;

/// Configurable validation limits for HUB-DATA.
///
/// These limits affect *admission* only and must not affect hashing semantics.
#[derive(Debug, Clone)]
pub struct ValidationLimits {
    /// Global max size for generic string fields (UTF-8 bytes).
    /// Individual fields also have their own maxima (below).
    pub max_string_bytes: usize,

    pub name_max_len: usize,
    pub description_max_len: usize,
    pub pointer_uri_max_len: usize,
    pub mime_type_max_len: usize,
    pub terms_uri_max_len: usize,
    pub nonce_max_len: usize,
    pub statement_max_len: usize,
    pub ref_uri_max_len: usize,

    /// Max tags count.
    pub max_tags: usize,
    /// Max length of an individual tag (UTF-8 bytes).
    pub max_tag_bytes: usize,
    /// Max account id length (UTF-8 bytes).
    pub max_account_bytes: usize,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            // Preserve previous MVP bounds by default (back-compat + tests).
            max_string_bytes: 1024,
            name_max_len: 96,
            description_max_len: 512,
            pointer_uri_max_len: 512,
            mime_type_max_len: 96,
            terms_uri_max_len: 512,
            nonce_max_len: 64,
            statement_max_len: 280,
            ref_uri_max_len: 512,
            max_tags: 16,
            max_tag_bytes: 32,
            max_account_bytes: 128,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("invalid field: {0}")]
    Invalid(String),
}

pub fn validate_register_dataset_v1(a: &RegisterDatasetV1) -> Result<(), ValidationError> {
    validate_register_dataset_v1_with_limits(a, &ValidationLimits::default())
}

pub fn validate_register_dataset_v1_with_limits(
    a: &RegisterDatasetV1,
    limits: &ValidationLimits,
) -> Result<(), ValidationError> {
    validate_account_id_with_limits("owner", &a.owner, limits)?;
    validate_bounded(
        "name",
        &a.name,
        limits.name_max_len.min(limits.max_string_bytes),
    )?;
    if a.name.trim().len() < NAME_MIN_LEN {
        return Err(ValidationError::Invalid("name is empty".to_string()));
    }
    if let Some(desc) = a.description.as_deref() {
        validate_bounded_allow_empty(
            "description",
            desc,
            limits.description_max_len.min(limits.max_string_bytes),
        )?;
    }
    if let Some(uri) = a.pointer_uri.as_deref() {
        validate_bounded_allow_empty(
            "pointer_uri",
            uri,
            limits.pointer_uri_max_len.min(limits.max_string_bytes),
        )?;
    }
    if let Some(mime) = a.mime_type.as_deref() {
        validate_bounded_allow_empty(
            "mime_type",
            mime,
            limits.mime_type_max_len.min(limits.max_string_bytes),
        )?;
    }
    // Tags must already be normalized (lowercase/trimmed), sorted, and de-duplicated.
    let normalized = normalize_tags_with_limits(&a.tags, limits)?;
    if normalized != a.tags {
        return Err(ValidationError::Invalid(
            "tags must be normalized (trim + lowercase), sorted, and de-duplicated".to_string(),
        ));
    }

    // Ensure deterministic dataset id matches derivation.
    let expected = derive_dataset_id(&a.owner, &a.name, &a.content_hash, a.schema_version);
    if expected != a.dataset_id {
        return Err(ValidationError::Invalid(
            "dataset_id does not match blake3(owner || name || content_hash || schema_version)"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn validate_issue_license_v1(a: &IssueLicenseV1) -> Result<(), ValidationError> {
    validate_issue_license_v1_with_limits(a, &ValidationLimits::default())
}

pub fn validate_issue_license_v1_with_limits(
    a: &IssueLicenseV1,
    limits: &ValidationLimits,
) -> Result<(), ValidationError> {
    validate_account_id_with_limits("licensor", &a.licensor, limits)?;
    validate_account_id_with_limits("licensee", &a.licensee, limits)?;
    validate_bounded(
        "nonce",
        &a.nonce,
        limits.nonce_max_len.min(limits.max_string_bytes),
    )?;
    if let Some(uri) = a.terms_uri.as_deref() {
        validate_bounded_allow_empty(
            "terms_uri",
            uri,
            limits.terms_uri_max_len.min(limits.max_string_bytes),
        )?;
    }

    let expected = derive_license_id(
        a.dataset_id,
        &a.licensee,
        a.rights,
        a.terms_hash.as_ref(),
        a.expires_at,
        &a.nonce,
    );
    if expected != a.license_id {
        return Err(ValidationError::Invalid(
            "license_id does not match blake3(dataset_id || licensee || rights || terms_hash || expires_at || nonce)"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn validate_append_attestation_v1(a: &AppendAttestationV1) -> Result<(), ValidationError> {
    validate_append_attestation_v1_with_limits(a, &ValidationLimits::default())
}

pub fn validate_append_attestation_v1_with_limits(
    a: &AppendAttestationV1,
    limits: &ValidationLimits,
) -> Result<(), ValidationError> {
    validate_account_id_with_limits("attestor", &a.attestor, limits)?;
    validate_bounded(
        "nonce",
        &a.nonce,
        limits.nonce_max_len.min(limits.max_string_bytes),
    )?;
    if let Some(s) = a.statement.as_deref() {
        validate_bounded_allow_empty(
            "statement",
            s,
            limits.statement_max_len.min(limits.max_string_bytes),
        )?;
    }
    if let Some(uri) = a.ref_uri.as_deref() {
        validate_bounded_allow_empty(
            "ref_uri",
            uri,
            limits.ref_uri_max_len.min(limits.max_string_bytes),
        )?;
    }

    let expected = derive_attestation_id(
        a.dataset_id,
        &a.attestor,
        &a.statement_hash,
        a.ref_hash.as_ref(),
        &a.nonce,
    );
    if expected != a.attestation_id {
        return Err(ValidationError::Invalid(
            "attestation_id does not match blake3(dataset_id || attestor || statement_hash || ref_hash || nonce)"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn validate_create_listing_v1(a: &CreateListingV1) -> Result<(), ValidationError> {
    validate_create_listing_v1_with_limits(a, &ValidationLimits::default())
}

pub fn validate_create_listing_v1_with_limits(
    a: &CreateListingV1,
    limits: &ValidationLimits,
) -> Result<(), ValidationError> {
    validate_account_id_with_limits("licensor", &a.licensor, limits)?;
    if a.price_microunits.0 == 0 {
        return Err(ValidationError::Invalid(
            "price_microunits must be > 0".to_string(),
        ));
    }
    if let Some(uri) = a.terms_uri.as_deref() {
        validate_bounded_allow_empty(
            "terms_uri",
            uri,
            limits.terms_uri_max_len.min(limits.max_string_bytes),
        )?;
    }

    let expected = derive_listing_id_v1(
        a.dataset_id,
        &a.licensor,
        a.price_microunits,
        &a.currency_asset_id,
        a.rights,
        a.terms_hash.as_ref(),
    );
    if expected != a.listing_id {
        return Err(ValidationError::Invalid(
            "listing_id does not match blake3(dataset_id || licensor || price || currency_asset_id || rights || terms_hash)"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn validate_grant_entitlement_v1(a: &GrantEntitlementV1) -> Result<(), ValidationError> {
    validate_grant_entitlement_v1_with_limits(a, &ValidationLimits::default())
}

pub fn validate_grant_entitlement_v1_with_limits(
    a: &GrantEntitlementV1,
    limits: &ValidationLimits,
) -> Result<(), ValidationError> {
    validate_account_id_with_limits("licensee", &a.licensee, limits)?;
    if let Some(actor) = a.actor.as_ref() {
        validate_account_id_with_limits("actor", actor, limits)?;
    }
    let expected =
        derive_entitlement_license_id_v1(a.dataset_id, a.listing_id, &a.licensee, &a.purchase_id);
    if expected != a.license_id {
        return Err(ValidationError::Invalid(
            "license_id does not match entitlement derivation rules".to_string(),
        ));
    }
    Ok(())
}

pub fn derive_dataset_id(
    owner: &AccountId,
    name: &str,
    content_hash: &Hex32,
    schema_version: u32,
) -> DatasetId {
    let mut h = blake3::Hasher::new();
    h.update(b"hub-data:dataset_id:v1");
    h.update(owner.0.as_bytes());
    h.update(b"\0");
    h.update(name.as_bytes());
    h.update(b"\0");
    h.update(content_hash.as_bytes());
    h.update(schema_version.to_be_bytes().as_slice());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    Hex32(out)
}

pub fn derive_license_id(
    dataset_id: DatasetId,
    licensee: &AccountId,
    rights: LicenseRightsV1,
    terms_hash: Option<&Hex32>,
    expires_at: Option<u64>,
    nonce: &str,
) -> LicenseId {
    let mut h = blake3::Hasher::new();
    h.update(b"hub-data:license_id:v1");
    h.update(dataset_id.as_bytes());
    h.update(b"\0");
    h.update(licensee.0.as_bytes());
    h.update(b"\0");
    h.update(rights.as_str().as_bytes());
    h.update(b"\0");
    if let Some(th) = terms_hash {
        h.update(th.as_bytes());
    }
    h.update(b"\0");
    if let Some(ts) = expires_at {
        h.update(ts.to_be_bytes().as_slice());
    }
    h.update(b"\0");
    h.update(nonce.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    Hex32(out)
}

pub fn derive_attestation_id(
    dataset_id: DatasetId,
    attestor: &AccountId,
    statement_hash: &Hex32,
    ref_hash: Option<&Hex32>,
    nonce: &str,
) -> AttestationId {
    let mut h = blake3::Hasher::new();
    h.update(b"hub-data:attestation_id:v1");
    h.update(dataset_id.as_bytes());
    h.update(b"\0");
    h.update(attestor.0.as_bytes());
    h.update(b"\0");
    h.update(statement_hash.as_bytes());
    h.update(b"\0");
    if let Some(rh) = ref_hash {
        h.update(rh.as_bytes());
    }
    h.update(b"\0");
    h.update(nonce.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    Hex32(out)
}

pub fn derive_listing_id_v1(
    dataset_id: DatasetId,
    licensor: &AccountId,
    price_microunits: PriceMicrounitsU128,
    currency_asset_id: &Hex32,
    rights: LicenseRightsV1,
    terms_hash: Option<&Hex32>,
) -> ListingId {
    let mut h = blake3::Hasher::new();
    h.update(b"hub-data:listing_id:v1");
    h.update(dataset_id.as_bytes());
    h.update(b"\0");
    h.update(licensor.0.as_bytes());
    h.update(b"\0");
    h.update(price_microunits.0.to_be_bytes().as_slice());
    h.update(b"\0");
    h.update(currency_asset_id.as_bytes());
    h.update(b"\0");
    h.update(rights.as_str().as_bytes());
    h.update(b"\0");
    if let Some(th) = terms_hash {
        h.update(th.as_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    Hex32(out)
}

pub fn derive_entitlement_license_id_v1(
    dataset_id: DatasetId,
    listing_id: ListingId,
    licensee: &AccountId,
    purchase_id: &l2_core::hub_linkage::PurchaseId,
) -> LicenseId {
    let mut h = blake3::Hasher::new();
    h.update(b"hub-data:entitlement_license_id:v1");
    h.update(dataset_id.as_bytes());
    h.update(b"\0");
    h.update(listing_id.as_bytes());
    h.update(b"\0");
    h.update(licensee.0.as_bytes());
    h.update(b"\0");
    h.update(purchase_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    Hex32(out)
}

pub fn normalize_tags(tags: &[String]) -> Result<Vec<String>, ValidationError> {
    normalize_tags_with_limits(tags, &ValidationLimits::default())
}

pub fn normalize_tags_with_limits(
    tags: &[String],
    limits: &ValidationLimits,
) -> Result<Vec<String>, ValidationError> {
    if tags.len() > limits.max_tags {
        return Err(ValidationError::Invalid(format!(
            "tags exceeds max count {}",
            limits.max_tags
        )));
    }
    let mut out = Vec::with_capacity(tags.len());
    for t in tags {
        let n = t.trim();
        if n.is_empty() {
            return Err(ValidationError::Invalid("tag is empty".to_string()));
        }
        if n.len() > limits.max_tag_bytes.min(limits.max_string_bytes) {
            return Err(ValidationError::Invalid(format!(
                "tag exceeds max length {}",
                limits.max_tag_bytes
            )));
        }
        out.push(n.to_ascii_lowercase());
    }
    out.sort();
    out.dedup();
    Ok(out)
}

pub fn validate_account_id(field: &str, a: &AccountId) -> Result<(), ValidationError> {
    validate_account_id_with_limits(field, a, &ValidationLimits::default())
}

pub fn validate_account_id_with_limits(
    field: &str,
    a: &AccountId,
    limits: &ValidationLimits,
) -> Result<(), ValidationError> {
    validate_bounded(field, &a.0, limits.max_account_bytes)
}

fn validate_bounded(field: &str, s: &str, max_len: usize) -> Result<(), ValidationError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(ValidationError::Invalid(format!("{field} is empty")));
    }
    if t.len() > max_len {
        return Err(ValidationError::Invalid(format!(
            "{field} exceeds max length {max_len}"
        )));
    }
    Ok(())
}

fn validate_bounded_allow_empty(
    field: &str,
    s: &str,
    max_len: usize,
) -> Result<(), ValidationError> {
    if s.len() > max_len {
        return Err(ValidationError::Invalid(format!(
            "{field} exceeds max length {max_len}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{AttestationPolicyV1, RegisterDatasetV1};

    #[test]
    fn register_dataset_respects_max_string_bytes() {
        let limits = ValidationLimits {
            max_string_bytes: 1024,
            name_max_len: 8,
            description_max_len: 512,
            pointer_uri_max_len: 512,
            mime_type_max_len: 96,
            terms_uri_max_len: 512,
            nonce_max_len: 64,
            statement_max_len: 280,
            ref_uri_max_len: 512,
            max_tags: 16,
            max_tag_bytes: 32,
            max_account_bytes: 128,
        };

        let owner = AccountId::new("acc-alice");
        let name = "123456789".to_string(); // 9 bytes > 8
        let content_hash = Hex32([1u8; 32]);
        let schema_version = 1u32;
        let dataset_id = derive_dataset_id(&owner, &name, &content_hash, schema_version);

        let a = RegisterDatasetV1 {
            schema_version,
            dataset_id,
            owner,
            name,
            description: None,
            content_hash,
            pointer_uri: None,
            mime_type: None,
            tags: vec![],
            attestation_policy: AttestationPolicyV1::Anyone,
        };

        let e = validate_register_dataset_v1_with_limits(&a, &limits).unwrap_err();
        assert!(e.to_string().contains("name exceeds max length"));
    }
}
