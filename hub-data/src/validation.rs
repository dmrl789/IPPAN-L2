#![forbid(unsafe_code)]

use crate::actions::{AppendAttestationV1, IssueLicenseV1, LicenseRightsV1, RegisterDatasetV1};
use crate::types::{AttestationId, DatasetId, Hex32, LicenseId};
use l2_core::AccountId;

pub const NAME_MIN_LEN: usize = 1;
pub const NAME_MAX_LEN: usize = 96;
pub const DESCRIPTION_MAX_LEN: usize = 512;
pub const POINTER_URI_MAX_LEN: usize = 512;
pub const MIME_TYPE_MAX_LEN: usize = 96;
pub const TAG_MAX_LEN: usize = 32;
pub const TAG_MAX_COUNT: usize = 16;
pub const TERMS_URI_MAX_LEN: usize = 512;
pub const NONCE_MAX_LEN: usize = 64;
pub const STATEMENT_MAX_LEN: usize = 280;
pub const REF_URI_MAX_LEN: usize = 512;
pub const ACCOUNT_MAX_LEN: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("invalid field: {0}")]
    Invalid(String),
}

pub fn validate_register_dataset_v1(a: &RegisterDatasetV1) -> Result<(), ValidationError> {
    validate_account_id("owner", &a.owner)?;
    validate_bounded("name", &a.name, NAME_MAX_LEN)?;
    if a.name.trim().len() < NAME_MIN_LEN {
        return Err(ValidationError::Invalid("name is empty".to_string()));
    }
    if let Some(desc) = a.description.as_deref() {
        validate_bounded_allow_empty("description", desc, DESCRIPTION_MAX_LEN)?;
    }
    if let Some(uri) = a.pointer_uri.as_deref() {
        validate_bounded_allow_empty("pointer_uri", uri, POINTER_URI_MAX_LEN)?;
    }
    if let Some(mime) = a.mime_type.as_deref() {
        validate_bounded_allow_empty("mime_type", mime, MIME_TYPE_MAX_LEN)?;
    }
    // Tags must already be normalized (lowercase/trimmed), sorted, and de-duplicated.
    let normalized = normalize_tags(&a.tags)?;
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

pub fn validate_issue_license_v1(
    a: &IssueLicenseV1,
    dataset_owner: &AccountId,
) -> Result<(), ValidationError> {
    validate_account_id("licensor", &a.licensor)?;
    validate_account_id("licensee", &a.licensee)?;
    validate_bounded("nonce", &a.nonce, NONCE_MAX_LEN)?;
    if let Some(uri) = a.terms_uri.as_deref() {
        validate_bounded_allow_empty("terms_uri", uri, TERMS_URI_MAX_LEN)?;
    }
    // MVP rule: licensor must be dataset.owner.
    if &a.licensor != dataset_owner {
        return Err(ValidationError::Invalid(
            "licensor must equal dataset.owner (MVP rule)".to_string(),
        ));
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
    validate_account_id("attestor", &a.attestor)?;
    validate_bounded("nonce", &a.nonce, NONCE_MAX_LEN)?;
    if let Some(s) = a.statement.as_deref() {
        validate_bounded_allow_empty("statement", s, STATEMENT_MAX_LEN)?;
    }
    if let Some(uri) = a.ref_uri.as_deref() {
        validate_bounded_allow_empty("ref_uri", uri, REF_URI_MAX_LEN)?;
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

pub fn normalize_tags(tags: &[String]) -> Result<Vec<String>, ValidationError> {
    if tags.len() > TAG_MAX_COUNT {
        return Err(ValidationError::Invalid(format!(
            "tags exceeds max count {TAG_MAX_COUNT}"
        )));
    }
    let mut out = Vec::with_capacity(tags.len());
    for t in tags {
        let n = t.trim();
        if n.is_empty() {
            return Err(ValidationError::Invalid("tag is empty".to_string()));
        }
        if n.len() > TAG_MAX_LEN {
            return Err(ValidationError::Invalid(format!(
                "tag exceeds max length {TAG_MAX_LEN}"
            )));
        }
        out.push(n.to_ascii_lowercase());
    }
    out.sort();
    out.dedup();
    Ok(out)
}

pub fn validate_account_id(field: &str, a: &AccountId) -> Result<(), ValidationError> {
    validate_bounded(field, &a.0, ACCOUNT_MAX_LEN)
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
