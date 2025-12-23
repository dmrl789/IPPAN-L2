#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::disallowed_types)]

//! HUB-FIN ↔ HUB-DATA linkage (payments + entitlements).
//!
//! This module is a tiny, shared “linkage contract” used by hubs and fin-node to:
//! - derive stable cross-hub IDs
//! - persist a resume-safe linkage receipt
//! - reference FIN payment and DATA entitlement actions deterministically

use crate::AccountId;
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::fmt;

/// 32-byte identifier encoded as lowercase hex in JSON.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hex32(pub [u8; 32]);

impl Hex32 {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let raw = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
        if raw.len() != 32 {
            return Err(format!("expected 32 bytes, got {}", raw.len()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(Self(out))
    }
}

impl fmt::Debug for Hex32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Hex32").field(&self.to_hex()).finish()
    }
}

impl fmt::Display for Hex32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Hex32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hex32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Hex32::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Stable linkage identifier:
/// `blake3(dataset_id || licensee || price || currency_asset_id || terms_hash || nonce)`.
///
/// Notes:
/// - Implementation uses a fixed prefix + `\0` separators for unambiguous decoding.
/// - All integer encodings are big-endian.
pub type PurchaseId = Hex32;

/// Reference to a FIN payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRef {
    pub fin_action_id: Hex32,
    /// Canonical hash of the FIN receipt or envelope (implementation-defined, but deterministic).
    pub fin_receipt_hash: Hex32,
}

/// Reference to a DATA entitlement grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementRef {
    pub data_action_id: Hex32,
    pub license_id: Hex32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkageStatus {
    Created,
    Paid,
    Entitled,
    FailedRecoverable,
}

/// Resume-safe receipt persisted by fin-node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkageReceiptV1 {
    pub purchase_id: PurchaseId,
    pub dataset_id: Hex32,
    pub listing_id: Hex32,
    pub licensee: AccountId,
    /// Price in integer microunits (no floats).
    pub price_microunits: u128,
    pub currency_asset_id: Hex32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_ref: Option<PaymentRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entitlement_ref: Option<EntitlementRef>,

    pub status: LinkageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl LinkageReceiptV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalizeError> {
        canonical_json_bytes(self)
    }

    pub fn canonical_hash_blake3(&self) -> Result<[u8; 32], CanonicalizeError> {
        let bytes = self.canonical_bytes()?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CanonicalizeError {
    #[error("serde error: {0}")]
    Serde(String),
}

/// Deterministic canonical JSON bytes (sorted object keys, compact).
pub fn canonical_json_bytes<T: Serialize>(v: &T) -> Result<Vec<u8>, CanonicalizeError> {
    let mut value = serde_json::to_value(v).map_err(|e| CanonicalizeError::Serde(e.to_string()))?;
    canonical_json_sort_in_place(&mut value);
    serde_json::to_vec(&value).map_err(|e| CanonicalizeError::Serde(e.to_string()))
}

fn canonical_json_sort_in_place(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(String, serde_json::Value)> =
                std::mem::take(map).into_iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            for (_, val) in entries.iter_mut() {
                canonical_json_sort_in_place(val);
            }
            let mut new_map = serde_json::Map::new();
            for (k, val) in entries {
                new_map.insert(k, val);
            }
            *map = new_map;
        }
        serde_json::Value::Array(arr) => {
            for x in arr.iter_mut() {
                canonical_json_sort_in_place(x);
            }
        }
        _ => {}
    }
}

/// Deterministically derive a `PurchaseId` (v1).
pub fn derive_purchase_id_v1(
    dataset_id: &Hex32,
    licensee: &AccountId,
    price_microunits: u128,
    currency_asset_id: &Hex32,
    terms_hash: Option<&Hex32>,
    nonce: &str,
) -> PurchaseId {
    let mut h = Hasher::new();
    h.update(b"hub-linkage:purchase_id:v1");
    h.update(dataset_id.as_bytes());
    h.update(b"\0");
    h.update(licensee.0.as_bytes());
    h.update(b"\0");
    h.update(price_microunits.to_be_bytes().as_slice());
    h.update(b"\0");
    h.update(currency_asset_id.as_bytes());
    h.update(b"\0");
    if let Some(th) = terms_hash {
        h.update(th.as_bytes());
    }
    h.update(b"\0");
    h.update(nonce.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    Hex32(out)
}
