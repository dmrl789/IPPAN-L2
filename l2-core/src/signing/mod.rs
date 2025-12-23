#![forbid(unsafe_code)]

//! Signed envelope types (feature-gated).
//!
//! - Signing scheme: Ed25519
//! - Message: domain-separator + canonical bytes of the *inner envelope*
//! - Index hash: blake3(canonical_bytes(inner))

use serde::{Deserialize, Serialize};

/// Domain separator (v1) to prevent cross-protocol replay.
pub const SIGNING_DOMAIN_SEPARATOR_V1: &[u8] = b"IPPAN-L2:SIGNED_ENVELOPE:V1\n";

/// Build the deterministic signing message bytes for a canonical inner payload.
///
/// Exact rule (v1):
/// `message = SIGNING_DOMAIN_SEPARATOR_V1 || canonical_bytes(inner)`
pub fn signing_message_bytes(inner_canonical_bytes: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(SIGNING_DOMAIN_SEPARATOR_V1.len() + inner_canonical_bytes.len());
    out.extend_from_slice(SIGNING_DOMAIN_SEPARATOR_V1);
    out.extend_from_slice(inner_canonical_bytes);
    out
}

/// Compute the signed hash used for indexing:
/// `signed_hash = blake3(canonical_bytes(inner))`
pub fn signed_hash_blake3(inner_canonical_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(inner_canonical_bytes).as_bytes()
}

/// Ed25519 signer identifier (v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerId {
    /// Raw Ed25519 public key bytes (32 bytes).
    #[serde(with = "hex_bytes")]
    pub pubkey: Vec<u8>,
}

impl SignerId {
    pub fn from_pubkey_bytes(pubkey: Vec<u8>) -> Result<Self, String> {
        if pubkey.len() != 32 {
            return Err(format!("expected 32-byte pubkey, got {}", pubkey.len()));
        }
        Ok(Self { pubkey })
    }

    pub fn pubkey_hex(&self) -> String {
        hex::encode(&self.pubkey)
    }
}

/// Ed25519 signature bytes (v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBytes {
    /// Raw Ed25519 signature bytes (64 bytes).
    #[serde(with = "hex_bytes")]
    pub sig: Vec<u8>,
}

impl SignatureBytes {
    pub fn from_sig_bytes(sig: Vec<u8>) -> Result<Self, String> {
        if sig.len() != 64 {
            return Err(format!("expected 64-byte signature, got {}", sig.len()));
        }
        Ok(Self { sig })
    }

    pub fn sig_hex(&self) -> String {
        hex::encode(&self.sig)
    }
}

/// Signed envelope wrapper (v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEnvelopeV1<T> {
    pub contract_version: String,
    pub inner: T,
    pub signer: SignerId,
    pub signature: SignatureBytes,
    /// `blake3(canonical_bytes(inner))` (hex in JSON).
    #[serde(with = "hex_32")]
    pub signed_hash: [u8; 32],
}

impl<T> SignedEnvelopeV1<T> {
    pub fn new(
        inner: T,
        signer: SignerId,
        signature: SignatureBytes,
        signed_hash: [u8; 32],
    ) -> Self {
        Self {
            contract_version: "v1".to_string(),
            inner,
            signer,
            signature,
            signed_hash,
        }
    }
}

/// Serde helpers for encoding raw bytes as lowercase hex strings.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

/// Serde helpers for encoding `[u8; 32]` as lowercase hex string.
mod hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
        if raw.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}
