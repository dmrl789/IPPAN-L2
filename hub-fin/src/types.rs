#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;

/// 32-byte identifier encoded as lowercase hex in JSON.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hex32(pub [u8; 32]);

pub type AssetId32 = Hex32;
pub type ActionId = Hex32;

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

/// Unsigned fixed-point amount represented as a scaled integer (`u128`).
///
/// JSON encoding uses a **string** (not a number) to avoid precision loss in JS clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AmountU128(pub u128);

impl AmountU128 {
    pub const fn new_scaled(v: u128) -> Self {
        Self(v)
    }
}

impl Serialize for AmountU128 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for AmountU128 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = AmountU128;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a u128 encoded as a string or an integer")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let n = v
                    .parse::<u128>()
                    .map_err(|e| E::custom(format!("invalid u128 string: {e}")))?;
                Ok(AmountU128(n))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(AmountU128(v as u128))
            }
        }
        deserializer.deserialize_any(V)
    }
}
