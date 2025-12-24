#![forbid(unsafe_code)]

//! Operational encryption-at-rest helpers.
//!
//! Global design constraints:
//! - Must not affect consensus-critical canonical bytes or action IDs.
//! - Must not log or persist key material outside of encrypted storage.
//! - Intended for encrypting stored values and exported artifacts.

mod value_v1;
mod xchacha20poly1305;

pub use value_v1::{
    EncryptedValueDecodeError, EncryptedValueV1, EncryptionError, KeyProvider, KeyProviderError,
    MasterKey, SledValueCipher,
};

pub use xchacha20poly1305::{decrypt, encrypt};
