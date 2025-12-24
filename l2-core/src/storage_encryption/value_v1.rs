#![forbid(unsafe_code)]

use blake3::Hasher;
use std::sync::Arc;

/// 32-byte master key for XChaCha20-Poly1305.
#[derive(Clone)]
pub struct MasterKey {
    pub key_id: String,
    pub key_bytes: [u8; 32],
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key bytes.
        f.debug_struct("MasterKey")
            .field("key_id", &self.key_id)
            .field("key_bytes", &"<redacted 32 bytes>")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyProviderError {
    #[error("ENCRYPTION_KEY_MISSING: {0}")]
    MissingKey(String),
    #[error("key provider error: {0}")]
    Other(String),
}

pub trait KeyProvider: Send + Sync {
    fn current_key(&self) -> Result<MasterKey, KeyProviderError>;
    fn key_by_id(&self, id: &str) -> Result<MasterKey, KeyProviderError>;
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("ENCRYPTION_UNSUPPORTED_VERSION: {0}")]
    UnsupportedVersion(String),
    #[error("ENCRYPTION_KEY_MISSING: {0}")]
    KeyMissing(String),
    #[error("ENCRYPTION_DECRYPT_FAILED: {0}")]
    DecryptFailed(String),
    #[error("encrypt failed: {0}")]
    EncryptFailed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptedValueDecodeError {
    #[error("not an encrypted value")]
    NotEncrypted,
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    #[error("malformed value: {0}")]
    Malformed(String),
}

/// Binary encoding for encrypted sled values (v1).
///
/// Layout:
/// - magic: b"IPPANEV"
/// - version: u8 (1)
/// - key_id_len: u16 (be)
/// - key_id bytes (utf-8)
/// - nonce: [u8; 24]
/// - ct_len: u32 (be)
/// - ct bytes
#[derive(Clone, Debug)]
pub struct EncryptedValueV1 {
    pub key_id: String,
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

const MAGIC: &[u8; 7] = b"IPPANEV";
const VERSION: u8 = 1;

impl EncryptedValueV1 {
    pub fn encode(&self) -> Vec<u8> {
        let key_id_bytes = self.key_id.as_bytes();
        let key_len_u16 = u16::try_from(key_id_bytes.len()).unwrap_or(u16::MAX);
        let ct_len_u32 = u32::try_from(self.ct.len()).unwrap_or(u32::MAX);

        let mut out =
            Vec::with_capacity(MAGIC.len() + 1 + 2 + key_id_bytes.len() + 24 + 4 + self.ct.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&key_len_u16.to_be_bytes());
        out.extend_from_slice(key_id_bytes);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&ct_len_u32.to_be_bytes());
        out.extend_from_slice(&self.ct);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EncryptedValueDecodeError> {
        if bytes.len() < MAGIC.len() + 1 {
            return Err(EncryptedValueDecodeError::NotEncrypted);
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(EncryptedValueDecodeError::NotEncrypted);
        }
        let v = bytes[MAGIC.len()];
        if v != VERSION {
            return Err(EncryptedValueDecodeError::UnsupportedVersion(v));
        }
        let mut cur = &bytes[MAGIC.len() + 1..];
        if cur.len() < 2 {
            return Err(EncryptedValueDecodeError::Malformed(
                "truncated key_id_len".to_string(),
            ));
        }
        let key_id_len = u16::from_be_bytes(cur[..2].try_into().unwrap()) as usize;
        cur = &cur[2..];
        if cur.len() < key_id_len + 24 + 4 {
            return Err(EncryptedValueDecodeError::Malformed(
                "truncated key_id/nonce/ct_len".to_string(),
            ));
        }
        let key_id = std::str::from_utf8(&cur[..key_id_len])
            .map_err(|_| EncryptedValueDecodeError::Malformed("key_id utf8".to_string()))?
            .to_string();
        cur = &cur[key_id_len..];
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&cur[..24]);
        cur = &cur[24..];
        let ct_len = u32::from_be_bytes(cur[..4].try_into().unwrap()) as usize;
        cur = &cur[4..];
        if cur.len() < ct_len {
            return Err(EncryptedValueDecodeError::Malformed(
                "truncated ciphertext".to_string(),
            ));
        }
        let ct = cur[..ct_len].to_vec();
        Ok(Self { key_id, nonce, ct })
    }

    pub fn is_encrypted(bytes: &[u8]) -> bool {
        bytes.len() > MAGIC.len() && &bytes[..MAGIC.len()] == MAGIC
    }
}

#[derive(Clone)]
pub struct SledValueCipher {
    provider: Arc<dyn KeyProvider>,
    store_name: String,
    allow_plaintext_read: bool,
}

impl std::fmt::Debug for SledValueCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SledValueCipher")
            .field("store_name", &self.store_name)
            .field("allow_plaintext_read", &self.allow_plaintext_read)
            .finish()
    }
}

impl SledValueCipher {
    pub fn new(
        provider: Arc<dyn KeyProvider>,
        store_name: impl Into<String>,
        allow_plaintext_read: bool,
    ) -> Self {
        Self {
            provider,
            store_name: store_name.into(),
            allow_plaintext_read,
        }
    }

    pub fn store_name(&self) -> &str {
        &self.store_name
    }

    pub fn allow_plaintext_read(&self) -> bool {
        self.allow_plaintext_read
    }

    pub fn current_key_id(&self) -> Result<String, EncryptionError> {
        let k = self
            .provider
            .current_key()
            .map_err(|e| EncryptionError::KeyMissing(e.to_string()))?;
        Ok(k.key_id)
    }

    pub fn encrypt_value(
        &self,
        sled_key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let k = self
            .provider
            .current_key()
            .map_err(|e| EncryptionError::KeyMissing(e.to_string()))?;
        let aad = build_value_aad(VERSION, &self.store_name, &k.key_id, &k.key_bytes, sled_key);
        let (nonce, ct) = super::encrypt(&k.key_bytes, plaintext, &aad)?;
        let ev = EncryptedValueV1 {
            key_id: k.key_id,
            nonce,
            ct,
        };
        Ok(ev.encode())
    }

    pub fn decrypt_value(
        &self,
        sled_key: &[u8],
        stored: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        match EncryptedValueV1::decode(stored) {
            Ok(ev) => {
                let k = self.provider.key_by_id(&ev.key_id).map_err(|e| {
                    EncryptionError::KeyMissing(format!("missing key_id={} ({e})", ev.key_id))
                })?;
                let aad = build_value_aad(
                    VERSION,
                    &self.store_name,
                    &ev.key_id,
                    &k.key_bytes,
                    sled_key,
                );
                super::decrypt(&k.key_bytes, &ev.nonce, &ev.ct, &aad)
            }
            Err(EncryptedValueDecodeError::NotEncrypted) => {
                if self.allow_plaintext_read {
                    Ok(stored.to_vec())
                } else {
                    Err(EncryptionError::DecryptFailed(
                        "plaintext value rejected (allow_plaintext_read=false)".to_string(),
                    ))
                }
            }
            Err(EncryptedValueDecodeError::UnsupportedVersion(v)) => Err(
                EncryptionError::UnsupportedVersion(format!("encrypted value version={v}")),
            ),
            Err(EncryptedValueDecodeError::Malformed(m)) => Err(EncryptionError::DecryptFailed(m)),
        }
    }
}

fn build_value_aad(
    value_version: u8,
    store_name: &str,
    key_id: &str,
    master_key_bytes: &[u8; 32],
    sled_key: &[u8],
) -> Vec<u8> {
    // Fixed-size binding for large sled keys:
    // - store_name bytes
    // - 0 separator
    // - value_version
    // - 0 separator
    // - key_id bytes
    // - 0 separator
    // - blake3(master_key_bytes)
    // - blake3(sled_key)
    let mk_hash = blake3::hash(master_key_bytes);
    let mut h = Hasher::new();
    h.update(sled_key);
    let key_hash = h.finalize();

    let mut aad = Vec::new();
    aad.extend_from_slice(store_name.as_bytes());
    aad.push(0);
    aad.push(value_version);
    aad.push(0);
    aad.extend_from_slice(key_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(mk_hash.as_bytes());
    aad.extend_from_slice(key_hash.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestProvider {
        k: MasterKey,
    }
    impl KeyProvider for TestProvider {
        fn current_key(&self) -> Result<MasterKey, KeyProviderError> {
            Ok(self.k.clone())
        }
        fn key_by_id(&self, id: &str) -> Result<MasterKey, KeyProviderError> {
            if id == self.k.key_id {
                Ok(self.k.clone())
            } else {
                Err(KeyProviderError::MissingKey(id.to_string()))
            }
        }
    }

    #[test]
    fn encrypted_value_roundtrip_encode_decode() {
        let ev = EncryptedValueV1 {
            key_id: "k1".to_string(),
            nonce: [7u8; 24],
            ct: vec![1, 2, 3],
        };
        let bytes = ev.encode();
        let back = EncryptedValueV1::decode(&bytes).expect("decode");
        assert_eq!(back.key_id, "k1");
        assert_eq!(back.nonce, [7u8; 24]);
        assert_eq!(back.ct, vec![1, 2, 3]);
    }

    #[test]
    fn encrypted_value_decode_rejects_plaintext() {
        let err = EncryptedValueV1::decode(b"hello").unwrap_err();
        assert!(matches!(err, EncryptedValueDecodeError::NotEncrypted));
    }

    #[test]
    fn ciphertext_tamper_fails() {
        // If the feature isn't enabled, skip: encryption helpers should error.
        if !cfg!(feature = "encryption-at-rest") {
            return;
        }

        let provider = Arc::new(TestProvider {
            k: MasterKey {
                key_id: "k1".to_string(),
                key_bytes: [9u8; 32],
            },
        });
        let c = SledValueCipher::new(provider, "hub-fin", false);
        let key = b"asset:abc";
        let pt = b"hello world";
        let enc = c.encrypt_value(key, pt).expect("encrypt");
        let mut enc2 = enc.clone();
        // flip last byte
        if let Some(x) = enc2.last_mut() {
            *x ^= 0x01;
        }
        let err = c.decrypt_value(key, &enc2).unwrap_err();
        assert!(matches!(err, EncryptionError::DecryptFailed(_)));
    }
}
