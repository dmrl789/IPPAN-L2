#![forbid(unsafe_code)]

use super::EncryptionError;

pub const NONCE_BYTES: usize = 24;

#[cfg(feature = "encryption-at-rest")]
fn random_nonce_24() -> Result<[u8; NONCE_BYTES], EncryptionError> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| EncryptionError::EncryptFailed(format!("nonce gen failed: {e}")))?;
    Ok(nonce)
}

#[cfg(not(feature = "encryption-at-rest"))]
fn random_nonce_24() -> Result<[u8; NONCE_BYTES], EncryptionError> {
    Err(EncryptionError::EncryptFailed(
        "encryption-at-rest feature not enabled".to_string(),
    ))
}

/// Encrypt with XChaCha20-Poly1305.
///
/// Returns `(nonce_24, ciphertext)`.
#[cfg(feature = "encryption-at-rest")]
pub fn encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; NONCE_BYTES], Vec<u8>), EncryptionError> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

    let nonce = random_nonce_24()?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| EncryptionError::EncryptFailed("aead encrypt failed".to_string()))?;
    Ok((nonce, ct))
}

#[cfg(not(feature = "encryption-at-rest"))]
pub fn encrypt(
    _key: &[u8; 32],
    _plaintext: &[u8],
    _aad: &[u8],
) -> Result<([u8; NONCE_BYTES], Vec<u8>), EncryptionError> {
    Err(EncryptionError::EncryptFailed(
        "encryption-at-rest feature not enabled".to_string(),
    ))
}

/// Decrypt with XChaCha20-Poly1305.
#[cfg(feature = "encryption-at-rest")]
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| EncryptionError::DecryptFailed("aead decrypt failed".to_string()))
}

#[cfg(not(feature = "encryption-at-rest"))]
pub fn decrypt(
    _key: &[u8; 32],
    _nonce: &[u8; NONCE_BYTES],
    _ciphertext: &[u8],
    _aad: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    Err(EncryptionError::DecryptFailed(
        "encryption-at-rest feature not enabled".to_string(),
    ))
}
