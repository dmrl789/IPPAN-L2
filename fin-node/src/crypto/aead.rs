#![forbid(unsafe_code)]

use l2_core::storage_encryption::EncryptionError;

/// Encrypt using XChaCha20-Poly1305.
///
/// Returns `(nonce_24, ciphertext)`.
pub fn encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; 24], Vec<u8>), EncryptionError> {
    match l2_core::storage_encryption::encrypt(key, plaintext, aad) {
        Ok(out) => {
            crate::metrics::ENCRYPTION_ENCRYPT_TOTAL.inc();
            Ok(out)
        }
        Err(e) => {
            crate::metrics::ENCRYPTION_FAILURES_TOTAL
                .with_label_values(&["encrypt"])
                .inc();
            Err(e)
        }
    }
}

/// Decrypt using XChaCha20-Poly1305.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    match l2_core::storage_encryption::decrypt(key, nonce, ciphertext, aad) {
        Ok(out) => {
            crate::metrics::ENCRYPTION_DECRYPT_TOTAL.inc();
            Ok(out)
        }
        Err(e) => {
            crate::metrics::ENCRYPTION_FAILURES_TOTAL
                .with_label_values(&["decrypt"])
                .inc();
            Err(e)
        }
    }
}
