#![forbid(unsafe_code)]

use base64::Engine as _;
use l2_core::storage_encryption::{EncryptionError, KeyProvider};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ArchiveCryptoError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Crypto(String),
    #[error("ENCRYPTION_UNSUPPORTED_VERSION: {0}")]
    UnsupportedVersion(String),
    #[error("invalid encrypted archive: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedArchiveHeaderV1 {
    pub schema_version: u32,
    pub inner_type: String,
    pub key_id: String,
    pub nonce_b64: String,
    pub aad_b64: String,
}

pub const ENCRYPTED_ARCHIVE_SCHEMA_V1: u32 = 1;

/// Write an encrypted archive as a deterministic tar with:
/// - header.json (metadata)
/// - payload.bin (ciphertext)
pub fn write_encrypted_archive_v1(
    out_path: &Path,
    provider: &dyn KeyProvider,
    inner_type: &str,
    aad: &[u8],
    plaintext_payload: &[u8],
) -> Result<EncryptedArchiveHeaderV1, ArchiveCryptoError> {
    let key = provider
        .current_key()
        .map_err(|e| ArchiveCryptoError::Crypto(e.to_string()))?;

    let (nonce, ct) = crate::crypto::aead::encrypt(&key.key_bytes, plaintext_payload, aad)
        .map_err(|e| ArchiveCryptoError::Crypto(e.to_string()))?;

    let header = EncryptedArchiveHeaderV1 {
        schema_version: ENCRYPTED_ARCHIVE_SCHEMA_V1,
        inner_type: inner_type.to_string(),
        key_id: key.key_id,
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce),
        aad_b64: base64::engine::general_purpose::STANDARD.encode(aad),
    };

    let header_bytes = serde_json::to_vec_pretty(&header)?;
    write_tar_atomic(
        out_path,
        &[("header.json", &header_bytes), ("payload.bin", &ct)],
    )?;
    Ok(header)
}

/// Read and decrypt an encrypted archive tar produced by `write_encrypted_archive_v1`.
pub fn read_encrypted_archive_v1(
    from_path: &Path,
    provider: &dyn KeyProvider,
    expected_inner_type: Option<&str>,
) -> Result<(EncryptedArchiveHeaderV1, Vec<u8>), ArchiveCryptoError> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    extract_tar(from_path, root)?;

    let header_raw = fs::read(root.join("header.json"))?;
    let header: EncryptedArchiveHeaderV1 = serde_json::from_slice(&header_raw)?;
    if header.schema_version != ENCRYPTED_ARCHIVE_SCHEMA_V1 {
        return Err(ArchiveCryptoError::UnsupportedVersion(format!(
            "archive schema_version={}",
            header.schema_version
        )));
    }
    if let Some(t) = expected_inner_type {
        if header.inner_type != t {
            return Err(ArchiveCryptoError::Invalid(format!(
                "inner_type mismatch: expected {t}, got {}",
                header.inner_type
            )));
        }
    }

    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(&header.nonce_b64)
        .map_err(|e| ArchiveCryptoError::Invalid(format!("invalid nonce_b64: {e}")))?;
    let aad = base64::engine::general_purpose::STANDARD
        .decode(&header.aad_b64)
        .map_err(|e| ArchiveCryptoError::Invalid(format!("invalid aad_b64: {e}")))?;
    if nonce_bytes.len() != 24 {
        return Err(ArchiveCryptoError::Invalid(format!(
            "invalid nonce length: {}",
            nonce_bytes.len()
        )));
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes);

    let ct = fs::read(root.join("payload.bin"))?;
    let key = provider
        .key_by_id(&header.key_id)
        .map_err(|e| ArchiveCryptoError::Crypto(e.to_string()))?;

    let pt =
        crate::crypto::aead::decrypt(&key.key_bytes, &nonce, &ct, &aad).map_err(|e| match e {
            EncryptionError::UnsupportedVersion(s) => ArchiveCryptoError::UnsupportedVersion(s),
            _ => ArchiveCryptoError::Crypto(e.to_string()),
        })?;
    Ok((header, pt))
}

fn extract_tar(src: &Path, dst: &Path) -> Result<(), ArchiveCryptoError> {
    let f = fs::File::open(src)?;
    let mut ar = tar::Archive::new(f);
    ar.unpack(dst)?;
    Ok(())
}

fn write_tar_atomic(out_path: &Path, files: &[(&str, &[u8])]) -> Result<(), ArchiveCryptoError> {
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let tmp_path = out_path.with_extension("tmp");
    let file = fs::File::create(&tmp_path)?;
    let mut builder = tar::Builder::new(file);

    // Deterministic ordering by file name.
    let mut sorted = files.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (name, bytes) in sorted {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder.append_data(&mut header, name, std::io::Cursor::new(bytes))?;
    }
    builder.finish()?;
    fs::rename(&tmp_path, out_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_core::storage_encryption::{KeyProviderError, MasterKey};

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
    fn encrypted_archive_roundtrip() {
        if !cfg!(feature = "encryption-at-rest") {
            return;
        }
        let tmp = tempfile::tempdir().expect("tmp");
        let out = tmp.path().join("x.tar");
        let p = TestProvider {
            k: MasterKey {
                key_id: "k1".to_string(),
                key_bytes: [3u8; 32],
            },
        };
        let aad = b"type=snapshot;hash=abc;v=1";
        let payload = b"hello";
        write_encrypted_archive_v1(&out, &p, "snapshot", aad, payload).expect("write");
        let (_hdr, pt) = read_encrypted_archive_v1(&out, &p, Some("snapshot")).expect("read");
        assert_eq!(pt, payload);
    }
}
