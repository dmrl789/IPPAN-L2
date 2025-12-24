#![forbid(unsafe_code)]

use crate::crypto::key_provider::SharedKeyProvider;
use l2_core::storage_encryption::{EncryptedValueV1, KeyProvider, SledValueCipher};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum EncryptToolError {
    #[error("db error: {0}")]
    Db(#[from] sled::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encrypt error: {0}")]
    Encrypt(String),
}

pub struct MigrateResult {
    pub scanned: u64,
    pub plaintext: u64,
    pub already_encrypted: u64,
    pub updated: u64,
}

/// Encrypt plaintext values in a sled tree in deterministic key order.
pub fn migrate_tree(
    db_dir: &str,
    tree_name: &str,
    provider: SharedKeyProvider,
    execute: bool,
) -> Result<MigrateResult, EncryptToolError> {
    let db = sled::open(db_dir)?;
    let tree = db.open_tree(tree_name)?;
    let cipher = SledValueCipher::new(provider, tree_name, true);

    // Collect first to avoid mutation during iteration borrow.
    let mut items: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for r in tree.iter() {
        let (k, v) = r?;
        items.push((k.to_vec(), v.to_vec()));
    }

    let mut res = MigrateResult {
        scanned: 0,
        plaintext: 0,
        already_encrypted: 0,
        updated: 0,
    };

    for (k, v) in items {
        res.scanned = res.scanned.saturating_add(1);
        if EncryptedValueV1::is_encrypted(&v) {
            res.already_encrypted = res.already_encrypted.saturating_add(1);
            continue;
        }
        res.plaintext = res.plaintext.saturating_add(1);
        if execute {
            let stored = cipher
                .encrypt_value(&k, &v)
                .map_err(|e| EncryptToolError::Encrypt(e.to_string()))?;
            tree.insert(k, stored)?;
            res.updated = res.updated.saturating_add(1);
        }
    }
    Ok(res)
}

pub struct RewrapResult {
    pub scanned: u64,
    pub rewrapped: u64,
    pub skipped_plaintext: u64,
    pub skipped_already_target: u64,
}

/// Re-encrypt encrypted values to `to_key_id`.
///
/// Plaintext values are skipped (use migrate first).
pub fn rewrap_tree(
    db_dir: &str,
    tree_name: &str,
    provider: SharedKeyProvider,
    to_key_id: &str,
    execute: bool,
) -> Result<RewrapResult, EncryptToolError> {
    let started = std::time::Instant::now();
    let db = sled::open(db_dir)?;
    let tree = db.open_tree(tree_name)?;

    // Two ciphers:
    // - old: decrypt by key_id in value header
    // - new: encrypt using pinned "current" key id
    let decrypt_cipher = SledValueCipher::new(provider.clone(), tree_name, false);
    let encrypt_cipher = SledValueCipher::new(
        Arc::new(PinnedKeyProvider {
            inner: provider.clone(),
            pinned_id: to_key_id.to_string(),
        }),
        tree_name,
        false,
    );

    let mut items: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for r in tree.iter() {
        let (k, v) = r?;
        items.push((k.to_vec(), v.to_vec()));
    }

    let mut res = RewrapResult {
        scanned: 0,
        rewrapped: 0,
        skipped_plaintext: 0,
        skipped_already_target: 0,
    };

    for (k, v) in items {
        res.scanned = res.scanned.saturating_add(1);
        let ev = match EncryptedValueV1::decode(&v) {
            Ok(ev) => ev,
            Err(_) => {
                res.skipped_plaintext = res.skipped_plaintext.saturating_add(1);
                continue;
            }
        };
        if ev.key_id == to_key_id {
            res.skipped_already_target = res.skipped_already_target.saturating_add(1);
            continue;
        }

        let plain = decrypt_cipher
            .decrypt_value(&k, &v)
            .map_err(|e| EncryptToolError::Encrypt(e.to_string()))?;
        let new_stored = encrypt_cipher
            .encrypt_value(&k, &plain)
            .map_err(|e| EncryptToolError::Encrypt(e.to_string()))?;
        if execute {
            tree.insert(k, new_stored)?;
        }
        res.rewrapped = res.rewrapped.saturating_add(1);
    }
    crate::metrics::ENCRYPTION_REWRAP_SECONDS
        .with_label_values(&[tree_name])
        .observe(started.elapsed().as_secs_f64());
    Ok(res)
}

/// Generate a new 32-byte master key and write it as hex.
///
/// Returns the key bytes (caller should NOT print them).
pub fn generate_and_write_key_hex(path: &Path, force: bool) -> Result<[u8; 32], EncryptToolError> {
    if path.exists() && !force {
        return Err(EncryptToolError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "key file exists (use --force to overwrite)",
        )));
    }
    let mut key = [0u8; 32];
    #[cfg(feature = "encryption-at-rest")]
    {
        getrandom::getrandom(&mut key)
            .map_err(|e| EncryptToolError::Encrypt(format!("key gen failed: {e}")))?;
    }
    #[cfg(not(feature = "encryption-at-rest"))]
    {
        let _ = force;
        return Err(EncryptToolError::Encrypt(
            "encryption-at-rest feature not enabled".to_string(),
        ));
    }

    let hex = hex::encode(key);
    std::fs::write(path, format!("{hex}\n"))?;

    // Best-effort permission hardening.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(key)
}

struct PinnedKeyProvider {
    inner: SharedKeyProvider,
    pinned_id: String,
}

impl KeyProvider for PinnedKeyProvider {
    fn current_key(
        &self,
    ) -> Result<l2_core::storage_encryption::MasterKey, l2_core::storage_encryption::KeyProviderError>
    {
        self.inner.key_by_id(&self.pinned_id)
    }
    fn key_by_id(
        &self,
        id: &str,
    ) -> Result<l2_core::storage_encryption::MasterKey, l2_core::storage_encryption::KeyProviderError>
    {
        self.inner.key_by_id(id)
    }
}
