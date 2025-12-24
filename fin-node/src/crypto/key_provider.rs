#![forbid(unsafe_code)]

use l2_core::storage_encryption::{KeyProvider, KeyProviderError, MasterKey};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::warn;

use crate::config::EncryptionConfig;

/// File-backed master key provider.
///
/// - `key_path` contains 32-byte hex (64 hex chars), whitespace allowed.
/// - `old_keys_dir` may contain historical keys for decrypting old data.
///   Expected file names: `<key_id>.key` or `<key_id>`.
#[derive(Clone, Debug)]
pub struct FileKeyProvider {
    key_id: String,
    key_path: PathBuf,
    old_keys_dir: Option<PathBuf>,
    /// Ordered list of acceptable key ids for decrypt lookup (newest first).
    keyring: Vec<String>,
}

impl FileKeyProvider {
    pub fn new(
        key_id: impl Into<String>,
        key_path: impl Into<PathBuf>,
        old_keys_dir: Option<PathBuf>,
        keyring: Vec<String>,
    ) -> Result<Self, KeyProviderError> {
        let key_id = key_id.into();
        if key_id.trim().is_empty() {
            return Err(KeyProviderError::Other(
                "encryption.key_id is empty".to_string(),
            ));
        }
        let key_path = key_path.into();
        if keyring.is_empty() {
            return Err(KeyProviderError::Other(
                "encryption.keyring must include at least the current key id".to_string(),
            ));
        }
        // Best-effort startup validation: current key must be readable + parseable.
        let _ = read_key_hex_file(&key_path)?;
        warn_if_perms_too_open(&key_path);

        if let Some(dir) = old_keys_dir.as_ref() {
            warn_if_dir_perms_too_open(dir);
        }

        let p = Self {
            key_id,
            key_path,
            old_keys_dir,
            keyring,
        };

        // Validate that each keyring id is resolvable (without printing key bytes).
        for id in &p.keyring {
            let _ = p.key_by_id(id)?;
        }
        Ok(p)
    }

    fn old_key_candidates(&self, id: &str) -> Vec<PathBuf> {
        let Some(dir) = self.old_keys_dir.as_ref() else {
            return Vec::new();
        };
        vec![dir.join(format!("{id}.key")), dir.join(id)]
    }
}

impl KeyProvider for FileKeyProvider {
    fn current_key(&self) -> Result<MasterKey, KeyProviderError> {
        let key_bytes = read_key_hex_file(&self.key_path)?;
        Ok(MasterKey {
            key_id: self.key_id.clone(),
            key_bytes,
        })
    }

    fn key_by_id(&self, id: &str) -> Result<MasterKey, KeyProviderError> {
        if id == self.key_id {
            return self.current_key();
        }
        for cand in self.old_key_candidates(id) {
            if cand.exists() {
                warn_if_perms_too_open(&cand);
                let key_bytes = read_key_hex_file(&cand)?;
                return Ok(MasterKey {
                    key_id: id.to_string(),
                    key_bytes,
                });
            }
        }
        Err(KeyProviderError::MissingKey(id.to_string()))
    }
}

pub fn read_key_hex_file(path: &Path) -> Result<[u8; 32], KeyProviderError> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        KeyProviderError::Other(format!("failed reading key file {}: {e}", path.display()))
    })?;
    let s = raw.trim();
    let bytes = hex::decode(s).map_err(|e| {
        KeyProviderError::Other(format!("invalid key hex in {}: {e}", path.display()))
    })?;
    if bytes.len() != 32 {
        return Err(KeyProviderError::Other(format!(
            "invalid key length in {}: expected 32 bytes, got {}",
            path.display(),
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn warn_if_perms_too_open(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if (mode & 0o077) != 0 {
                warn!(
                    key_path = %path.display(),
                    mode = format!("{mode:o}"),
                    "encryption key file permissions are too open (recommend 0400 or 0600)"
                );
            }
        }
    }
}

fn warn_if_dir_perms_too_open(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if (mode & 0o077) != 0 {
                warn!(
                    dir = %path.display(),
                    mode = format!("{mode:o}"),
                    "encryption key directory permissions are too open (recommend 0700)"
                );
            }
        }
    }
}

pub type SharedKeyProvider = Arc<dyn KeyProvider>;

pub fn build_from_config(cfg: &EncryptionConfig) -> Result<Option<SharedKeyProvider>, String> {
    if !cfg.enabled {
        return Ok(None);
    }
    if !cfg!(feature = "encryption-at-rest") {
        return Err(
            "encryption.enabled=true requires building fin-node with feature encryption-at-rest"
                .to_string(),
        );
    }
    if cfg.provider.trim() != "file" {
        return Err(format!(
            "unsupported encryption provider: {} (supported: file)",
            cfg.provider.trim()
        ));
    }
    let old_dir = if cfg.old_keys_dir.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(cfg.old_keys_dir.trim()))
    };
    let provider = FileKeyProvider::new(
        cfg.key_id.trim(),
        PathBuf::from(cfg.key_path.trim()),
        old_dir,
        cfg.keyring.clone(),
    )
    .map_err(|e| e.to_string())?;
    Ok(Some(Arc::new(provider)))
}
