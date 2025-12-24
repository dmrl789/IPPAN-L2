#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::disallowed_types)]

use std::path::Path;

use l2_core::{canonical_decode, canonical_encode, canonical_hash, Batch, Hash32, Receipt, Tx};
use sled::Tree;
use thiserror::Error;
use tracing::info;

pub const SCHEMA_VERSION: &str = "1";
const META_SCHEMA_KEY: &[u8] = b"schema_version";

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage error: {0}")]
    Sled(#[from] sled::Error),
    #[error("canonical encoding error: {0}")]
    Canonical(#[from] l2_core::CanonicalError),
    #[error("schema mismatch: expected {expected}, found {found:?}")]
    SchemaMismatch {
        expected: String,
        found: Option<String>,
    },
}

pub struct Storage {
    #[allow(dead_code)]
    db: sled::Db,
    tx_pool: Tree,
    batches: Tree,
    receipts: Tree,
    meta: Tree,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let db = sled::open(path)?;
        let tx_pool = db.open_tree("tx_pool")?;
        let batches = db.open_tree("batches")?;
        let receipts = db.open_tree("receipts")?;
        let meta = db.open_tree("meta")?;
        let storage = Self {
            db,
            tx_pool,
            batches,
            receipts,
            meta,
        };
        storage.init_schema()?;
        Ok(storage)
    }

    pub fn put_tx(&self, tx: &Tx) -> Result<Hash32, StorageError> {
        let hash = canonical_hash(tx)?;
        let bytes = canonical_encode(tx)?;
        self.tx_pool.insert(hash.0, bytes)?;
        Ok(hash)
    }

    pub fn get_tx(&self, hash: &Hash32) -> Result<Option<Tx>, StorageError> {
        self.tx_pool
            .get(hash.0)
            .map(|opt| opt.map(|ivec| canonical_decode(&ivec)))?
            .transpose()
            .map_err(Into::into)
    }

    pub fn put_batch(&self, batch: &Batch) -> Result<Hash32, StorageError> {
        let hash = canonical_hash(batch)?;
        let bytes = canonical_encode(batch)?;
        self.batches.insert(hash.0, bytes)?;
        Ok(hash)
    }

    pub fn get_batch(&self, hash: &Hash32) -> Result<Option<Batch>, StorageError> {
        self.batches
            .get(hash.0)
            .map(|opt| opt.map(|ivec| canonical_decode(&ivec)))?
            .transpose()
            .map_err(Into::into)
    }

    pub fn put_receipt(&self, receipt: &Receipt) -> Result<(), StorageError> {
        let bytes = canonical_encode(receipt)?;
        self.receipts.insert(receipt.tx_hash.0, bytes)?;
        Ok(())
    }

    pub fn get_receipt(&self, hash: &Hash32) -> Result<Option<Receipt>, StorageError> {
        self.receipts
            .get(hash.0)
            .map(|opt| opt.map(|ivec| canonical_decode(&ivec)))?
            .transpose()
            .map_err(Into::into)
    }

    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.meta.insert(key.as_bytes(), value)?;
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.meta.get(key.as_bytes())?.map(|ivec| ivec.to_vec()))
    }

    fn init_schema(&self) -> Result<(), StorageError> {
        let existing = self.meta.get(META_SCHEMA_KEY)?;
        match existing {
            Some(val) => {
                let current = String::from_utf8_lossy(&val).to_string();
                if current != SCHEMA_VERSION {
                    return Err(StorageError::SchemaMismatch {
                        expected: SCHEMA_VERSION.to_string(),
                        found: Some(current),
                    });
                }
            }
            None => {
                self.meta
                    .insert(META_SCHEMA_KEY, SCHEMA_VERSION.as_bytes())?;
                info!(schema = SCHEMA_VERSION, "initialized schema version");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_core::ChainId;
    use tempfile::tempdir;

    #[test]
    fn store_and_load_tx() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");
        let tx = Tx {
            chain_id: ChainId(1),
            nonce: 1,
            from: "alice".to_string(),
            payload: vec![1, 2, 3],
        };
        let hash = storage.put_tx(&tx).expect("put");
        let loaded = storage.get_tx(&hash).expect("get").expect("present");
        assert_eq!(loaded, tx);
    }

    #[test]
    fn schema_version_is_enforced() {
        let dir = tempdir().expect("tmpdir");
        {
            let storage = Storage::open(dir.path()).expect("open");
            storage
                .meta
                .insert(META_SCHEMA_KEY, b"999")
                .expect("overwrite");
            storage.meta.flush().expect("flush");
        }
        // Drop storage to ensure write is persisted
        let reopened = Storage::open(dir.path());
        assert!(matches!(reopened, Err(StorageError::SchemaMismatch { .. })));
    }
}
