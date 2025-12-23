#![forbid(unsafe_code)]

use sled::IVec;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("db error: {0}")]
    Db(#[from] sled::Error),
}

#[derive(Debug, Clone)]
pub struct PolicyStore {
    tree: sled::Tree,
}

impl PolicyStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = sled::open(path)?;
        let tree = db.open_tree("fin-node-policy")?;
        Ok(Self { tree })
    }

    #[allow(dead_code)]
    pub fn open_temporary() -> Result<Self, StoreError> {
        let db = sled::Config::new().temporary(true).open()?;
        let tree = db.open_tree("fin-node-policy")?;
        Ok(Self { tree })
    }

    pub fn allow_add(&self, account: &str) -> Result<(), StoreError> {
        self.tree
            .insert(keys::compliance_allow(account), IVec::from(&b"1"[..]))?;
        Ok(())
    }

    pub fn allow_remove(&self, account: &str) -> Result<(), StoreError> {
        let _ = self.tree.remove(keys::compliance_allow(account))?;
        Ok(())
    }

    pub fn deny_add(&self, account: &str) -> Result<(), StoreError> {
        self.tree
            .insert(keys::compliance_deny(account), IVec::from(&b"1"[..]))?;
        Ok(())
    }

    pub fn deny_remove(&self, account: &str) -> Result<(), StoreError> {
        let _ = self.tree.remove(keys::compliance_deny(account))?;
        Ok(())
    }

    pub fn is_allowlisted(&self, account: &str) -> Result<bool, StoreError> {
        Ok(self.tree.contains_key(keys::compliance_allow(account))?)
    }

    pub fn is_denylisted(&self, account: &str) -> Result<bool, StoreError> {
        Ok(self.tree.contains_key(keys::compliance_deny(account))?)
    }

    pub fn counts(&self) -> Result<(usize, usize), StoreError> {
        let mut allow = 0usize;
        for r in self.tree.scan_prefix(keys::compliance_allow_prefix()) {
            let _ = r?;
            allow += 1;
        }
        let mut deny = 0usize;
        for r in self.tree.scan_prefix(keys::compliance_deny_prefix()) {
            let _ = r?;
            deny += 1;
        }
        Ok((allow, deny))
    }
}

pub mod keys {
    pub fn compliance_allow(account: &str) -> Vec<u8> {
        format!("compliance_allow:{account}").into_bytes()
    }

    pub fn compliance_allow_prefix() -> &'static [u8] {
        b"compliance_allow:"
    }

    pub fn compliance_deny(account: &str) -> Vec<u8> {
        format!("compliance_deny:{account}").into_bytes()
    }

    pub fn compliance_deny_prefix() -> &'static [u8] {
        b"compliance_deny:"
    }
}
