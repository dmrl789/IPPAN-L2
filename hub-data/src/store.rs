#![forbid(unsafe_code)]

use crate::actions::{AppendAttestationV1, IssueLicenseV1, RegisterDatasetV1};
use crate::types::{ActionId, AttestationId, DatasetId, LicenseId};
use sled::IVec;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("db error: {0}")]
    Db(#[from] sled::Error),
    #[error("decode error: {0}")]
    Decode(String),
}

#[derive(Debug, Clone)]
pub struct DataStore {
    tree: sled::Tree,
}

impl DataStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = sled::open(path)?;
        let tree = db.open_tree("hub-data")?;
        Ok(Self { tree })
    }

    pub fn get_dataset(
        &self,
        dataset_id: DatasetId,
    ) -> Result<Option<RegisterDatasetV1>, StoreError> {
        let key = keys::dataset(dataset_id);
        let Some(v) = self.tree.get(key)? else {
            return Ok(None);
        };
        serde_json::from_slice::<RegisterDatasetV1>(&v)
            .map(Some)
            .map_err(|e| StoreError::Decode(format!("failed decoding dataset json: {e}")))
    }

    pub fn put_dataset(&self, dataset: &RegisterDatasetV1) -> Result<(), StoreError> {
        let key = keys::dataset(dataset.dataset_id);
        let bytes = serde_json::to_vec(dataset)
            .map_err(|e| StoreError::Decode(format!("failed encoding dataset json: {e}")))?;
        self.tree.insert(key, bytes)?;
        Ok(())
    }

    pub fn list_dataset_ids(&self) -> Result<Vec<DatasetId>, StoreError> {
        let mut out = Vec::new();
        for r in self.tree.scan_prefix(keys::dataset_prefix()) {
            let (k, _) = r?;
            let s = String::from_utf8(k.to_vec())
                .map_err(|e| StoreError::Decode(format!("invalid utf8 key: {e}")))?;
            let (_, tail) = s
                .split_once(':')
                .ok_or_else(|| StoreError::Decode("invalid dataset key".to_string()))?;
            out.push(
                crate::types::Hex32::from_hex(tail)
                    .map_err(|e| StoreError::Decode(format!("invalid dataset_id in key: {e}")))?,
            );
        }
        Ok(out)
    }

    pub fn get_license(&self, license_id: LicenseId) -> Result<Option<IssueLicenseV1>, StoreError> {
        let key = keys::license(license_id);
        let Some(v) = self.tree.get(key)? else {
            return Ok(None);
        };
        serde_json::from_slice::<IssueLicenseV1>(&v)
            .map(Some)
            .map_err(|e| StoreError::Decode(format!("failed decoding license json: {e}")))
    }

    pub fn put_license(&self, license: &IssueLicenseV1) -> Result<(), StoreError> {
        let key = keys::license(license.license_id);
        let bytes = serde_json::to_vec(license)
            .map_err(|e| StoreError::Decode(format!("failed encoding license json: {e}")))?;
        self.tree.insert(key, bytes)?;
        Ok(())
    }

    pub fn put_license_index(
        &self,
        dataset_id: DatasetId,
        license_id: LicenseId,
    ) -> Result<(), StoreError> {
        self.tree.insert(
            keys::license_by_dataset(dataset_id, license_id),
            IVec::from(&b"1"[..]),
        )?;
        Ok(())
    }

    pub fn list_license_ids_by_dataset(
        &self,
        dataset_id: DatasetId,
    ) -> Result<Vec<LicenseId>, StoreError> {
        let prefix = keys::license_by_dataset_prefix(dataset_id);
        let mut out = Vec::new();
        for r in self.tree.scan_prefix(prefix) {
            let (k, _) = r?;
            let s = String::from_utf8(k.to_vec())
                .map_err(|e| StoreError::Decode(format!("invalid utf8 key: {e}")))?;
            let (_, tail) = s
                .rsplit_once(':')
                .ok_or_else(|| StoreError::Decode("invalid lic_by_dataset key".to_string()))?;
            out.push(
                crate::types::Hex32::from_hex(tail)
                    .map_err(|e| StoreError::Decode(format!("invalid license_id in key: {e}")))?,
            );
        }
        Ok(out)
    }

    pub fn list_licenses_by_dataset(
        &self,
        dataset_id: DatasetId,
    ) -> Result<Vec<IssueLicenseV1>, StoreError> {
        let ids = self.list_license_ids_by_dataset(dataset_id)?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(l) = self.get_license(id)? {
                out.push(l);
            }
        }
        Ok(out)
    }

    pub fn get_attestation(
        &self,
        attestation_id: AttestationId,
    ) -> Result<Option<AppendAttestationV1>, StoreError> {
        let key = keys::attestation(attestation_id);
        let Some(v) = self.tree.get(key)? else {
            return Ok(None);
        };
        serde_json::from_slice::<AppendAttestationV1>(&v)
            .map(Some)
            .map_err(|e| StoreError::Decode(format!("failed decoding attestation json: {e}")))
    }

    pub fn put_attestation(&self, att: &AppendAttestationV1) -> Result<(), StoreError> {
        let key = keys::attestation(att.attestation_id);
        let bytes = serde_json::to_vec(att)
            .map_err(|e| StoreError::Decode(format!("failed encoding attestation json: {e}")))?;
        self.tree.insert(key, bytes)?;
        Ok(())
    }

    pub fn put_attestation_index(
        &self,
        dataset_id: DatasetId,
        attestation_id: AttestationId,
    ) -> Result<(), StoreError> {
        self.tree.insert(
            keys::attestation_by_dataset(dataset_id, attestation_id),
            IVec::from(&b"1"[..]),
        )?;
        Ok(())
    }

    pub fn list_attestation_ids_by_dataset(
        &self,
        dataset_id: DatasetId,
    ) -> Result<Vec<AttestationId>, StoreError> {
        let prefix = keys::attestation_by_dataset_prefix(dataset_id);
        let mut out = Vec::new();
        for r in self.tree.scan_prefix(prefix) {
            let (k, _) = r?;
            let s = String::from_utf8(k.to_vec())
                .map_err(|e| StoreError::Decode(format!("invalid utf8 key: {e}")))?;
            let (_, tail) = s
                .rsplit_once(':')
                .ok_or_else(|| StoreError::Decode("invalid att_by_dataset key".to_string()))?;
            out.push(
                crate::types::Hex32::from_hex(tail).map_err(|e| {
                    StoreError::Decode(format!("invalid attestation_id in key: {e}"))
                })?,
            );
        }
        Ok(out)
    }

    pub fn list_attestations_by_dataset(
        &self,
        dataset_id: DatasetId,
    ) -> Result<Vec<AppendAttestationV1>, StoreError> {
        let ids = self.list_attestation_ids_by_dataset(dataset_id)?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(a) = self.get_attestation(id)? {
                out.push(a);
            }
        }
        Ok(out)
    }

    /// Export a deterministic, audit-friendly state snapshot (v1).
    ///
    /// - Deterministic ordering (sorted by dataset_id, then by license/attestation id).
    /// - No timestamps are included in the snapshot.
    pub fn export_snapshot_v1(&self) -> Result<DataStateSnapshotV1, StoreError> {
        let dataset_ids = self.list_dataset_ids()?;
        let mut datasets = Vec::with_capacity(dataset_ids.len());
        for did in dataset_ids {
            let dataset = self.get_dataset(did)?.ok_or_else(|| {
                StoreError::Decode("dataset disappeared during snapshot".to_string())
            })?;
            let licenses = self.list_licenses_by_dataset(did)?;
            let attestations = self.list_attestations_by_dataset(did)?;
            datasets.push(DatasetSnapshotV1 {
                dataset,
                licenses,
                attestations,
            });
        }
        Ok(DataStateSnapshotV1 {
            schema_version: 1,
            datasets,
        })
    }

    pub fn is_applied(&self, action_id: ActionId) -> Result<bool, StoreError> {
        Ok(self.tree.contains_key(keys::applied(action_id))?)
    }

    pub fn mark_applied(&self, action_id: ActionId) -> Result<(), StoreError> {
        self.tree
            .insert(keys::applied(action_id), IVec::from(&b"1"[..]))?;
        Ok(())
    }

    pub fn put_apply_receipt(
        &self,
        action_id: ActionId,
        receipt_json: &[u8],
    ) -> Result<(), StoreError> {
        self.tree
            .insert(keys::apply_receipt(action_id), receipt_json)?;
        Ok(())
    }

    pub fn get_apply_receipt(&self, action_id: ActionId) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .tree
            .get(keys::apply_receipt(action_id))?
            .map(|v| v.to_vec()))
    }

    /// Store a fin-node receipt (includes L1 submission metadata).
    pub fn put_final_receipt(
        &self,
        action_id: ActionId,
        receipt_json: &[u8],
    ) -> Result<(), StoreError> {
        self.tree.insert(keys::receipt(action_id), receipt_json)?;
        Ok(())
    }

    pub fn get_final_receipt(&self, action_id: ActionId) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.tree.get(keys::receipt(action_id))?.map(|v| v.to_vec()))
    }

    pub(crate) fn tree(&self) -> &sled::Tree {
        &self.tree
    }
}

pub mod keys {
    use super::*;

    pub fn dataset(dataset_id: DatasetId) -> Vec<u8> {
        format!("dataset:{}", dataset_id.to_hex()).into_bytes()
    }

    pub fn dataset_prefix() -> &'static [u8] {
        b"dataset:"
    }

    pub fn license(license_id: LicenseId) -> Vec<u8> {
        format!("license:{}", license_id.to_hex()).into_bytes()
    }

    pub fn license_by_dataset(dataset_id: DatasetId, license_id: LicenseId) -> Vec<u8> {
        format!(
            "lic_by_dataset:{}:{}",
            dataset_id.to_hex(),
            license_id.to_hex()
        )
        .into_bytes()
    }

    pub fn license_by_dataset_prefix(dataset_id: DatasetId) -> Vec<u8> {
        format!("lic_by_dataset:{}:", dataset_id.to_hex()).into_bytes()
    }

    pub fn attestation(attestation_id: AttestationId) -> Vec<u8> {
        format!("attest:{}", attestation_id.to_hex()).into_bytes()
    }

    pub fn attestation_by_dataset(dataset_id: DatasetId, attestation_id: AttestationId) -> Vec<u8> {
        format!(
            "att_by_dataset:{}:{}",
            dataset_id.to_hex(),
            attestation_id.to_hex()
        )
        .into_bytes()
    }

    pub fn attestation_by_dataset_prefix(dataset_id: DatasetId) -> Vec<u8> {
        format!("att_by_dataset:{}:", dataset_id.to_hex()).into_bytes()
    }

    pub fn applied(action_id: ActionId) -> Vec<u8> {
        format!("applied:{}", action_id.to_hex()).into_bytes()
    }

    pub fn receipt(action_id: ActionId) -> Vec<u8> {
        format!("receipt:{}", action_id.to_hex()).into_bytes()
    }

    pub fn apply_receipt(action_id: ActionId) -> Vec<u8> {
        format!("apply_receipt:{}", action_id.to_hex()).into_bytes()
    }
}

/// Deterministic export schema (v1).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DataStateSnapshotV1 {
    pub schema_version: u32,
    pub datasets: Vec<DatasetSnapshotV1>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DatasetSnapshotV1 {
    pub dataset: RegisterDatasetV1,
    pub licenses: Vec<IssueLicenseV1>,
    pub attestations: Vec<AppendAttestationV1>,
}
