#![forbid(unsafe_code)]

use crate::actions::{
    AppendAttestationV1, CreateListingV1, GrantEntitlementV1, IssueLicenseV1, RegisterDatasetV1,
};
use crate::types::{ActionId, AttestationId, DatasetId, LicenseId, ListingId};
use l2_core::hub_linkage::PurchaseId;
use sled::IVec;
use std::io::Write;
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

    /// List license ids by dataset in stable order with cursor pagination.
    ///
    /// - `after` is the last seen license id hex (exclusive).
    /// - Ordering is lexicographic by license id hex (via key ordering).
    pub fn list_license_ids_by_dataset_page(
        &self,
        dataset_id: DatasetId,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<LicenseId>, StoreError> {
        let prefix = keys::license_by_dataset_prefix(dataset_id);
        scan_index_tail_hex_page(&self.tree, &prefix, after, limit)
            .into_iter()
            .map(|hex| crate::types::Hex32::from_hex(&hex).map_err(StoreError::Decode))
            .collect()
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

    pub fn get_listing(
        &self,
        listing_id: ListingId,
    ) -> Result<Option<CreateListingV1>, StoreError> {
        let key = keys::listing(listing_id);
        let Some(v) = self.tree.get(key)? else {
            return Ok(None);
        };
        serde_json::from_slice::<CreateListingV1>(&v)
            .map(Some)
            .map_err(|e| StoreError::Decode(format!("failed decoding listing json: {e}")))
    }

    pub fn put_listing(&self, listing: &CreateListingV1) -> Result<(), StoreError> {
        let key = keys::listing(listing.listing_id);
        let bytes = serde_json::to_vec(listing)
            .map_err(|e| StoreError::Decode(format!("failed encoding listing json: {e}")))?;
        self.tree.insert(key, bytes)?;
        Ok(())
    }

    pub fn put_listing_index(
        &self,
        dataset_id: DatasetId,
        listing_id: ListingId,
    ) -> Result<(), StoreError> {
        self.tree.insert(
            keys::listing_by_dataset(dataset_id, listing_id),
            IVec::from(&b"1"[..]),
        )?;
        Ok(())
    }

    pub fn list_listing_ids_by_dataset(
        &self,
        dataset_id: DatasetId,
    ) -> Result<Vec<ListingId>, StoreError> {
        let prefix = keys::listing_by_dataset_prefix(dataset_id);
        let mut out = Vec::new();
        for r in self.tree.scan_prefix(prefix) {
            let (k, _) = r?;
            let s = String::from_utf8(k.to_vec())
                .map_err(|e| StoreError::Decode(format!("invalid utf8 key: {e}")))?;
            let (_, tail) = s
                .rsplit_once(':')
                .ok_or_else(|| StoreError::Decode("invalid listing_by_dataset key".to_string()))?;
            out.push(
                crate::types::Hex32::from_hex(tail)
                    .map_err(|e| StoreError::Decode(format!("invalid listing_id in key: {e}")))?,
            );
        }
        Ok(out)
    }

    pub fn list_listing_ids_by_dataset_page(
        &self,
        dataset_id: DatasetId,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ListingId>, StoreError> {
        let prefix = keys::listing_by_dataset_prefix(dataset_id);
        scan_index_tail_hex_page(&self.tree, &prefix, after, limit)
            .into_iter()
            .map(|hex| crate::types::Hex32::from_hex(&hex).map_err(StoreError::Decode))
            .collect()
    }

    pub fn list_listings_by_dataset(
        &self,
        dataset_id: DatasetId,
    ) -> Result<Vec<CreateListingV1>, StoreError> {
        let ids = self.list_listing_ids_by_dataset(dataset_id)?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(x) = self.get_listing(id)? {
                out.push(x);
            }
        }
        Ok(out)
    }

    pub fn get_entitlement(
        &self,
        purchase_id: PurchaseId,
    ) -> Result<Option<GrantEntitlementV1>, StoreError> {
        let key = keys::entitlement(purchase_id);
        let Some(v) = self.tree.get(key)? else {
            return Ok(None);
        };
        serde_json::from_slice::<GrantEntitlementV1>(&v)
            .map(Some)
            .map_err(|e| StoreError::Decode(format!("failed decoding entitlement json: {e}")))
    }

    pub fn put_entitlement(&self, ent: &GrantEntitlementV1) -> Result<(), StoreError> {
        let key = keys::entitlement(ent.purchase_id);
        let bytes = serde_json::to_vec(ent)
            .map_err(|e| StoreError::Decode(format!("failed encoding entitlement json: {e}")))?;
        self.tree.insert(key, bytes)?;
        Ok(())
    }

    pub fn put_entitlement_index_by_dataset(
        &self,
        dataset_id: DatasetId,
        purchase_id: PurchaseId,
    ) -> Result<(), StoreError> {
        self.tree.insert(
            keys::ent_by_dataset(dataset_id, purchase_id),
            IVec::from(&b"1"[..]),
        )?;
        Ok(())
    }

    pub fn put_entitlement_index_by_licensee(
        &self,
        licensee: &str,
        purchase_id: PurchaseId,
    ) -> Result<(), StoreError> {
        self.tree.insert(
            keys::ent_by_licensee(licensee, purchase_id),
            IVec::from(&b"1"[..]),
        )?;
        Ok(())
    }

    pub fn list_purchase_ids_by_dataset(
        &self,
        dataset_id: DatasetId,
    ) -> Result<Vec<PurchaseId>, StoreError> {
        let prefix = keys::ent_by_dataset_prefix(dataset_id);
        let mut out = Vec::new();
        for r in self.tree.scan_prefix(prefix) {
            let (k, _) = r?;
            let s = String::from_utf8(k.to_vec())
                .map_err(|e| StoreError::Decode(format!("invalid utf8 key: {e}")))?;
            let (_, tail) = s
                .rsplit_once(':')
                .ok_or_else(|| StoreError::Decode("invalid ent_by_dataset key".to_string()))?;
            out.push(PurchaseId::from_hex(tail).map_err(StoreError::Decode)?);
        }
        Ok(out)
    }

    pub fn list_purchase_ids_by_dataset_page(
        &self,
        dataset_id: DatasetId,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<PurchaseId>, StoreError> {
        let prefix = keys::ent_by_dataset_prefix(dataset_id);
        scan_index_tail_hex_page(&self.tree, &prefix, after, limit)
            .into_iter()
            .map(|hex| PurchaseId::from_hex(&hex).map_err(StoreError::Decode))
            .collect()
    }

    pub fn list_purchase_ids_by_licensee(
        &self,
        licensee: &str,
    ) -> Result<Vec<PurchaseId>, StoreError> {
        let prefix = keys::ent_by_licensee_prefix(licensee);
        let mut out = Vec::new();
        for r in self.tree.scan_prefix(prefix) {
            let (k, _) = r?;
            let s = String::from_utf8(k.to_vec())
                .map_err(|e| StoreError::Decode(format!("invalid utf8 key: {e}")))?;
            let (_, tail) = s
                .rsplit_once(':')
                .ok_or_else(|| StoreError::Decode("invalid ent_by_licensee key".to_string()))?;
            out.push(PurchaseId::from_hex(tail).map_err(StoreError::Decode)?);
        }
        Ok(out)
    }

    pub fn list_purchase_ids_by_licensee_page(
        &self,
        licensee: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<PurchaseId>, StoreError> {
        let prefix = keys::ent_by_licensee_prefix(licensee);
        scan_index_tail_hex_page(&self.tree, &prefix, after, limit)
            .into_iter()
            .map(|hex| PurchaseId::from_hex(&hex).map_err(StoreError::Decode))
            .collect()
    }

    pub fn list_entitlements_by_dataset(
        &self,
        dataset_id: DatasetId,
    ) -> Result<Vec<GrantEntitlementV1>, StoreError> {
        let ids = self.list_purchase_ids_by_dataset(dataset_id)?;
        let mut out = Vec::with_capacity(ids.len());
        for pid in ids {
            if let Some(x) = self.get_entitlement(pid)? {
                out.push(x);
            }
        }
        Ok(out)
    }

    pub fn list_entitlements_by_licensee(
        &self,
        licensee: &str,
    ) -> Result<Vec<GrantEntitlementV1>, StoreError> {
        let ids = self.list_purchase_ids_by_licensee(licensee)?;
        let mut out = Vec::with_capacity(ids.len());
        for pid in ids {
            if let Some(x) = self.get_entitlement(pid)? {
                out.push(x);
            }
        }
        Ok(out)
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

    pub fn list_attestation_ids_by_dataset_page(
        &self,
        dataset_id: DatasetId,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AttestationId>, StoreError> {
        let prefix = keys::attestation_by_dataset_prefix(dataset_id);
        scan_index_tail_hex_page(&self.tree, &prefix, after, limit)
            .into_iter()
            .map(|hex| {
                crate::types::Hex32::from_hex(&hex)
                    .map_err(|e| StoreError::Decode(format!("invalid attestation_id in key: {e}")))
            })
            .collect()
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

    pub fn get_state_version(&self) -> Result<Option<u32>, StoreError> {
        let Some(v) = self.tree.get(keys::state_version())? else {
            return Ok(None);
        };
        let s = String::from_utf8(v.to_vec())
            .map_err(|e| StoreError::Decode(format!("invalid utf8 state_version: {e}")))?;
        let n = s
            .parse::<u32>()
            .map_err(|e| StoreError::Decode(format!("invalid state_version integer: {e}")))?;
        Ok(Some(n))
    }

    pub fn set_state_version(&self, v: u32) -> Result<(), StoreError> {
        self.tree
            .insert(keys::state_version(), v.to_string().into_bytes())?;
        Ok(())
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

    /// Flush pending writes to disk (best-effort).
    pub fn flush(&self) -> Result<(), StoreError> {
        self.tree.flush()?;
        Ok(())
    }

    /// Export the underlying sled tree as a deterministic KV stream (v1).
    ///
    /// Format (repeated records, big-endian lengths):
    /// - u32 key_len
    /// - u32 val_len
    /// - key bytes
    /// - val bytes
    ///
    /// Ordering: lexicographic by raw key bytes (sled iteration order).
    ///
    /// This is intended for operational snapshots (audit/recovery), not consensus.
    pub fn export_kv_v1<W: Write>(&self, w: &mut W) -> Result<(), StoreError> {
        for r in self.tree.iter() {
            let (k, v) = r?;
            write_kv_record_v1(w, k.as_ref(), v.as_ref())
                .map_err(|e| StoreError::Decode(format!("kv export write failed: {e}")))?;
        }
        Ok(())
    }

    /// Clear the underlying tree (dangerous).
    ///
    /// Intended for snapshot restore with explicit operator confirmation.
    pub fn clear_all(&self) -> Result<(), StoreError> {
        self.tree.clear()?;
        Ok(())
    }

    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.tree.is_empty())
    }

    /// Import a deterministic KV stream written by `export_kv_v1`.
    ///
    /// This overwrites any existing keys found in the stream.
    pub fn import_kv_v1(bytes: &[u8], path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let store = Self::open(path)?;
        for (k, v) in read_kv_records_v1(bytes)
            .map_err(|e| StoreError::Decode(format!("kv import decode failed: {e}")))?
        {
            store.tree.insert(k, v)?;
        }
        Ok(store)
    }

    /// Import a deterministic KV stream written by `export_kv_v1` into this store.
    pub fn import_kv_v1_into(&self, bytes: &[u8]) -> Result<(), StoreError> {
        for (k, v) in read_kv_records_v1(bytes)
            .map_err(|e| StoreError::Decode(format!("kv import decode failed: {e}")))?
        {
            self.tree.insert(k, v)?;
        }
        Ok(())
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

    pub fn listing(listing_id: ListingId) -> Vec<u8> {
        format!("listing:{}", listing_id.to_hex()).into_bytes()
    }

    pub fn listing_by_dataset(dataset_id: DatasetId, listing_id: ListingId) -> Vec<u8> {
        format!(
            "listings_by_dataset:{}:{}",
            dataset_id.to_hex(),
            listing_id.to_hex()
        )
        .into_bytes()
    }

    pub fn listing_by_dataset_prefix(dataset_id: DatasetId) -> Vec<u8> {
        format!("listings_by_dataset:{}:", dataset_id.to_hex()).into_bytes()
    }

    pub fn licensor_allow(dataset_id: DatasetId, licensor: &str) -> Vec<u8> {
        format!("licensor_allow:{}:{licensor}", dataset_id.to_hex()).into_bytes()
    }

    pub fn attestor_allow(dataset_id: DatasetId, attestor: &str) -> Vec<u8> {
        format!("attestor_allow:{}:{attestor}", dataset_id.to_hex()).into_bytes()
    }

    pub fn entitlement(purchase_id: PurchaseId) -> Vec<u8> {
        format!("entitlement:{}", purchase_id.to_hex()).into_bytes()
    }

    pub fn ent_by_dataset(dataset_id: DatasetId, purchase_id: PurchaseId) -> Vec<u8> {
        format!(
            "ent_by_dataset:{}:{}",
            dataset_id.to_hex(),
            purchase_id.to_hex()
        )
        .into_bytes()
    }

    pub fn ent_by_dataset_prefix(dataset_id: DatasetId) -> Vec<u8> {
        format!("ent_by_dataset:{}:", dataset_id.to_hex()).into_bytes()
    }

    pub fn ent_by_licensee(licensee: &str, purchase_id: PurchaseId) -> Vec<u8> {
        format!("ent_by_licensee:{licensee}:{}", purchase_id.to_hex()).into_bytes()
    }

    pub fn ent_by_licensee_prefix(licensee: &str) -> Vec<u8> {
        format!("ent_by_licensee:{licensee}:").into_bytes()
    }

    pub fn applied(action_id: ActionId) -> Vec<u8> {
        format!("applied:{}", action_id.to_hex()).into_bytes()
    }

    pub fn state_version() -> &'static [u8] {
        b"state_version"
    }

    pub fn receipt(action_id: ActionId) -> Vec<u8> {
        format!("receipt:{}", action_id.to_hex()).into_bytes()
    }

    pub fn apply_receipt(action_id: ActionId) -> Vec<u8> {
        format!("apply_receipt:{}", action_id.to_hex()).into_bytes()
    }
}

fn scan_index_tail_hex_page(
    tree: &sled::Tree,
    prefix: &[u8],
    after: Option<&str>,
    limit: usize,
) -> Vec<String> {
    // Keys are ASCII strings of the form:
    //   "<prefix><hex>"
    // We iterate in lexicographic order.
    let start = if let Some(after) = after {
        let mut s = prefix.to_vec();
        s.extend_from_slice(after.as_bytes());
        // Ensure we start strictly after the cursor key.
        s.push(0);
        s
    } else {
        prefix.to_vec()
    };

    let mut out = Vec::new();
    for r in tree.range(start..) {
        let (k, _) = match r {
            Ok(x) => x,
            Err(_) => break,
        };
        if !k.starts_with(prefix) {
            break;
        }
        if out.len() >= limit {
            break;
        }
        let s = match std::str::from_utf8(k.as_ref()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let Some((_, tail)) = s.rsplit_once(':') else {
            continue;
        };
        out.push(tail.to_string());
    }
    out
}

#[cfg(test)]
mod pagination_tests {
    use super::*;

    #[test]
    fn license_ids_by_dataset_page_paginates_stably() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = DataStore::open(tmp.path()).expect("open");
        let did = crate::types::Hex32([0u8; 32]);

        // Insert 5 index keys with increasing license ids.
        for i in 1u8..=5u8 {
            let lid = crate::types::Hex32([i; 32]);
            store
                .tree
                .insert(keys::license_by_dataset(did, lid), IVec::from(&b"1"[..]))
                .expect("insert");
        }

        let page1 = store
            .list_license_ids_by_dataset_page(did, None, 2)
            .expect("page1");
        assert_eq!(page1.len(), 2);
        let after = page1.last().unwrap().to_hex();

        let page2 = store
            .list_license_ids_by_dataset_page(did, Some(&after), 2)
            .expect("page2");
        assert_eq!(page2.len(), 2);
        assert!(page2[0].to_hex() > after);
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

fn write_kv_record_v1<W: Write>(w: &mut W, k: &[u8], v: &[u8]) -> std::io::Result<()> {
    let k_len = u32::try_from(k.len()).unwrap_or(u32::MAX);
    let v_len = u32::try_from(v.len()).unwrap_or(u32::MAX);
    w.write_all(&k_len.to_be_bytes())?;
    w.write_all(&v_len.to_be_bytes())?;
    w.write_all(k)?;
    w.write_all(v)?;
    Ok(())
}

type KvPairs = Vec<(Vec<u8>, Vec<u8>)>;

fn read_kv_records_v1(mut bytes: &[u8]) -> Result<KvPairs, String> {
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 8 {
            return Err("truncated kv record header".to_string());
        }
        let k_len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let v_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
        bytes = &bytes[8..];
        if bytes.len() < k_len.saturating_add(v_len) {
            return Err("truncated kv record payload".to_string());
        }
        let k = bytes[..k_len].to_vec();
        let v = bytes[k_len..k_len + v_len].to_vec();
        bytes = &bytes[k_len + v_len..];
        out.push((k, v));
    }
    Ok(out)
}
