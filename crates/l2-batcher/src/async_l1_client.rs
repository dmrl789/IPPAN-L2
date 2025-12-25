//! Async adapter for the L1 contract client.
//!
//! This module provides an async wrapper around the blocking `L1Client` trait
//! from `l2_core::l1_contract`, allowing the batcher to use contract-based
//! submission in an async context.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use l2_core::l1_contract::{
    IdempotencyKey, L1ChainStatus, L1Client, L1ClientError, L1InclusionProof, L1SubmitResult,
    L1TxId, L2BatchEnvelopeV1,
};
use std::sync::Arc;

/// Status of a batch submission for reconciliation.
#[derive(Debug, Clone, Default)]
pub struct BatchStatus {
    /// Whether the batch is included in an L1 block.
    pub included: bool,
    /// L1 transaction ID if known.
    pub l1_tx_id: Option<String>,
    /// L1 block number where included.
    pub l1_block: Option<u64>,
    /// IPPAN network timestamp.
    pub ippan_time: Option<u64>,
}

/// Finality status for an L1 block.
#[derive(Debug, Clone, Default)]
pub struct FinalityStatus {
    /// Number of confirmations (blocks since inclusion).
    pub confirmations: u64,
    /// Whether finality has been reached.
    pub finalized: bool,
}

/// Async L1 client trait for contract-based batch submission.
#[async_trait]
pub trait AsyncL1Client: Send + Sync {
    /// Get the current L1 chain status.
    async fn chain_status(&self) -> Result<L1ChainStatus, L1ClientError>;

    /// Submit a batch envelope to L1.
    async fn submit_batch(
        &self,
        batch: &L2BatchEnvelopeV1,
    ) -> Result<L1SubmitResult, L1ClientError>;

    /// Query inclusion status by idempotency key.
    async fn get_inclusion(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<L1InclusionProof>, L1ClientError>;

    /// Query finality status by L1 transaction ID.
    async fn get_finality(
        &self,
        l1_tx_id: &L1TxId,
    ) -> Result<Option<L1InclusionProof>, L1ClientError>;

    /// Get batch status for reconciliation (higher-level API).
    ///
    /// This method queries L1 by idempotency key and returns a simplified
    /// status for the reconciler.
    async fn get_batch_status(&self, idempotency_key: &str) -> Result<BatchStatus, L1ClientError> {
        // Parse idempotency key
        let key_bytes = hex::decode(idempotency_key)
            .map_err(|e| L1ClientError::DecodeError(format!("invalid idempotency key: {e}")))?;

        if key_bytes.len() != 32 {
            return Err(L1ClientError::DecodeError(
                "idempotency key must be 32 bytes".to_string(),
            ));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        let key = IdempotencyKey(key_array);

        match self.get_inclusion(&key).await? {
            Some(proof) => Ok(BatchStatus {
                included: true,
                l1_tx_id: Some(proof.l1_tx_id.0),
                l1_block: Some(proof.height.0),
                ippan_time: None, // L1InclusionProof doesn't have ippan_time in v1
            }),
            None => Ok(BatchStatus::default()),
        }
    }

    /// Get finality status for a given L1 block.
    ///
    /// This method queries the chain status and computes confirmations.
    async fn get_finality_status(&self, l1_block: u64) -> Result<FinalityStatus, L1ClientError> {
        let chain_status = self.chain_status().await?;
        let current_height = chain_status.height.0;

        if l1_block > current_height {
            return Ok(FinalityStatus::default());
        }

        let confirmations = current_height.saturating_sub(l1_block);

        Ok(FinalityStatus {
            confirmations,
            finalized: chain_status
                .finalized_height
                .is_some_and(|fh| l1_block <= fh.0),
        })
    }
}

/// Blocking-to-async adapter for L1Client implementations.
///
/// This adapter uses `tokio::task::spawn_blocking` to run blocking L1Client
/// calls without blocking the async runtime.
#[derive(Clone)]
pub struct BlockingL1ClientAdapter<C> {
    client: Arc<C>,
}

impl<C> BlockingL1ClientAdapter<C>
where
    C: L1Client + Send + Sync + 'static,
{
    /// Create a new adapter wrapping the given blocking client.
    pub fn new(client: C) -> Self {
        Self {
            client: Arc::new(client),
        }
    }

    /// Create a new adapter from an Arc.
    pub fn from_arc(client: Arc<C>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl<C> AsyncL1Client for BlockingL1ClientAdapter<C>
where
    C: L1Client + Send + Sync + 'static,
{
    async fn chain_status(&self) -> Result<L1ChainStatus, L1ClientError> {
        let client = Arc::clone(&self.client);
        tokio::task::spawn_blocking(move || client.chain_status())
            .await
            .map_err(|e| L1ClientError::Network(format!("spawn_blocking error: {e}")))?
    }

    async fn submit_batch(
        &self,
        batch: &L2BatchEnvelopeV1,
    ) -> Result<L1SubmitResult, L1ClientError> {
        let client = Arc::clone(&self.client);
        let batch = batch.clone();
        tokio::task::spawn_blocking(move || client.submit_batch(&batch))
            .await
            .map_err(|e| L1ClientError::Network(format!("spawn_blocking error: {e}")))?
    }

    async fn get_inclusion(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<L1InclusionProof>, L1ClientError> {
        let client = Arc::clone(&self.client);
        let key = *idempotency_key;
        tokio::task::spawn_blocking(move || client.get_inclusion(&key))
            .await
            .map_err(|e| L1ClientError::Network(format!("spawn_blocking error: {e}")))?
    }

    async fn get_finality(
        &self,
        l1_tx_id: &L1TxId,
    ) -> Result<Option<L1InclusionProof>, L1ClientError> {
        let client = Arc::clone(&self.client);
        let tx_id = l1_tx_id.clone();
        tokio::task::spawn_blocking(move || client.get_finality(&tx_id))
            .await
            .map_err(|e| L1ClientError::Network(format!("spawn_blocking error: {e}")))?
    }
}

/// Native async L1 client using reqwest async.
///
/// This is a fully async implementation that doesn't require spawn_blocking.
/// Uses the same endpoint configuration as the blocking HTTP client.
#[cfg(feature = "async-l1-http")]
pub mod native_async {
    use super::*;
    use base64::Engine as _;
    use reqwest::StatusCode;
    use serde::Deserialize;
    use std::time::Duration;

    /// Configuration for the async HTTP L1 client.
    #[derive(Debug, Clone)]
    pub struct AsyncL1HttpConfig {
        pub base_url: String,
        pub api_key: Option<String>,
        pub endpoints: L1EndpointPaths,
        pub timeout_ms: u64,
        pub retry_max: u32,
        pub retry_base_delay_ms: u64,
    }

    /// Endpoint paths for L1 contract methods.
    #[derive(Debug, Clone, Default)]
    pub struct L1EndpointPaths {
        pub chain_status: Option<String>,
        pub submit_batch: Option<String>,
        pub get_inclusion: Option<String>,
        pub get_finality: Option<String>,
    }

    impl Default for AsyncL1HttpConfig {
        fn default() -> Self {
            Self {
                base_url: String::new(),
                api_key: None,
                endpoints: L1EndpointPaths::default(),
                timeout_ms: 10_000,
                retry_max: 3,
                retry_base_delay_ms: 250,
            }
        }
    }

    /// Native async HTTP client for L1 contract operations.
    pub struct AsyncHttpL1Client {
        cfg: AsyncL1HttpConfig,
        client: reqwest::Client,
    }

    impl AsyncHttpL1Client {
        pub fn new(cfg: AsyncL1HttpConfig) -> Result<Self, L1ClientError> {
            if cfg.base_url.trim().is_empty() {
                return Err(L1ClientError::Config("base_url is empty".to_string()));
            }
            let client = reqwest::Client::builder()
                .timeout(Duration::from_millis(cfg.timeout_ms))
                .build()
                .map_err(|e| L1ClientError::Config(format!("failed to build http client: {e}")))?;
            Ok(Self { cfg, client })
        }

        fn join_url(&self, path: &str) -> String {
            let base = self.cfg.base_url.trim_end_matches('/');
            let path = path.trim_start_matches('/');
            format!("{base}/{path}")
        }

        fn require_endpoint<'a>(
            endpoint: &'a Option<String>,
            name: &'static str,
        ) -> Result<&'a str, L1ClientError> {
            endpoint
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or(L1ClientError::EndpointMissing(name))
        }

        fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
            match self
                .cfg
                .api_key
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(key) => req.header("Authorization", key),
                None => req,
            }
        }

        fn idempotency_key_str(id: &IdempotencyKey) -> String {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.as_bytes())
        }

        async fn json_404_none<T: for<'de> Deserialize<'de>>(
            resp: reqwest::Response,
        ) -> Result<Option<T>, L1ClientError> {
            let status = resp.status();
            if status == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !status.is_success() {
                return Err(L1ClientError::HttpStatus(status.as_u16()));
            }
            let parsed: T = resp
                .json()
                .await
                .map_err(|e| L1ClientError::DecodeError(e.to_string()))?;
            Ok(Some(parsed))
        }
    }

    #[async_trait]
    impl AsyncL1Client for AsyncHttpL1Client {
        async fn chain_status(&self) -> Result<L1ChainStatus, L1ClientError> {
            let path = Self::require_endpoint(&self.cfg.endpoints.chain_status, "chain_status")?;
            let url = self.join_url(path);
            let resp = self.auth(self.client.get(&url)).send().await.map_err(|e| {
                if e.is_timeout() {
                    L1ClientError::Timeout
                } else {
                    L1ClientError::Network(e.to_string())
                }
            })?;
            if !resp.status().is_success() {
                return Err(L1ClientError::HttpStatus(resp.status().as_u16()));
            }
            resp.json()
                .await
                .map_err(|e| L1ClientError::DecodeError(e.to_string()))
        }

        async fn submit_batch(
            &self,
            batch: &L2BatchEnvelopeV1,
        ) -> Result<L1SubmitResult, L1ClientError> {
            let path = Self::require_endpoint(&self.cfg.endpoints.submit_batch, "submit_batch")?;
            let url = self.join_url(path);
            let resp = self
                .auth(self.client.post(&url).json(batch))
                .send()
                .await
                .map_err(|e| {
                    if e.is_timeout() {
                        L1ClientError::Timeout
                    } else {
                        L1ClientError::Network(e.to_string())
                    }
                })?;
            let status = resp.status();
            if !status.is_success() {
                // Try to parse error response for "already known" detection
                let body = resp.text().await.unwrap_or_default();
                if let Ok(parsed) = serde_json::from_str::<L1SubmitResult>(&body) {
                    if parsed.already_known {
                        return Ok(parsed);
                    }
                }
                return Err(L1ClientError::HttpStatus(status.as_u16()));
            }
            resp.json()
                .await
                .map_err(|e| L1ClientError::DecodeError(e.to_string()))
        }

        async fn get_inclusion(
            &self,
            idempotency_key: &IdempotencyKey,
        ) -> Result<Option<L1InclusionProof>, L1ClientError> {
            let path_tpl =
                Self::require_endpoint(&self.cfg.endpoints.get_inclusion, "get_inclusion")?;
            let path = path_tpl.replace("{id}", &Self::idempotency_key_str(idempotency_key));
            let url = self.join_url(&path);
            let resp = self.auth(self.client.get(&url)).send().await.map_err(|e| {
                if e.is_timeout() {
                    L1ClientError::Timeout
                } else {
                    L1ClientError::Network(e.to_string())
                }
            })?;
            Self::json_404_none(resp).await
        }

        async fn get_finality(
            &self,
            l1_tx_id: &L1TxId,
        ) -> Result<Option<L1InclusionProof>, L1ClientError> {
            let path_tpl =
                Self::require_endpoint(&self.cfg.endpoints.get_finality, "get_finality")?;
            let path = path_tpl.replace("{l1_tx_id}", &l1_tx_id.0);
            let url = self.join_url(&path);
            let resp = self.auth(self.client.get(&url)).send().await.map_err(|e| {
                if e.is_timeout() {
                    L1ClientError::Timeout
                } else {
                    L1ClientError::Network(e.to_string())
                }
            })?;
            Self::json_404_none(resp).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_core::l1_contract::mock_client::MockL1Client;
    use l2_core::l1_contract::{Base64Bytes, ContractVersion, FixedAmountV1, HubPayloadEnvelopeV1};
    use l2_core::L2HubId;

    fn test_envelope() -> L2BatchEnvelopeV1 {
        let hub_payload = HubPayloadEnvelopeV1 {
            contract_version: ContractVersion::V1,
            hub: L2HubId::Fin,
            schema_version: "test-v1".to_string(),
            content_type: "application/json".to_string(),
            payload: Base64Bytes(b"test payload".to_vec()),
        };

        L2BatchEnvelopeV1::new(
            L2HubId::Fin,
            "test-batch-001",
            1,
            10,
            Some("commitment-hash".to_string()),
            FixedAmountV1(0),
            hub_payload,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn blocking_adapter_submit_batch() {
        let mock = MockL1Client::new("testnet");
        let adapter = BlockingL1ClientAdapter::new(mock);

        let envelope = test_envelope();
        let result = adapter.submit_batch(&envelope).await.unwrap();

        assert!(result.accepted);
        assert!(!result.already_known);
        assert!(result.l1_tx_id.is_some());
    }

    #[tokio::test]
    async fn blocking_adapter_idempotent_replay() {
        let mock = MockL1Client::new("testnet");
        let adapter = BlockingL1ClientAdapter::new(mock);

        let envelope = test_envelope();

        // First submission
        let result1 = adapter.submit_batch(&envelope).await.unwrap();
        assert!(result1.accepted);
        assert!(!result1.already_known);

        // Second submission (idempotent replay)
        let result2 = adapter.submit_batch(&envelope).await.unwrap();
        assert!(result2.accepted);
        assert!(result2.already_known);
        assert_eq!(result1.l1_tx_id, result2.l1_tx_id);
    }

    #[tokio::test]
    async fn blocking_adapter_chain_status() {
        let mock = MockL1Client::new("testnet");
        let adapter = BlockingL1ClientAdapter::new(mock);

        let status = adapter.chain_status().await.unwrap();
        assert_eq!(status.network_id.0, "testnet");
        assert!(status.height.0 > 0);
    }

    #[tokio::test]
    async fn blocking_adapter_get_inclusion() {
        let mock = MockL1Client::new("testnet");
        let adapter = BlockingL1ClientAdapter::new(mock);

        let envelope = test_envelope();
        let _ = adapter.submit_batch(&envelope).await.unwrap();

        let inclusion = adapter
            .get_inclusion(&envelope.idempotency_key)
            .await
            .unwrap();
        assert!(inclusion.is_some());
        let proof = inclusion.unwrap();
        assert!(!proof.finalized);
    }
}
