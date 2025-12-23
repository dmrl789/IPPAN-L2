//! HTTP transport adapter for the L1 ↔ L2 contract.
//!
//! IMPORTANT: This adapter **does not** assume any default endpoint paths.
//! All paths must be provided explicitly via [`L1RpcConfig::endpoints`].
#![forbid(unsafe_code)]

use super::{
    IdempotencyKey, L1ChainStatus, L1Client, L1ClientError, L1InclusionProof, L1SubmitResult,
    L1TxId, L2BatchEnvelopeV1,
};
use base64::Engine as _;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// HTTP binding configuration for L1 RPC calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1RpcConfig {
    pub base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    pub endpoints: L1EndpointMap,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// Endpoint paths for contract methods.
///
/// These are **paths**, not full URLs (e.g. `"/status"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1EndpointMap {
    #[serde(default)]
    pub chain_status: Option<String>,
    #[serde(default)]
    pub submit_batch: Option<String>,
    #[serde(default)]
    pub get_inclusion: Option<String>, // supports "{id}"
    #[serde(default)]
    pub get_finality: Option<String>, // supports "{l1_tx_id}"
}

impl L1RpcConfig {
    pub fn validate(&self) -> Result<(), L1ClientError> {
        if self.base_url.trim().is_empty() {
            return Err(L1ClientError::Config("l1.base_url is empty".to_string()));
        }
        if self.endpoints.chain_status.as_deref().unwrap_or("").trim().is_empty() {
            return Err(L1ClientError::Config(
                "missing endpoints.chain_status in config".to_string(),
            ));
        }
        if self.endpoints.submit_batch.as_deref().unwrap_or("").trim().is_empty() {
            return Err(L1ClientError::Config(
                "missing endpoints.submit_batch in config".to_string(),
            ));
        }
        if self.endpoints.get_inclusion.as_deref().unwrap_or("").trim().is_empty() {
            return Err(L1ClientError::Config(
                "missing endpoints.get_inclusion in config".to_string(),
            ));
        }
        if self.endpoints.get_finality.as_deref().unwrap_or("").trim().is_empty() {
            return Err(L1ClientError::Config(
                "missing endpoints.get_finality in config".to_string(),
            ));
        }
        Ok(())
    }
}

/// Blocking HTTP client implementing the L1 contract.
#[derive(Debug, Clone)]
pub struct HttpL1Client {
    cfg: L1RpcConfig,
    client: Client,
}

impl HttpL1Client {
    pub fn new(cfg: L1RpcConfig) -> Result<Self, L1ClientError> {
        cfg.validate()?;
        let timeout = Duration::from_millis(cfg.timeout_ms.unwrap_or(10_000));
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| L1ClientError::Config(format!("failed to build http client: {e}")))?;
        Ok(Self { cfg, client })
    }

    fn join_url(&self, path: &str) -> String {
        let base = self.cfg.base_url.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{base}/{path}")
    }

    fn replace_token(path: &str, token: &str, value: &str) -> String {
        path.replace(token, value)
    }

    fn idempotency_key_str(id: &IdempotencyKey) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.as_bytes())
    }

    fn auth(&self, req: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
        match self.cfg.api_key.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(key) => req.header("Authorization", key),
            None => req,
        }
    }

    fn json_404_none<T: for<'de> Deserialize<'de>>(
        resp: reqwest::blocking::Response,
    ) -> Result<Option<T>, L1ClientError> {
        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(L1ClientError::Protocol(format!("http status {status}")));
        }
        let parsed: T = resp
            .json()
            .map_err(|e| L1ClientError::Serialization(e.to_string()))?;
        Ok(Some(parsed))
    }
}

impl L1Client for HttpL1Client {
    fn chain_status(&self) -> Result<L1ChainStatus, L1ClientError> {
        let path = self
            .cfg
            .endpoints
            .chain_status
            .as_deref()
            .ok_or_else(|| L1ClientError::Config("missing endpoints.chain_status in config".to_string()))?;
        let url = self.join_url(path);
        let resp = self
            .auth(self.client.get(url))
            .send()
            .map_err(|e| L1ClientError::Network(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(L1ClientError::Protocol(format!("http status {status}")));
        }
        resp.json()
            .map_err(|e| L1ClientError::Serialization(e.to_string()))
    }

    fn submit_batch(&self, batch: &L2BatchEnvelopeV1) -> Result<L1SubmitResult, L1ClientError> {
        let path = self
            .cfg
            .endpoints
            .submit_batch
            .as_deref()
            .ok_or_else(|| L1ClientError::Config("missing endpoints.submit_batch in config".to_string()))?;
        let url = self.join_url(path);
        let resp = self
            .auth(self.client.post(url).json(batch))
            .send()
            .map_err(|e| L1ClientError::Network(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(L1ClientError::Protocol(format!("http status {status}")));
        }
        resp.json()
            .map_err(|e| L1ClientError::Serialization(e.to_string()))
    }

    fn get_inclusion(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<L1InclusionProof>, L1ClientError> {
        let path_tpl = self
            .cfg
            .endpoints
            .get_inclusion
            .as_deref()
            .ok_or_else(|| L1ClientError::Config("missing endpoints.get_inclusion in config".to_string()))?;
        let path = Self::replace_token(path_tpl, "{id}", &Self::idempotency_key_str(idempotency_key));
        let url = self.join_url(&path);
        let resp = self
            .auth(self.client.get(url))
            .send()
            .map_err(|e| L1ClientError::Network(e.to_string()))?;
        Self::json_404_none(resp)
    }

    fn get_finality(&self, l1_tx_id: &L1TxId) -> Result<Option<L1InclusionProof>, L1ClientError> {
        let path_tpl = self
            .cfg
            .endpoints
            .get_finality
            .as_deref()
            .ok_or_else(|| L1ClientError::Config("missing endpoints.get_finality in config".to_string()))?;
        let path = Self::replace_token(path_tpl, "{l1_tx_id}", &l1_tx_id.0);
        let url = self.join_url(&path);
        let resp = self
            .auth(self.client.get(url))
            .send()
            .map_err(|e| L1ClientError::Network(e.to_string()))?;
        Self::json_404_none(resp)
    }
}

