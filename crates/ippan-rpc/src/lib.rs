#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::disallowed_types)]

use std::time::Duration;

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Configuration for the IPPAN RPC client.
#[derive(Debug, Clone)]
pub struct IppanRpcConfig {
    pub base_url: String,
    pub timeout_ms: u64,
    pub retry_max: u32,
}

impl IppanRpcConfig {
    pub const DEFAULT_TIMEOUT_MS: u64 = 2_000;
    pub const DEFAULT_RETRY_MAX: u32 = 3;

    pub fn from_env() -> Result<Self, IppanRpcError> {
        let base_url = std::env::var("IPPAN_RPC_URL")
            .map_err(|_| IppanRpcError::Config("IPPAN_RPC_URL is not set".to_string()))?;
        if base_url.trim().is_empty() {
            return Err(IppanRpcError::Config("IPPAN_RPC_URL is empty".to_string()));
        }

        let timeout_ms = std::env::var("IPPAN_RPC_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(Self::DEFAULT_TIMEOUT_MS);
        let retry_max = std::env::var("IPPAN_RPC_RETRY_MAX")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(Self::DEFAULT_RETRY_MAX);

        Ok(Self {
            base_url,
            timeout_ms,
            retry_max,
        })
    }
}

#[derive(Debug, Error)]
pub enum IppanRpcError {
    #[error("config error: {0}")]
    Config(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("http status {status} body={body}")]
    HttpStatus { status: u16, body: String },
    #[error("decode error: {0}")]
    Decode(String),
}

/// Response from `GET /status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Request payload for `POST /tx/payment`.
#[cfg(feature = "tx-payment-endpoint")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentTxRequest {
    pub from: String,
    pub to: String,
    pub amount: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Request payload for `POST /tx`.
#[cfg(feature = "tx-generic-endpoint")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataTxRequest {
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
}

/// Response body when submitting a transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxSubmissionResponse {
    pub tx_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Response body for `GET /tx/{hash}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxQueryResponse {
    pub tx_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone)]
pub struct IppanRpcClient {
    cfg: IppanRpcConfig,
    client: reqwest::Client,
}

impl IppanRpcClient {
    pub fn new(cfg: IppanRpcConfig) -> Result<Self, IppanRpcError> {
        if cfg.base_url.trim().is_empty() {
            return Err(IppanRpcError::Config("base_url is empty".to_string()));
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .build()
            .map_err(|e| IppanRpcError::Config(format!("failed to build http client: {e}")))?;
        Ok(Self { cfg, client })
    }

    pub async fn status(&self) -> Result<StatusResponse, IppanRpcError> {
        let url = self.join("/status");
        self.get_json("status", &url).await
    }

    #[cfg(feature = "tx-payment-endpoint")]
    pub async fn submit_payment_tx(
        &self,
        req: &PaymentTxRequest,
    ) -> Result<TxSubmissionResponse, IppanRpcError> {
        let url = self.join("/tx/payment");
        self.post_json("tx_payment", &url, req).await
    }

    #[cfg(feature = "tx-generic-endpoint")]
    pub async fn submit_data_tx(
        &self,
        req: &DataTxRequest,
    ) -> Result<TxSubmissionResponse, IppanRpcError> {
        let url = self.join("/tx");
        self.post_json("tx_data", &url, req).await
    }

    pub async fn get_tx(&self, hash: &str) -> Result<Option<TxQueryResponse>, IppanRpcError> {
        let path = format!("/tx/{hash}");
        let url = self.join(&path);
        self.get_json_optional("tx_lookup", &url).await
    }

    fn join(&self, path: &str) -> String {
        let base = self.cfg.base_url.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{base}/{path}")
    }

    async fn get_json<T>(&self, op: &'static str, url: &str) -> Result<T, IppanRpcError>
    where
        T: for<'de> Deserialize<'de>,
    {
        self.send_with_retry(op, || self.client.get(url)).await
    }

    async fn get_json_optional<T>(
        &self,
        op: &'static str,
        url: &str,
    ) -> Result<Option<T>, IppanRpcError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let attempts = self.cfg.retry_max.max(1);
        for attempt in 1..=attempts {
            let resp = match self.client.get(url).send().await {
                Ok(resp) => resp,
                Err(err) => {
                    if attempt == attempts || !is_retryable(&err) {
                        return Err(map_reqwest_error(err));
                    }
                    backoff(op, attempt).await;
                    continue;
                }
            };
            if resp.status() == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            match Self::map_response(op, resp).await {
                Ok(parsed) => return Ok(Some(parsed)),
                Err(err) => {
                    if attempt == attempts
                        || !matches!(err, IppanRpcError::HttpStatus { status, .. } if status >= 500)
                    {
                        return Err(err);
                    }
                    backoff(op, attempt).await;
                }
            }
        }
        Err(IppanRpcError::Config(
            "retry loop exhausted unexpectedly".to_string(),
        ))
    }

    async fn post_json<T, B>(
        &self,
        op: &'static str,
        url: &str,
        body: &B,
    ) -> Result<T, IppanRpcError>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize + ?Sized,
    {
        self.send_with_retry(op, || self.client.post(url).json(body))
            .await
    }

    async fn send_with_retry<T, F>(&self, op: &'static str, make_req: F) -> Result<T, IppanRpcError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn() -> reqwest::RequestBuilder,
    {
        let attempts = self.cfg.retry_max.max(1);
        for attempt in 1..=attempts {
            let builder = make_req();
            let url = builder
                .try_clone()
                .and_then(|r| r.build().ok())
                .map(|req| req.url().to_string())
                .unwrap_or_default();
            info!(operation = op, attempt, url = %url, "sending request");
            let resp = match builder.send().await {
                Ok(resp) => resp,
                Err(err) => {
                    warn!(operation = op, attempt, error = %err, "request error");
                    if attempt == attempts || !is_retryable(&err) {
                        return Err(map_reqwest_error(err));
                    }
                    backoff(op, attempt).await;
                    continue;
                }
            };

            match Self::map_response(op, resp).await {
                Ok(parsed) => return Ok(parsed),
                Err(err) => {
                    if attempt == attempts {
                        return Err(err);
                    }
                    if let IppanRpcError::HttpStatus { status, .. } = &err {
                        if *status >= 500 {
                            backoff(op, attempt).await;
                            continue;
                        }
                    }
                    return Err(err);
                }
            }
        }

        Err(IppanRpcError::Config(
            "retry loop exhausted unexpectedly".to_string(),
        ))
    }

    async fn map_response<T>(op: &'static str, resp: reqwest::Response) -> Result<T, IppanRpcError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| IppanRpcError::Network(format!("{e}")))?;
        if !status.is_success() {
            warn!(operation = op, status = status.as_u16(), body = %body, "non-success status");
            return Err(IppanRpcError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }
        serde_json::from_str(&body)
            .map_err(|e| IppanRpcError::Decode(format!("{e}")))
            .inspect(|_parsed| {
                debug!(operation = op, "response decoded");
            })
    }
}

fn is_retryable(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect()
}

fn map_reqwest_error(err: reqwest::Error) -> IppanRpcError {
    if err.is_timeout() || err.is_connect() {
        return IppanRpcError::Network(err.to_string());
    }
    if err.is_body() || err.is_decode() {
        return IppanRpcError::Decode(err.to_string());
    }
    IppanRpcError::Network(err.to_string())
}

async fn backoff(op: &str, attempt: u32) {
    let delay_ms = backoff_delay_ms(attempt);
    warn!(operation = op, attempt, delay_ms, "retrying after backoff");
    sleep(Duration::from_millis(delay_ms)).await;
}

fn backoff_delay_ms(attempt: u32) -> u64 {
    // Exponential backoff capped at 2s, deterministic (no jitter).
    let exp = attempt.saturating_sub(1);
    let base = 100u64.saturating_mul(2u64.saturating_pow(exp));
    base.min(2_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config(base_url: String) -> IppanRpcConfig {
        IppanRpcConfig {
            base_url,
            timeout_ms: 1_000,
            retry_max: 3,
        }
    }

    #[tokio::test]
    async fn status_success() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "network": "devnet",
            "height": 123,
            "node_id": "abc",
            "extra": {"foo": "bar"}
        });
        Mock::given(method("GET"))
            .and(path("/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;

        let client = IppanRpcClient::new(test_config(server.uri())).unwrap();
        let status = client.status().await.unwrap();
        assert_eq!(status.network, Some("devnet".to_string()));
        assert_eq!(status.height, Some(123));
        assert_eq!(status.node_id, Some("abc".to_string()));
        assert!(status.extra.contains_key("foo"));
    }

    #[cfg(feature = "tx-payment-endpoint")]
    #[tokio::test]
    async fn payment_tx_retries_on_500() {
        let server = MockServer::start().await;
        let request = PaymentTxRequest {
            from: "alice".to_string(),
            to: "bob".to_string(),
            amount: 10,
            memo: None,
            nonce: None,
            fee: None,
            metadata: None,
        };

        Mock::given(method("POST"))
            .and(path("/tx/payment"))
            .and(body_json(&request))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/tx/payment"))
            .and(body_json(&request))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tx_hash": "abc123",
                "accepted": true
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = IppanRpcClient::new(test_config(server.uri())).unwrap();
        let resp = client.submit_payment_tx(&request).await.unwrap();
        assert_eq!(resp.tx_hash, "abc123");
        assert_eq!(resp.accepted, Some(true));
    }

    #[tokio::test]
    async fn tx_lookup_404_is_none() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/tx/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = IppanRpcClient::new(test_config(server.uri())).unwrap();
        let resp = client.get_tx("missing").await.unwrap();
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn tx_lookup_success() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "tx_hash": "abc123",
            "status": "confirmed",
            "height": 500,
            "success": true
        });
        Mock::given(method("GET"))
            .and(path("/tx/abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;

        let client = IppanRpcClient::new(test_config(server.uri())).unwrap();
        let resp = client.get_tx("abc123").await.unwrap();
        assert!(resp.is_some());
        let tx = resp.unwrap();
        assert_eq!(tx.tx_hash, "abc123");
        assert_eq!(tx.status, Some("confirmed".to_string()));
        assert_eq!(tx.height, Some(500));
        assert_eq!(tx.success, Some(true));
    }

    #[tokio::test]
    async fn status_retries_on_500_then_fails() {
        let server = MockServer::start().await;
        // Return 500 for all attempts (max 3)
        Mock::given(method("GET"))
            .and(path("/status"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .expect(3)
            .mount(&server)
            .await;

        let client = IppanRpcClient::new(test_config(server.uri())).unwrap();
        let result = client.status().await;
        assert!(result.is_err());
        if let Err(IppanRpcError::HttpStatus { status, body }) = result {
            assert_eq!(status, 500);
            assert_eq!(body, "internal error");
        } else {
            panic!("expected HttpStatus error");
        }
    }

    #[tokio::test]
    async fn json_parse_error_returns_decode_error() {
        let server = MockServer::start().await;
        // Return invalid JSON
        Mock::given(method("GET"))
            .and(path("/status"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
            .mount(&server)
            .await;

        let client = IppanRpcClient::new(test_config(server.uri())).unwrap();
        let result = client.status().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(IppanRpcError::Decode(_))));
    }

    #[cfg(feature = "tx-generic-endpoint")]
    #[tokio::test]
    async fn data_tx_submit_success() {
        let server = MockServer::start().await;
        let request = DataTxRequest {
            data: "deadbeef".to_string(),
            memo: Some("test memo".to_string()),
            nonce: Some(42),
        };

        Mock::given(method("POST"))
            .and(path("/tx"))
            .and(body_json(&request))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tx_hash": "xyz789",
                "accepted": true,
                "status": "pending"
            })))
            .mount(&server)
            .await;

        let client = IppanRpcClient::new(test_config(server.uri())).unwrap();
        let resp = client.submit_data_tx(&request).await.unwrap();
        assert_eq!(resp.tx_hash, "xyz789");
        assert_eq!(resp.accepted, Some(true));
        assert_eq!(resp.status, Some("pending".to_string()));
    }

    #[tokio::test]
    async fn config_rejects_empty_url() {
        let config = IppanRpcConfig {
            base_url: "".to_string(),
            timeout_ms: 1000,
            retry_max: 3,
        };
        let result = IppanRpcClient::new(config);
        assert!(result.is_err());
        assert!(matches!(result, Err(IppanRpcError::Config(_))));
    }

    #[test]
    fn backoff_delay_is_bounded() {
        // Ensure backoff delay doesn't grow unbounded
        assert_eq!(backoff_delay_ms(1), 100);
        assert_eq!(backoff_delay_ms(2), 200);
        assert_eq!(backoff_delay_ms(3), 400);
        assert_eq!(backoff_delay_ms(4), 800);
        assert_eq!(backoff_delay_ms(5), 1600);
        assert_eq!(backoff_delay_ms(6), 2000); // Capped at 2s
        assert_eq!(backoff_delay_ms(100), 2000); // Still capped
    }
}
