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
use std::cmp;
use std::error::Error as _;
use std::time::Duration;
use tracing::{debug, warn};

/// HTTP binding configuration for L1 RPC calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1RpcConfig {
    pub base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    pub endpoints: L1EndpointMap,
    /// Deprecated: use `connect_timeout_ms` and `request_timeout_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,

    /// TCP/TLS connection timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,

    /// Total request timeout (includes connect, headers, body).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_ms: Option<u64>,

    /// Bounded retry policy for transient failures.
    #[serde(default)]
    pub retry: RetryConfig,
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

/// Retry configuration for transient errors only (timeouts, 5xx, connection reset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay_ms: 250,
            max_delay_ms: 2_000,
        }
    }
}

impl L1RpcConfig {
    pub fn validate_base(&self) -> Result<(), L1ClientError> {
        if self.base_url.trim().is_empty() {
            return Err(L1ClientError::Config("l1.base_url is empty".to_string()));
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
        cfg.validate_base()?;
        let request_timeout =
            Duration::from_millis(cfg.request_timeout_ms.or(cfg.timeout_ms).unwrap_or(10_000));
        let connect_timeout = Duration::from_millis(cfg.connect_timeout_ms.unwrap_or(3_000));
        let client = Client::builder()
            .timeout(request_timeout)
            .connect_timeout(connect_timeout)
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

    fn json_404_none<T: for<'de> Deserialize<'de>>(
        resp: reqwest::blocking::Response,
    ) -> Result<Option<T>, L1ClientError> {
        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(L1ClientError::HttpStatus(status.as_u16()));
        }
        let parsed: T = resp.json().map_err(|e| map_reqwest_decode_error(&e))?;
        Ok(Some(parsed))
    }

    fn is_transient_status(status: StatusCode) -> bool {
        status.is_server_error()
    }

    fn jitter_ms(seed: u64, attempt: u32, max_jitter_ms: u64) -> u64 {
        if max_jitter_ms == 0 {
            return 0;
        }
        // Tiny deterministic xorshift64* derived from seed+attempt.
        let mut x = seed ^ (u64::from(attempt).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        x % (max_jitter_ms + 1)
    }

    fn backoff_delay_ms(&self, attempt: u32, seed: u64) -> u64 {
        // attempt is 1-based.
        let exp = attempt.saturating_sub(1);
        let mult = 1u64.checked_shl(exp).unwrap_or(u64::MAX);
        let base = self.cfg.retry.base_delay_ms.saturating_mul(mult);
        let capped = cmp::min(base, self.cfg.retry.max_delay_ms);
        // Bounded jitter: up to 50% of the (capped) delay.
        let jitter_cap = capped / 2;
        capped.saturating_add(Self::jitter_ms(seed, attempt, jitter_cap))
    }

    fn is_transient_reqwest_error(err: &reqwest::Error) -> bool {
        if err.is_timeout() || err.is_connect() {
            return true;
        }
        // Best-effort: treat connection reset/broken pipe as transient.
        let mut src = err.source();
        while let Some(e) = src {
            if let Some(io) = e.downcast_ref::<std::io::Error>() {
                return matches!(
                    io.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                );
            }
            src = e.source();
        }
        false
    }

    fn send_with_retry_response(
        &self,
        op: &'static str,
        idempotency_key: Option<&IdempotencyKey>,
        make_req: impl Fn() -> reqwest::blocking::RequestBuilder,
    ) -> Result<reqwest::blocking::Response, L1ClientError> {
        let attempts = cmp::max(1, self.cfg.retry.max_attempts);
        let seed = idempotency_key
            .map(|k| {
                // Deterministic seed from first 8 bytes.
                u64::from_be_bytes(k.as_bytes()[0..8].try_into().unwrap_or([0u8; 8]))
            })
            .unwrap_or(0);

        let idem_str = idempotency_key.map(Self::idempotency_key_str);

        let mut last_err: Option<L1ClientError> = None;
        for attempt in 1..=attempts {
            debug!(
                op,
                attempt,
                attempts,
                idempotency_key = idem_str.as_deref().unwrap_or(""),
                "l1 request"
            );

            let resp = self.auth(make_req()).send();
            match resp {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return Ok(resp);
                    }
                    if attempt < attempts && Self::is_transient_status(status) {
                        let delay_ms = self.backoff_delay_ms(attempt, seed);
                        warn!(
                            op,
                            attempt,
                            attempts,
                            status = status.as_u16(),
                            delay_ms,
                            "transient l1 http status; retrying"
                        );
                        std::thread::sleep(Duration::from_millis(delay_ms));
                        last_err = Some(L1ClientError::HttpStatus(status.as_u16()));
                        continue;
                    }
                    if Self::is_transient_status(status) {
                        return Err(L1ClientError::RetryExhausted {
                            attempts,
                            last_error: Box::new(L1ClientError::HttpStatus(status.as_u16())),
                        });
                    }
                    // Non-transient non-2xx: return the response for the caller to interpret.
                    return Ok(resp);
                }
                Err(e) => {
                    let err = map_reqwest_send_error(&e);
                    let transient = matches!(err, L1ClientError::Timeout)
                        || Self::is_transient_reqwest_error(&e);
                    if attempt < attempts && transient {
                        let delay_ms = self.backoff_delay_ms(attempt, seed);
                        warn!(
                            op,
                            attempt,
                            attempts,
                            delay_ms,
                            error = %e,
                            "transient l1 transport error; retrying"
                        );
                        std::thread::sleep(Duration::from_millis(delay_ms));
                        last_err = Some(err);
                        continue;
                    }
                    if transient {
                        return Err(L1ClientError::RetryExhausted {
                            attempts,
                            last_error: Box::new(err),
                        });
                    }
                    return Err(err);
                }
            }
        }

        Err(L1ClientError::RetryExhausted {
            attempts,
            last_error: Box::new(
                last_err.unwrap_or_else(|| L1ClientError::Network("unknown error".to_string())),
            ),
        })
    }
}

impl L1Client for HttpL1Client {
    fn chain_status(&self) -> Result<L1ChainStatus, L1ClientError> {
        let path = Self::require_endpoint(&self.cfg.endpoints.chain_status, "chain_status")?;
        let url = self.join_url(path);
        let resp =
            self.send_with_retry_response("chain_status", None, || self.client.get(url.clone()))?;
        if !resp.status().is_success() {
            return Err(L1ClientError::HttpStatus(resp.status().as_u16()));
        }
        resp.json().map_err(|e| map_reqwest_decode_error(&e))
    }

    fn submit_batch(&self, batch: &L2BatchEnvelopeV1) -> Result<L1SubmitResult, L1ClientError> {
        let path = Self::require_endpoint(&self.cfg.endpoints.submit_batch, "submit_batch")?;
        let url = self.join_url(path);
        let idem = &batch.idempotency_key;

        // Submit is expected to be idempotent. We retry only transient errors (timeouts/5xx/etc).
        // If the server returns a non-2xx but encodes "already known", treat as success.
        let resp = self.send_with_retry_response("submit_batch", Some(idem), || {
            self.client.post(url.clone()).json(batch)
        })?;
        let status = resp.status();
        if status.is_success() {
            return resp.json().map_err(|e| map_reqwest_decode_error(&e));
        }

        // Non-2xx: attempt to decode an L1SubmitResult. If it indicates "already known",
        // we treat it as success (idempotent replay).
        let body = resp.text().unwrap_or_default();
        if let Ok(parsed) = serde_json::from_str::<L1SubmitResult>(&body) {
            if parsed.already_known || submit_looks_already_known(&parsed) {
                return Ok(parsed);
            }
        }
        Err(L1ClientError::HttpStatus(status.as_u16()))
    }

    fn get_inclusion(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<L1InclusionProof>, L1ClientError> {
        let path_tpl = Self::require_endpoint(&self.cfg.endpoints.get_inclusion, "get_inclusion")?;
        let path = Self::replace_token(
            path_tpl,
            "{id}",
            &Self::idempotency_key_str(idempotency_key),
        );
        let url = self.join_url(&path);
        let resp = self.send_with_retry_response("get_inclusion", Some(idempotency_key), || {
            self.client.get(url.clone())
        })?;
        Self::json_404_none(resp)
    }

    fn get_finality(&self, l1_tx_id: &L1TxId) -> Result<Option<L1InclusionProof>, L1ClientError> {
        let path_tpl = Self::require_endpoint(&self.cfg.endpoints.get_finality, "get_finality")?;
        let path = Self::replace_token(path_tpl, "{l1_tx_id}", &l1_tx_id.0);
        let url = self.join_url(&path);
        let resp =
            self.send_with_retry_response("get_finality", None, || self.client.get(url.clone()))?;
        Self::json_404_none(resp)
    }
}

fn map_reqwest_send_error(err: &reqwest::Error) -> L1ClientError {
    if err.is_timeout() {
        return L1ClientError::Timeout;
    }
    L1ClientError::Network(err.to_string())
}

fn map_reqwest_decode_error(err: &reqwest::Error) -> L1ClientError {
    if err.is_timeout() {
        return L1ClientError::Timeout;
    }
    L1ClientError::DecodeError(err.to_string())
}

fn submit_looks_already_known(res: &L1SubmitResult) -> bool {
    let code = res.error_code.as_deref().unwrap_or("").to_ascii_lowercase();
    let msg = res.message.as_deref().unwrap_or("").to_ascii_lowercase();
    code.contains("already") || code.contains("duplicate") || msg.contains("already known")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_status_classification_only_retries_5xx() {
        assert!(HttpL1Client::is_transient_status(
            StatusCode::INTERNAL_SERVER_ERROR
        ));
        assert!(HttpL1Client::is_transient_status(StatusCode::BAD_GATEWAY));
        assert!(!HttpL1Client::is_transient_status(StatusCode::BAD_REQUEST));
        assert!(!HttpL1Client::is_transient_status(StatusCode::UNAUTHORIZED));
        assert!(!HttpL1Client::is_transient_status(StatusCode::NOT_FOUND));
    }

    #[test]
    fn submit_idempotency_detection() {
        let ok = L1SubmitResult {
            accepted: true,
            already_known: true,
            l1_tx_id: None,
            error_code: None,
            message: Some("already known".to_string()),
        };
        assert!(submit_looks_already_known(&ok) || ok.already_known);

        let ok2 = L1SubmitResult {
            accepted: false,
            already_known: false,
            l1_tx_id: None,
            error_code: Some("ALREADY_KNOWN".to_string()),
            message: None,
        };
        assert!(submit_looks_already_known(&ok2));

        let not_ok = L1SubmitResult {
            accepted: false,
            already_known: false,
            l1_tx_id: None,
            error_code: Some("VALIDATION_FAILED".to_string()),
            message: Some("bad request".to_string()),
        };
        assert!(!submit_looks_already_known(&not_ok));
    }
}
