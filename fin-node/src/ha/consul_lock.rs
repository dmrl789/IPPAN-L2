#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

use crate::ha::lock_provider::{
    LeaderInfo, LeaderLockProvider, LockProviderError, LockState, Result,
};
use base64::Engine as _;
use serde::Deserialize;
use std::time::Duration;

/// Minimal Consul session lock provider (KV + session TTL).
///
/// This is feature-gated (`ha-consul`) and intended for environments where Consul is the standard
/// coordination plane.
///
/// Semantics:
/// - The lock is held by the session attached to the KV key.
/// - We write the `node_id` as the KV value (no extra metadata).
/// - Renew is performed by renewing the session TTL.
#[derive(Debug, Clone)]
pub struct ConsulLockProvider {
    client: reqwest::blocking::Client,
    address: String,
    key: String,
    session_id: String,
    session_ttl_ms: u64,
}

impl ConsulLockProvider {
    pub fn connect_and_validate(
        address: String,
        key: String,
        session_ttl: String,
        node_id: String,
    ) -> Result<Self> {
        if address.trim().is_empty() {
            return Err(LockProviderError::Misconfigured(
                "consul address is empty".to_string(),
            ));
        }
        if key.trim().is_empty() {
            return Err(LockProviderError::Misconfigured(
                "consul key is empty".to_string(),
            ));
        }
        let session_ttl_ms = parse_consul_ttl_ms(&session_ttl)?;

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|e| LockProviderError::Misconfigured(e.to_string()))?;

        let session_id = create_session(&client, &address, &session_ttl, &node_id)?;

        Ok(Self {
            client,
            address,
            key,
            session_id,
            session_ttl_ms,
        })
    }

    fn kv_url(&self) -> String {
        let address = self.address.trim_end_matches('/');
        format!("{address}/v1/kv/{}", self.key.trim_start_matches('/'))
    }

    fn session_renew_url(&self) -> String {
        let address = self.address.trim_end_matches('/');
        format!("{address}/v1/session/renew/{}", self.session_id)
    }

    fn session_destroy_url(&self) -> String {
        let address = self.address.trim_end_matches('/');
        format!("{address}/v1/session/destroy/{}", self.session_id)
    }

    fn now_ms() -> u64 {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
    }
}

impl LeaderLockProvider for ConsulLockProvider {
    fn provider_type(&self) -> &'static str {
        "consul"
    }

    fn try_acquire(&self, node_id: &str) -> Result<LockState> {
        let url = format!("{}?acquire={}", self.kv_url(), self.session_id);
        let resp = self
            .client
            .put(url)
            .body(node_id.to_string())
            .send()
            .map_err(map_reqwest_err)?;
        if !resp.status().is_success() {
            return Err(LockProviderError::Backend(format!(
                "consul kv acquire http {}",
                resp.status()
            )));
        }
        let ok = resp
            .text()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("true");
        Ok(if ok {
            LockState::Acquired
        } else {
            LockState::NotLeader
        })
    }

    fn renew(&self, node_id: &str) -> Result<LockState> {
        // Verify we still hold the lock (session + value).
        let holder = self.current_holder()?;
        let Some(holder) = holder else {
            return Ok(LockState::Expired);
        };
        if holder.node_id != node_id {
            return Ok(LockState::NotLeader);
        }

        let resp = self
            .client
            .put(self.session_renew_url())
            .send()
            .map_err(map_reqwest_err)?;
        if resp.status().as_u16() == 404 {
            return Ok(LockState::Expired);
        }
        if !resp.status().is_success() {
            return Err(LockProviderError::Backend(format!(
                "consul session renew http {}",
                resp.status()
            )));
        }
        Ok(LockState::Acquired)
    }

    fn release(&self, node_id: &str) -> Result<()> {
        let url = format!("{}?release={}", self.kv_url(), self.session_id);
        let resp = self
            .client
            .put(url)
            .body(node_id.to_string())
            .send()
            .map_err(map_reqwest_err)?;
        if !resp.status().is_success() {
            return Err(LockProviderError::Backend(format!(
                "consul kv release http {}",
                resp.status()
            )));
        }

        // Best-effort: destroy our session so it can't hold locks.
        let _ = self.client.put(self.session_destroy_url()).send();
        Ok(())
    }

    fn current_holder(&self) -> Result<Option<LeaderInfo>> {
        let resp = self
            .client
            .get(self.kv_url())
            .send()
            .map_err(map_reqwest_err)?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(LockProviderError::Backend(format!(
                "consul kv get http {}",
                resp.status()
            )));
        }
        let body = resp.text().unwrap_or_default();
        let entries: Vec<ConsulKvEntry> =
            serde_json::from_str(&body).map_err(|e| LockProviderError::Backend(e.to_string()))?;
        let Some(entry) = entries.into_iter().next() else {
            return Ok(None);
        };
        let Some(b64) = entry.value else {
            return Ok(None);
        };
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| LockProviderError::Backend(e.to_string()))?;
        let node_id =
            String::from_utf8(decoded).map_err(|e| LockProviderError::Backend(e.to_string()))?;

        // Consul does not expose an exact expiry timestamp for the session via the KV record.
        // We conservatively report "now + configured TTL" as a hint for operators/clients.
        let expires_at_ms = Self::now_ms().saturating_add(self.session_ttl_ms);
        Ok(Some(LeaderInfo {
            node_id,
            expires_at_ms,
        }))
    }
}

#[derive(Debug, Deserialize)]
struct ConsulKvEntry {
    #[serde(rename = "Value")]
    value: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct ConsulSessionCreateReq {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "TTL")]
    ttl: String,
    #[serde(rename = "LockDelay")]
    lock_delay: String,
    #[serde(rename = "Behavior")]
    behavior: String,
}

#[derive(Debug, Deserialize)]
struct ConsulSessionCreateResp {
    #[serde(rename = "ID")]
    id: String,
}

fn create_session(
    client: &reqwest::blocking::Client,
    address: &str,
    ttl: &str,
    node_id: &str,
) -> Result<String> {
    let address = address.trim_end_matches('/');
    let url = format!("{address}/v1/session/create");
    let req = ConsulSessionCreateReq {
        name: format!("ippan-l2-leader:{node_id}"),
        ttl: ttl.to_string(),
        lock_delay: "0s".to_string(),
        behavior: "delete".to_string(),
    };

    let resp = client.put(url).json(&req).send().map_err(map_reqwest_err)?;
    if !resp.status().is_success() {
        return Err(LockProviderError::Backend(format!(
            "consul session create http {}",
            resp.status()
        )));
    }
    let body = resp.text().unwrap_or_default();
    let out: ConsulSessionCreateResp =
        serde_json::from_str(&body).map_err(|e| LockProviderError::Backend(e.to_string()))?;
    Ok(out.id)
}

fn parse_consul_ttl_ms(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(LockProviderError::Misconfigured(
            "consul session_ttl is empty".to_string(),
        ));
    }
    // Minimal parser for values like "15s", "1m", "15000ms".
    if let Some(x) = s.strip_suffix("ms") {
        let v: u64 = x.trim().parse().map_err(|_| {
            LockProviderError::Misconfigured(format!("invalid consul session_ttl: {s}"))
        })?;
        return Ok(v.max(1));
    }
    if let Some(x) = s.strip_suffix('s') {
        let v: u64 = x.trim().parse().map_err(|_| {
            LockProviderError::Misconfigured(format!("invalid consul session_ttl: {s}"))
        })?;
        return Ok(v.saturating_mul(1_000).max(1));
    }
    if let Some(x) = s.strip_suffix('m') {
        let v: u64 = x.trim().parse().map_err(|_| {
            LockProviderError::Misconfigured(format!("invalid consul session_ttl: {s}"))
        })?;
        return Ok(v.saturating_mul(60_000).max(1));
    }
    Err(LockProviderError::Misconfigured(format!(
        "invalid consul session_ttl (expected ms/s/m suffix): {s}"
    )))
}

fn map_reqwest_err(e: reqwest::Error) -> LockProviderError {
    if e.is_timeout() {
        return LockProviderError::Timeout(e.to_string());
    }
    if e.is_connect() {
        return LockProviderError::Connection(e.to_string());
    }
    LockProviderError::Backend(e.to_string())
}
