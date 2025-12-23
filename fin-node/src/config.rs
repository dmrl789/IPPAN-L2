#![forbid(unsafe_code)]
// Workspace clippy config forbids float types, but `serde` derive macros generate
// visitors that reference `f32`/`f64` even if our config structs do not use them.
#![allow(clippy::disallowed_types)]

use l2_core::l1_contract::http_client::L1RpcConfig;
use serde::Deserialize;
use std::fs;

#[derive(Debug, Clone, Deserialize)]
pub struct FinNodeConfig {
    #[serde(default)]
    pub node: NodeConfig,
    pub l1: L1Config,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    #[serde(default = "default_node_label")]
    pub label: String,
}

fn default_node_label() -> String {
    "fin-node".to_string()
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            label: default_node_label(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct L1Config {
    #[serde(flatten)]
    pub rpc: L1RpcConfig,
    #[serde(default)]
    pub expected_network_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default = "default_metrics_enabled")]
    pub metrics_enabled: bool,
}

fn default_bind_address() -> String {
    "0.0.0.0:3000".to_string()
}

fn default_metrics_enabled() -> bool {
    true
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            metrics_enabled: default_metrics_enabled(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_receipts_dir")]
    pub receipts_dir: String,
}

fn default_receipts_dir() -> String {
    "receipts".to_string()
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            receipts_dir: default_receipts_dir(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

fn resolve_env_refs(mut v: toml::Value) -> Result<toml::Value, String> {
    fn walk(v: &mut toml::Value) -> Result<(), String> {
        match v {
            toml::Value::String(s) => {
                if let Some(var) = s.strip_prefix("env:") {
                    let var = var.trim();
                    if var.is_empty() {
                        return Err("invalid env: reference (empty var name)".to_string());
                    }
                    let val = std::env::var(var)
                        .map_err(|_| format!("missing required environment variable: {var}"))?;
                    *s = val;
                }
            }
            toml::Value::Array(arr) => {
                for x in arr {
                    walk(x)?;
                }
            }
            toml::Value::Table(map) => {
                for (_, x) in map.iter_mut() {
                    walk(x)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    walk(&mut v)?;
    Ok(v)
}

pub fn load_config(path: &str) -> Result<FinNodeConfig, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("failed to read config {path}: {e}"))?;
    let parsed: toml::Value =
        toml::from_str(&raw).map_err(|e| format!("failed to parse config {path}: {e}"))?;
    let resolved = resolve_env_refs(parsed)?;
    resolved
        .try_into::<FinNodeConfig>()
        .map_err(|e| format!("failed to decode config {path}: {e}"))
}

impl FinNodeConfig {
    pub fn validate_for_mode_http(&self) -> Result<(), String> {
        if self.node.label.trim().is_empty() {
            return Err("node.label is empty".to_string());
        }

        self.l1
            .rpc
            .validate_base()
            .map_err(|e| format!("invalid [l1] config: {e}"))?;

        // Required endpoints must be explicit for real integration.
        let eps = &self.l1.rpc.endpoints;
        let missing = [
            ("l1.endpoints.chain_status", eps.chain_status.as_deref()),
            ("l1.endpoints.submit_batch", eps.submit_batch.as_deref()),
            ("l1.endpoints.get_inclusion", eps.get_inclusion.as_deref()),
            ("l1.endpoints.get_finality", eps.get_finality.as_deref()),
        ]
        .into_iter()
        .filter(|(_, v)| v.unwrap_or("").trim().is_empty())
        .map(|(k, _)| k)
        .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(format!(
                "missing required endpoint paths: {}",
                missing.join(", ")
            ));
        }

        if self.l1.rpc.retry.max_attempts == 0 {
            return Err("l1.retry.max_attempts must be >= 1".to_string());
        }

        Ok(())
    }
}
