use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::env;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub ippan: IppanConfig,
    pub ethereum: EthereumConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IppanConfig {
    pub rpc_url: String,
    pub poll_interval_ms: u64,
    pub subject_type: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EthereumConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub oracle_contract_address: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub score_scale: u64,
    pub max_updates_per_round: usize,
}

impl AppConfig {
    pub fn from_toml(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed reading config file: {}", path.display()))?;
        let mut cfg: AppConfig = toml::from_str(&raw).context("failed parsing config toml")?;

        // Env overrides (explicit) first.
        if let Ok(v) = env::var("IPPAN_RPC_URL") {
            if !v.trim().is_empty() {
                cfg.ippan.rpc_url = v;
            }
        }
        if let Ok(v) = env::var("ETH_RPC_URL") {
            if !v.trim().is_empty() {
                cfg.ethereum.rpc_url = v;
            }
        }

        // Resolve env:VAR references.
        cfg.ippan.rpc_url = resolve_env_ref(&cfg.ippan.rpc_url)?;
        cfg.ethereum.rpc_url = resolve_env_ref(&cfg.ethereum.rpc_url)?;

        if cfg.security.score_scale == 0 {
            return Err(anyhow!("security.score_scale must be > 0"));
        }
        if cfg.security.max_updates_per_round == 0 {
            return Err(anyhow!("security.max_updates_per_round must be > 0"));
        }

        Ok(cfg)
    }
}

pub fn resolve_env_ref(value: &str) -> Result<String> {
    const PREFIX: &str = "env:";
    if let Some(var) = value.strip_prefix(PREFIX) {
        let var = var.trim();
        if var.is_empty() {
            return Err(anyhow!("invalid env ref: {value}"));
        }
        return env::var(var).with_context(|| format!("missing env var {var} for {value}"));
    }
    Ok(value.to_string())
}

pub fn required_env(name: &str) -> Result<String> {
    env::var(name).with_context(|| format!("missing required env var {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn resolve_env_ref_reads_env_var() {
        env::set_var("TEST_ENV_REF", "http://example.com");
        let resolved = resolve_env_ref("env:TEST_ENV_REF").unwrap();
        assert_eq!(resolved, "http://example.com");
    }

    #[test]
    fn from_toml_resolves_env_refs_and_overrides() {
        env::set_var("ETH_RPC_URL", "https://rpc.example");
        env::set_var("IPPAN_RPC_URL", "http://ippan.example");

        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(
            f,
            r#"
[ippan]
rpc_url = "env:IGNORED"
poll_interval_ms = 1234
subject_type = "validator"

[ethereum]
rpc_url = "env:ETH_RPC_URL"
chain_id = 11155111
oracle_contract_address = "0x0000000000000000000000000000000000000001"

[security]
score_scale = 1000000
max_updates_per_round = 10
"#
        )
        .unwrap();

        let cfg = AppConfig::from_toml(f.path()).unwrap();
        assert_eq!(cfg.ippan.rpc_url, "http://ippan.example");
        assert_eq!(cfg.ethereum.rpc_url, "https://rpc.example");
    }
}
