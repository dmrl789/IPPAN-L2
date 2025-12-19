use crate::model::SubjectScore;
use anyhow::{anyhow, Context, Result};
use reqwest::Url;
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct IppanClient {
    base_url: Url,
    score_scale: u64,
    subject_type: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct ValidatorEntry {
    validator_id: String,
    uptime_percent: serde_json::Value,
}

impl IppanClient {
    pub fn new(base_url: &str, score_scale: u64, subject_type: String) -> Result<Self> {
        let base_url = Url::parse(base_url).context("invalid IPPAN rpc_url")?;
        let http = reqwest::Client::builder()
            .user_agent("ippan-eth-oracle-daemon/0.1")
            .build()
            .context("failed to build http client")?;

        Ok(Self {
            base_url,
            score_scale,
            subject_type,
            http,
        })
    }

    pub async fn fetch_scores(&self) -> Result<Vec<SubjectScore>> {
        match self.subject_type.as_str() {
            "validator" => self.fetch_validator_scores().await,
            "handle" => self.fetch_validator_scores().await, // v1 placeholder: same source
            other => Err(anyhow!("unsupported subject_type: {other}")),
        }
    }

    async fn fetch_validator_scores(&self) -> Result<Vec<SubjectScore>> {
        // v1 placeholder endpoint. If your DevNet differs, update this mapping and README.
        let url = self
            .base_url
            .join("validators")
            .context("failed joining /validators endpoint")?;

        let entries: Vec<ValidatorEntry> = self
            .http
            .get(url)
            .send()
            .await
            .context("failed calling IPPAN endpoint")?
            .error_for_status()
            .context("IPPAN endpoint returned error status")?
            .json()
            .await
            .context("failed parsing IPPAN JSON")?;

        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let subject_id = sha256_32(e.validator_id.as_bytes());
            let uptime = parse_decimal(&e.uptime_percent)
                .with_context(|| format!("invalid uptime_percent for {}", e.validator_id))?;
            let scaled = (uptime * Decimal::from(self.score_scale)).trunc();
            let score_u64 = scaled
                .to_u64()
                .ok_or_else(|| anyhow!("scaled uptime out of range for u64"))?;

            out.push(SubjectScore {
                subject_id,
                score: score_u64,
            });
        }

        Ok(out)
    }
}

fn sha256_32(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn parse_decimal(v: &serde_json::Value) -> Result<Decimal> {
    match v {
        serde_json::Value::Number(n) => {
            // Parse via string to avoid float rounding artifacts.
            Decimal::from_str_exact(&n.to_string()).map_err(|e| anyhow!(e))
        }
        serde_json::Value::String(s) => Decimal::from_str_exact(s).map_err(|e| anyhow!(e)),
        other => Err(anyhow!("expected number/string, got {other}")),
    }
}
