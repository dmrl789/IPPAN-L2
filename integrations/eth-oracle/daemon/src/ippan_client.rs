use crate::model::SubjectScore;
use anyhow::Result;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct IppanClient {
    pub base_url: String,
    pub score_scale: u64,
    client: reqwest::Client,
}

impl IppanClient {
    pub fn new(base_url: &str, score_scale: u64) -> Self {
        // Keep client construction infallible here (panic-free) by falling back to a default client
        // if the builder fails for any reason.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            base_url: base_url.to_string(),
            score_scale,
            client,
        }
    }

    /// v1: fetch validator voting power from an IPPAN DevNet node HTTP endpoint.
    ///
    /// Assumption for v1 (documented in integrations/eth-oracle/README.md):
    /// - IPPAN DevNet exposes a Tendermint/CometBFT-compatible endpoint at `GET /validators`
    /// - The per-validator metric is `voting_power` (integer-like string)
    pub async fn fetch_scores(&self) -> Result<Vec<SubjectScore>> {
        let url = endpoint_url(&self.base_url, "/validators");
        let resp = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(anyhow::anyhow!("IPPAN endpoint returned HTTP status {status}"));
        }

        let body = resp.text().await?;
        let mut out = parse_validators_response(&body, self.score_scale)?;

        // Deterministic ordering.
        out.sort_by(|a, b| a.subject_id.cmp(&b.subject_id));
        Ok(out)
    }
}

fn endpoint_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{base}/{path}")
}

#[derive(Debug, Deserialize)]
struct RawValidatorsRpcResponse {
    result: RawValidatorsResult,
}

#[derive(Debug, Deserialize)]
struct RawValidatorsResult {
    validators: Vec<RawValidator>,
}

#[derive(Debug, Deserialize)]
struct RawValidator {
    /// Validator identifier (Tendermint "address", hex-like string).
    address: String,
    /// Voting power (integer-like string).
    voting_power: String,
}

fn parse_validators_response(body: &str, score_scale: u64) -> Result<Vec<SubjectScore>> {
    let parsed: RawValidatorsRpcResponse = serde_json::from_str(body)?;
    let mut out = Vec::with_capacity(parsed.result.validators.len());

    for v in parsed.result.validators {
        let addr = v.address.trim();
        if addr.is_empty() {
            continue;
        }

        let voting_power: u64 = match v.voting_power.trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Scale deterministically (avoid overflow).
        let scaled = (u128::from(voting_power) * u128::from(score_scale)).min(u128::from(u64::MAX));

        out.push(SubjectScore {
            subject_id: *blake3::hash(addr.as_bytes()).as_bytes(),
            score: scaled as u64,
        });
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_validators_and_scales_scores_deterministically() {
        let json = r#"
        {
          "jsonrpc": "2.0",
          "id": -1,
          "result": {
            "block_height": "123",
            "validators": [
              { "address": "BEEF01", "pub_key": { "type": "x", "value": "y" }, "voting_power": "10", "proposer_priority": "0" },
              { "address": "AABBCC", "pub_key": { "type": "x", "value": "y" }, "voting_power": "2", "proposer_priority": "0" }
            ],
            "count": "2",
            "total": "2"
          }
        }"#;

        let mut scores = parse_validators_response(json, 1_000_000).unwrap();
        scores.sort_by(|a, b| a.subject_id.cmp(&b.subject_id));

        let expected_a = SubjectScore {
            subject_id: *blake3::hash(b"AABBCC").as_bytes(),
            score: 2_000_000,
        };
        let expected_b = SubjectScore {
            subject_id: *blake3::hash(b"BEEF01").as_bytes(),
            score: 10_000_000,
        };

        assert_eq!(scores, vec![expected_a, expected_b]);
    }
}
