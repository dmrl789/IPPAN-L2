use crate::model::SubjectScore;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct IppanClient {
    pub base_url: String,
    pub score_scale: u64,
}

impl IppanClient {
    pub fn new(base_url: &str, score_scale: u64) -> Self {
        Self {
            base_url: base_url.to_string(),
            score_scale,
        }
    }

    /// v1: mocked scores; will be replaced with real IPPAN RPC.
    pub async fn fetch_scores(&self) -> Result<Vec<SubjectScore>> {
        // Produce two deterministic dummy subjects
        let s1 = SubjectScore {
            subject_id: *blake3::hash(b"validator-1").as_bytes(),
            score: 50 * self.score_scale,
        };
        let s2 = SubjectScore {
            subject_id: *blake3::hash(b"validator-2").as_bytes(),
            score: 80 * self.score_scale,
        };
        Ok(vec![s1, s2])
    }
}
