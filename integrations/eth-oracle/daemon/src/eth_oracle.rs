use crate::config::{required_env, EthereumConfig};
use crate::model::SubjectScore;
use anyhow::{anyhow, Context, Result};
use ethers::prelude::*;
use std::sync::Arc;

abigen!(
    IppanAiOracle,
    r#"[
      {"inputs":[{"internalType":"address","name":"_updater","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},
      {"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subject","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"score","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"timestamp","type":"uint256"}],"name":"ScoreUpdated","type":"event"},
      {"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"count","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"timestamp","type":"uint256"}],"name":"BatchScoreUpdated","type":"event"},
      {"inputs":[{"internalType":"bytes32","name":"subject","type":"bytes32"}],"name":"getScore","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
      {"inputs":[],"name":"updater","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},
      {"inputs":[{"internalType":"bytes32","name":"subject","type":"bytes32"},{"internalType":"uint256","name":"score","type":"uint256"}],"name":"updateScore","outputs":[],"stateMutability":"nonpayable","type":"function"},
      {"inputs":[{"internalType":"bytes32[]","name":"subjects","type":"bytes32[]"},{"internalType":"uint256[]","name":"newScores","type":"uint256[]"}],"name":"updateScores","outputs":[],"stateMutability":"nonpayable","type":"function"}
    ]"#
);

type SignerClient = SignerMiddleware<Provider<Http>, LocalWallet>;

#[derive(Clone)]
pub struct EthOracleClient {
    contract: IppanAiOracle<SignerClient>,
}

impl EthOracleClient {
    pub async fn new(cfg: &EthereumConfig) -> Result<Self> {
        let rpc_url = cfg.rpc_url.clone();
        let provider = Provider::<Http>::try_from(rpc_url.clone())
            .with_context(|| format!("invalid ethereum rpc url: {rpc_url}"))?;

        let private_key = required_env("ETH_PRIVATE_KEY")?;
        let wallet: LocalWallet = private_key
            .parse::<LocalWallet>()
            .context("failed parsing ETH_PRIVATE_KEY")?
            .with_chain_id(cfg.chain_id);

        let client = SignerMiddleware::new(provider, wallet);
        let client = Arc::new(client);

        let addr: Address = cfg
            .oracle_contract_address
            .parse()
            .context("invalid oracle_contract_address")?;
        if addr == Address::zero() {
            return Err(anyhow!(
                "oracle_contract_address is zero; deploy and update config"
            ));
        }

        let contract = IppanAiOracle::new(addr, client);
        Ok(Self { contract })
    }

    pub async fn push_scores(&self, scores: &[SubjectScore]) -> Result<TxHash> {
        if scores.is_empty() {
            return Err(anyhow!("push_scores called with empty score list"));
        }

        let pending = if scores.len() == 1 {
            let s = &scores[0];
            self.contract
                .update_score(H256::from(s.subject_id), U256::from(s.score))
                .send()
                .await
                .context("failed sending updateScore tx")?
        } else {
            let mut subjects = Vec::with_capacity(scores.len());
            let mut new_scores = Vec::with_capacity(scores.len());
            for s in scores {
                subjects.push(H256::from(s.subject_id));
                new_scores.push(U256::from(s.score));
            }

            self.contract
                .update_scores(subjects, new_scores)
                .send()
                .await
                .context("failed sending updateScores tx")?
        };

        let receipt = pending
            .await
            .context("failed waiting for tx confirmation")?
            .ok_or_else(|| anyhow!("tx dropped from mempool"))?;

        Ok(receipt.transaction_hash)
    }
}
