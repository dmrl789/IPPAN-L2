#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::disallowed_types)]

//! IPPAN L2 Bridge Module
//!
//! This module handles deposits (L1 → L2) and withdrawals (L2 → L1).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use l2_core::{canonical_encode, ChainId};
use l2_storage::Storage;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::interval;
use tracing::{debug, info, warn};

// ============== Deposit Types ==============

/// Status of a deposit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositStatus {
    /// Deposit seen on L1 but not yet verified.
    Pending,
    /// Deposit verified and credited to L2.
    Verified,
    /// Deposit rejected (invalid proof, already claimed, etc.).
    Rejected,
}

/// A deposit event from L1 to L2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositEvent {
    /// L1 transaction hash (source of deposit).
    pub l1_tx_hash: String,
    /// Sender address on L1.
    pub from_l1: String,
    /// Recipient address on L2.
    pub to_l2: String,
    /// Asset identifier (e.g., "IPN", "USDC").
    pub asset: String,
    /// Amount in smallest units.
    pub amount: u128,
    /// Memo field from L1 tx (contains routing info).
    pub memo: Option<String>,
    /// Timestamp when deposit was seen (ms since epoch).
    pub seen_at_ms: u64,
    /// Current status of the deposit.
    pub status: DepositStatus,
    /// L2 chain ID this deposit is for.
    pub chain_id: ChainId,
    /// Nonce for idempotency.
    #[serde(default)]
    pub nonce: u64,
}

impl DepositEvent {
    /// Parse L2 recipient from memo field.
    ///
    /// Expected format: `l2_to=<addr>` or `to=<addr>`
    pub fn parse_to_l2_from_memo(memo: &str) -> Option<String> {
        for part in memo.split(&[',', ';', ' '][..]) {
            let part = part.trim();
            if let Some(addr) = part.strip_prefix("l2_to=") {
                return Some(addr.to_string());
            }
            if let Some(addr) = part.strip_prefix("to=") {
                return Some(addr.to_string());
            }
        }
        None
    }

    /// Create a deposit ID for storage key.
    pub fn deposit_id(&self) -> String {
        format!("{}:{}", self.l1_tx_hash, self.nonce)
    }
}

/// Request to claim a deposit manually.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositClaimRequest {
    /// L1 transaction hash.
    pub l1_tx_hash: String,
    /// Optional proof fields (depends on L1 capabilities).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<serde_json::Value>,
}

/// Response to a deposit claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositClaimResponse {
    /// Whether the claim was accepted.
    pub accepted: bool,
    /// The deposit event (if accepted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposit: Option<DepositEvent>,
    /// Error message (if rejected).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============== Withdrawal Types ==============

/// Status of a withdrawal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawStatus {
    /// Withdrawal request submitted.
    Pending,
    /// Withdrawal posted to L1.
    Posted,
    /// Withdrawal confirmed on L1.
    Confirmed,
    /// Withdrawal failed.
    Failed,
}

/// A withdrawal request from L2 to L1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawRequest {
    /// Unique withdrawal ID.
    pub id: String,
    /// Sender address on L2.
    pub from_l2: String,
    /// Recipient address on L1.
    pub to_l1: String,
    /// Asset identifier.
    pub asset: String,
    /// Amount in smallest units.
    pub amount: u128,
    /// Nonce for replay protection.
    pub nonce: u64,
    /// Signature from L2 account (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    /// Timestamp when request was created (ms since epoch).
    pub created_at_ms: u64,
    /// Current status.
    pub status: WithdrawStatus,
    /// L1 transaction hash (if posted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l1_tx: Option<String>,
    /// L2 chain ID.
    pub chain_id: ChainId,
}

impl WithdrawRequest {
    /// Generate a withdrawal ID.
    pub fn generate_id(from: &str, nonce: u64) -> String {
        let data = format!("{from}:{nonce}");
        let hash = l2_core::canonical_hash_bytes(data.as_bytes());
        hex::encode(&hash[..16])
    }

    /// Create memo for L1 transaction.
    pub fn to_memo(&self) -> String {
        format!(
            "withdraw_id={};from_l2={};amount={}",
            self.id, self.from_l2, self.amount
        )
    }
}

// ============== Legacy Event Types (for backwards compatibility) ==============

/// Legacy message event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub chain_id: ChainId,
    pub from: String,
    pub payload: Vec<u8>,
    pub emitted_ms: u64,
}

/// Legacy bridge event enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeEvent {
    Deposit(DepositEvent),
    Withdraw(WithdrawRequest),
    Message(Message),
}

// ============== Configuration ==============

/// Bridge configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Polling interval for L1 watcher (ms).
    pub poll_interval_ms: u64,
    /// L1 bridge address/handle to watch.
    pub bridge_address: String,
    /// L2 chain ID.
    pub chain_id: ChainId,
    /// Maximum deposits to process per poll.
    pub max_deposits_per_poll: usize,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 2_000,
            bridge_address: String::new(),
            chain_id: ChainId(1),
            max_deposits_per_poll: 100,
        }
    }
}

impl BridgeConfig {
    /// Create from environment variables.
    pub fn from_env() -> Self {
        let poll_interval_ms = std::env::var("L2_BRIDGE_POLL_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2_000);
        let bridge_address = std::env::var("L2_BRIDGE_ADDRESS").unwrap_or_default();
        let chain_id = std::env::var("L2_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(ChainId)
            .unwrap_or(ChainId(1));
        let max_deposits_per_poll = std::env::var("L2_BRIDGE_MAX_DEPOSITS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        Self {
            poll_interval_ms,
            bridge_address,
            chain_id,
            max_deposits_per_poll,
        }
    }
}

// ============== Errors ==============

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("storage error: {0}")]
    Storage(#[from] l2_storage::StorageError),
    #[error("watcher error: {0}")]
    Watcher(String),
    #[error("canonical error: {0}")]
    Canonical(#[from] l2_core::CanonicalError),
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("invalid deposit: {0}")]
    InvalidDeposit(String),
    #[error("duplicate deposit: {0}")]
    DuplicateDeposit(String),
}

// ============== L1 Watcher Trait ==============

/// Trait for L1 watchers.
#[async_trait]
pub trait L1Watcher: Send + Sync {
    /// Poll for new events.
    async fn poll_events(&self) -> Result<Vec<BridgeEvent>, BridgeError>;

    /// Verify a deposit claim.
    async fn verify_deposit(&self, l1_tx_hash: &str) -> Result<Option<DepositEvent>, BridgeError>;
}

/// Stub watcher that does nothing (for testing).
pub struct LoggingWatcher;

#[async_trait]
impl L1Watcher for LoggingWatcher {
    async fn poll_events(&self) -> Result<Vec<BridgeEvent>, BridgeError> {
        debug!("stub L1 watcher poll");
        Ok(Vec::new())
    }

    async fn verify_deposit(&self, l1_tx_hash: &str) -> Result<Option<DepositEvent>, BridgeError> {
        debug!(l1_tx_hash, "stub verify deposit");
        Ok(None)
    }
}

/// IPPAN RPC-based L1 watcher.
pub struct IppanL1Watcher {
    client: ippan_rpc::IppanRpcClient,
    config: BridgeConfig,
}

impl IppanL1Watcher {
    /// Create a new IPPAN L1 watcher.
    pub fn new(
        rpc_config: ippan_rpc::IppanRpcConfig,
        bridge_config: BridgeConfig,
    ) -> Result<Self, BridgeError> {
        let client = ippan_rpc::IppanRpcClient::new(rpc_config)
            .map_err(|e| BridgeError::Rpc(format!("failed to create RPC client: {e}")))?;
        Ok(Self {
            client,
            config: bridge_config,
        })
    }
}

#[async_trait]
impl L1Watcher for IppanL1Watcher {
    async fn poll_events(&self) -> Result<Vec<BridgeEvent>, BridgeError> {
        // For MVP, we don't have a "list txs" endpoint on IPPAN
        // This is a best-effort implementation that logs the limitation
        debug!(
            bridge_address = %self.config.bridge_address,
            "IPPAN L1 watcher: no list txs endpoint available, use manual deposit claims"
        );
        Ok(Vec::new())
    }

    async fn verify_deposit(&self, l1_tx_hash: &str) -> Result<Option<DepositEvent>, BridgeError> {
        // Query the L1 tx to verify it exists and extract deposit info
        let tx_info = self
            .client
            .get_tx(l1_tx_hash)
            .await
            .map_err(|e| BridgeError::Rpc(format!("failed to get tx {l1_tx_hash}: {e}")))?;

        match tx_info {
            Some(tx) => {
                // Check if tx was successful
                if !tx.success.unwrap_or(false) && tx.height.is_none() {
                    return Ok(None);
                }

                // For MVP, we need to parse deposit info from the tx
                // This is simplified - in production would parse tx data more carefully
                info!(
                    l1_tx_hash,
                    status = ?tx.status,
                    height = ?tx.height,
                    "verified L1 tx exists"
                );

                // Return None for now - actual deposit parsing would depend on tx format
                // The claim endpoint will allow users to provide deposit details
                Ok(None)
            }
            None => Ok(None),
        }
    }
}

// ============== Bridge Snapshot ==============

#[derive(Debug, Clone, Default)]
pub struct BridgeSnapshot {
    pub enabled: bool,
    pub last_event_time_ms: Option<u64>,
    pub deposits_verified: u64,
    pub withdrawals_pending: u64,
}

#[derive(Clone)]
struct BridgeState {
    last_event_time_ms: Option<u64>,
    deposits_verified: u64,
    withdrawals_pending: u64,
}

impl From<BridgeState> for BridgeSnapshot {
    fn from(state: BridgeState) -> Self {
        Self {
            enabled: true,
            last_event_time_ms: state.last_event_time_ms,
            deposits_verified: state.deposits_verified,
            withdrawals_pending: state.withdrawals_pending,
        }
    }
}

// ============== Bridge Handle ==============

pub struct BridgeHandle {
    state: Arc<Mutex<BridgeState>>,
}

impl Clone for BridgeHandle {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl BridgeHandle {
    pub async fn snapshot(&self) -> BridgeSnapshot {
        self.state.lock().await.clone().into()
    }
}

// ============== Bridge Runner ==============

pub fn spawn(
    config: BridgeConfig,
    storage: Arc<Storage>,
    watcher: Arc<dyn L1Watcher>,
) -> BridgeHandle {
    let state = Arc::new(Mutex::new(BridgeState {
        last_event_time_ms: None,
        deposits_verified: 0,
        withdrawals_pending: 0,
    }));
    tokio::spawn(run_loop(config, storage, watcher, Arc::clone(&state)));
    BridgeHandle { state }
}

async fn run_loop(
    config: BridgeConfig,
    storage: Arc<Storage>,
    watcher: Arc<dyn L1Watcher>,
    state: Arc<Mutex<BridgeState>>,
) {
    let mut ticker = interval(Duration::from_millis(config.poll_interval_ms));
    loop {
        ticker.tick().await;
        match watcher.poll_events().await {
            Ok(events) => {
                for event in events {
                    if let Err(err) = persist_event(&storage, &event).await {
                        warn!(error = %err, "failed to persist bridge event");
                    }
                    let mut guard = state.lock().await;
                    guard.last_event_time_ms = Some(event_time(&event));
                    if matches!(event, BridgeEvent::Deposit(_)) {
                        guard.deposits_verified = guard.deposits_verified.saturating_add(1);
                    }
                }
            }
            Err(err) => warn!(error = %err, "watcher errored"),
        }
    }
}

async fn persist_event(storage: &Storage, event: &BridgeEvent) -> Result<(), BridgeError> {
    let encoded = canonical_encode(event)?;
    storage.set_meta("bridge:last_event", &encoded)?;
    Ok(())
}

fn event_time(event: &BridgeEvent) -> u64 {
    match event {
        BridgeEvent::Deposit(ev) => ev.seen_at_ms,
        BridgeEvent::Withdraw(ev) => ev.created_at_ms,
        BridgeEvent::Message(ev) => ev.emitted_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    struct StaticWatcher;

    #[async_trait]
    impl L1Watcher for StaticWatcher {
        async fn poll_events(&self) -> Result<Vec<BridgeEvent>, BridgeError> {
            Ok(vec![BridgeEvent::Deposit(DepositEvent {
                l1_tx_hash: "abc123".to_string(),
                from_l1: "alice".to_string(),
                to_l2: "alice_l2".to_string(),
                asset: "IPN".to_string(),
                amount: 1000,
                memo: Some("l2_to=alice_l2".to_string()),
                seen_at_ms: 123,
                status: DepositStatus::Verified,
                chain_id: ChainId(1),
                nonce: 0,
            })])
        }

        async fn verify_deposit(
            &self,
            _l1_tx_hash: &str,
        ) -> Result<Option<DepositEvent>, BridgeError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn records_last_event_time() {
        let dir = tempdir().expect("tmpdir");
        let storage = Arc::new(Storage::open(dir.path()).expect("open"));
        let watcher: Arc<dyn L1Watcher> = Arc::new(StaticWatcher {});
        let handle = spawn(BridgeConfig::default(), storage, watcher);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let snapshot = handle.snapshot().await;
        assert_eq!(snapshot.last_event_time_ms, Some(123));
    }

    #[test]
    fn parse_to_l2_from_memo() {
        assert_eq!(
            DepositEvent::parse_to_l2_from_memo("l2_to=alice"),
            Some("alice".to_string())
        );
        assert_eq!(
            DepositEvent::parse_to_l2_from_memo("foo=bar,l2_to=bob"),
            Some("bob".to_string())
        );
        assert_eq!(
            DepositEvent::parse_to_l2_from_memo("to=charlie"),
            Some("charlie".to_string())
        );
        assert_eq!(DepositEvent::parse_to_l2_from_memo("no_match"), None);
    }

    #[test]
    fn withdraw_request_memo() {
        let req = WithdrawRequest {
            id: "wd123".to_string(),
            from_l2: "alice".to_string(),
            to_l1: "alice_l1".to_string(),
            asset: "IPN".to_string(),
            amount: 1000,
            nonce: 1,
            sig: None,
            created_at_ms: 0,
            status: WithdrawStatus::Pending,
            l1_tx: None,
            chain_id: ChainId(1),
        };
        let memo = req.to_memo();
        assert!(memo.contains("withdraw_id=wd123"));
        assert!(memo.contains("from_l2=alice"));
        assert!(memo.contains("amount=1000"));
    }

    #[test]
    fn withdraw_id_generation() {
        let id1 = WithdrawRequest::generate_id("alice", 1);
        let id2 = WithdrawRequest::generate_id("alice", 2);
        let id3 = WithdrawRequest::generate_id("alice", 1);

        assert_ne!(id1, id2);
        assert_eq!(id1, id3);
        assert!(!id1.is_empty());
    }
}
