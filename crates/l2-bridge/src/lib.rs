#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::disallowed_types)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use l2_core::{canonical_encode, ChainId};
use l2_storage::Storage;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::interval;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositEvent {
    pub chain_id: ChainId,
    pub from: String,
    pub amount: u64,
    pub payload: Vec<u8>,
    pub emitted_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawRequest {
    pub chain_id: ChainId,
    pub to: String,
    pub amount: u64,
    pub request_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub chain_id: ChainId,
    pub from: String,
    pub payload: Vec<u8>,
    pub emitted_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeEvent {
    Deposit(DepositEvent),
    Withdraw(WithdrawRequest),
    Message(Message),
}

#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub poll_interval_ms: u64,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 1_000,
        }
    }
}

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("storage error: {0}")]
    Storage(#[from] l2_storage::StorageError),
    #[error("watcher error: {0}")]
    Watcher(String),
}

#[async_trait]
pub trait L1Watcher: Send + Sync {
    async fn poll_events(&self) -> Result<Vec<BridgeEvent>, BridgeError>;
}

pub struct LoggingWatcher;

#[async_trait]
impl L1Watcher for LoggingWatcher {
    async fn poll_events(&self) -> Result<Vec<BridgeEvent>, BridgeError> {
        info!("stub L1 watcher poll");
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone, Default)]
pub struct BridgeSnapshot {
    pub enabled: bool,
    pub last_event_time_ms: Option<u64>,
}

struct BridgeState {
    last_event_time_ms: Option<u64>,
}

impl From<BridgeState> for BridgeSnapshot {
    fn from(state: BridgeState) -> Self {
        Self {
            enabled: true,
            last_event_time_ms: state.last_event_time_ms,
        }
    }
}

pub struct BridgeHandle {
    state: Arc<Mutex<BridgeState>>,
}

impl BridgeHandle {
    pub async fn snapshot(&self) -> BridgeSnapshot {
        self.state.lock().await.clone().into()
    }
}

pub fn spawn(
    config: BridgeConfig,
    storage: Arc<Storage>,
    watcher: Arc<dyn L1Watcher>,
) -> BridgeHandle {
    let state = Arc::new(Mutex::new(BridgeState {
        last_event_time_ms: None,
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
        BridgeEvent::Deposit(ev) => ev.emitted_ms,
        BridgeEvent::Withdraw(ev) => ev.request_ms,
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
                chain_id: ChainId(1),
                from: "alice".to_string(),
                amount: 10,
                payload: vec![1],
                emitted_ms: 123,
            })])
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
}
