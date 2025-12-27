#![forbid(unsafe_code)]
// Workspace clippy config forbids float types, but `serde` derive macros generate
// visitors that reference `f32`/`f64` even if our config structs do not use them.
#![allow(clippy::disallowed_types)]

use l2_core::l1_contract::http_client::L1RpcConfig;
use l2_core::policy::PolicyMode;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;

#[derive(Debug, Clone, Deserialize)]
pub struct FinNodeConfig {
    #[serde(default)]
    pub node: NodeConfig,
    pub l1: L1Config,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub pagination: PaginationConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
    #[serde(default)]
    pub pruning: PruningConfig,
    #[serde(default)]
    pub cors: CorsConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub encryption: EncryptionConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub recon: ReconConfig,
    #[serde(default)]
    pub linkage: LinkageConfig,
    #[serde(default)]
    pub ha: HaConfig,
    #[serde(default)]
    pub snapshots: SnapshotsConfig,
    #[serde(default)]
    pub bootstrap: BootstrapConfig,
}

// ============================================================
// Security mode configuration for endpoint gating
// ============================================================

/// Node security mode determines which endpoints are available.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityMode {
    /// Development mode: all endpoints enabled, no auth required.
    #[default]
    Devnet,
    /// Staging mode: some ops endpoints require auth.
    Staging,
    /// Production mode: strict endpoint gating, auth required for sensitive ops.
    Prod,
}

impl SecurityMode {
    /// Check if this mode allows devnet-only endpoints (e.g., `/m2m/topup`).
    pub fn allows_devnet_endpoints(&self) -> bool {
        matches!(self, Self::Devnet)
    }

    /// Check if this mode allows unauthenticated admin/ops endpoints.
    pub fn allows_unauthenticated_ops(&self) -> bool {
        matches!(self, Self::Devnet)
    }

    /// Check if this mode requires auth for list proofs endpoints.
    pub fn requires_auth_for_list_proofs(&self) -> bool {
        matches!(self, Self::Prod)
    }

    /// Check if this mode requires auth for eth header submission.
    pub fn requires_auth_for_eth_headers(&self) -> bool {
        matches!(self, Self::Staging | Self::Prod)
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Staging => "staging",
            Self::Prod => "prod",
        }
    }
}

/// Security configuration for endpoint gating and authentication.
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    /// Security mode (devnet/staging/prod).
    #[serde(default)]
    pub mode: SecurityMode,
    /// Admin ops token (HMAC-based, simple MVP auth).
    /// Required in staging/prod for ops endpoints.
    #[serde(default)]
    pub admin_token: String,
    /// Allowlisted bridge proof submitter public keys (hex-encoded ed25519).
    #[serde(default)]
    pub bridge_submitters: Vec<String>,
    /// Allowlisted attestor public keys (hex-encoded ed25519).
    #[serde(default)]
    pub attestor_keys: Vec<String>,
    /// Request timeout in milliseconds.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Maximum query string length (bytes).
    #[serde(default = "default_max_query_string_bytes")]
    pub max_query_string_bytes: usize,
}

fn default_request_timeout_ms() -> u64 {
    30_000
}

fn default_max_query_string_bytes() -> usize {
    4096
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            mode: SecurityMode::Devnet,
            admin_token: String::new(),
            bridge_submitters: Vec::new(),
            attestor_keys: Vec::new(),
            request_timeout_ms: default_request_timeout_ms(),
            max_query_string_bytes: default_max_query_string_bytes(),
        }
    }
}

impl SecurityConfig {
    pub fn validate(&self) -> Result<(), String> {
        // In prod/staging, admin_token should be set
        if matches!(self.mode, SecurityMode::Prod | SecurityMode::Staging) {
            if self.admin_token.trim().is_empty() {
                return Err(
                    "[security].admin_token is empty (required for staging/prod mode)".to_string(),
                );
            }
            if self.admin_token.len() < 32 {
                return Err(
                    "[security].admin_token is too short (min 32 chars for staging/prod)"
                        .to_string(),
                );
            }
        }

        // Validate bridge submitter keys
        for (i, k) in self.bridge_submitters.iter().enumerate() {
            if k.trim().is_empty() {
                return Err(format!("[security].bridge_submitters[{i}] is empty"));
            }
            let raw = hex::decode(k).map_err(|e| {
                format!("[security].bridge_submitters[{i}] invalid hex: {e}")
            })?;
            if raw.len() != 32 {
                return Err(format!(
                    "[security].bridge_submitters[{i}] must be 32 bytes (got {})",
                    raw.len()
                ));
            }
        }

        // Validate attestor keys
        for (i, k) in self.attestor_keys.iter().enumerate() {
            if k.trim().is_empty() {
                return Err(format!("[security].attestor_keys[{i}] is empty"));
            }
            let raw = hex::decode(k)
                .map_err(|e| format!("[security].attestor_keys[{i}] invalid hex: {e}"))?;
            if raw.len() != 32 {
                return Err(format!(
                    "[security].attestor_keys[{i}] must be 32 bytes (got {})",
                    raw.len()
                ));
            }
        }

        if self.request_timeout_ms == 0 {
            return Err("[security].request_timeout_ms must be >= 1".to_string());
        }

        if self.max_query_string_bytes == 0 {
            return Err("[security].max_query_string_bytes must be >= 1".to_string());
        }

        Ok(())
    }

    /// Check if a given admin token matches.
    pub fn verify_admin_token(&self, token: &str) -> bool {
        if self.admin_token.is_empty() {
            return false;
        }
        // Constant-time comparison for security
        constant_time_eq(self.admin_token.as_bytes(), token.as_bytes())
    }

    /// Check if a bridge submitter pubkey is allowlisted.
    pub fn is_bridge_submitter_allowed(&self, pubkey_hex: &str) -> bool {
        // Empty list means allow all (devnet behavior)
        if self.bridge_submitters.is_empty() {
            return true;
        }
        self.bridge_submitters
            .iter()
            .any(|k| k.eq_ignore_ascii_case(pubkey_hex))
    }

    /// Check if an attestor pubkey is allowlisted.
    pub fn is_attestor_allowed(&self, pubkey_hex: &str) -> bool {
        // Empty list means allow all (devnet behavior)
        if self.attestor_keys.is_empty() {
            return true;
        }
        self.attestor_keys
            .iter()
            .any(|k| k.eq_ignore_ascii_case(pubkey_hex))
    }
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================
// Encryption-at-rest configuration (feature: encryption-at-rest)
// ============================================================

#[derive(Debug, Clone, Deserialize)]
pub struct EncryptionConfig {
    /// Enable encryption-at-rest behavior for sled values and exported archives.
    #[serde(default)]
    pub enabled: bool,
    /// Key provider type (MVP: "file").
    #[serde(default)]
    pub provider: String,
    /// Current key id (e.g. "k1").
    #[serde(default)]
    pub key_id: String,
    /// Path to current master key file (32-byte hex).
    #[serde(default)]
    pub key_path: String,
    /// Optional directory containing old keys (for decrypt of historical values).
    #[serde(default)]
    pub old_keys_dir: String,
    /// Ordered list of key ids acceptable for decrypt lookup (newest first).
    #[serde(default)]
    pub keyring: Vec<String>,
    /// Dev-only escape hatch: allow reading plaintext values when encryption is enabled.
    #[serde(default)]
    pub allow_plaintext_read: bool,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "file".to_string(),
            key_id: String::new(),
            key_path: String::new(),
            old_keys_dir: String::new(),
            keyring: Vec::new(),
            allow_plaintext_read: false,
        }
    }
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
    /// Best-effort overload protection. If `inflight_requests >= max_inflight_requests`, the
    /// server rejects new requests with HTTP 503.
    #[serde(default = "default_max_inflight_requests")]
    pub max_inflight_requests: usize,
}

fn default_bind_address() -> String {
    "0.0.0.0:3000".to_string()
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_max_inflight_requests() -> usize {
    64
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            metrics_enabled: default_metrics_enabled(),
            max_inflight_requests: default_max_inflight_requests(),
        }
    }
}

/// Admission/abuse-resistance limits.
#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    /// Max HTTP request body size (bytes). Oversized bodies return HTTP 413.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    /// Max body size for bridge proof endpoints (bytes).
    #[serde(default = "default_max_bridge_proof_bytes")]
    pub max_bridge_proof_bytes: usize,
    /// Max string size for user-provided fields (UTF-8 bytes).
    #[serde(default = "default_max_string_bytes")]
    pub max_string_bytes: usize,
    /// Max number of tags in requests that include tags.
    #[serde(default = "default_max_tags")]
    pub max_tags: usize,
    /// Max length of an individual tag (UTF-8 bytes).
    #[serde(default = "default_max_tag_bytes")]
    pub max_tag_bytes: usize,
    /// Max number of items in batch-like inputs (CLI/API) where applicable.
    #[serde(default = "default_max_batch_items")]
    pub max_batch_items: usize,
    /// Max size of receipt blobs returned or processed (bytes).
    #[serde(default = "default_max_receipt_bytes")]
    pub max_receipt_bytes: usize,
    /// Best-effort JSON depth limit for request bodies.
    #[serde(default = "default_max_json_depth")]
    pub max_json_depth: usize,
    /// Max number of MPT proof nodes in merkle proofs.
    #[serde(default = "default_max_mpt_proof_nodes")]
    pub max_mpt_proof_nodes: usize,
    /// Max total bytes for all MPT proof nodes combined.
    #[serde(default = "default_max_mpt_proof_bytes")]
    pub max_mpt_proof_bytes: usize,
    /// Max RLP-encoded header size (bytes).
    #[serde(default = "default_max_header_rlp_bytes")]
    pub max_header_rlp_bytes: usize,
    /// Max RLP-encoded receipt size (bytes).
    #[serde(default = "default_max_receipt_rlp_bytes")]
    pub max_receipt_rlp_bytes: usize,
}

fn default_max_body_bytes() -> usize {
    256 * 1024
}
fn default_max_bridge_proof_bytes() -> usize {
    512 * 1024
}
fn default_max_string_bytes() -> usize {
    1024
}
fn default_max_tags() -> usize {
    32
}
fn default_max_tag_bytes() -> usize {
    48
}
fn default_max_batch_items() -> usize {
    256
}
fn default_max_receipt_bytes() -> usize {
    256 * 1024
}
fn default_max_json_depth() -> usize {
    64
}
fn default_max_mpt_proof_nodes() -> usize {
    32
}
fn default_max_mpt_proof_bytes() -> usize {
    64 * 1024
}
fn default_max_header_rlp_bytes() -> usize {
    8 * 1024
}
fn default_max_receipt_rlp_bytes() -> usize {
    32 * 1024
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: default_max_body_bytes(),
            max_bridge_proof_bytes: default_max_bridge_proof_bytes(),
            max_string_bytes: default_max_string_bytes(),
            max_tags: default_max_tags(),
            max_tag_bytes: default_max_tag_bytes(),
            max_batch_items: default_max_batch_items(),
            max_receipt_bytes: default_max_receipt_bytes(),
            max_json_depth: default_max_json_depth(),
            max_mpt_proof_nodes: default_max_mpt_proof_nodes(),
            max_mpt_proof_bytes: default_max_mpt_proof_bytes(),
            max_header_rlp_bytes: default_max_header_rlp_bytes(),
            max_receipt_rlp_bytes: default_max_receipt_rlp_bytes(),
        }
    }
}

/// In-memory token bucket rate limiting (best-effort).
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,
    #[serde(default = "default_rate_limit_burst")]
    pub burst: u32,
}

fn default_rate_limit_enabled() -> bool {
    false
}
fn default_requests_per_minute() -> u32 {
    120
}
fn default_rate_limit_burst() -> u32 {
    60
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_rate_limit_enabled(),
            requests_per_minute: default_requests_per_minute(),
            burst: default_rate_limit_burst(),
        }
    }
}

/// Cursor pagination defaults for list endpoints.
#[derive(Debug, Clone, Deserialize)]
pub struct PaginationConfig {
    #[serde(default = "default_pagination_default_limit")]
    pub default_limit: usize,
    #[serde(default = "default_pagination_max_limit")]
    pub max_limit: usize,
}

fn default_pagination_default_limit() -> usize {
    50
}
fn default_pagination_max_limit() -> usize {
    200
}

impl Default for PaginationConfig {
    fn default() -> Self {
        Self {
            default_limit: default_pagination_default_limit(),
            max_limit: default_pagination_max_limit(),
        }
    }
}

/// Retention policy for bounded growth.
#[derive(Debug, Clone, Deserialize)]
pub struct RetentionConfig {
    #[serde(default = "default_receipts_days")]
    pub receipts_days: u32,
    #[serde(default = "default_recon_failed_days")]
    pub recon_failed_days: u32,
    /// Audit event log retention. `0` means infinite (do not prune audit log).
    #[serde(default = "default_audit_days")]
    pub audit_days: u32,
    #[serde(default = "default_min_receipts_keep")]
    pub min_receipts_keep: usize,
}

fn default_receipts_days() -> u32 {
    30
}
fn default_recon_failed_days() -> u32 {
    7
}
fn default_audit_days() -> u32 {
    0
}
fn default_min_receipts_keep() -> usize {
    1000
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            receipts_days: default_receipts_days(),
            recon_failed_days: default_recon_failed_days(),
            audit_days: default_audit_days(),
            min_receipts_keep: default_min_receipts_keep(),
        }
    }
}

/// Background pruning job configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct PruningConfig {
    #[serde(default = "default_pruning_enabled")]
    pub enabled: bool,
    /// Interval between pruning runs (seconds).
    #[serde(default = "default_pruning_interval_secs")]
    pub interval_secs: u64,
}

fn default_pruning_enabled() -> bool {
    false
}
fn default_pruning_interval_secs() -> u64 {
    86_400
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            enabled: default_pruning_enabled(),
            interval_secs: default_pruning_interval_secs(),
        }
    }
}

/// Basic CORS configuration (default deny).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CorsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allow_origins: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_receipts_dir")]
    pub receipts_dir: String,
    #[serde(default = "default_fin_db_dir")]
    pub fin_db_dir: String,
    #[serde(default = "default_data_db_dir")]
    pub data_db_dir: String,
    #[serde(default = "default_policy_db_dir")]
    pub policy_db_dir: String,
    #[serde(default = "default_recon_db_dir")]
    pub recon_db_dir: String,
    /// Sled DB for append-only audit log + canonical envelope archive.
    #[serde(default = "default_audit_db_dir")]
    pub audit_db_dir: String,
    /// Sled DB for bootstrap metadata + file changelog (incremental snapshots).
    #[serde(default = "default_bootstrap_db_dir")]
    pub bootstrap_db_dir: String,
}

fn default_receipts_dir() -> String {
    "receipts".to_string()
}

fn default_fin_db_dir() -> String {
    "fin_db".to_string()
}

fn default_data_db_dir() -> String {
    "data_db".to_string()
}

fn default_policy_db_dir() -> String {
    "policy_db".to_string()
}

fn default_recon_db_dir() -> String {
    "recon_db".to_string()
}

fn default_audit_db_dir() -> String {
    "audit_db".to_string()
}

fn default_bootstrap_db_dir() -> String {
    "bootstrap_db".to_string()
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            receipts_dir: default_receipts_dir(),
            fin_db_dir: default_fin_db_dir(),
            data_db_dir: default_data_db_dir(),
            policy_db_dir: default_policy_db_dir(),
            recon_db_dir: default_recon_db_dir(),
            audit_db_dir: default_audit_db_dir(),
            bootstrap_db_dir: default_bootstrap_db_dir(),
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

fn default_policy_mode() -> PolicyMode {
    PolicyMode::Permissive
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_policy_mode")]
    pub mode: PolicyMode,
    #[serde(default)]
    pub admins: Vec<String>,
    #[serde(default)]
    pub compliance: ComplianceConfig,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            mode: PolicyMode::Permissive,
            admins: Vec::new(),
            compliance: ComplianceConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ComplianceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub strategy: ComplianceStrategy,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            strategy: ComplianceStrategy::None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStrategy {
    #[default]
    None,
    GlobalAllowlist,
    GlobalDenylist,
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

#[derive(Debug, Clone, Deserialize)]
pub struct ReconConfig {
    #[serde(default = "default_recon_enabled")]
    pub enabled: bool,
    /// Base tick interval; due scheduling is still driven by `next_check_at`.
    #[serde(default = "default_recon_interval_secs")]
    pub interval_secs: u64,
    #[serde(default = "default_recon_batch_limit")]
    pub batch_limit: usize,
    #[serde(default = "default_recon_max_scan")]
    pub max_scan: usize,
    #[serde(default = "default_recon_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_recon_base_delay_secs")]
    pub base_delay_secs: u64,
    #[serde(default = "default_recon_max_delay_secs")]
    pub max_delay_secs: u64,
}

fn default_recon_enabled() -> bool {
    true
}
fn default_recon_interval_secs() -> u64 {
    30
}
fn default_recon_batch_limit() -> usize {
    50
}
fn default_recon_max_scan() -> usize {
    5_000
}
fn default_recon_max_attempts() -> u32 {
    50
}
fn default_recon_base_delay_secs() -> u64 {
    2
}
fn default_recon_max_delay_secs() -> u64 {
    300
}

impl Default for ReconConfig {
    fn default() -> Self {
        Self {
            enabled: default_recon_enabled(),
            interval_secs: default_recon_interval_secs(),
            batch_limit: default_recon_batch_limit(),
            max_scan: default_recon_max_scan(),
            max_attempts: default_recon_max_attempts(),
            base_delay_secs: default_recon_base_delay_secs(),
            max_delay_secs: default_recon_max_delay_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LinkageConfig {
    #[serde(default)]
    pub entitlement_policy: LinkageEntitlementPolicy,
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LinkageEntitlementPolicy {
    #[default]
    Optimistic,
    FinalityRequired,
}

impl Default for LinkageConfig {
    fn default() -> Self {
        Self {
            entitlement_policy: LinkageEntitlementPolicy::Optimistic,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct HaConfig {
    #[serde(default = "default_ha_enabled")]
    pub enabled: bool,
    /// Unique identifier for this node instance (used as the lock holder id).
    #[serde(default = "default_ha_node_id")]
    pub node_id: String,
    /// Lease duration (milliseconds). The leader renews every `lease_ms/3`.
    #[serde(default = "default_ha_lease_ms")]
    pub lease_ms: u64,
    /// Directory used for the Sled-based leader lock (must be shared across nodes).
    #[serde(default = "default_ha_lock_db_dir")]
    pub lock_db_dir: String,
    /// Optional external lock provider configuration. Defaults to the built-in sled lock.
    #[serde(default)]
    pub lock: HaLockConfig,
    /// Write policy when HA is enabled.
    #[serde(default)]
    pub write_mode: HaWriteMode,
    /// Optional mapping from node_id -> base HTTP URL (used for leader hints).
    #[serde(default)]
    pub leader_urls: BTreeMap<String, String>,
}

fn default_ha_enabled() -> bool {
    false
}

fn default_ha_node_id() -> String {
    "fin-node-1".to_string()
}

fn default_ha_lease_ms() -> u64 {
    15_000
}

fn default_ha_lock_db_dir() -> String {
    "ha_db".to_string()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct HaLockConfig {
    #[serde(default)]
    pub provider: HaLockProvider,
    #[serde(default)]
    pub redis: HaRedisLockConfig,
    #[serde(default)]
    pub consul: HaConsulLockConfig,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HaLockProvider {
    /// Built-in sled-based TTL lease under `[ha].lock_db_dir` (default).
    #[default]
    Sled,
    /// Redis-based distributed TTL lock (feature: `ha-redis`).
    Redis,
    /// Consul session lock (feature: `ha-consul`).
    Consul,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HaRedisLockConfig {
    /// Redis connection URL (e.g. `redis://host:6379`).
    #[serde(default)]
    pub url: String,
    /// Redis key to coordinate leadership (single key for the cluster).
    #[serde(default = "default_ha_redis_key")]
    pub key: String,
    /// Optional override for the lease duration (ms). Defaults to `[ha].lease_ms`.
    #[serde(default)]
    pub lease_ms: Option<u64>,
    /// Best-effort connect/IO timeout (ms).
    #[serde(default = "default_ha_redis_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
}

fn default_ha_redis_key() -> String {
    "ippan:l2:leader".to_string()
}

fn default_ha_redis_connect_timeout_ms() -> u64 {
    2_000
}

impl Default for HaRedisLockConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            key: default_ha_redis_key(),
            lease_ms: None,
            connect_timeout_ms: default_ha_redis_connect_timeout_ms(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct HaConsulLockConfig {
    /// Consul HTTP address (e.g. `http://consul:8500`).
    #[serde(default)]
    pub address: String,
    /// KV key used for leadership coordination.
    #[serde(default = "default_ha_consul_key")]
    pub key: String,
    /// Session TTL string (e.g. `"15s"`). Defaults to `15s` if empty.
    #[serde(default = "default_ha_consul_session_ttl")]
    pub session_ttl: String,
}

fn default_ha_consul_key() -> String {
    "ippan/l2/leader".to_string()
}

fn default_ha_consul_session_ttl() -> String {
    "15s".to_string()
}

impl Default for HaConsulLockConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            key: default_ha_consul_key(),
            session_ttl: default_ha_consul_session_ttl(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HaWriteMode {
    /// Only the leader accepts mutating HTTP requests.
    #[default]
    LeaderOnly,
    /// Allow writes on all nodes (dev mode; still bounded by shared storage contention).
    AllowAll,
}

impl Default for HaConfig {
    fn default() -> Self {
        Self {
            enabled: default_ha_enabled(),
            node_id: default_ha_node_id(),
            lease_ms: default_ha_lease_ms(),
            lock_db_dir: default_ha_lock_db_dir(),
            lock: HaLockConfig::default(),
            write_mode: HaWriteMode::LeaderOnly,
            leader_urls: BTreeMap::new(),
        }
    }
}

impl HaConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.node_id.trim().is_empty() {
            return Err("[ha].node_id is empty".to_string());
        }
        if self.lease_ms == 0 {
            return Err("[ha].lease_ms must be >= 1".to_string());
        }

        match self.lock.provider {
            HaLockProvider::Sled => {
                if self.lock_db_dir.trim().is_empty() {
                    return Err("[ha].lock_db_dir is empty".to_string());
                }
            }
            HaLockProvider::Redis => {
                if !cfg!(feature = "ha-redis") {
                    return Err(
                        "ha.lock.provider=redis requires building fin-node with feature ha-redis"
                            .to_string(),
                    );
                }
                if self.lock.redis.url.trim().is_empty() {
                    return Err("[ha.lock.redis].url is empty".to_string());
                }
                if self.lock.redis.key.trim().is_empty() {
                    return Err("[ha.lock.redis].key is empty".to_string());
                }
                let lease_ms = self.lock.redis.lease_ms.unwrap_or(self.lease_ms);
                if lease_ms == 0 {
                    return Err("[ha.lock.redis].lease_ms must be >= 1".to_string());
                }
                if self.lock.redis.connect_timeout_ms == 0 {
                    return Err("[ha.lock.redis].connect_timeout_ms must be >= 1".to_string());
                }
            }
            HaLockProvider::Consul => {
                if !cfg!(feature = "ha-consul") {
                    return Err(
                        "ha.lock.provider=consul requires building fin-node with feature ha-consul"
                            .to_string(),
                    );
                }
                if self.lock.consul.address.trim().is_empty() {
                    return Err("[ha.lock.consul].address is empty".to_string());
                }
                if self.lock.consul.key.trim().is_empty() {
                    return Err("[ha.lock.consul].key is empty".to_string());
                }
                if self.lock.consul.session_ttl.trim().is_empty() {
                    return Err("[ha.lock.consul].session_ttl is empty".to_string());
                }
            }
        }

        Ok(())
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

        self.security
            .validate()
            .map_err(|e| format!("invalid [security] config: {e}"))?;

        self.ha
            .validate()
            .map_err(|e| format!("invalid [ha] config: {e}"))?;

        self.encryption
            .validate()
            .map_err(|e| format!("invalid [encryption] config: {e}"))?;

        Ok(())
    }

    /// Get the security mode.
    pub fn security_mode(&self) -> SecurityMode {
        self.security.mode
    }
}

impl EncryptionConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if !cfg!(feature = "encryption-at-rest") {
            return Err(
                "encryption.enabled=true requires building fin-node with feature encryption-at-rest"
                    .to_string(),
            );
        }
        if self.provider.trim().is_empty() {
            return Err("[encryption].provider is empty".to_string());
        }
        if self.provider.trim() != "file" {
            return Err(format!(
                "[encryption].provider={} unsupported (MVP supports: file)",
                self.provider.trim()
            ));
        }
        if self.key_id.trim().is_empty() {
            return Err("[encryption].key_id is empty".to_string());
        }
        if self.key_path.trim().is_empty() {
            return Err("[encryption].key_path is empty".to_string());
        }
        if self.keyring.is_empty() {
            return Err("[encryption].keyring is empty (must include current key id)".to_string());
        }
        for (i, k) in self.keyring.iter().enumerate() {
            if k.trim().is_empty() {
                return Err(format!("[encryption].keyring[{i}] is empty"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SnapshotsConfig {
    /// Enable snapshot functionality (create/restore/scheduler).
    #[serde(default = "default_snapshots_enabled")]
    pub enabled: bool,
    /// Directory where snapshots are written by the scheduler (and default CLI output).
    #[serde(default = "default_snapshots_output_dir")]
    pub output_dir: String,
    /// Maximum number of snapshots to keep when rotation is enabled.
    #[serde(default = "default_snapshots_max_snapshots")]
    pub max_snapshots: usize,
    /// Optional interval for cutting base snapshots (e.g. "7d", "24h").
    ///
    /// If set, the scheduler uses interval-based base+delta scheduling (instead of daily cron).
    #[serde(default)]
    pub base_every: Option<String>,
    /// Optional interval for cutting delta snapshots (e.g. "15m", "1h").
    ///
    /// If set, the scheduler uses interval-based base+delta scheduling (instead of daily cron).
    #[serde(default)]
    pub delta_every: Option<String>,
    /// Number of base snapshots to retain (base+delta retention mode).
    #[serde(default = "default_snapshots_retain_bases")]
    pub retain_bases: usize,
    /// Maximum deltas to retain for a base snapshot.
    ///
    /// Note: the scheduler never prunes deltas required to reach the latest state for the current base.
    #[serde(default = "default_snapshots_retain_deltas_per_base")]
    pub retain_deltas_per_base: usize,
    /// Optional hook executed after a snapshot is successfully created.
    ///
    /// The snapshot path will be passed as the last argument.
    #[serde(default)]
    pub post_snapshot_hook: Option<String>,
    /// Optional hook executed before restore begins.
    ///
    /// The snapshot path will be passed as the last argument.
    #[serde(default)]
    pub pre_restore_hook: Option<String>,
    #[serde(default)]
    pub schedule: SnapshotScheduleConfig,
}

fn default_snapshots_enabled() -> bool {
    false
}

fn default_snapshots_output_dir() -> String {
    "snapshots".to_string()
}

fn default_snapshots_max_snapshots() -> usize {
    10
}

fn default_snapshots_retain_bases() -> usize {
    4
}

fn default_snapshots_retain_deltas_per_base() -> usize {
    672
}

impl Default for SnapshotsConfig {
    fn default() -> Self {
        Self {
            enabled: default_snapshots_enabled(),
            output_dir: default_snapshots_output_dir(),
            max_snapshots: default_snapshots_max_snapshots(),
            base_every: None,
            delta_every: None,
            retain_bases: default_snapshots_retain_bases(),
            retain_deltas_per_base: default_snapshots_retain_deltas_per_base(),
            post_snapshot_hook: None,
            pre_restore_hook: None,
            schedule: SnapshotScheduleConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SnapshotScheduleConfig {
    #[serde(default = "default_snapshot_schedule_enabled")]
    pub enabled: bool,
    /// Simplified cron string (minute hour * * *).
    ///
    /// Supported format: `"M H * * *"` where M and H are integers.
    #[serde(default)]
    pub cron: Option<String>,
}

fn default_snapshot_schedule_enabled() -> bool {
    false
}

impl Default for SnapshotScheduleConfig {
    fn default() -> Self {
        Self {
            enabled: default_snapshot_schedule_enabled(),
            cron: None,
        }
    }
}

// ============================================================
// Bootstrap (remote fetcher) configuration
// ============================================================

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BootstrapConfig {
    #[serde(default)]
    pub remote: BootstrapRemoteConfig,
    /// Multi-source snapshot repository configuration (mirrors/quorum/pinned).
    #[serde(default)]
    pub sources: BootstrapSourcesConfig,
    #[serde(default)]
    pub signing: BootstrapSigningConfig,
    #[serde(default)]
    pub p2p: BootstrapP2pConfig,
    #[serde(default)]
    pub transfer: BootstrapTransferConfig,
    /// Trusted pinned snapshot set (used when `[bootstrap.sources].mode = "pinned"`).
    #[serde(default)]
    pub pinned: BootstrapPinnedConfig,
}

/// Multi-source repository selection mode.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapSourcesMode {
    /// Use a single HTTP source (back-compat default).
    #[default]
    Single,
    /// Use multiple mirrors (best-effort failover; no quorum required for index).
    Mirrors,
    /// Require quorum agreement across sources for index hash + artifact hashes.
    MirrorsQuorum,
    /// Accept only explicitly pinned base+delta hashes.
    Pinned,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapArtifactQuorumMode {
    /// Download once from best source; verify against index/pinned hash.
    #[default]
    HashOnly,
    /// Download from N sources; require identical content hash (and size match).
    BytesQuorum,
}

/// Remote bootstrap sources configuration (HTTP mirrors + optional peers).
#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapSourcesConfig {
    #[serde(default)]
    pub mode: BootstrapSourcesMode,
    /// Primary HTTP base URL (defaults to `[bootstrap.remote].base_url` when empty).
    #[serde(default)]
    pub primary: String,
    /// Additional HTTP mirror base URLs.
    #[serde(default)]
    pub mirrors: Vec<String>,
    /// Quorum required in `mirrors_quorum` mode.
    #[serde(default = "default_bootstrap_sources_quorum")]
    pub quorum: usize,
    /// Bounded maximum number of sources considered (primary + mirrors + peers).
    #[serde(default = "default_bootstrap_sources_max_sources")]
    pub max_sources: usize,
    /// Artifact quorum mode.
    #[serde(default)]
    pub artifact_quorum_mode: BootstrapArtifactQuorumMode,
    /// In `bytes_quorum`, number of distinct sources required.
    #[serde(default = "default_bootstrap_sources_artifact_quorum")]
    pub artifact_quorum: usize,
}

fn default_bootstrap_sources_quorum() -> usize {
    2
}

fn default_bootstrap_sources_max_sources() -> usize {
    5
}

fn default_bootstrap_sources_artifact_quorum() -> usize {
    1
}

impl Default for BootstrapSourcesConfig {
    fn default() -> Self {
        Self {
            mode: BootstrapSourcesMode::Single,
            primary: String::new(),
            mirrors: Vec::new(),
            quorum: default_bootstrap_sources_quorum(),
            max_sources: default_bootstrap_sources_max_sources(),
            artifact_quorum_mode: BootstrapArtifactQuorumMode::HashOnly,
            artifact_quorum: default_bootstrap_sources_artifact_quorum(),
        }
    }
}

/// Pinned trusted snapshot set.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct BootstrapPinnedConfig {
    /// Base snapshot manifest hash (required in pinned mode).
    #[serde(default)]
    pub base_hash: String,
    /// Ordered delta manifest hashes (optional; may be empty to restore base only).
    #[serde(default)]
    pub delta_hashes: Vec<String>,
    /// Optional pinned index.json hash (blake3(index_bytes)) for extra auditing.
    #[serde(default)]
    pub index_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapRemoteConfig {
    /// Enable remote bootstrap fetch.
    #[serde(default = "default_bootstrap_remote_enabled")]
    pub enabled: bool,
    /// Logical name for this remote (used by `--remote`).
    #[serde(default = "default_bootstrap_remote_name")]
    pub name: String,
    /// Base URL of the snapshot repository.
    #[serde(default)]
    pub base_url: String,
    /// Relative path to the index JSON (default: "index.json").
    #[serde(default = "default_bootstrap_remote_index_path")]
    pub index_path: String,
    /// Local cache directory for downloads + state.
    #[serde(default = "default_bootstrap_remote_download_dir")]
    pub download_dir: String,
    /// Maximum total download size (MB) for a single fetch.
    #[serde(default = "default_bootstrap_remote_max_download_mb")]
    pub max_download_mb: u64,
    /// Connect timeout (ms).
    #[serde(default = "default_bootstrap_remote_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Read timeout (ms).
    #[serde(default = "default_bootstrap_remote_read_timeout_ms")]
    pub read_timeout_ms: u64,
    /// Parallel artifact download concurrency.
    #[serde(default = "default_bootstrap_remote_concurrency")]
    pub concurrency: usize,
}

fn default_bootstrap_remote_enabled() -> bool {
    false
}

fn default_bootstrap_remote_name() -> String {
    "default".to_string()
}

fn default_bootstrap_remote_index_path() -> String {
    "index.json".to_string()
}

fn default_bootstrap_remote_download_dir() -> String {
    "./bootstrap_cache".to_string()
}

fn default_bootstrap_remote_max_download_mb() -> u64 {
    4096
}

fn default_bootstrap_remote_connect_timeout_ms() -> u64 {
    3000
}

fn default_bootstrap_remote_read_timeout_ms() -> u64 {
    30_000
}

fn default_bootstrap_remote_concurrency() -> usize {
    4
}

impl Default for BootstrapRemoteConfig {
    fn default() -> Self {
        Self {
            enabled: default_bootstrap_remote_enabled(),
            name: default_bootstrap_remote_name(),
            base_url: String::new(),
            index_path: default_bootstrap_remote_index_path(),
            download_dir: default_bootstrap_remote_download_dir(),
            max_download_mb: default_bootstrap_remote_max_download_mb(),
            connect_timeout_ms: default_bootstrap_remote_connect_timeout_ms(),
            read_timeout_ms: default_bootstrap_remote_read_timeout_ms(),
            concurrency: default_bootstrap_remote_concurrency(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapSigningConfig {
    /// Enable signature verification (best-effort unless `required=true`).
    #[serde(default = "default_bootstrap_signing_enabled")]
    pub enabled: bool,
    /// If true: missing/invalid signatures refuse bootstrap.
    #[serde(default = "default_bootstrap_signing_required")]
    pub required: bool,
    /// Allowlisted publisher Ed25519 public keys (hex-encoded 32 bytes).
    #[serde(default)]
    pub publisher_pubkeys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapP2pConfig {
    /// Enable peer-list bootstrap distribution (opt-in).
    #[serde(default = "default_bootstrap_p2p_enabled")]
    pub enabled: bool,
    /// List of peer base URLs hosting bootstrap artifacts (MVP: HTTP gateways).
    #[serde(default)]
    pub peers: Vec<String>,
    /// Quorum of distinct peers required for an artifact.
    ///
    /// - 1: accept first valid artifact
    /// - >=2: require N distinct peers to independently produce a valid artifact
    #[serde(default = "default_bootstrap_p2p_quorum")]
    pub quorum: usize,
    /// Maximum peer failures tolerated per artifact before falling back.
    #[serde(default = "default_bootstrap_p2p_max_failures")]
    pub max_failures: usize,
}

fn default_bootstrap_p2p_enabled() -> bool {
    false
}

fn default_bootstrap_p2p_quorum() -> usize {
    1
}

fn default_bootstrap_p2p_max_failures() -> usize {
    3
}

impl Default for BootstrapP2pConfig {
    fn default() -> Self {
        Self {
            enabled: default_bootstrap_p2p_enabled(),
            peers: Vec::new(),
            quorum: default_bootstrap_p2p_quorum(),
            max_failures: default_bootstrap_p2p_max_failures(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapTransferConfig {
    /// Maximum concurrent downloads (global within a fetch).
    #[serde(default = "default_bootstrap_transfer_max_concurrency")]
    pub max_concurrency: usize,
    /// Best-effort global download cap in megabits/sec. `0` disables rate limiting.
    #[serde(default = "default_bootstrap_transfer_max_mbps")]
    pub max_mbps: u64,
    /// Per-peer request timeout (ms) for peer-list sources.
    #[serde(default = "default_bootstrap_transfer_per_peer_timeout_ms")]
    pub per_peer_timeout_ms: u64,
}

fn default_bootstrap_transfer_max_concurrency() -> usize {
    4
}

fn default_bootstrap_transfer_max_mbps() -> u64 {
    0
}

fn default_bootstrap_transfer_per_peer_timeout_ms() -> u64 {
    20_000
}

impl Default for BootstrapTransferConfig {
    fn default() -> Self {
        Self {
            max_concurrency: default_bootstrap_transfer_max_concurrency(),
            max_mbps: default_bootstrap_transfer_max_mbps(),
            per_peer_timeout_ms: default_bootstrap_transfer_per_peer_timeout_ms(),
        }
    }
}

fn default_bootstrap_signing_enabled() -> bool {
    false
}

fn default_bootstrap_signing_required() -> bool {
    false
}

impl Default for BootstrapSigningConfig {
    fn default() -> Self {
        Self {
            enabled: default_bootstrap_signing_enabled(),
            required: default_bootstrap_signing_required(),
            publisher_pubkeys: Vec::new(),
        }
    }
}

impl BootstrapConfig {
    pub fn validate(&self) -> Result<(), String> {
        self.remote.validate()?;
        self.sources
            .validate(&self.remote, &self.p2p, &self.pinned)?;
        self.signing.validate(&self.remote)?;
        self.p2p.validate(&self.remote)?;
        self.transfer.validate(&self.remote)?;
        self.pinned.validate(&self.sources)?;
        Ok(())
    }
}

impl BootstrapSourcesConfig {
    pub fn validate(
        &self,
        remote: &BootstrapRemoteConfig,
        p2p: &BootstrapP2pConfig,
        pinned: &BootstrapPinnedConfig,
    ) -> Result<(), String> {
        if !remote.enabled {
            // Sources configuration is ignored when remote is disabled.
            return Ok(());
        }

        let primary = self.primary.trim();
        let fallback_primary = remote.base_url.trim();
        let resolved_primary = if primary.is_empty() {
            fallback_primary
        } else {
            primary
        };

        if matches!(self.mode, BootstrapSourcesMode::Pinned) {
            // Pinned mode does not require any specific remote URLs (may still be used to fetch).
            if pinned.base_hash.trim().is_empty() {
                return Err(
                    "[bootstrap.pinned].base_hash is empty (required for pinned mode)".to_string(),
                );
            }
            return Ok(());
        }

        // For non-pinned modes, we need at least a primary URL (from sources.primary or remote.base_url).
        if resolved_primary.is_empty() {
            return Err(
                "[bootstrap.sources].primary is empty and [bootstrap.remote].base_url is empty"
                    .to_string(),
            );
        }

        if self.max_sources == 0 {
            return Err("[bootstrap.sources].max_sources must be >= 1".to_string());
        }
        if self.max_sources > 10 {
            // Keep it bounded (global rule).
            return Err("[bootstrap.sources].max_sources must be <= 10".to_string());
        }

        // Validate mirrors list.
        for (i, m) in self.mirrors.iter().enumerate() {
            if m.trim().is_empty() {
                return Err(format!("[bootstrap.sources].mirrors[{i}] is empty"));
            }
        }

        if matches!(
            self.mode,
            BootstrapSourcesMode::Mirrors | BootstrapSourcesMode::MirrorsQuorum
        ) && self.mirrors.is_empty()
        {
            return Err(
                "[bootstrap.sources].mode=mirrors* requires at least one entry in mirrors[]"
                    .to_string(),
            );
        }

        if matches!(self.mode, BootstrapSourcesMode::MirrorsQuorum) {
            if self.quorum == 0 {
                return Err("[bootstrap.sources].quorum must be >= 1".to_string());
            }
            // Count configured sources (primary + mirrors + optional peers if enabled).
            let peer_n = if p2p.enabled { p2p.peers.len() } else { 0 };
            let total_sources = 1usize
                .saturating_add(self.mirrors.len())
                .saturating_add(peer_n)
                .min(self.max_sources);
            if self.quorum > total_sources {
                return Err(format!(
                    "[bootstrap.sources].quorum must be <= effective sources (got quorum={}, sources={})",
                    self.quorum, total_sources
                ));
            }
        }

        if matches!(
            self.artifact_quorum_mode,
            BootstrapArtifactQuorumMode::BytesQuorum
        ) {
            if self.artifact_quorum == 0 {
                return Err("[bootstrap.sources].artifact_quorum must be >= 1".to_string());
            }
            if self.artifact_quorum > self.max_sources {
                return Err(
                    "[bootstrap.sources].artifact_quorum must be <= max_sources".to_string()
                );
            }
        }

        Ok(())
    }
}

impl BootstrapPinnedConfig {
    pub fn validate(&self, sources: &BootstrapSourcesConfig) -> Result<(), String> {
        if sources.mode != BootstrapSourcesMode::Pinned {
            return Ok(());
        }
        if self.base_hash.trim().is_empty() {
            return Err("[bootstrap.pinned].base_hash is empty".to_string());
        }
        validate_hash_hex("[bootstrap.pinned].base_hash", &self.base_hash)?;
        for (i, h) in self.delta_hashes.iter().enumerate() {
            validate_hash_hex(&format!("[bootstrap.pinned].delta_hashes[{i}]"), h)?;
        }
        if let Some(h) = self.index_hash.as_deref() {
            if !h.trim().is_empty() {
                validate_hash_hex("[bootstrap.pinned].index_hash", h)?;
            }
        }
        Ok(())
    }
}

fn validate_hash_hex(field: &str, h: &str) -> Result<(), String> {
    let raw = hex::decode(h.trim()).map_err(|e| format!("{field} invalid hex: {e}"))?;
    if raw.len() != 32 {
        return Err(format!(
            "{field} must be 32 bytes hex (blake3 hex, 64 chars); got {} bytes",
            raw.len()
        ));
    }
    Ok(())
}

impl BootstrapRemoteConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.name.trim().is_empty() {
            return Err("[bootstrap.remote].name is empty".to_string());
        }
        if self.base_url.trim().is_empty() {
            return Err("[bootstrap.remote].base_url is empty".to_string());
        }
        if self.index_path.trim().is_empty() {
            return Err("[bootstrap.remote].index_path is empty".to_string());
        }
        if self.download_dir.trim().is_empty() {
            return Err("[bootstrap.remote].download_dir is empty".to_string());
        }
        if self.max_download_mb == 0 {
            return Err("[bootstrap.remote].max_download_mb must be >= 1".to_string());
        }
        if self.connect_timeout_ms == 0 {
            return Err("[bootstrap.remote].connect_timeout_ms must be >= 1".to_string());
        }
        if self.read_timeout_ms == 0 {
            return Err("[bootstrap.remote].read_timeout_ms must be >= 1".to_string());
        }
        if self.concurrency == 0 {
            return Err("[bootstrap.remote].concurrency must be >= 1".to_string());
        }
        if self.concurrency > 32 {
            return Err("[bootstrap.remote].concurrency must be <= 32".to_string());
        }
        Ok(())
    }
}

impl BootstrapSigningConfig {
    pub fn validate(&self, remote: &BootstrapRemoteConfig) -> Result<(), String> {
        if !remote.enabled {
            // Signing settings are ignored when remote is disabled.
            return Ok(());
        }
        if !self.enabled && self.required {
            return Err("[bootstrap.signing].required=true requires enabled=true".to_string());
        }
        if !self.enabled {
            return Ok(());
        }
        if self.publisher_pubkeys.is_empty() {
            return Err("[bootstrap.signing].publisher_pubkeys is empty".to_string());
        }
        for (i, k) in self.publisher_pubkeys.iter().enumerate() {
            let raw = hex::decode(k).map_err(|e| {
                format!("[bootstrap.signing].publisher_pubkeys[{i}] invalid hex: {e}")
            })?;
            if raw.len() != 32 {
                return Err(format!(
                    "[bootstrap.signing].publisher_pubkeys[{i}] must be 32 bytes (got {})",
                    raw.len()
                ));
            }
        }
        Ok(())
    }
}

impl BootstrapP2pConfig {
    pub fn validate(&self, remote: &BootstrapRemoteConfig) -> Result<(), String> {
        if !remote.enabled {
            // Peer distribution settings are ignored when remote is disabled.
            return Ok(());
        }
        if !self.enabled {
            return Ok(());
        }
        if self.peers.is_empty() {
            return Err("[bootstrap.p2p].peers is empty".to_string());
        }
        if self.quorum == 0 {
            return Err("[bootstrap.p2p].quorum must be >= 1".to_string());
        }
        if self.quorum > self.peers.len() {
            return Err("[bootstrap.p2p].quorum must be <= peers.len()".to_string());
        }
        if self.max_failures == 0 {
            return Err("[bootstrap.p2p].max_failures must be >= 1".to_string());
        }
        for (i, p) in self.peers.iter().enumerate() {
            if p.trim().is_empty() {
                return Err(format!("[bootstrap.p2p].peers[{i}] is empty"));
            }
        }
        Ok(())
    }
}

impl BootstrapTransferConfig {
    pub fn validate(&self, remote: &BootstrapRemoteConfig) -> Result<(), String> {
        if !remote.enabled {
            return Ok(());
        }
        if self.max_concurrency == 0 {
            return Err("[bootstrap.transfer].max_concurrency must be >= 1".to_string());
        }
        if self.max_concurrency > 32 {
            return Err("[bootstrap.transfer].max_concurrency must be <= 32".to_string());
        }
        if self.per_peer_timeout_ms == 0 {
            return Err("[bootstrap.transfer].per_peer_timeout_ms must be >= 1".to_string());
        }
        Ok(())
    }
}
