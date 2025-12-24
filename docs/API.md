# IPPAN-L2 API Reference

This document describes the public API surface of IPPAN-L2 crates.

## L2 Node HTTP surface (MVP)

The `l2-node` service exposes a minimal operational API:

| Endpoint | Purpose |
|----------|---------|
| `GET /healthz` | Liveness probe |
| `GET /readyz` | Readiness probe (fails if storage cannot be opened) |
| `GET /status` | Structured status with leader/queue/batcher/bridge/settlement fields |
| `GET /metrics` | Prometheus metrics export |
| `POST /tx` | Transaction submission |
| `GET /tx/{hash}` | Transaction lookup |
| `GET /batch/{hash}` | Batch lookup |
| `POST /tx/force` | Forced inclusion request |
| `POST /bridge/deposit/claim` | Claim deposit from L1 |
| `POST /bridge/withdraw` | Request withdrawal to L1 |

The full contract is defined in `openapi.yaml`; SDK generators should target that file to avoid drift.

## Contract Posting

The L2 node uses contract-based batch posting to L1 by default. This is controlled by `L2_POSTER_MODE`:

- **`contract`** (default): Uses `L2BatchEnvelopeV1` with deterministic idempotency keys
- **`raw`**: Uses legacy IPPAN RPC `/tx` endpoint (for debugging)

### L2BatchEnvelopeV1 Structure

When posting to L1, batches are wrapped in a versioned envelope:

```json
{
  "contract_version": "V1",
  "hub": "Fin",
  "batch_id": "aabbccdd...",
  "sequence": 42,
  "tx_count": 10,
  "commitment": "merkle_root_hex...",
  "fee": 0,
  "idempotency_key": "deterministic_key...",
  "hub_payload": {
    "contract_version": "V1",
    "hub": "Fin",
    "schema_version": "batch-envelope-v1",
    "content_type": "application/octet-stream",
    "payload": "base64_encoded_canonical_bytes..."
  }
}
```

The `hub_payload.payload` contains the canonical (bincode) encoding of `BatchEnvelope`, NOT JSON. This ensures deterministic, version-stable byte representation.

### Settlement Status

The `/status` endpoint includes settlement information:

```json
{
  "settlement": {
    "poster_mode": "contract",
    "last_submitted_batch_hash": "aabbccdd...",
    "last_l1_tx_id": "l1tx_12345",
    "pending_submissions": 0,
    "confirmed_submissions": 42
  }
}
```

See [SETTLEMENT.md](SETTLEMENT.md) for full details on the settlement architecture.

## Stability Guarantees

### Stable APIs (v0.1.0+)

These types and interfaces are considered stable and will follow semantic versioning:

| Type | Crate | Description |
|------|-------|-------------|
| `L2TransactionEnvelope<T>` | `l2-core` | Generic transaction wrapper |
| `L2HubId` | `l2-core` | Hub identifier enum |
| `L2BatchId` | `l2-core` | Batch identifier |
| `L2Batch` | `l2-core` | Batch metadata |
| `L2Proof` | `l2-core` | Proof structure |
| `AccountId` | `l2-core` | Account identifier |
| `AssetId` | `l2-core` | Asset identifier |
| `FixedAmount` | `l2-core` | Fixed-point amount |
| `SettlementRequest` | `l2-core` | L1 settlement request |
| `SettlementResult` | `l2-core` | L1 settlement result |

### Experimental APIs

These APIs may change without warning:

- Internal engine implementations
- Storage backends
- HTTP endpoints (planned)

## Core Types

### L2TransactionEnvelope

Generic wrapper for hub-specific transactions.

```rust
use l2_core::{L2TransactionEnvelope, L2HubId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2TransactionEnvelope<T> {
    pub hub: L2HubId,
    pub tx_id: String,
    pub payload: T,
}
```

**JSON Format:**
```json
{
  "hub": "Fin",
  "tx_id": "tx-001",
  "payload": { ... }
}
```

### L2HubId

Identifies which hub a transaction belongs to.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum L2HubId {
    Fin,    // Finance Hub
    Data,   // Data Hub
    M2m,    // Machine-to-Machine Hub
    World,  // Applications Hub
    Bridge, // Cross-chain Bridge Hub
}
```

**JSON Format:** `"Fin"`, `"Data"`, `"M2m"`, `"World"`, `"Bridge"`

### L2BatchId

Opaque batch identifier.

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct L2BatchId(pub String);
```

**JSON Format:** `"batch-001"`

### L2Batch

Batch metadata for settlement.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Batch {
    pub hub: L2HubId,
    pub batch_id: L2BatchId,
    pub tx_count: u64,
    pub commitment: Option<String>,
}
```

**JSON Format:**
```json
{
  "hub": "Fin",
  "batch_id": "batch-001",
  "tx_count": 10,
  "commitment": "0xabc123..."
}
```

### FixedAmount

Fixed-point amount with 6 decimal places (scale factor: 1,000,000).

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FixedAmount {
    inner: i128,  // Scaled value
}

pub const FIXED_AMOUNT_SCALE: i128 = 1_000_000;
```

**JSON Format:** Integer representing scaled value
```json
{ "amount": 10000000 }  // Represents 10.000000
```

**Important:** This type enforces deterministic arithmetic. No floating point.

### AccountId / AssetId

Opaque identifiers for accounts and assets.

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetId(pub String);
```

**JSON Format:** String values
```json
{ "account": "acc-alice", "asset": "asset-eurx" }
```

## FIN Hub Types

### FinOperation

Operations supported by the Finance Hub.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FinOperation {
    RegisterFungibleAsset {
        asset_id: AssetId,
        symbol: String,
        name: String,
        decimals: u8,
    },
    Mint {
        asset_id: AssetId,
        to: AccountId,
        amount: FixedAmount,
    },
    Burn {
        asset_id: AssetId,
        from: AccountId,
        amount: FixedAmount,
    },
    Transfer {
        asset_id: AssetId,
        from: AccountId,
        to: AccountId,
        amount: FixedAmount,
    },
}
```

**JSON Format (Transfer example):**
```json
{
  "Transfer": {
    "asset_id": "asset-eurx",
    "from": "acc-alice",
    "to": "acc-bob",
    "amount": { "inner": 10000000 }
  }
}
```

### FinTransaction

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinTransaction {
    pub tx_id: String,
    pub op: FinOperation,
}
```

## DATA Hub Types

### Attestation

Content attestation for the Data Hub.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub content_hash: ContentHash,
    pub issuer: AccountId,
    pub claim_type: String,
    pub url: Option<String>,
    pub platform: Option<String>,
}
```

**JSON Format:**
```json
{
  "content_hash": "abc123...",
  "issuer": "acc-alice",
  "claim_type": "authorship",
  "url": "https://example.com/article",
  "platform": "ExampleNews"
}
```

## Settlement API

### SettlementRequest

Request to settle a batch on IPPAN CORE.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementRequest {
    pub hub: L2HubId,
    pub batch: L2Batch,
    pub fee: FixedAmount,
}
```

### SettlementResult

Result from L1 settlement.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementResult {
    pub hub: L2HubId,
    pub batch_id: L2BatchId,
    pub l1_reference: String,
    pub finalised: bool,
}
```

## Wire Format

All types use JSON for wire format with serde. Field names are explicit and stable.

### Versioning

When breaking changes are needed, new versions will be introduced:
- `v1` prefix in API paths
- Version field in envelope if needed

### Encoding Rules

1. **Integers**: JSON numbers (no floating point)
2. **Byte arrays**: Hex-encoded strings with `0x` prefix where applicable
3. **Enums**: Externally tagged (e.g., `{"Fin": {...}}`)
4. **Options**: `null` or value

## Golden Fixtures

Test fixtures are provided to verify serialization compatibility.

Location: `tests/fixtures/`

```rust
#[test]
fn test_fin_transaction_serialization() {
    let fixture = include_str!("fixtures/fin_transaction.json");
    let tx: FinTransaction = serde_json::from_str(fixture).unwrap();
    let reserialized = serde_json::to_string(&tx).unwrap();
    // Verify round-trip
}
```

## Error Types

### SettlementError

```rust
#[derive(Debug, thiserror::Error)]
pub enum SettlementError {
    #[error("network error talking to IPPAN CORE: {0}")]
    Network(String),
    #[error("CORE rejected settlement: {0}")]
    Rejected(String),
    #[error("unexpected internal error: {0}")]
    Internal(String),
}
```

### FinStateError

```rust
#[derive(Debug, thiserror::Error)]
pub enum FinStateError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("asset already exists: {0}")]
    AssetAlreadyExists(String),
    #[error("invalid decimals: {0}")]
    InvalidDecimals(u8),
    #[error("asset not registered: {0}")]
    UnknownAsset(String),
    #[error("insufficient balance for account: {0}")]
    InsufficientBalance(String),
}
```

## Trait Interfaces

### L1SettlementClient

Interface for L1 communication.

```rust
pub trait L1SettlementClient {
    fn submit_settlement(
        &self,
        request: SettlementRequest,
    ) -> Result<SettlementResult, SettlementError>;
}
```

### FinStateStore

Interface for FIN state storage.

```rust
pub trait FinStateStore {
    fn load_state(&self) -> FinState;
    fn save_state(&self, state: &FinState) -> Result<(), FinStateError>;
}
```

### DataStateStore

Interface for DATA state storage.

```rust
pub trait DataStateStore {
    fn load_state(&self) -> DataState;
    fn save_state(&self, state: &DataState) -> Result<(), DataStateError>;
}
```

## Deprecation Policy

1. Deprecated items marked with `#[deprecated]`
2. One minor version warning period
3. Removed in next major version

## Backward Compatibility

- Wire format changes are backward compatible within a major version
- New optional fields may be added (defaults used if missing)
- Existing fields will not be removed or renamed within a major version
