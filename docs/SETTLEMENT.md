# L2 Settlement Architecture

This document describes how IPPAN L2 settles batches to L1 (IPPAN CORE).

## Settlement Model

IPPAN L2 uses a contract-based settlement model where:

1. **Batches** are collected by the batcher and formed into `Batch` structures
2. **BatchEnvelope** wraps the batch with metadata (tx_root, prev_batch_hash, etc.)
3. **L2BatchEnvelopeV1** is the L1-facing envelope submitted via `L1Client::submit_batch`
4. **Idempotency** is provided by deterministic keys derived from envelope content

## Posting Modes

The L2 node supports two posting modes, controlled by `L2_POSTER_MODE`:

### Contract Mode (Default)

```
L2_POSTER_MODE=contract
```

- Uses `L2BatchEnvelopeV1` envelope format
- Submits via `L1Client::submit_batch` contract method
- Provides deterministic idempotency keys
- Supports proper finality/inclusion tracking
- **Recommended for production**

### Raw Mode (Legacy)

```
L2_POSTER_MODE=raw
```

- Uses IPPAN RPC `/tx` endpoint
- Posts batch metadata as JSON in data field
- No idempotency key guarantees
- **For debugging/legacy only**

## Envelope Structure

### BatchPayload

The inner payload that gets signed:

```rust
pub struct BatchPayload {
    pub l2_chain_id: ChainId,
    pub batch_hash: Hash32,
    pub prev_batch_hash: Hash32,  // Chain link to previous batch
    pub created_at_ms: u64,
    pub tx_count: u32,
    pub tx_bytes: u64,
    pub tx_root: Hash32,           // Merkle root of tx hashes
    pub payload: Vec<u8>,          // Canonical batch bytes
}
```

### BatchEnvelope

Optionally-signed envelope containing the payload:

```rust
pub struct BatchEnvelope {
    pub version: String,           // "v1"
    pub payload: BatchPayload,
    pub sequencer_pubkey: Vec<u8>, // Ed25519 pubkey (32 bytes)
    pub sequencer_sig: Vec<u8>,    // Ed25519 sig (64 bytes)
    pub envelope_hash: [u8; 32],   // Hash of payload
}
```

### L2BatchEnvelopeV1

The L1-facing envelope:

```rust
pub struct L2BatchEnvelopeV1 {
    pub contract_version: ContractVersion,
    pub hub: L2HubId,
    pub batch_id: String,
    pub sequence: u64,
    pub tx_count: u64,
    pub commitment: Option<String>,  // tx_root hex
    pub fee: FixedAmountV1,
    pub idempotency_key: IdempotencyKey,
    pub hub_payload: HubPayloadEnvelopeV1,
}
```

## Canonical Payload Rules

**Critical**: The L1-settled payload MUST be:

1. `canonical_encode(BatchEnvelope)` bytes (bincode, little-endian, fixed-int)
2. Embedded in `HubPayloadEnvelopeV1.payload` (base64 encoded)
3. **NOT JSON** - canonical binary provides deterministic, version-stable bytes

This ensures:
- Identical inputs produce identical idempotency keys
- Payloads can be verified independently
- No floating-point or non-deterministic values

## Batch Chaining

Batches are chained via `prev_batch_hash`:

1. **Genesis batch**: `prev_batch_hash = Hash32([0u8; 32])` (zero hash)
2. **Subsequent batches**: `prev_batch_hash = hash of previous batch`
3. **Persistence**: `prev_batch_hash` is stored per `(hub, chain_id)` in storage
4. **Update policy**: Updated on successful `submit_batch` response

This creates a linked chain of batches for each hub/chain combination.

## Idempotency

The idempotency key is derived deterministically from:

1. Hub identifier
2. Batch ID
3. Sequence number
4. Tx count
5. Hub payload hash

This ensures:
- **Same batch → same key**: Resubmissions are detected
- **AlreadyKnown responses**: Treated as success, not failure
- **Safe retries**: Can retry without creating duplicates

## Settlement Flow

```
┌─────────┐   ┌─────────────┐   ┌──────────────┐   ┌────────┐
│ Batcher │──▶│ BatchEnvelope│──▶│L2BatchEnvelope│──▶│   L1   │
└─────────┘   └─────────────┘   └──────────────┘   └────────┘
                    │                    │
                    ▼                    ▼
              canonical_encode    submit_batch()
                    │                    │
                    ▼                    ▼
              Binary bytes       Idempotency key
```

1. Batcher collects transactions into a `Batch`
2. Bridge builds `BatchEnvelope` with tx_root and prev_hash
3. `BatchEnvelope` is canonical-encoded to bytes
4. Bytes are wrapped in `L2BatchEnvelopeV1`
5. Envelope is submitted to L1 via `submit_batch`
6. On success/AlreadyKnown, `prev_batch_hash` is updated

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `L2_POSTER_MODE` | `contract` | Posting mode: `contract` or `raw` |
| `L2_HUB_ID` | `fin` | Hub identifier: `fin`, `data`, `m2m`, `world`, `bridge` |
| `L2_CONTENT_TYPE` | `json` | Content type: `json` or `binary` |
| `L2_BATCH_FEE` | `0` | Protocol fee (scaled integer) |
| `L2_POST_MAX_RETRIES` | `3` | Max retry attempts |
| `L2_POST_RETRY_DELAY_MS` | `500` | Base retry delay (ms) |
| `L2_L1_TIMEOUT_MS` | `30000` | L1 request timeout (ms) |
| `L2_FORCE_REPOST` | `false` | Force repost even if already posted |

### Feature Flags

| Feature | Description |
|---------|-------------|
| `contract-posting` | Enable contract-based batch posting |
| `signed-envelopes` | Enable Ed25519 envelope signing |
| `async-l1-http` | Enable native async HTTP L1 client |

## Monitoring

### Status Endpoint

`GET /status` returns settlement info:

```json
{
  "settlement": {
    "poster_mode": "contract",
    "last_submitted_batch_hash": "abc123...",
    "last_l1_tx_id": "l1tx_xyz...",
    "pending_submissions": 0,
    "confirmed_submissions": 42
  }
}
```

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `l2_contract_submit_total` | Counter | Total contract submissions |
| `l2_contract_submit_retries_total` | Counter | Total retry attempts |
| `l2_contract_already_known_total` | Counter | AlreadyKnown responses |
| `l2_contract_failed_total` | Counter | Failed submissions |
| `l2_batches_pending` | Gauge | Pending batches |
| `l2_batches_posted` | Gauge | Posted batches |
| `l2_batches_confirmed` | Gauge | Confirmed batches |

## See Also

- [API Reference](API.md)
- [Contract Posting Ops](ops/contract-posting.md)
- [L1 Settlement API](l1-settlement-api.md)
