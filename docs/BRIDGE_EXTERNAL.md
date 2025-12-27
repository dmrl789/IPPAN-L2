# External Chain Bridge Integration

This document describes the External Chain Bridge Adapter and Proof-Carrying Intents system
for IPPAN L2. This enables the BRIDGE hub to interact with external blockchains (starting with
Ethereum) in a non-custodial, deterministic, and verifiable manner.

## Overview

The External Chain Bridge allows IPPAN to:

1. **Observe external events**: Monitor events on external chains (e.g., ERC20 deposits on Ethereum)
2. **Produce deterministic attestations**: Create signed proofs of external events
3. **Bind attestations to Intent state transitions**: Gate Intent `Prepare` phase on proof verification
4. **Anchor everything on IPPAN CORE**: Post settlement transactions via existing contract posting

### Design Principles

- **Non-authoritative integration**: External proofs are treated as statements, not as source of truth
- **Determinism**: All hashing, encoding, and state transitions are deterministic
- **Verifiable proofs**: Every external event claim must be backed by a verifiable proof
- **No new crypto**: Reuse existing `blake3` for hashing, `ed25519` for signatures
- **Incremental trust**: Support for upgrading from trusted attestations to merkle proofs

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           IPPAN BRIDGE Hub                               │
├──────────────┬──────────────┬──────────────┬───────────────────────────┤
│              │              │              │                           │
│  External    │  External    │   Intent     │     External Proof        │
│  Proof API   │  Proof       │   Router     │     Reconciler            │
│              │  Storage     │              │     (background)          │
│              │              │              │                           │
├──────────────┴──────────────┴──────────────┴───────────────────────────┤
│                                                                         │
│                        IPPAN L2 Storage (sled)                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        External Blockchains                              │
│                                                                         │
│   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    │
│   │   Ethereum      │    │   Sepolia       │    │   Holesky       │    │
│   │   Mainnet       │    │   Testnet       │    │   Testnet       │    │
│   └─────────────────┘    └─────────────────┘    └─────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. External Proof Types (`l2-core/src/external_proof.rs`)

#### ExternalChainId

Identifies external blockchains:

```rust
pub enum ExternalChainId {
    EthereumMainnet,           // Chain ID 1
    EthereumSepolia,           // Chain ID 11155111
    EthereumHolesky,           // Chain ID 17000
    Other { chain_id: u64, name: String },
}
```

#### Verification Modes

The bridge supports multiple verification modes with different trust assumptions:

| Mode | Trust Assumption | Speed | Use Case |
|------|------------------|-------|----------|
| `attestation` | Trust in allowlisted attestors | Fast | Production MVP, trusted operators |
| `eth_merkle_receipt_proof` | Trust in Ethereum consensus | Slower | Fully decentralized, trustless |
| `merkle_with_headers` | Verified header chain | Moderate | Deterministic confirmations (MVP light client) |

```rust
pub enum VerificationMode {
    /// Verification via signed attestation from a trusted attestor.
    Attestation,
    /// Verification via Ethereum Merkle Patricia Trie receipt inclusion proof.
    EthMerkleReceiptProof,
}
```

#### Header Chain Verification (Light Client MVP)

When the `eth-headers` feature is enabled, Merkle proofs can be verified against a locally
stored and validated Ethereum header chain. This provides:

1. **Deterministic confirmations**: Computed from verified header depth, not external RPC claims
2. **Block hash validation**: Proofs are anchored to known, verified headers
3. **Receipt root verification**: Uses stored header's receipts_root as source of truth

Trust model:
- **Checkpoints**: Explicitly trusted header hashes serve as roots of trust
- **Chain validation**: Headers must descend from checkpoints to be verified
- **Fork choice**: Highest block number wins; ties broken by lexicographically smallest hash

#### ExternalEventProofV1

Versioned enum for different proof types:

```rust
pub enum ExternalEventProofV1 {
    /// Trusted attestor signs a statement about an event
    EthReceiptAttestationV1(EthReceiptAttestationV1),
    /// Full Merkle Patricia Trie proof against block header
    EthReceiptMerkleProofV1(EthReceiptMerkleProofV1),
}
```

#### EthReceiptAttestationV1

Attestation mode - a signed attestation from a trusted party:

```rust
pub struct EthReceiptAttestationV1 {
    pub chain: ExternalChainId,        // Which chain
    pub tx_hash: [u8; 32],             // Transaction hash
    pub log_index: u32,                // Log index in receipt
    pub contract: [u8; 20],            // Contract address
    pub topic0: [u8; 32],              // Event signature
    pub data_hash: [u8; 32],           // Blake3 hash of event data
    pub block_number: u64,             // Block number
    pub block_hash: [u8; 32],          // Block hash
    pub confirmations: u32,            // Confirmations at attestation time
    pub attestor_pubkey: [u8; 32],     // Ed25519 public key
    pub signature: [u8; 64],           // Ed25519 signature
}
```

#### EthReceiptMerkleProofV1

Merkle proof mode - cryptographic proof of event inclusion:

```rust
pub struct EthReceiptMerkleProofV1 {
    pub chain: ExternalChainId,        // Which chain
    pub tx_hash: [u8; 32],             // Transaction hash
    pub log_index: u32,                // Log index in receipt
    pub contract: [u8; 20],            // Contract address
    pub topic0: [u8; 32],              // Event signature
    pub data_hash: [u8; 32],           // Blake3 hash of event data
    pub block_number: u64,             // Block number
    pub block_hash: [u8; 32],          // Block hash (keccak256 of header_rlp)
    pub header_rlp: Vec<u8>,           // RLP-encoded block header
    pub tx_index: u32,                 // Transaction index in block
    pub receipt_rlp: Vec<u8>,          // RLP-encoded receipt
    pub proof_nodes: Vec<Vec<u8>>,     // MPT proof nodes
    pub confirmations: Option<u32>,    // Optional: for confirmation policy
    pub tip_block_number: Option<u64>, // Optional: current chain tip
}
```

Merkle proof verification:
1. Verify `keccak256(header_rlp) == block_hash`
2. Extract `receipts_root` from block header
3. Verify receipt inclusion via MPT proof against `receipts_root`
4. Decode receipt and extract log at `log_index`
5. Verify log matches: `contract`, `topic0`, `blake3(data) == data_hash`

#### ExternalProofState

Lifecycle states for proofs:

```rust
pub enum ExternalProofState {
    Unverified,                        // Just submitted, pending verification
    Verified { verified_at_ms: u64 },  // Successfully verified
    Rejected { reason: String, rejected_at_ms: u64 }, // Failed verification
}
```

### 2. External Proof Storage (`l2-storage/src/external.rs`)

Persistent storage using sled trees:

- `external_proofs` - Stores `ExternalEventProofV1` by `ExternalProofId`
- `external_proof_states` - Stores `ExternalProofState` by `ExternalProofId`
- `proof_to_intents` - Maps proofs to bound intents
- `intent_to_proofs` - Maps intents to required proofs

Key operations:

```rust
// Store a new proof
storage.put_proof_if_absent(&proof, now_ms)?;

// Update verification state
storage.set_proof_state(&proof_id, ExternalProofState::verified(now_ms))?;

// Bind proof to intent
storage.bind_proof_to_intent(&proof_id, &intent_id, now_ms)?;

// Check if all proofs for intent are verified
let ready = storage.all_proofs_verified_for_intent(&intent_id)?;
```

### 3. External Intent Types (`l2-core/src/intent.rs`)

New intent kinds for external operations:

```rust
pub enum IntentKind {
    // ... existing kinds ...
    ExternalLockAndMint,       // Lock on external chain, mint on IPPAN
    ExternalBurnAndUnlock,     // Burn on IPPAN, unlock on external chain
}
```

Payload for external lock-and-mint:

```rust
pub struct ExternalLockAndMintPayload {
    pub external_chain: String,        // "ethereum_mainnet"
    pub external_asset: String,        // Contract address
    pub amount: u64,
    pub recipient: String,             // IPPAN account
    pub wrapped_asset_id: String,      // IPPAN wrapped asset
    pub proof_id: String,              // Hex-encoded ExternalProofId
    pub memo: Option<String>,
}
```

### 4. Ethereum Adapter (`l2-bridge/src/eth_adapter.rs`)

#### ExternalVerifier Trait

Generic interface for proof verification:

```rust
pub trait ExternalVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &ExternalEventProofV1,
        expected_binding: Option<&ExpectedEventBinding>,
    ) -> Result<VerifiedEvent, ExternalVerifyError>;
}
```

#### EthAttestationVerifier

Verifies `EthReceiptAttestationV1` proofs:

1. Basic structural validation
2. Attestor public key allowlist check
3. Ed25519 signature verification
4. Confirmation count check (mainnet vs testnet thresholds)
5. Optional event binding verification

Configuration:

```rust
pub struct EthAttestationVerifierConfig {
    pub attestor_pubkeys: HashSet<String>,    // Allowed attestors
    pub min_confirmations_mainnet: u32,       // Default: 12
    pub min_confirmations_testnet: u32,       // Default: 6
}
```

Environment variables:

```bash
ETH_ATTESTOR_PUBKEYS="hex1,hex2,hex3"        # Comma-separated Ed25519 pubkeys
ETH_MIN_CONFIRMATIONS_MAINNET=12
ETH_MIN_CONFIRMATIONS_TESTNET=6
```

### 5. External Proof Reconciler (`l2-bridge/src/external_proof_reconciler.rs`)

Background process that:

1. Polls for unverified proofs
2. Verifies each proof using `ExternalVerifier`
3. Updates proof state to `Verified` or `Rejected`
4. Runs only on leader node (leader-only)

Configuration:

```rust
pub struct ExternalProofReconcilerConfig {
    pub enabled: bool,
    pub poll_interval_ms: u64,          // Default: 5000
    pub max_proofs_per_cycle: usize,    // Default: 100
}
```

### 6. Ethereum Header Chain (Light Client MVP)

The header chain subsystem (`eth-headers` feature) provides trust-minimized confirmation
counting without relying on external RPCs.

#### Components

| Component | Location | Description |
|-----------|----------|-------------|
| `EthereumHeaderV1` | `l2-core/src/eth_header.rs` | Canonical header struct with RLP encoding |
| `EthHeaderStorage` | `l2-storage/src/eth_headers.rs` | Persistent header store with fork choice |
| `HeaderVerifier` | `l2-bridge/src/eth_headers_verify.rs` | Checkpoint-based verification |
| `EthHeaderApi` | `l2-bridge/src/eth_headers_api.rs` | HTTP API for header submission/query |

#### Trust Model

The MVP light client uses **explicit checkpoints** as trust anchors:

```
                    Checkpoint (trusted)
                         │
                         ▼
                    Block N (verified)
                         │
                    ┌────┴────┐
                    ▼         ▼
              Block N+1   Block N+1' (fork)
              (verified)  (verified)
                    │
                    ▼
              Block N+2 (best tip)
```

1. **Checkpoints**: Trusted header hashes that serve as roots of trust
2. **Verification**: Headers descending from checkpoints are "verified"
3. **Confirmations**: Computed as `best_tip_number - block_number + 1`
4. **Fork choice**: Deterministic (highest number, then smallest hash)

#### Configuration

```bash
# Bootstrap checkpoints (chain_id:hash:number,...)
ETH_BOOTSTRAP_CHECKPOINTS="1:0xabc123...:18000000"

# Confirmation thresholds
ETH_MIN_CONFIRMATIONS_MAINNET=12
ETH_MIN_CONFIRMATIONS_TESTNET=6

# Allow uncheckpointed headers (devnet mode)
ETH_HEADER_ALLOW_UNCHECKPOINTED=false
```

#### API Endpoints (devnet mode)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/bridge/eth/headers` | POST | Submit headers (requires `DEVNET=1`) |
| `/bridge/eth/headers/best_tip` | GET | Get current best tip |
| `/bridge/eth/headers/:hash` | GET | Get header by hash |
| `/bridge/eth/confirmations/:hash` | GET | Get confirmations for block |
| `/bridge/eth/headers/stats` | GET | Header chain statistics |

#### Header-Aware Merkle Proofs

When header verification is required (`REQUIRE_HEADER_VERIFICATION=1`), Merkle proofs:

1. Must reference blocks known in the header store
2. Must be on a verified chain (descend from checkpoint)
3. Have confirmations computed from header depth (not from proof payload)
4. Use stored header's receipts_root (not from proof)

If the block is not yet known, the proof remains **pending** (not rejected).

### 7. External Proof API (`l2-bridge/src/external_proof_api.rs`)

HTTP API endpoints for proof management:

#### Submit Proof

```
POST /bridge/proofs
```

##### Attestation Mode Request

Submit a signed attestation from a trusted attestor:

```json
{
    "proof_type": "eth_receipt_attestation_v1",
    "chain": "ethereum_mainnet",
    "tx_hash": "0xaabbccdd...",
    "log_index": 0,
    "contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "topic0": "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
    "data_hash": "0x1234567890abcdef...",
    "block_number": 18000000,
    "block_hash": "0x9876543210fedcba...",
    "confirmations": 15,
    "attestor_pubkey": "0x11223344...",
    "signature": "0x55667788..."
}
```

##### Merkle Proof Mode Request

Submit a cryptographic Merkle Patricia Trie proof:

```json
{
    "proof_type": "eth_receipt_merkle_v1",
    "chain": "ethereum_mainnet",
    "tx_hash": "0xaabbccdd...",
    "log_index": 0,
    "contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "topic0": "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
    "data_hash": "0x1234567890abcdef...",
    "block_number": 18000000,
    "block_hash": "0x9876543210fedcba...",
    "tx_index": 42,
    "header_rlp": "0xf90210a0...",
    "receipt_rlp": "0xf901a8...",
    "proof_nodes": [
        "0xf851a0...",
        "0xf8b180a0...",
        "0xe219a0..."
    ],
    "confirmations": 12,
    "tip_block_number": 18000012
}
```

##### Response

```json
{
    "proof_id": "abc123...",
    "was_new": true,
    "chain": "ethereum:1",
    "proof_type": "eth_receipt_merkle_v1",
    "verification_mode": "eth_merkle_receipt_proof",
    "block_number": 18000000
}
```

#### Get Proof Status

```
GET /bridge/proofs/:proof_id
```

Response:
```json
{
    "proof_id": "abc123...",
    "chain": "ethereum:1",
    "proof_type": "eth_receipt_merkle_v1",
    "verification_mode": "eth_merkle_receipt_proof",
    "block_number": 18000000,
    "tx_hash": "0xaabbccdd...",
    "state": "verified",
    "is_verified": true,
    "is_rejected": false
}
```

#### List Proofs

```
GET /bridge/proofs?state=unverified&limit=100
```

#### Bind Proof to Intent

```
POST /bridge/proofs/:proof_id/bind/:intent_id
```

#### Check Intent Proofs

```
GET /bridge/intents/:intent_id/proofs/verified
```

Response:
```json
{
    "intent_id": "xyz789...",
    "all_verified": true,
    "total_proofs": 1,
    "verified_count": 1,
    "unverified_count": 0,
    "rejected_count": 0
}
```

## Workflow: External Lock-and-Mint

### Step 1: User Deposits on Ethereum

User sends ERC20 tokens to the IPPAN bridge contract on Ethereum:

```solidity
function deposit(address token, uint256 amount, bytes32 ippanRecipient) external;
```

### Step 2: Attestor Observes Event

A trusted attestor (oracle daemon) observes the deposit event and creates an attestation:

```rust
let attestation = EthReceiptAttestationV1 {
    chain: ExternalChainId::EthereumMainnet,
    tx_hash: [/* deposit tx hash */],
    log_index: 0,
    contract: [/* bridge contract */],
    topic0: [/* Deposit event signature */],
    data_hash: blake3_hash(event_data),
    block_number: 18_123_456,
    block_hash: [/* block hash */],
    confirmations: 15,
    attestor_pubkey: my_pubkey,
    signature: sign(attestation_data),
};
```

### Step 3: Submit Proof to IPPAN

```bash
curl -X POST http://ippan-node/bridge/proofs \
  -H "Content-Type: application/json" \
  -d @attestation.json
```

### Step 4: Create External Intent

```bash
curl -X POST http://ippan-node/bridge/intents \
  -H "Content-Type: application/json" \
  -d '{
    "kind": "ExternalLockAndMint",
    "payload": {
      "external_chain": "ethereum_mainnet",
      "external_asset": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      "amount": 1000000,
      "recipient": "alice",
      "wrapped_asset_id": "wUSDC",
      "proof_id": "abc123..."
    },
    "from_hub": "bridge",
    "to_hub": "fin"
  }'
```

### Step 5: Bind Proof to Intent

```bash
curl -X POST http://ippan-node/bridge/proofs/{proof_id}/bind/{intent_id}
```

### Step 6: Wait for Verification

The reconciler automatically verifies the proof. Check status:

```bash
curl http://ippan-node/bridge/intents/{intent_id}/proofs/verified
```

### Step 7: Prepare Intent

Once all proofs are verified, the intent can proceed to `Prepared` state:

```bash
curl -X POST http://ippan-node/bridge/intents/{intent_id}/prepare
```

### Step 8: Commit Intent

Complete the cross-hub operation:

```bash
curl -X POST http://ippan-node/bridge/intents/{intent_id}/commit
```

## Security Considerations

### Verification Modes and Trust Assumptions

The bridge supports two verification modes with different trust/security tradeoffs:

#### Attestation Mode

Trust assumptions:
1. **Attestor honesty**: The attestor correctly observes and reports external events
2. **Key security**: The attestor's private key is not compromised
3. **Allowlist management**: The attestor allowlist is correctly maintained

Verification checks:
1. **Basic validation**: All fields are non-zero and well-formed
2. **Attestor allowlist**: The attestor's public key must be in the configured allowlist
3. **Signature verification**: Ed25519 signature over canonical attestation data
4. **Confirmation threshold**: Minimum confirmations (12 for mainnet, 6 for testnet)
5. **Event binding** (optional): Contract, topic0, data_hash, chain match expected values

Best for: Production deployments with trusted operators, fast verification.

#### Merkle Proof Mode

Trust assumptions:
1. **Block finality**: The block header is valid and sufficiently confirmed
2. **Ethereum consensus**: Trust in Ethereum's consensus mechanism

Verification checks:
1. **Block hash verification**: `keccak256(header_rlp) == block_hash`
2. **Receipts root extraction**: Parse block header to get `receipts_root`
3. **MPT proof verification**: Verify receipt inclusion against `receipts_root`
4. **Receipt decoding**: Parse receipt RLP and extract log at `log_index`
5. **Event filter matching**: Verify `contract`, `topic0`, `blake3(data) == data_hash`
6. **Confirmation policy**: Optional minimum block confirmations

Best for: Trustless, decentralized deployments. No trusted third party required.

### Confirmation Policy

Both modes support confirmation thresholds to prevent reorg attacks:

| Chain | Attestation Default | Merkle Proof Default |
|-------|---------------------|----------------------|
| Mainnet | 12 blocks | 12 blocks |
| Testnet | 6 blocks | 6 blocks |

Configure via environment variables:
```bash
# For attestation verifier
ETH_MIN_CONFIRMATIONS_MAINNET=12
ETH_MIN_CONFIRMATIONS_TESTNET=6

# For Merkle proof reconciler
MERKLE_PROOF_MIN_CONFIRMATIONS_MAINNET=12
MERKLE_PROOF_MIN_CONFIRMATIONS_TESTNET=6
```

#### Header-Aware Merkle Proof Mode (requires `eth-headers` feature)

Trust assumptions:
1. **Bootstrap checkpoints**: Explicitly configured trusted header hashes
2. **Header chain validity**: Headers structurally valid and linked
3. **No sync committee verification** (MVP limitation)

Verification checks:
1. **Block known**: Block hash must exist in header store
2. **Verified chain**: Block must descend from a checkpoint
3. **Confirmations from headers**: Computed from header depth, not proof claims
4. **Receipt root from store**: Uses stored header's receipts_root
5. **Full MPT verification**: Same as basic Merkle proof mode

Best for: Deterministic, local confirmation counting without external RPC.

### Choosing a Verification Mode

| Consideration | Attestation | Merkle Proof | Merkle + Headers |
|---------------|-------------|--------------|------------------|
| Trust requirement | Trusted attestor | Ethereum consensus | Bootstrap checkpoints |
| Confirmation source | Proof payload | Proof payload | Header chain depth |
| External RPC needed | No | For proof gen | For header submission |
| Verification speed | Fast | Moderate | Moderate |
| Decentralization | Semi-centralized | Decentralized | Deterministic |

For production:
1. **Start**: Attestation mode for speed and simplicity
2. **Upgrade**: Merkle proofs for trustless verification
3. **Best**: Merkle + Headers for deterministic confirmations

## Configuration

### Environment Variables

```bash
# Attestation verifier configuration
ETH_ATTESTOR_PUBKEYS="pubkey1_hex,pubkey2_hex"
ETH_MIN_CONFIRMATIONS_MAINNET=12
ETH_MIN_CONFIRMATIONS_TESTNET=6

# Merkle proof reconciler confirmation policy
MERKLE_PROOF_MIN_CONFIRMATIONS_MAINNET=12
MERKLE_PROOF_MIN_CONFIRMATIONS_TESTNET=6

# Reconciler configuration
EXTERNAL_PROOF_RECONCILER_ENABLED=true
EXTERNAL_PROOF_POLL_MS=5000
EXTERNAL_PROOF_MAX_PER_CYCLE=100

# Header chain configuration (eth-headers feature)
ETH_BOOTSTRAP_CHECKPOINTS="1:0xabc123...:18000000"  # chain_id:hash:number
ETH_HEADER_ALLOW_UNCHECKPOINTED=false               # Allow headers without checkpoints (devnet)
REQUIRE_HEADER_VERIFICATION=false                   # Require header store for Merkle proofs
ETH_CHAIN_ID=1                                       # Default chain ID for API
DEVNET=0                                             # Enable devnet mode (header submission)
ETH_MAX_HEADERS_PER_REQUEST=100                      # Max headers per submission
```

### Feature Flags

Merkle proof verification requires the `merkle-proofs` feature:

```bash
cargo build -p l2-bridge --features merkle-proofs
```

Without this feature, Merkle proofs will be rejected with "feature not enabled".

Header chain verification requires the `eth-headers` feature:

```bash
cargo build -p l2-bridge --features eth-headers
```

The `eth-headers` feature implies `merkle-proofs` and enables:
- Ethereum header storage and verification
- Deterministic confirmation counting from headers
- Header submission API (devnet mode)
- Header-aware Merkle proof verification

### Running the Reconciler

The reconciler is started automatically when the IPPAN node starts with HA mode enabled.
It only runs on the leader node to prevent duplicate verification.

## Testing

Run the external proof tests:

```bash
cargo test -p l2-bridge --test external_proofs
```

Run the Merkle proof verification tests (requires `merkle-proofs` feature):

```bash
cargo test -p l2-bridge --features merkle-proofs --test eth_merkle_vectors
```

Run all bridge tests:

```bash
cargo test -p l2-bridge --features merkle-proofs
```

### Test Coverage

The Merkle proof test suite (`eth_merkle_vectors.rs`) includes:

- **Valid proofs**: ERC20 Transfer events, Bridge deposit events
- **Tamper detection**: Mutated proof nodes, wrong block hash
- **Filter validation**: Wrong contract, wrong topic0, wrong data hash
- **Bounds checking**: Invalid log index, empty proof nodes

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/bridge/proofs` | POST | Submit a new external proof |
| `/bridge/proofs/:proof_id` | GET | Get proof status |
| `/bridge/proofs` | GET | List proofs (with state filter) |
| `/bridge/proofs/:proof_id/bind/:intent_id` | POST | Bind proof to intent |
| `/bridge/intents/:intent_id/proofs` | GET | List proofs for intent |
| `/bridge/intents/:intent_id/proofs/verified` | GET | Check if all proofs verified |
| `/bridge/status` | GET | Get proof counts |

## Error Codes

| Code | Description |
|------|-------------|
| `invalid_request` | Request validation failed (400) |
| `not_found` | Proof or intent not found (404) |
| `storage_error` | Database error (500) |
| `encoding_error` | Serialization error (400) |
| `internal_error` | Unexpected error (500) |

## Glossary

- **External Proof**: A cryptographic proof of an event on an external blockchain
- **Attestation**: A signed statement from a trusted party about an external event
- **Merkle Proof**: A cryptographic proof using Merkle Patricia Trie (MPT) inclusion
- **MPT (Merkle Patricia Trie)**: Ethereum's data structure for storing receipts
- **Receipt RLP**: RLP-encoded Ethereum transaction receipt
- **Header RLP**: RLP-encoded Ethereum block header
- **Receipts Root**: The MPT root hash of all receipts in a block
- **Proof Nodes**: The MPT path from receipts root to receipt leaf
- **Verification Mode**: The method used to verify a proof (attestation or merkle)
- **Proof-Carrying Intent**: An intent that requires external proof(s) to proceed
- **Reconciler**: Background process that verifies external proofs
- **Binding**: Association between a proof and an intent
- **Confirmation Policy**: Minimum block confirmations required for proof acceptance
- **Header Chain**: A sequence of Ethereum block headers with parent links
- **Checkpoint**: An explicitly trusted header hash used as a root of trust
- **Verified Chain**: Headers that descend from a checkpoint
- **Best Tip**: The highest-numbered verified block (with hash tie-breaking)
- **Fork Choice**: Algorithm for selecting the canonical chain among competing forks
- **Light Client**: A system that validates block headers without full state
