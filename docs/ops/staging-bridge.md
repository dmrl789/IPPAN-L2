# Staging Bridge Runbook

This document provides operational guidance for running the IPPAN L2 bridge in staging mode.

## Overview

In staging mode (`NODE_SECURITY_MODE=staging`), the bridge requires authentication for sensitive operations while maintaining flexibility for testing. This mode is designed to be as close to production as possible while allowing necessary debugging and testing workflows.

## Security Modes

| Mode | Auth Required | Devnet Endpoints | Ops Endpoints | Raw Poster |
|------|---------------|------------------|---------------|------------|
| `devnet` | No | ✅ | ✅ | ✅ |
| `staging` | Yes | ❌ | ✅ (auth) | ✅ |
| `prod` | Yes | ❌ | ❌ | ❌ |

## Required Environment Variables

### Core Configuration

```bash
# Security mode - must be "staging" for this runbook
export NODE_SECURITY_MODE=staging

# Admin token for authenticated endpoints
# Generate a secure token: openssl rand -hex 32
export IPPAN_ADMIN_TOKEN=<your-secure-token>

# Chain ID
export L2_CHAIN_ID=1

# Listen address
export L2_LISTEN_ADDR=0.0.0.0:3000

# Database path
export L2_DB_PATH=./data/l2
```

### Bridge Configuration

```bash
# Enable bridge functionality
export BRIDGE_ENABLED=true

# Minimum confirmations for mainnet Merkle proofs
export MERKLE_PROOF_MIN_CONFIRMATIONS_MAINNET=12

# Minimum confirmations for testnet Merkle proofs
export MERKLE_PROOF_MIN_CONFIRMATIONS_TESTNET=6

# Require header verification for Merkle proofs (recommended)
export REQUIRE_HEADER_VERIFICATION=true
```

### Optional Configuration

```bash
# External proof reconciler settings
export EXTERNAL_PROOF_POLL_MS=5000
export EXTERNAL_PROOF_MAX_PER_CYCLE=100
export EXTERNAL_PROOF_RECONCILER_ENABLED=true

# Ethereum header API (if using eth-headers feature)
export ETH_CHAIN_ID=1
export DEVNET=0  # Disable raw header submission without auth
export ETH_MAX_HEADERS_PER_REQUEST=100
```

## Authentication

All protected endpoints in staging mode require the `X-IPPAN-ADMIN-TOKEN` header.

### Protected Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/bridge/proofs` | POST | Submit external proof |
| `/bridge/proofs` | GET | List proofs |
| `/bridge/proofs/:proof_id` | GET | Get proof status |
| `/bridge/eth/execution_headers` | POST | Submit execution headers |
| `/bridge/eth/headers/stats` | GET | Get header chain statistics |

### Example: Authenticated Request

```bash
curl -X POST http://localhost:3000/bridge/proofs \
  -H "Content-Type: application/json" \
  -H "X-IPPAN-ADMIN-TOKEN: $IPPAN_ADMIN_TOKEN" \
  -d '{...}'
```

### Unauthenticated Request (401 Error)

```bash
curl http://localhost:3000/bridge/proofs
# Response: {"error": "missing X-IPPAN-ADMIN-TOKEN header", "code": "missing_token"}
```

## Workflow: Submit Execution Headers

Execution headers establish the trusted chain state for Merkle proof verification.

### 1. Prepare Headers

```json
{
  "headers": [
    {
      "rlp": "0xf90...",  // RLP-encoded block header
      "expected_hash": "0xabc123..."  // Optional: expected block hash
    }
  ]
}
```

### 2. Submit Headers

```bash
curl -X POST http://localhost:3000/bridge/eth/execution_headers \
  -H "Content-Type: application/json" \
  -H "X-IPPAN-ADMIN-TOKEN: $IPPAN_ADMIN_TOKEN" \
  -d @headers.json
```

### 3. Check Response

```json
{
  "accepted": true,
  "headers_count": 1,
  "message": "..."
}
```

## Workflow: Submit a Proof

External proofs verify Ethereum events for bridge operations.

### 1. Prepare Merkle Proof

```json
{
  "proof_type": "eth_receipt_merkle_v1",
  "chain": "ethereum_mainnet",
  "tx_hash": "0x1234...",
  "log_index": 0,
  "contract": "0xContractAddress...",
  "topic0": "0xEventSignature...",
  "data_hash": "0xBlake3HashOfEventData...",
  "block_number": 18500000,
  "block_hash": "0xBlockHash...",
  "tx_index": 42,
  "header_rlp": "0xRlpEncodedHeader...",
  "receipt_rlp": "0xRlpEncodedReceipt...",
  "proof_nodes": ["0xNode1...", "0xNode2...", "..."],
  "confirmations": 12,
  "tip_block_number": 18500100
}
```

### 2. Submit Proof

```bash
curl -X POST http://localhost:3000/bridge/proofs \
  -H "Content-Type: application/json" \
  -H "X-IPPAN-ADMIN-TOKEN: $IPPAN_ADMIN_TOKEN" \
  -d @proof.json
```

### 3. Check Response

```json
{
  "proof_id": "0xabc123...",
  "was_new": true,
  "chain": "ethereum:1",
  "proof_type": "eth_receipt_merkle_v1",
  "verification_mode": "eth_merkle_receipt_proof",
  "block_number": 18500000
}
```

## Workflow: Monitor Proof Verification

### 1. Check Status Endpoint

```bash
curl http://localhost:3000/status | jq '.bridge.proofs'
```

### 2. Expected Response

```json
{
  "pending_proofs_total": 5,
  "pending_proofs_missing_execution_header": 2,
  "verified_proofs_total": 100,
  "rejected_proofs_total": 3,
  "last_proof_verify_ms": 1735000000000,
  "last_reconcile_ms": 1735000005000,
  "last_reconcile_ok_ms": 1735000005000,
  "last_reconcile_err_ms": null,
  "security_mode": "staging"
}
```

### 3. Key Metrics to Watch

| Field | Description | Action if High |
|-------|-------------|----------------|
| `pending_proofs_total` | Proofs awaiting verification | Check reconciler status |
| `pending_proofs_missing_execution_header` | Proofs blocked on headers | Submit missing headers |
| `rejected_proofs_total` | Failed verification | Check proof formatting |

### 4. Get Individual Proof Status

```bash
curl -H "X-IPPAN-ADMIN-TOKEN: $IPPAN_ADMIN_TOKEN" \
  http://localhost:3000/bridge/proofs/0xabc123...
```

Response:

```json
{
  "proof_id": "0xabc123...",
  "chain": "ethereum:1",
  "proof_type": "eth_receipt_merkle_v1",
  "verification_mode": "eth_merkle_receipt_proof",
  "block_number": 18500000,
  "tx_hash": "0x1234...",
  "state": "verified",
  "is_verified": true,
  "is_rejected": false,
  "rejection_reason": null
}
```

## State Transitions

```
Unverified → Verified   (success)
Unverified → Rejected   (permanent failure)
Unverified → Unverified (transient error, retry later)
```

## Common Failure Modes

### 1. Missing Execution Header

**Symptom**: Proof stays in `unverified` state, `pending_proofs_missing_execution_header` increasing

**Cause**: The block referenced by the proof is not in the header store

**Solution**:
```bash
# Check if block exists
curl -H "X-IPPAN-ADMIN-TOKEN: $IPPAN_ADMIN_TOKEN" \
  http://localhost:3000/bridge/eth/headers/stats

# Submit missing headers
curl -X POST http://localhost:3000/bridge/eth/execution_headers \
  -H "X-IPPAN-ADMIN-TOKEN: $IPPAN_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"headers": [...]}'
```

### 2. Insufficient Confirmations

**Symptom**: Proof rejected with "insufficient confirmations"

**Cause**: Block doesn't have enough confirmations from the header chain tip

**Solution**:
- Wait for more blocks to be confirmed
- Submit more recent headers to extend the chain
- Check `MERKLE_PROOF_MIN_CONFIRMATIONS_MAINNET` setting

### 3. Log Mismatch

**Symptom**: Proof rejected with "contract mismatch" or "topic0 mismatch"

**Cause**: The event data in the proof doesn't match the receipt

**Solution**:
- Verify contract address is correct
- Verify topic0 (event signature) matches
- Re-fetch receipt data from Ethereum node
- Verify log_index is correct

### 4. Block Hash Mismatch

**Symptom**: Proof rejected with "block hash mismatch"

**Cause**: The header RLP doesn't hash to the claimed block hash

**Solution**:
- Verify header_rlp is correct
- Ensure header wasn't modified during encoding
- Re-fetch header from Ethereum node

### 5. MPT Proof Invalid

**Symptom**: Proof rejected with "MPT proof verification failed"

**Cause**: Merkle Patricia Trie proof nodes don't form valid path

**Solution**:
- Regenerate proof from Ethereum node
- Verify tx_index is correct
- Ensure no proof nodes are truncated or corrupted

### 6. Auth Token Invalid

**Symptom**: 401 Unauthorized response

**Cause**: Token missing or doesn't match configured token

**Solution**:
```bash
# Verify token is set
echo $IPPAN_ADMIN_TOKEN

# Test token
curl -I -H "X-IPPAN-ADMIN-TOKEN: $IPPAN_ADMIN_TOKEN" \
  http://localhost:3000/bridge/proofs
```

## Request Limits

To prevent DoS attacks, request body sizes are limited:

| Endpoint | Max Body Size |
|----------|---------------|
| `/bridge/proofs` (POST) | 512 KiB |
| `/bridge/eth/execution_headers` (POST) | 1 MiB |
| All other endpoints | 256 KiB |

Additional proof validation limits:
- Max proof nodes: 64
- Max proof nodes total bytes: 128 KiB
- Max headers per submission: 100

## Troubleshooting

### Check Node Status

```bash
# Overall status
curl http://localhost:3000/status | jq

# Health check
curl http://localhost:3000/healthz

# Readiness check
curl http://localhost:3000/readyz
```

### Check Logs

```bash
# Enable debug logging
RUST_LOG=debug ./l2-node

# Filter for bridge/proof messages
RUST_LOG=l2_bridge=debug,l2_node=debug ./l2-node
```

### Restart Recovery

If the node crashes, on restart:
1. The reconciler will automatically scan for in-flight operations
2. Pending proofs will be re-processed
3. Check `/status` to monitor recovery progress

## Metrics

Prometheus metrics are available at `/metrics`:

```bash
curl http://localhost:3000/metrics | grep -E 'l2_bridge|proof'
```

Key metrics:
- `l2_bridge_deposits_total` - Total deposits processed
- `l2_bridge_withdrawals_total` - Total withdrawals
- `l2_last_reconcile_ms` - Last reconciliation timestamp

## Security Considerations

1. **Token Management**: Store `IPPAN_ADMIN_TOKEN` securely (e.g., HashiCorp Vault, AWS Secrets Manager)
2. **Network Security**: Use TLS termination proxy in front of the node
3. **Access Control**: Limit who has the admin token
4. **Audit Logging**: Monitor auth failures in logs
5. **Rate Limiting**: Consider additional rate limiting at the network level

## See Also

- [Bridge Operations](./bridge.md) - General bridge operations
- [Devnet Runbook](./devnet-runbook.md) - Development environment setup
- [Production Config](./prod-config.md) - Production configuration guide
