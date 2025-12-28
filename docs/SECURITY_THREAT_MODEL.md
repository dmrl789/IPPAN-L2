# IPPAN-L2 Security Threat Model

This document describes the security threat model for IPPAN-L2, including attacker goals, mitigations, trust assumptions, and system invariants.

## Table of Contents

- [Attacker Goals](#attacker-goals)
- [Attack Surface Inventory](#attack-surface-inventory)
- [Mitigations](#mitigations)
- [Trust Assumptions](#trust-assumptions)
- [System Invariants](#system-invariants)
- [Security Mode Reference](#security-mode-reference)

---

## Attacker Goals

### 1. Denial of Service (DoS)

**Goal:** Exhaust node resources to prevent legitimate operations.

**Attack vectors:**
- Large request bodies overwhelming memory/CPU
- Deep JSON nesting causing stack exhaustion
- Excessive MPT proof nodes causing unbounded computation
- Request floods exceeding rate limits
- Long query strings consuming parsing resources

**Impact:** Node unavailability, degraded performance for legitimate users.

### 2. Double Spend / Double Charge

**Goal:** Credit an account multiple times for the same external event.

**Attack vectors:**
- Replaying the same bridge proof with different proof_ids
- Exploiting race conditions in intent lifecycle
- Submitting conflicting transactions during settlement window

**Impact:** Economic loss, ledger inconsistency.

### 3. Ledger Poisoning

**Goal:** Corrupt the state database with invalid or malicious data.

**Attack vectors:**
- Malformed action payloads bypassing validation
- SQL/NoSQL injection (not applicable: sled is key-value)
- State version confusion during migrations
- Concurrent modification without proper locking

**Impact:** Corrupted state, loss of funds, audit trail broken.

### 4. Proof Spoofing

**Goal:** Submit fake external proofs that verify as valid.

**Attack vectors:**
- Forged attestor signatures
- Malformed MPT proofs that pass verification
- Header hash collisions (computationally infeasible)
- Exploiting parsing bugs in RLP decoder

**Impact:** Unauthorized minting, false bridge deposits credited.

### 5. Intent Race Conditions

**Goal:** Exploit timing windows in multi-hub atomic operations.

**Attack vectors:**
- Abort intent after payment but before entitlement
- Double-spend during prepare→commit window
- Timeout exploitation to orphan partial operations

**Impact:** Inconsistent state between hubs, stuck funds.

### 6. Unauthorized Access

**Goal:** Access restricted endpoints or perform privileged operations.

**Attack vectors:**
- Missing auth on admin endpoints
- Token/key disclosure through logs or errors
- Privilege escalation via policy bypass

**Impact:** Unauthorized modifications, data exfiltration.

---

## Attack Surface Inventory

### Public HTTP Endpoints

| Endpoint Group | Risk Level | Mitigations |
|---------------|------------|-------------|
| `/healthz`, `/readyz`, `/metrics` | Low | No auth, rate-limit exempt |
| `/fin/actions`, `/data/*` (POST) | High | Auth, rate limiting, payload caps |
| `/bridge/proofs` (POST) | High | Auth (prod), size limits, validation |
| `/bridge/intent/*` | High | Rate limiting, timeout enforcement |
| `/recon/pending`, list endpoints | Medium | Pagination, auth in prod |
| GET by ID endpoints | Low | Input validation, bounded response |

### Background Processes

| Process | Risk Level | Mitigations |
|---------|------------|-------------|
| Reconciliation loop | Medium | Bounded batch size, graceful shutdown |
| Pruning job | Low | Safe deletion with retention minimums |
| Snapshot scheduler | Medium | Write pause, atomic operations |
| HA leader election | Medium | TTL-based leases, fencing tokens |

### External Dependencies

| Dependency | Trust Level | Risk |
|-----------|-------------|------|
| L1 RPC | High trust | Must return canonical chain state |
| Sled DB | High trust | Crash-consistent, local-only |
| Attestors | Configurable | Trust depends on allowlist policy |
| ETH headers | Verifiable | Trustless with merkle proofs |

---

## Mitigations

### Payload Size Limits

```toml
[limits]
max_body_bytes = 262144        # 256 KiB general
max_bridge_proof_bytes = 524288  # 512 KiB for proofs
max_mpt_proof_nodes = 32
max_mpt_proof_bytes = 65536    # 64 KiB
max_header_rlp_bytes = 8192    # 8 KiB
max_receipt_rlp_bytes = 32768  # 32 KiB
max_json_depth = 64
```

### Rate Limiting

- **Algorithm:** Deterministic token bucket (no jitter)
- **Scope:** Per-IP, per-actor, per-route-category
- **Route costs:** Submit=2x, Bridge=3x, Intent=2x, General=1x
- **Metric:** `http_rate_limited_total{route}`

### Idempotency

- **Actions:** Content-addressed by canonical hash
- **Proofs:** Deduplicated by proof_id (blake3 hash)
- **Intents:** Idempotency key prevents double-creation

### Monotonic State

- **FIN hub:** Balances monotonically bounded (no underflow)
- **DATA hub:** Entitlements append-only
- **Settlements:** State machine with valid transitions only

### Authentication Gating

- **Security modes:** devnet, staging, prod
- **Admin token:** Required for ops endpoints in staging/prod
- **Allowlists:** Configurable for bridge submitters and attestors

### Input Validation

- **Hex parsing:** Early rejection of malformed hex
- **Field bounds:** max_string_bytes, max_tags, etc.
- **Canonical IDs:** machine_id/tx_id format enforcement

---

## Trust Assumptions

### 1. Attestation Trust

**Assumption:** Attestor signatures are only accepted if:
- The attestor pubkey is in the configured allowlist
- The signature is cryptographically valid (ed25519)
- The attestor has stake at risk (out of scope for L2)

**Implication:** A compromised attestor can forge proofs.

**Mitigation:** Use merkle proofs (`eth_receipt_merkle_v1`) for trustless verification.

### 2. Merkle Inclusion Trust Boundary

**Assumption:** If a merkle proof verifies against a block hash:
- The event genuinely occurred in that block
- The block is on the canonical chain

**Implication:** We trust the block hash is correct.

**Mitigation:** 
- Header chain verification (`eth-headers` feature)
- Light client finality (`eth-lightclient` feature)
- Confirmation count requirements

### 3. Header/Light Client Status

| Mode | Trust | Finality |
|------|-------|----------|
| Attestation only | High (trust attestor) | Soft (configurable confirmations) |
| Merkle + headers | Medium (trust header chain) | Soft (block confirmations) |
| Merkle + light client | Low (cryptographic) | Hard (sync committee finality) |

**Current status:** Light client is optional feature, not default.

### 4. Operator Trust

**Assumption:** Node operators:
- Run official binaries from trusted builds
- Protect secrets (admin tokens, encryption keys)
- Configure appropriate security mode for environment

**Implication:** Malicious operator can steal funds.

**Mitigation:** Out of scope for MVP; multi-party threshold in roadmap.

### 5. L1 Contract Trust

**Assumption:** The L1 settlement contract:
- Correctly validates batches
- Returns canonical inclusion/finality status
- Does not equivocate

**Implication:** L1 bugs could cause L2 state divergence.

**Mitigation:** L1 contract auditing (separate scope).

---

## System Invariants

These invariants are enforced by the codebase and tested in CI:

### FIN Hub Invariants

1. **Balance Non-Negativity:** `balance[account][asset] >= 0` always
2. **Supply Conservation:** `sum(balances) == minted - burned` for each asset
3. **Transfer Atomicity:** Debit and credit happen together or not at all
4. **Mint Authority:** Only authorized issuer can mint (policy enforced)

### DATA Hub Invariants

1. **Dataset Uniqueness:** `dataset_id` is content-addressed, no duplicates
2. **License Ownership:** License can only be issued by dataset owner/delegatee
3. **Entitlement Monotonicity:** Once granted, entitlement cannot be revoked
4. **Attestation Append-Only:** Attestations can only be added, never modified

### Intent Invariants

1. **Lifecycle Valid:** Intent state transitions follow state machine
2. **Atomicity:** Either all hub operations complete or none do
3. **Timeout Enforcement:** Expired intents cannot commit
4. **Proof Binding:** Proofs bound to intent cannot be reused elsewhere

### Settlement Invariants

1. **State Machine:** `pending → submitted → included → final` only
2. **No Double Finalization:** Each batch finalized exactly once
3. **Monotonic Sequence:** Batch sequence numbers increase
4. **Crash Recovery:** Incomplete operations resume correctly after restart

### Bridge Invariants

1. **Proof Uniqueness:** Same proof cannot credit twice
2. **Verification Before Credit:** No credit without valid proof
3. **Confirmation Depth:** Only finalized events trigger credits
4. **Chain Isolation:** Proof for chain X cannot credit on chain Y

---

## Security Mode Reference

### Devnet Mode (default)

```toml
[security]
mode = "devnet"
```

- All endpoints enabled
- No authentication required
- Higher rate limits
- Suitable for local development and testing

### Staging Mode

```toml
[security]
mode = "staging"
admin_token = "your-32-char-min-token"
```

- ETH header submission requires auth
- Moderate rate limits
- Suitable for test networks

### Production Mode

```toml
[security]
mode = "prod"
admin_token = "env:ADMIN_TOKEN"
bridge_submitters = ["pubkey1hex", "pubkey2hex"]
attestor_keys = ["attestor1hex"]
```

- Devnet-only endpoints disabled (`/m2m/topup`, ledger ops)
- List proofs requires auth
- ETH header submission requires auth
- Strict rate limits and payload caps
- Allowlists enforced for submitters and attestors

---

## Appendix: Checklist for Security Review

- [ ] All POST endpoints have payload size limits
- [ ] Rate limiting covers all non-health endpoints
- [ ] Admin endpoints gated in staging/prod
- [ ] Hex input validated before processing
- [ ] JSON depth limited
- [ ] MPT proof bounds enforced
- [ ] Error messages don't leak secrets
- [ ] Logs don't contain sensitive data
- [ ] Metrics don't expose internal state
- [ ] Graceful shutdown handles in-flight requests
- [ ] State machine transitions are explicit
- [ ] Idempotency keys prevent double-processing
- [ ] Timeout enforcement prevents resource exhaustion
