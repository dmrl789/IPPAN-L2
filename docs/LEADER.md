# IPPAN-L2 Leader / Sequencer Model (MVP)

## Role

- Accept transactions, order them deterministically, and cut batches.
- Post batches to IPPAN L1 (CORE) for data availability.
- Run reconciliation loop to confirm posted batches.
- Act as bridge watcher coordinator (stubbed) until multi-leader HA exists.

## Mode

- **MVP:** Single active leader (`L2_LEADER_MODE=single`). Follower nodes serve reads but do not batch/post.
- **Term/ID:** Leader exposes `{id, term_id}` in `/status` for operators to correlate logs.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `L2_LEADER_MODE` | `single` | Leader election mode (only `single` supported in MVP) |
| `L2_LEADER` | `1` | Set to `1` for leader, `0` for read-only follower |
| `LEADER_ID` | `sequencer-0` | Unique identifier for this sequencer instance |
| `LEADER_TERM` | `0` | Term/epoch ID (static `0` for MVP single-leader) |
| `L2_SEQUENCER_KEY_PATH` | (empty) | Path to Ed25519 signing key file for batch envelopes |

### Leader Behavior

When `L2_LEADER=1`:
- Accepts `POST /tx` requests (transaction submission)
- Runs batcher loop to create and post batches
- Runs reconciler to confirm posted batches
- Exposes full read/write API

When `L2_LEADER=0`:
- Serves read-only endpoints (`GET /tx/{hash}`, `GET /batch/{hash}`, `/status`)
- Returns `403 Forbidden` on write endpoints
- Does not run batcher or reconciler
- Useful for read replicas or hot-standby nodes

### Sequencer Key (Optional)

The sequencer key is used to sign batch envelopes before posting.
This provides non-repudiation and allows verification of batch origin.

```bash
# Generate a new Ed25519 key
openssl genpkey -algorithm ed25519 -out sequencer.key
export L2_SEQUENCER_KEY_PATH=./sequencer.key
```

## Status Endpoint

The `/status` endpoint exposes leader information:

```json
{
  "leader": {
    "mode": "single",
    "is_leader": true,
    "leader_pubkey": "sequencer-0",
    "term_id": 0,
    "last_heartbeat_ms": 12345
  }
}
```

## Failover + Rotation Strategy

- **Short term (MVP):** Manual failover; operator promotes a standby, bumps term, and restarts.
- **Future:** Lease-based rotation with heartbeat and deterministic lock (etcd/consul/ZK or L1 lock primitive).
- **Forced inclusion:** Unimplemented in MVP. Roadmap: allow clients to submit proof-of-delay to force inclusion via L1 contract hook.

## Operational Notes

1. **Write isolation:** Only the leader should write to `tx_pool`/`batches`. Followers stay read-only.

2. **Term management:** Leader term changes should be recorded in meta storage to prevent stale batches from posting.

3. **Health checks:** `/readyz` returns unhealthy on storage errors or if leader services fail.

4. **Graceful promotion:** To promote a follower:
   ```bash
   # On new leader:
   export L2_LEADER=1
   export LEADER_TERM=$((CURRENT_TERM + 1))
   # Restart the node
   ```

5. **Monitoring:** Watch these metrics:
   - `l2_batches_pending` - Batches waiting to be posted
   - `l2_batches_posted` - Batches successfully posted
   - `l2_batches_confirmed` - Batches confirmed on L1
   - `l2_post_failures_total` - Posting failures

## Anti-Censorship (Future)

The MVP single-leader model has a censorship risk. Future versions will implement:

1. **Forced inclusion window:** Transactions not included within N blocks can be force-included via L1 contract.
2. **Multi-leader rotation:** Rotating leader set to prevent sustained censorship.
3. **Inclusion proofs:** Cryptographic proof that a transaction was offered but not included.
