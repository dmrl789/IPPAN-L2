# IPPAN-L2 Leader / Sequencer Model (MVP)

## Role

- Accept transactions, order them deterministically, and cut batches.
- Trigger posting to IPPAN L1 (stubbed) and surface status/metrics.
- Act as bridge watcher coordinator (stubbed) until multi-leader HA exists.

## Mode

- **MVP:** single active leader (configured instance). Follower nodes can stay hot-standby but do not batch/post.
- **Term/ID:** leader exposes `{id, term}` in `/status` for operators to correlate logs.

## Failover + Rotation Strategy

- **Short term:** manual failover; operator promotes a standby, bumps term, and restarts batcher/bridge tasks.
- **Future:** lease-based rotation with heartbeat and deterministic lock (e.g., etcd/consul/ZK or L1 lock primitive).
- **Forced inclusion:** unimplemented in MVP. Roadmap: allow clients to submit proof-of-delay to force inclusion via L1 contract hook.

## Operational Notes

- Only the leader should write to `tx_pool`/`batches`. Followers should stay read-only until promoted.
- Leader term changes must be recorded in meta storage to prevent stale batches from posting.
- `/readyz` should flip to unhealthy on storage errors or if leader services are intentionally disabled.
