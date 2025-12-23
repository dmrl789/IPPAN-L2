# HA Migration Guide (sled → Redis / Consul)

This guide explains when and how to migrate `fin-node` HA from the **built-in sled lock** (shared storage required) to an **external lock provider** (Redis or Consul).

## When to move to Redis / Consul

Use an external provider when you need any of the following:

- Multi-node HA across **independent machines / disks / regions**
- Avoiding correctness assumptions about **NFS** (misconfigurations can cause split-brain)
- A standard, operator-managed coordination system (Redis/Consul) with clear failure visibility

## Important: what external locking does (and does not) do

- **Does**: ensure **only one node** is leader at a time (within TTL bounds) even when node disks are independent.
- **Does not**: replicate hub state between nodes. If follower nodes serve reads from their own local state, reads may be stale/inconsistent.

Recommended production routing:

- Route **writes** to the leader (or let followers return `NOT_LEADER` and retry via `leader_url`).
- If you require consistent reads across nodes, either:
  - serve reads from the leader, or
  - use a shared/replicated state layer (not provided by `fin-node` today).

## Common NFS failure modes (sled lock)

The built-in sled lock under `[ha].lock_db_dir` requires correctly shared storage. Examples of unsafe setups:

- Nodes mount **different exports** at the same path
- NFS attribute caching / stale reads cause nodes to not observe recent writes
- Split-brain due to **stale file handles**, partial partitions, or misconfigured `noac`/cache options

If you cannot guarantee NFS correctness, migrate to Redis/Consul.

## Migration: Redis provider

1) Build `fin-node` with the Redis feature:

- `--features ha-redis` (or compile with all features in CI)

2) Use the template config:

- `configs/ha-redis.toml`

3) Deploy:

- Ensure all nodes point at the **same Redis** cluster.
- Ensure `ha.node_id` is unique per node.
- Start nodes and confirm exactly one leader via `GET /api/v1/ha/status`.

Operational safety:

- If Redis is unreachable at startup and `provider=redis`, `fin-node` fails fast.
- If Redis becomes unreachable after leadership acquired, the leader **steps down**.

## Migration: Consul provider

1) Build `fin-node` with the Consul feature:

- `--features ha-consul`

2) Use the template config:

- `configs/ha-consul.toml`

3) Deploy:

- Ensure all nodes point at the same Consul cluster.
- Confirm leadership via `GET /api/v1/ha/status`.

## How to validate leadership safety

- **Single-leader invariant**: at any time, at most one node reports `is_leader=true`.
- **Failover bound**: if a leader stops renewing, a follower becomes leader after approximately `lease_ms` (+ polling).
- **Error observability**:
  - Check `ha_lock_errors_total{provider,reason}` for provider failures.
  - Confirm `ha_lock_provider{type="..."}` is set to 1 for the active provider.

