# High Availability (HA) for `fin-node` (leader election light)

`fin-node` supports **multi-instance operation** with a minimal **leader-only scheduling** model:

- **Exactly one node** runs background **writer loops** (reconciliation, pruning) at a time.
- **All nodes** can serve **read-only** HTTP APIs.
- **Write HTTP requests** can be **leader-only** (recommended) or **allowed on all nodes** (dev).

This is **not** consensus (no Raft/etcd). It is a **best-effort leader lock** using a shared Sled-backed TTL lease.

## Assumptions / requirements

- **Shared storage is required** for correctness (active/active reads, leader-only writers):
  - receipt directory
  - sled DB directories (fin/data/policy/recon)
  - HA lock directory (`[ha].lock_db_dir`)
- If storage is **not** shared across nodes, the built-in lock **cannot coordinate** leadership. See **Limitations**.

## Leader-only tasks list

The following background tasks mutate state or produce side effects and are therefore **leader-only**:

- **Reconciliation loop** (`recon`): updates receipts’ submit state, dequeues/re-schedules work in the recon queue.
- **Pruning loop** (`pruning`): deletes old receipt files under `storage.receipts_dir`.

Safe-on-all-nodes (read-only):

- All **GET** HTTP endpoints (health/ready/metrics/OpenAPI, reads of assets/datasets/receipts, recon pending list).

Notes:

- The Ethereum oracle is a **separate binary** (`ippan_eth_oracle_daemon`) and is **not embedded** in `fin-node`.

## Configuration

Enable HA via the `[ha]` section:

```toml
[ha]
enabled = true
node_id = "fin-node-1"        # must be unique per instance
lease_ms = 15000              # leader renews every lease_ms/3
lock_db_dir = "shared/ha_db"  # MUST be shared across nodes
write_mode = "leader_only"    # recommended: leader_only | allow_all

[ha.leader_urls]
fin-node-1 = "http://10.0.0.11:3000"
fin-node-2 = "http://10.0.0.12:3000"
```

## Write routing policy

When `[ha].write_mode = "leader_only"`:

- Non-leader nodes reject mutating requests (`POST/PUT/PATCH/DELETE`) with **HTTP 503** and error code **`NOT_LEADER`**.
- The response includes `error.leader_url` when configured via `[ha.leader_urls]`.

When `[ha].write_mode = "allow_all"`:

- All nodes accept writes (dev mode). If storage is shared, writes may still contend; correctness depends on idempotency and storage semantics.

## HA status endpoint

`GET /api/v1/ha/status` returns:

```json
{
  "enabled": true,
  "node_id": "fin-node-1",
  "is_leader": true,
  "leader_id": "fin-node-1",
  "lease_ms": 15000,
  "expires_in_ms": 12345
}
```

## Metrics

- `ha_is_leader` (gauge 0/1)
- `ha_leader_changes_total{event="became_leader|stepped_down"}`
- `ha_lock_acquire_failures_total{reason="contended|error"}`

## Deployment patterns

### A) Active/passive (shared volume)

- Run two nodes against the **same shared volume**.
- Only the leader runs recon/pruning; followers serve reads.
- If the leader stops renewing, a follower becomes leader **after TTL** (bounded by `lease_ms`).

### B) Two nodes behind an LB (reads everywhere, writes to leader)

- Send **GET** traffic to all nodes.
- For writes, either:
  - route to the leader at the load balancer, or
  - let followers return `NOT_LEADER` and have clients retry via `error.leader_url`.

## Failure playbook

- **Leader crash**: followers take over after `lease_ms` (plus their election polling interval).
- **Split brain (storage not shared)**: cannot be prevented by this mechanism. Do not use built-in HA without shared storage.
- **Clock skew**: lease uses wall-clock milliseconds; moderate skew is tolerated, but extreme skew can delay leadership changes.

## Limitations / next steps

- Built-in leadership requires **shared storage**; otherwise use an **external lock provider** (Redis/Consul/etc.) or a shared DB.
- No multi-region preference / leader affinity (could be added as a scoring hook).
- Followers currently **reject** writes; optional improvement: **request forwarding** to leader.
- Lease timestamps use `SystemTime` (wall clock), not a monotonic clock (acceptable for operational scheduling only).

