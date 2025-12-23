# High Availability (HA) for `fin-node` (leader election light)

`fin-node` supports **multi-instance operation** with a minimal **leader-only scheduling** model:

- **Exactly one node** runs background **writer loops** (reconciliation, pruning) at a time.
- **All nodes** can serve **read-only** HTTP APIs.
- **Write HTTP requests** can be **leader-only** (recommended) or **allowed on all nodes** (dev).

This is **not** consensus (no Raft/etcd). It is a **best-effort leader lock** using a TTL lease.

## Assumptions / requirements

- **Shared storage is required** for correctness when using the built-in (sled-based) lock:
  - receipt directory
  - sled DB directories (fin/data/policy/recon)
  - HA lock directory (`[ha].lock_db_dir`)

> **WARNING — shared-storage requirement (sled lock)**
>
> The default HA leader lock is stored in the local sled DB under `[ha].lock_db_dir`.
> **All HA nodes MUST point at the same shared, correctly configured volume** for the lock to coordinate leadership.
>
> If nodes are configured with **separate disks** (or a **misconfigured NFS** where not all nodes observe the same writes),
> two nodes can simultaneously believe they are leader (**split-brain**). This can cause concurrent writer loops (recon/pruning)
> and state corruption / unexpected side effects.
>
> If you need HA across **independent machines/disks/regions**, configure an **external lock provider** (e.g. Redis/Consul).

## Deployment safety matrix

| Deployment pattern | Safe? | Notes |
|---|---:|---|
| Single node | ✅ | No leader contention. |
| Multi-node + shared volume | ✅ | Supported by default sled-based lock (shared `[ha].lock_db_dir`). |
| Multi-node + separate disks | ❌ | Unsafe until an **external lock provider** is enabled. |

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

[ha.lock]
provider = "sled"             # sled | redis | consul (sled is default)

[ha.lock.redis]
url = "redis://host:6379"
key = "ippan:l2:leader"
lease_ms = 15000
connect_timeout_ms = 2000

[ha.lock.consul]
address = "http://consul:8500"
key = "ippan/l2/leader"
session_ttl = "15s"

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
- **Split brain (storage not shared / NFS misconfigured)**: cannot be prevented by the built-in (sled) lock. Use shared storage correctly, or use an external lock provider.
- **Clock skew**: lease uses wall-clock milliseconds; moderate skew is tolerated, but extreme skew can delay leadership changes.

## Limitations / next steps

### Limitations (current)

1) **Shared storage required** when using the internal (sled) lock provider.  
2) **External lock provider required** for independent disks / regions.  
3) HA provides **leader-only scheduling**, not consensus (no ordering guarantees).  
4) Network partitions can **delay leadership handover** until TTL expiry / connectivity restored.  
5) Write routing depends on **operator configuration** (`leader_only` vs `allow_all`).  

### Next steps (roadmap, max 8)

1) Redis-based leader lock provider (this work)  
2) Consul lock provider for regulated environments  
3) Request forwarding to leader instead of rejection  
4) Per-workflow sharded leadership (future)  
5) Multi-region active/active read scaling  
6) External queue integration (Kafka / NATS)  
7) Encrypted-at-rest state stores  
8) Formal HA correctness proofs

