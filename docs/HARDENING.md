# Production Hardening (v1)

This document tracks the production hardening work for `fin-node` + hubs.

Goals:
- **Admission hardening** (limits, rate limits, pagination) that **fails fast** with **clear errors**.
- **Bounded growth** (retention/pruning) for receipts + recon state.
- **Graceful shutdown + backpressure**.
- **Observability baseline** (metrics + dashboard guidance).

Non-goals:
- Full WAF / DDoS mitigation at the edge.
- Distributed rate limiting / coordination.
- Enterprise authn/authz.

## Attack surface inventory

### HTTP endpoints (public)

All HTTP endpoints are implemented in `fin-node/src/http_server.rs` (single-process `tiny_http` server).

#### Health/metrics

- **GET `/healthz`**
  - **Input**: none
  - **Response**: JSON
- **GET `/readyz`**
  - **Input**: none
  - **Response**: JSON (includes L1 status summary)
- **GET `/metrics`** (only when enabled)
  - **Input**: none
  - **Response**: Prometheus text format

#### Reconciliation

- **GET `/recon/pending`**
  - **Input**: currently none
  - **Current behavior**: returns up to 500 pending items (unpaged)
  - **Plan**: add `limit` + `cursor` pagination and cap `limit` via config.

#### Hub submission endpoints (write)

These endpoints accept JSON bodies and are potentially expensive (validation + DB + L1 submit).

- **POST `/fin/actions`**
  - **Input**: JSON `hub_fin::FinActionRequestV1`
  - **Plan**:
    - enforce `limits.max_body_bytes`
    - validate field lengths / counts using configurable limits
    - rate limit per IP + per actor account (derived from the action)
- **POST `/data/datasets`**
  - **Input**: JSON `hub_data::RegisterDatasetRequestV1`
  - **Plan**: same as above; actor = `owner`
- **POST `/data/licenses`**
  - **Input**: JSON `hub_data::IssueLicenseRequestV1`
  - **Plan**: same as above; actor = `licensor` (and optionally `licensee` for stricter configs)
- **POST `/data/attestations`**
  - **Input**: JSON `hub_data::AppendAttestationRequestV1`
  - **Plan**: same as above; actor = `attestor`
- **POST `/data/listings`**
  - **Input**: JSON `hub_data::CreateListingRequestV1`
  - **Plan**: same as above; actor = `licensor`
- **POST `/data/allowlist/licensors`**
  - **Input**: JSON `hub_data::AddLicensorRequestV1`
  - **Plan**: same as above; actor = `actor`
- **POST `/data/allowlist/attestors`**
  - **Input**: JSON `hub_data::AddAttestorRequestV1`
  - **Plan**: same as above; actor = `actor`
- **POST `/linkage/buy-license`**
  - **Input**: JSON `BuyLicenseRequestV1`
  - **Plan**: same as above; actor = `buyer` (from linkage request)

#### Hub query endpoints (read)

These endpoints are attractive for abuse if they return unbounded lists.

- **GET `/data/datasets/:id`**
  - **Input**: `:id` hex string
  - **Plan**: validate hex format and length; keep response bounded.
- **GET `/data/licenses/:id`**
  - **Input**: `:id` hex string
- **GET `/data/listings?dataset_id=...`**
  - **Input**: query string (currently requires `dataset_id`)
  - **Plan**: add `limit` + `cursor` pagination, stable ordering by listing id (hex).
- **GET `/data/datasets/:id/licenses`**
  - **Input**: `:id` hex string
  - **Current risk**: unbounded list
  - **Plan**: add `limit` + `cursor` pagination, stable ordering by license id (hex).
- **GET `/data/datasets/:id/attestations`**
  - **Input**: `:id` hex string
  - **Current risk**: unbounded list
  - **Plan**: add `limit` + `cursor` pagination, stable ordering by attestation id (hex).
- **GET `/data/entitlements?dataset_id=...|licensee=...`**
  - **Input**: query string
  - **Current behavior**: offset/limit (no max cap)
  - **Plan**: switch to cursor-based paging where possible; cap max `limit`.

- **GET `/fin/assets/:id`**
  - **Input**: `:id` hex string
- **GET `/fin/balances?asset_id=...&account=...`**
  - **Input**: query string
  - **Plan**: validate `asset_id` hex and bound `account` length.

#### Receipts

- **GET `/fin/receipts/:action_id`** (alias: **GET `/receipts/fin/:action_id`**)
  - **Input**: `:action_id` hex string
  - **Plan**: validate hex format and cap receipt response size if feasible.
- **GET `/data/receipts/:action_id`** (alias: **GET `/receipts/data/:action_id`**)
  - **Input**: `:action_id` hex string

### CLI commands (public entrypoints)

All CLI entrypoints are implemented in `fin-node/src/main.rs` using `clap`.

- **`fin-node run`**: start HTTP server + recon loop.
- **`fin-node l1 status|check|inclusion|finality`**: read-only L1 helpers.
- **`fin-node submit-batch`**: reads a JSON envelope from file/stdin; optionally submits to L1; writes a receipt file.
- **`fin-node gen-example`**: writes example JSON envelope to disk.
- **`fin-node data export-state --out ...`**: exports a full deterministic snapshot (operator-only; potentially large).
- **`fin-node fin delegate|revoke-delegate`**: modifies local FIN store delegation state.
- **`fin-node policy allow|deny add|remove` / `policy status`**: modifies local policy store.

### Background loops / daemons

- **Reconciliation loop** (`fin-node/src/main.rs` spawns a thread):
  - **Current**: infinite loop with fixed sleep; no shutdown signal; work bounded by recon config (`batch_limit`, `max_scan`).
  - **Plan**: add cancellation token, graceful shutdown, and explicit `max_items_per_tick` / backpressure integration.

## Limits plan (what we will enforce)

All limits must be configurable (config file), with strict production defaults.

Planned config (defaults shown):

```toml
[limits]
max_body_bytes = 262144        # 256 KiB
max_string_bytes = 1024
max_tags = 32
max_tag_bytes = 48
max_batch_items = 256
max_receipt_bytes = 262144

[rate_limit]
enabled = true
requests_per_minute = 120
burst = 60

[pagination]
default_limit = 50
max_limit = 200

[retention]
receipts_days = 30
recon_failed_days = 7
min_receipts_keep = 1000

[pruning]
enabled = true
interval_secs = 86400

[server]
max_inflight_requests = 64
overload_queue_threshold = 0 # tiny_http is mostly synchronous; this is best-effort

[cors]
enabled = false
allow_origins = []
```

Notes:
- Limits affect **admission only** (validation/rejection) and must not change hashing semantics.
- For list endpoints we will provide **stable ordering** and **cursor** pagination (cursor = last seen id).

## Hardening checklist (to be completed)

### Config & defaults

- **Prod config**: `configs/prod.toml` has strict defaults:
  - limits enabled, rate limiting enabled, pagination capped, pruning enabled
- **Devnet config**: `configs/devnet.toml` has moderate defaults (bounded, but higher than prod)
- **Local config**: `configs/local.toml` is permissive (rate limiting + pruning disabled by default)

### Request limits & validation

- **Body size**: `limits.max_body_bytes` enforced for all JSON POST endpoints (**HTTP 413**).
- **JSON depth**: `limits.max_json_depth` enforced (best-effort, **HTTP 400**).
- **Field bounds**: configurable validation limits are passed into hubs via fin-node config.
- **Receipt size**: `limits.max_receipt_bytes` used by pruning to skip oversized files (operator should tune).

### Rate limiting

- **Per-IP**: enabled via `[rate_limit]` (best-effort, in-memory).
- **Per-actor**: enabled via `[rate_limit]` (actor derived from request).
- **HTTP 429** with `Retry-After`.
- **Known limitation**: not shared across multiple fin-node instances.

### Pagination

- **List endpoints**: support `limit` (default/max) and `cursor` (last seen id).
- **Stable ordering**: lexicographic by id (hex) for deterministic paging.
- **Responses**: include `items` and optional `next_cursor`.

### Retention & pruning

- **Background pruning**: enabled via `[pruning]` (interval seconds).
- **Manual pruning**: `fin-node prune --dry-run|--execute`.
- **Safety**: always keeps `retention.min_receipts_keep` newest receipts.

### Graceful shutdown & backpressure

- **SIGINT/SIGTERM** triggers graceful shutdown of HTTP + background threads.
- **Overload protection**: `server.max_inflight_requests` returns **HTTP 503** when exceeded.
- **Sled flush**: best-effort flush on shutdown.

### Errors & security

- **Unified error format**:
  - `{"error":{"code":"...","message":"...","request_id":"..."}}`
- **Request id**: response header `X-Request-Id` on all responses.
- **Security headers**: `X-Content-Type-Options: nosniff`.
- **CORS**: configurable; default deny.

### Observability

- **Metrics**: HTTP, rate limiting, payload rejects, pruning deletes, receipts, recon, and L1 RPC.
- **Dashboard**: see `docs/DASHBOARD.md` for recommended panels/alerts.

