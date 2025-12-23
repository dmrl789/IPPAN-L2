# fin-node HTTP API Inventory (current)

This is a **code-derived inventory** of the current `fin-node` HTTP surface, taken from the request dispatcher in `fin-node/src/http_server.rs`.

Notes:
- **Handler location**: HTTP routing is implemented as a single `match (method, path)` with some prefix-based path parsing for path parameters.
- **Schemas**: request/response JSON types are defined in `hub-fin`, `hub-data`, `l2-core`, and `fin-node` (see “Primary types”).

## Routes

| Method | Path | Handler (high level) | Primary types | Handler file |
|---|---|---|---|---|
| GET | `/healthz` | liveness | `HealthResponse` | `fin-node/src/http_server.rs` |
| GET | `/readyz` | readiness (L1 `chain_status`) | `ReadyResponse` | `fin-node/src/http_server.rs` |
| GET | `/metrics` | prometheus scrape (optional) | `text/plain` | `fin-node/src/http_server.rs` |
| GET | `/recon/pending` | list recon pending (cursor pagination) | `ReconItem`, `ReconMetadata` | `fin-node/src/http_server.rs` |
| POST | `/fin/actions` | submit FIN action | `hub_fin::FinActionRequestV1` → `fin_node::fin_api::SubmitActionResponseV1` | `fin-node/src/http_server.rs` |
| GET | `/fin/assets/{asset_id}` | get FIN asset definition | `hub_fin::CreateAssetV1` | `fin-node/src/http_server.rs` |
| GET | `/fin/balances` | get FIN balance by `(asset_id, account)` | inline JSON `{amount_scaled_u128}` | `fin-node/src/http_server.rs` |
| GET | `/fin/receipts/{action_id}` | fetch FIN action receipt JSON | `fin_node::fin_api::FinActionReceiptV1` | `fin-node/src/http_server.rs` |
| GET | `/receipts/fin/{action_id}` | legacy alias of FIN receipt endpoint | `fin_node::fin_api::FinActionReceiptV1` | `fin-node/src/http_server.rs` |
| POST | `/data/datasets` | register dataset | `hub_data::RegisterDatasetRequestV1` → `fin_node::data_api::SubmitDataActionResponseV1` | `fin-node/src/http_server.rs` |
| POST | `/data/licenses` | issue license | `hub_data::IssueLicenseRequestV1` → `fin_node::data_api::SubmitDataActionResponseV1` | `fin-node/src/http_server.rs` |
| POST | `/data/attestations` | append attestation | `hub_data::AppendAttestationRequestV1` → `fin_node::data_api::SubmitDataActionResponseV1` | `fin-node/src/http_server.rs` |
| POST | `/data/listings` | create listing | `hub_data::CreateListingRequestV1` → `fin_node::data_api::SubmitDataActionResponseV1` | `fin-node/src/http_server.rs` |
| POST | `/data/allowlist/licensors` | allowlist licensor for dataset | `hub_data::AddLicensorRequestV1` → `fin_node::data_api::SubmitDataActionResponseV1` | `fin-node/src/http_server.rs` |
| POST | `/data/allowlist/attestors` | allowlist attestor for dataset | `hub_data::AddAttestorRequestV1` → `fin_node::data_api::SubmitDataActionResponseV1` | `fin-node/src/http_server.rs` |
| GET | `/data/datasets/{dataset_id}` | get dataset definition | `hub_data::RegisterDatasetV1` | `fin-node/src/http_server.rs` |
| GET | `/data/datasets/{dataset_id}/licenses` | list licenses by dataset (cursor pagination) | `hub_data::IssueLicenseV1` | `fin-node/src/http_server.rs` |
| GET | `/data/datasets/{dataset_id}/attestations` | list attestations by dataset (cursor pagination) | `hub_data::AppendAttestationV1` | `fin-node/src/http_server.rs` |
| GET | `/data/listings` | list listings by dataset (cursor pagination) | `hub_data::CreateListingV1` | `fin-node/src/http_server.rs` |
| GET | `/data/entitlements` | list entitlements by dataset or licensee (cursor pagination; legacy `offset` supported) | `hub_data::GrantEntitlementV1` (enriched view) | `fin-node/src/http_server.rs` |
| GET | `/data/licenses/{license_id}` | get license definition | `hub_data::IssueLicenseV1` | `fin-node/src/http_server.rs` |
| GET | `/data/receipts/{action_id}` | fetch DATA action receipt JSON | `fin_node::data_api::DataActionReceiptV1` | `fin-node/src/http_server.rs` |
| GET | `/receipts/data/{action_id}` | legacy alias of DATA receipt endpoint | `fin_node::data_api::DataActionReceiptV1` | `fin-node/src/http_server.rs` |
| POST | `/linkage/buy-license` | execute payment (FIN) then entitlement (DATA) | `fin_node::linkage::BuyLicenseRequestV1` → `l2_core::hub_linkage::LinkageReceiptV1` | `fin-node/src/http_server.rs` |
| GET | `/linkage/purchase/{purchase_id}` | fetch linkage purchase receipt | `l2_core::hub_linkage::LinkageReceiptV1` | `fin-node/src/http_server.rs` |

## Query parameters (current behavior)

### `GET /recon/pending`
- **limit**: integer (default `pagination.default_limit`, max `pagination.max_limit`)
- **cursor**: string cursor of the form `"{kind}:{id}"` (exclusive)

### `GET /data/datasets/{dataset_id}/licenses`
- **limit**: integer (default/max as above)
- **cursor**: string cursor (license id hex, exclusive)

### `GET /data/datasets/{dataset_id}/attestations`
- **limit**: integer (default/max as above)
- **cursor**: string cursor (attestation id hex, exclusive)

### `GET /data/listings`
- **dataset_id**: required hex32 dataset id
- **limit**: integer (default/max as above)
- **cursor**: string cursor (listing id hex, exclusive)

### `GET /data/entitlements`
Exactly one of:
- **dataset_id**: hex32 dataset id
- **licensee**: account id string

Pagination:
- **cursor**: string cursor (purchase id hex, exclusive) — enables cursor paging
- **limit**: integer (default/max as above)

Legacy (non-cursor) paging:
- **offset**: integer (default 0) — only used when `cursor` is not provided

### `GET /fin/balances`
- **asset_id**: required hex32 asset id
- **account**: required account id string

