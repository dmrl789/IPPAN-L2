# API Versioning (fin-node)

`fin-node` uses **path-based versioning**:

- **Current**: `/api/v1/...`
- **Headers**:
  - `X-Api-Version: v1` (always present on responses)
  - `X-Request-Id: <id>` (always present on responses)

## Backward compatibility

To avoid breaking existing clients, `fin-node` currently keeps **legacy unversioned paths** working (e.g. `/fin/actions`).

Rules:
- New integrations should always use **`/api/v1/...`**.
- Legacy paths may be removed only through the deprecation policy (see `docs/DEPRECATION.md`).

## Adding new endpoints

- Add endpoints under `/api/v1`.
- Update:
  - `docs/openapi/fin-node.openapi.json`
  - `docs/openapi/INVENTORY.md`
  - `scripts/check_openapi_drift.sh` (CI drift check)

## Evolving schemas

All request/response payloads should:
- Include a `schema_version` field where a wrapper exists today.
- Introduce new fields as optional first (non-breaking).
- Only remove/rename fields in a new API version (`/api/v2/...`) or a minor versioned schema bump explicitly documented as breaking.

