# HUB-DATA MVP v1 — HTTP API

fin-node exposes HUB-DATA under `/data/*`.

All responses include `schema_version: 1`.

## Run (local mock L1)

```bash
export IPPAN_L2_CONFIG=./configs/local.toml
cargo run -p fin-node -- --l1-mode mock run
```

Server default: `http://127.0.0.1:3000`

## Create actions

### Register dataset

`POST /data/datasets`

```bash
curl -sS -X POST "http://127.0.0.1:3000/data/datasets" \
  -H "Content-Type: application/json" \
  -d '{
    "owner": "acc-alice",
    "name": "Example Dataset v1",
    "description": "Example dataset for HUB-DATA MVP v1",
    "content_hash": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "pointer_uri": "ipfs://bafybeigdyrztl5example",
    "mime_type": "application/json",
    "tags": ["Example", "dataset", "ai"],
    "schema_version": 1
  }'
```

Returns:

- `dataset_id` (hex)
- `action_id` (hex)
- local apply outcome + L1 submit result
- `receipt_path` (e.g. `receipts/data/<action_id>.json`)

### Issue license

`POST /data/licenses`

`rights` is one of: `view`, `use`, `commercial_use`, `derivative_use`.

```bash
curl -sS -X POST "http://127.0.0.1:3000/data/licenses" \
  -H "Content-Type: application/json" \
  -d '{
    "dataset_id": "<DATASET_ID_HEX>",
    "licensor": "acc-alice",
    "licensee": "acc-bob",
    "rights": "use",
    "terms_uri": "https://example.com/terms/v1",
    "terms_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "expires_at": 2000000000,
    "price_microunits": "1000000",
    "nonce": "lic-001"
  }'
```

Returns `license_id` + `action_id` + receipt metadata.

### Append attestation

`POST /data/attestations`

```bash
curl -sS -X POST "http://127.0.0.1:3000/data/attestations" \
  -H "Content-Type: application/json" \
  -d '{
    "dataset_id": "<DATASET_ID_HEX>",
    "attestor": "acc-carol",
    "statement": "quality:good",
    "ref_uri": "https://example.com/eval/001",
    "nonce": "att-001"
  }'
```

Returns `attestation_id` + `action_id` + receipt metadata.

### Create listing (priced sale offer)

`POST /data/listings`

Creates a deterministic listing for a dataset, priced in HUB-FIN microunits.

```bash
DATASET_ID="<DATASET_ID_HEX>"
ASSET_ID="<HUB_FIN_ASSET_ID_HEX>"

curl -sS -X POST "http://127.0.0.1:3000/data/listings" \
  -H "Content-Type: application/json" \
  -d "{
    \"dataset_id\": \"${DATASET_ID}\",
    \"licensor\": \"acc-alice\",
    \"rights\": \"use\",
    \"price_microunits\": \"1000000\",
    \"currency_asset_id\": \"${ASSET_ID}\",
    \"terms_uri\": \"https://example.com/terms/v1\",
    \"terms_hash\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"
  }"
```

Returns:
- `listing_id` (hex, derived deterministically)
- `action_id` (hex)
- local apply outcome + L1 submit result + `receipt_path`

## Queries

### Get dataset

`GET /data/datasets/:dataset_id`

```bash
curl -sS "http://127.0.0.1:3000/data/datasets/<DATASET_ID_HEX>"
```

### List dataset licenses

`GET /data/datasets/:dataset_id/licenses`

```bash
curl -sS "http://127.0.0.1:3000/data/datasets/<DATASET_ID_HEX>/licenses"
```

### List dataset attestations

`GET /data/datasets/:dataset_id/attestations`

```bash
curl -sS "http://127.0.0.1:3000/data/datasets/<DATASET_ID_HEX>/attestations"
```

### Get license

`GET /data/licenses/:license_id`

```bash
curl -sS "http://127.0.0.1:3000/data/licenses/<LICENSE_ID_HEX>"
```

### Get action receipt

`GET /data/receipts/:action_id`

```bash
curl -sS "http://127.0.0.1:3000/data/receipts/<ACTION_ID_HEX>"
```

### List listings for dataset

`GET /data/listings?dataset_id=...`

```bash
curl -sS "http://127.0.0.1:3000/data/listings?dataset_id=<DATASET_ID_HEX>"
```

### List entitlements (who is entitled?)

`GET /data/entitlements?dataset_id=...`

```bash
curl -sS "http://127.0.0.1:3000/data/entitlements?dataset_id=<DATASET_ID_HEX>&offset=0&limit=100"
```

`GET /data/entitlements?licensee=...`

```bash
curl -sS "http://127.0.0.1:3000/data/entitlements?licensee=acc-bob&offset=0&limit=100"
```

The entitlement rows include:
- `purchase_id`, `dataset_id`, `listing_id`, `licensee`
- `price_microunits`, `currency_asset_id`
- `references` (`fin_action_id`, `fin_receipt_hash`, `data_action_id`, `license_id`)

