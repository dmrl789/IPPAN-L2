# M2M Fee Model

This document describes the Machine-to-Machine (M2M) fee model for IPPAN L2, designed for deterministic, predictable transaction costs that IoT devices and automated systems can rely on.

## Overview

The M2M fee model provides:

1. **Deterministic pricing** - No auctions, no dynamic markets. Fees are calculated from a fixed schedule.
2. **Pre-budgeting** - Machines can estimate exact costs before submission.
3. **Reservation system** - Fees are reserved at submission, finalized at batch inclusion.
4. **Rate limiting** - Quotas prevent spam without requiring fee bidding.
5. **Forced inclusion** - Safety-critical devices can bypass quotas with strict daily limits.

## Fee Schedule

All fees are expressed as scaled integers with 6 decimal places (i.e., 1.0 IPN = 1,000,000 scaled units).

### Default Schedule

| Parameter | Scaled Value | Description |
|-----------|--------------|-------------|
| `rate_exec_unit_scaled` | 1 | Cost per execution unit |
| `rate_per_byte_scaled` | 10 | Cost per byte of tx payload |
| `rate_per_write_scaled` | 1000 | Cost per storage write |
| `base_fee_scaled` | 10,000 | Fixed per-transaction overhead |
| `min_fee_scaled` | 1,000 | Minimum fee (floor) |
| `max_fee_scaled` | 100,000,000 | Maximum fee (cap) |

### Fee Calculation

```
fee = base_fee + (exec_units × rate_exec_unit) + (data_bytes × rate_per_byte) + (writes × rate_per_write)
fee = clamp(fee, min_fee, max_fee)
```

All arithmetic uses checked operations to prevent overflow.

## API Endpoints

### Fee Estimation

Estimate the fee for a transaction before submission.

```bash
POST /m2m/fee/estimate
Content-Type: application/json

{
  "exec_units": 1000,
  "data_bytes": 500,
  "writes": 2
}
```

Response:
```json
{
  "breakdown": {
    "exec_units": 1000,
    "data_bytes": 500,
    "storage_writes": 2,
    "total_fee": 17000
  },
  "schedule": {
    "min_fee": 1000,
    "max_fee": 100000000,
    "base_fee": 10000,
    "rate_per_exec_unit": 1,
    "rate_per_byte": 10,
    "rate_per_write": 1000
  }
}
```

### Check Balance

Query the current balance for a machine.

```bash
GET /m2m/balance/{machine_id}
```

Response:
```json
{
  "machine_id": "device-001",
  "balance_scaled": 1000000,
  "reserved_scaled": 50000,
  "forced_class": "standard"
}
```

### Top-up (Devnet Only)

Add funds to a machine's balance. Only available when `DEVNET=1`.

```bash
POST /m2m/topup
Content-Type: application/json

{
  "machine_id": "device-001",
  "amount_scaled": 1000000
}
```

Response:
```json
{
  "success": true,
  "new_balance_scaled": 2000000,
  "error": null
}
```

### Get Fee Schedule

Query the current fee schedule.

```bash
GET /m2m/schedule
```

Response:
```json
{
  "min_fee": 1000,
  "max_fee": 100000000,
  "base_fee": 10000,
  "rate_per_exec_unit": 1,
  "rate_per_byte": 10,
  "rate_per_write": 1000
}
```

## Fee Flow

### 1. Transaction Submission

When a machine submits a transaction:

1. **Fee Estimation**: The node computes the fee based on payload size
2. **Quota Check**: For standard machines, rate limits are checked
3. **Fee Reservation**: The fee is reserved from the machine's balance
4. **Enqueue**: The transaction is added to the batcher queue

If reservation fails due to insufficient balance:
```
HTTP 402 Payment Required
{"error": "insufficient balance: required 50000, available 30000"}
```

If quota is exceeded:
```
HTTP 429 Too Many Requests
{"error": "quota exceeded: ..."}
```

### 2. Batch Creation

When the batcher creates a batch:

1. **Fee Finalization**: For each tx, the actual fee is computed (MVP: same as estimated)
2. **Refund Unused**: Any excess reservation is released back to balance
3. **Batch Totals**: Aggregated fees are recorded for the batch

### 3. Settlement

Batch fee totals are persisted for auditing and can be included in settlement metadata.

## Quotas

### Standard Rate Limiting

Standard machines are subject to quota windows:

- **Window Duration**: 60 seconds (configurable)
- **Max Units per Window**: Based on fee amount

Quotas prevent spam without requiring fee auctions. Once the quota resets (after the window expires), the machine can submit again.

### Quota Bypass

Machines with `ForcedInclusion` class bypass standard quotas but are subject to:

- **Daily Limit**: Maximum forced txs per day (default: 100)
- **Still Pay Fees**: Forced inclusion does not waive fees

## Forced Inclusion

Safety-critical devices (e.g., emergency shutoff signals) can be granted `ForcedInclusion` class:

```rust
pub enum ForcedClass {
    Standard,        // Normal rate limiting
    ForcedInclusion, // Bypass quotas, strict daily cap
}
```

### Setting Forced Class

Currently done through direct storage operations (admin API planned):

```rust
m2m_storage.set_forced_class("device-emergency-001", ForcedClass::ForcedInclusion, now_ms)?;
```

### Forced Inclusion Limits

```rust
ForcedInclusionLimits {
    max_per_day: 100,  // Maximum forced txs per day
    day_start_ms: ..., // Resets at midnight UTC
    used_today: ...,   // Counter for current day
}
```

## Machine ID Format

Machine IDs must be:
- 1-64 characters
- Alphanumeric, dash (`-`), or underscore (`_`) only
- No leading/trailing whitespace

Valid examples:
- `device-001`
- `sensor_temperature_42`
- `IoT-Gateway-A`

Invalid examples:
- `` (empty)
- `device with spaces`
- `device@invalid`

## Metrics

The following Prometheus metrics are exposed:

| Metric | Type | Description |
|--------|------|-------------|
| `l2_m2m_fee_reserved_total` | Counter | Total fees reserved |
| `l2_m2m_fee_finalised_total` | Counter | Total fees finalized |
| `l2_m2m_quota_reject_total` | Counter | Quota rejections |
| `l2_m2m_insufficient_balance_reject_total` | Counter | Insufficient balance rejections |
| `l2_m2m_forced_included_total` | Counter | Forced inclusion txs |

## Status Endpoint

The `/status` endpoint includes M2M fee info:

```json
{
  "m2m_fees": {
    "enabled": true,
    "schedule": {
      "min_fee": 1000,
      "max_fee": 100000000,
      "base_fee": 10000,
      "rate_per_exec_unit": 1,
      "rate_per_byte": 10,
      "rate_per_write": 1000
    },
    "total_machines": 42,
    "forced_machines": 3,
    "total_reserved_scaled": 5000000,
    "total_finalised_scaled": 4500000,
    "pending_reservations": 5
  }
}
```

## Example: IoT Device Integration

```python
import requests
import json

NODE_URL = "http://localhost:3000"
MACHINE_ID = "sensor-temp-001"

# 1. Check balance
resp = requests.get(f"{NODE_URL}/m2m/balance/{MACHINE_ID}")
balance = resp.json()
print(f"Balance: {balance['balance_scaled']} scaled units")

# 2. Estimate fee for a 100-byte payload
resp = requests.post(f"{NODE_URL}/m2m/fee/estimate", json={
    "exec_units": 100,
    "data_bytes": 100,
    "writes": 1
})
estimate = resp.json()
required_fee = estimate["breakdown"]["total_fee"]
print(f"Estimated fee: {required_fee}")

# 3. Check if we have enough balance
available = balance["balance_scaled"] - balance["reserved_scaled"]
if available < required_fee:
    print("Insufficient balance!")
    exit(1)

# 4. Submit transaction
payload = {"temperature": 25.5, "humidity": 60}.encode("utf-8").hex()
resp = requests.post(f"{NODE_URL}/tx", json={
    "chain_id": 1,
    "from": MACHINE_ID,
    "nonce": 1,
    "payload": payload
})

if resp.status_code == 200:
    tx_hash = resp.json()["tx_hash"]
    print(f"Transaction submitted: {tx_hash}")
elif resp.status_code == 402:
    print("Payment required: insufficient balance")
elif resp.status_code == 429:
    print("Rate limited: quota exceeded")
```

## Design Principles

1. **No Floats**: All calculations use scaled integers (6 decimals)
2. **No Randomness**: Deterministic fee calculation across all nodes
3. **No Speculation**: Fees are policy-based, not market-based
4. **Overflow Safety**: All arithmetic uses checked operations
5. **Crash Safe**: All state changes are atomic via sled transactions

> **Note**: The [GBDT Organiser](./ORGANISER.md) influences batch *scheduling and fairness*
> (batch timing, queue draining, forced traffic treatment), but **never** changes fee rates
> or accepts unpaid transactions. Fee pricing remains determined by the schedule above.

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DEVNET` | `0` | Enable devnet features (topup endpoint) |
| `L2_FORCE_INCLUDE_MAX_EPOCHS` | `3` | Max epochs for forced inclusion |
| `L2_FORCE_MAX_PER_ACCOUNT` | `5` | Max forced txs per account per epoch |

## Future Enhancements

Planned improvements (not yet implemented):

- **Execution Metering**: Actual fee based on execution cost (currently uses estimates)
- **Batch Fee Distribution**: Distribution of collected fees to validators
- **Fee Delegation**: Allow one machine to pay fees for another
- **Admin API**: REST endpoints for managing forced class and limits
