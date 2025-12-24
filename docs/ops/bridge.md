# Bridge Operations Runbook

This document describes how to operate the L1-L2 bridge in IPPAN-L2.

## Overview

The bridge enables asset transfers between L1 (IPPAN Core) and L2:
- **Deposits**: Move assets from L1 to L2
- **Withdrawals**: Move assets from L2 to L1

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BRIDGE_ENABLED` | `true` | Enable bridge watcher |
| `L2_BRIDGE_POLL_MS` | `2000` | L1 polling interval |
| `L2_BRIDGE_ADDRESS` | (required) | L1 bridge address/handle |
| `L2_BRIDGE_MAX_DEPOSITS` | `100` | Max deposits per poll cycle |
| `L2_CHAIN_ID` | `1` | L2 chain identifier |

### Example Configuration

```bash
export BRIDGE_ENABLED=1
export L2_BRIDGE_POLL_MS=2000
export L2_BRIDGE_ADDRESS="l2_bridge_v1"
export L2_CHAIN_ID=1
```

## Deposits (L1 → L2)

### How Deposits Work

1. User sends L1 payment to the bridge address with memo:
   ```
   l2_to=<recipient_address>
   ```
2. Bridge watcher detects the L1 transaction
3. L2 credits the recipient's balance
4. Deposit status transitions: `pending` → `verified`

### Manual Deposit Claim

If the bridge watcher doesn't detect a deposit automatically, users can claim manually:

```bash
curl -X POST http://localhost:3000/bridge/deposit/claim \
  -H "Content-Type: application/json" \
  -d '{
    "l1_tx_hash": "abc123..."
  }'
```

Response:

```json
{
  "accepted": true,
  "deposit": {
    "l1_tx_hash": "abc123...",
    "from_l1": "alice_l1",
    "to_l2": "alice_l2",
    "asset": "IPN",
    "amount": 1000000,
    "status": "pending"
  }
}
```

### Check Deposit Status

```bash
curl http://localhost:3000/bridge/deposit/abc123:0
```

Response:

```json
{
  "l1_tx_hash": "abc123...",
  "from_l1": "alice_l1",
  "to_l2": "alice_l2",
  "asset": "IPN",
  "amount": 1000000,
  "status": "verified",
  "seen_at_ms": 1735000000000
}
```

### Deposit Status Values

| Status | Description |
|--------|-------------|
| `pending` | Deposit seen, awaiting verification |
| `verified` | Deposit verified and credited to L2 |
| `rejected` | Deposit invalid or already claimed |

## Withdrawals (L2 → L1)

### Request a Withdrawal

```bash
curl -X POST http://localhost:3000/bridge/withdraw \
  -H "Content-Type: application/json" \
  -d '{
    "from": "alice_l2",
    "to_l1": "alice_l1",
    "asset": "IPN",
    "amount": 500000,
    "nonce": 1
  }'
```

Response:

```json
{
  "accepted": true,
  "withdraw_id": "wd_abc123...",
  "status": "pending"
}
```

### Check Withdrawal Status

```bash
curl http://localhost:3000/bridge/withdraw/wd_abc123
```

Response:

```json
{
  "id": "wd_abc123...",
  "from_l2": "alice_l2",
  "to_l1": "alice_l1",
  "asset": "IPN",
  "amount": 500000,
  "status": "posted",
  "l1_tx": "l1_tx_xyz..."
}
```

### Withdrawal Status Values

| Status | Description |
|--------|-------------|
| `pending` | Request submitted, awaiting posting |
| `posted` | Posted to L1, awaiting confirmation |
| `confirmed` | Confirmed on L1 |
| `failed` | Withdrawal failed |

### Withdrawal Flow

1. User submits withdrawal request to L2
2. Leader node collects pending withdrawals
3. Leader posts to L1:
   ```
   To: <to_l1>
   Amount: <amount>
   Memo: withdraw_id=<id>;from_l2=<from>;amount=<amount>
   ```
4. Status transitions: `pending` → `posted` → `confirmed`

## Status Endpoint

```bash
curl http://localhost:3000/status | jq '.bridge'
```

Response:

```json
{
  "enabled": true,
  "watcher_running": true,
  "deposits_total": 42,
  "withdrawals_total": 15,
  "withdrawals_pending": 2
}
```

## Metrics

| Metric | Description |
|--------|-------------|
| `l2_bridge_deposits_total` | Total deposits processed |
| `l2_bridge_withdrawals_total` | Total withdrawal requests |
| `l2_bridge_withdrawals_posted_total` | Withdrawals posted to L1 |
| `l2_bridge_withdrawals_confirmed_total` | Withdrawals confirmed on L1 |

```bash
curl http://localhost:3000/metrics | grep l2_bridge
```

## Example Workflows

### Deposit from L1 to L2

```bash
# 1. On L1: Send payment to bridge address
# (Using IPPAN CLI or wallet)
ippan tx send --to l2_bridge_v1 --amount 1000 --memo "l2_to=alice_l2"

# 2. Wait for bridge watcher (or claim manually)
sleep 10

# 3. Check deposit status
DEPOSIT_ID="<l1_tx_hash>:0"
curl http://localhost:3000/bridge/deposit/$DEPOSIT_ID | jq
```

### Withdraw from L2 to L1

```bash
# 1. Submit withdrawal request
RESULT=$(curl -s -X POST http://localhost:3000/bridge/withdraw \
  -H "Content-Type: application/json" \
  -d '{
    "from": "alice_l2",
    "to_l1": "alice_l1",
    "asset": "IPN",
    "amount": 500000,
    "nonce": 1
  }')
WITHDRAW_ID=$(echo $RESULT | jq -r '.withdraw_id')

# 2. Monitor withdrawal status
watch -n 5 "curl -s http://localhost:3000/bridge/withdraw/$WITHDRAW_ID | jq '.status'"

# 3. Wait for confirmation
# Status should progress: pending -> posted -> confirmed
```

## Troubleshooting

### Deposit Not Detected

1. Verify L1 transaction:
   ```bash
   curl $IPPAN_RPC_URL/tx/<l1_tx_hash>
   ```

2. Check memo format includes `l2_to=`:
   ```
   l2_to=<recipient>
   ```

3. Try manual claim:
   ```bash
   curl -X POST http://localhost:3000/bridge/deposit/claim \
     -d '{"l1_tx_hash":"<hash>"}'
   ```

### Withdrawal Stuck in Pending

1. Check if this node is leader:
   ```bash
   curl http://localhost:3000/status | jq '.leader.is_leader'
   ```
   Only the leader posts withdrawals.

2. Check IPPAN RPC connectivity:
   ```bash
   curl $IPPAN_RPC_URL/status
   ```

3. Check logs for posting errors

### Duplicate Deposit/Withdrawal

```json
{"accepted": false, "error": "deposit already exists"}
```

The deposit/withdrawal ID is unique. Check if it was already processed.

### Withdrawal Failed

1. Check the withdrawal status for error details:
   ```bash
   curl http://localhost:3000/bridge/withdraw/<id> | jq
   ```

2. Common causes:
   - Insufficient balance on bridge account
   - L1 network issues
   - Invalid recipient address

## Memo Format

### Deposit Memo (L1 → L2)

```
l2_to=<recipient_address>
```

Alternative format:
```
to=<recipient_address>
```

### Withdrawal Memo (L2 → L1)

```
withdraw_id=<id>;from_l2=<sender>;amount=<amount>
```

## Security Considerations

1. **Nonce Management**: Each withdrawal requires a unique nonce per account
2. **Idempotency**: Duplicate submissions are rejected (same from + nonce)
3. **Rate Limiting**: Consider implementing withdrawal limits
4. **Verification**: All deposits should be verified against L1 before crediting
5. **Audit Logging**: All bridge operations are logged for audit purposes

## Best Practices

1. **Monitor Bridge Balance**: Ensure the L1 bridge account has sufficient funds
2. **Watch for Stuck Transactions**: Alert on pending withdrawals > N minutes
3. **Backup Recovery**: Keep records of pending withdrawals for manual recovery
4. **Test on DevNet**: Always test bridge operations on DevNet first

## Limitations (MVP)

1. **No Automatic L1 Watcher**: IPPAN may not have a "list txs" endpoint; manual claims may be needed
2. **Single Asset**: MVP supports one asset type per bridge deployment
3. **No Withdrawal Limits**: Rate limiting not implemented in MVP
4. **Leader-Only Posting**: Only the leader can post withdrawals to L1
5. **Best-Effort Verification**: L1 verification depends on available IPPAN RPC endpoints
