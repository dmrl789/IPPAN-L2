#!/bin/bash
# DevNet Smoke Test Script
#
# Usage: ./scripts/devnet_smoke.sh [BASE_URL]
#
# Environment:
#   BASE_URL - L2 node URL (default: http://localhost:3000)
#   TX_COUNT - Number of transactions to submit (default: 10)
#   CHAIN_ID - L2 chain ID (default: 1)

set -e

BASE_URL="${1:-${BASE_URL:-http://localhost:3000}}"
TX_COUNT="${TX_COUNT:-10}"
CHAIN_ID="${CHAIN_ID:-1}"

echo "========================================"
echo "IPPAN-L2 DevNet Smoke Test"
echo "========================================"
echo "Base URL: $BASE_URL"
echo "TX Count: $TX_COUNT"
echo "Chain ID: $CHAIN_ID"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

passed=0
failed=0

check() {
    local name="$1"
    local result="$2"
    if [ "$result" = "true" ] || [ "$result" = "0" ]; then
        echo -e "${GREEN}✓${NC} $name"
        ((passed++))
    else
        echo -e "${RED}✗${NC} $name"
        ((failed++))
    fi
}

warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Test 1: Health check
echo ""
echo "--- Health Checks ---"
health=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/healthz" || echo "000")
check "Health endpoint" "$([ "$health" = "200" ] && echo true)"

ready=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/readyz" || echo "000")
check "Ready endpoint" "$([ "$ready" = "200" ] && echo true)"

# Test 2: Status endpoint
echo ""
echo "--- Status Check ---"
status=$(curl -s "$BASE_URL/status")
if [ -n "$status" ]; then
    check "Status endpoint" "true"
    
    # Parse status fields
    is_leader=$(echo "$status" | grep -o '"is_leader":[^,}]*' | cut -d: -f2)
    batcher_enabled=$(echo "$status" | grep -o '"enabled":[^,}]*' | head -1 | cut -d: -f2)
    queue_depth=$(echo "$status" | grep -o '"depth":[^,}]*' | cut -d: -f2)
    queue_capacity=$(echo "$status" | grep -o '"capacity":[^,}]*' | cut -d: -f2)
    
    echo "  Leader: $is_leader"
    echo "  Batcher enabled: $batcher_enabled"
    echo "  Queue: $queue_depth / $queue_capacity"
else
    check "Status endpoint" "false"
fi

# Test 3: Submit transactions
echo ""
echo "--- Transaction Submission ---"
tx_hashes=()
tx_success=0
tx_failed=0

for i in $(seq 1 "$TX_COUNT"); do
    payload=$(printf "smoke_test_%04d" "$i" | xxd -p | tr -d '\n')
    response=$(curl -s -X POST "$BASE_URL/tx" \
        -H "Content-Type: application/json" \
        -d "{
            \"chain_id\": $CHAIN_ID,
            \"from\": \"smoke_test_sender\",
            \"nonce\": $i,
            \"payload\": \"$payload\"
        }" 2>/dev/null || echo '{"accepted":false}')
    
    accepted=$(echo "$response" | grep -o '"accepted":[^,}]*' | cut -d: -f2)
    if [ "$accepted" = "true" ]; then
        ((tx_success++))
        tx_hash=$(echo "$response" | grep -o '"tx_hash":"[^"]*"' | cut -d'"' -f4)
        if [ -n "$tx_hash" ]; then
            tx_hashes+=("$tx_hash")
        fi
    else
        ((tx_failed++))
        error=$(echo "$response" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
        if [ "$error" = "queue full" ]; then
            warn "Queue full (429) - waiting for batch processing"
            sleep 2
        fi
    fi
done

echo "  Submitted: $tx_success / $TX_COUNT"
if [ "$tx_failed" -gt 0 ]; then
    warn "Failed: $tx_failed"
fi
check "Transaction submission (>50%)" "$([ "$tx_success" -gt $((TX_COUNT/2)) ] && echo true)"

# Test 4: Wait for batch processing
echo ""
echo "--- Batch Processing ---"
echo "Waiting for batch creation..."
sleep 3

status_after=$(curl -s "$BASE_URL/status")
last_batch_hash=$(echo "$status_after" | grep -o '"last_batch_hash":"[^"]*"' | cut -d'"' -f4)

if [ -n "$last_batch_hash" ] && [ "$last_batch_hash" != "null" ]; then
    check "Batch created" "true"
    echo "  Last batch: $last_batch_hash"
    
    # Query the batch
    batch_response=$(curl -s "$BASE_URL/batch/$last_batch_hash")
    if echo "$batch_response" | grep -q '"batch_hash"'; then
        check "Batch query" "true"
        tx_count=$(echo "$batch_response" | grep -o '"tx_count":[^,}]*' | cut -d: -f2)
        echo "  TX count in batch: $tx_count"
    else
        check "Batch query" "false"
    fi
else
    warn "No batch created yet (may need more time)"
    check "Batch created" "false"
fi

# Test 5: Posting status
echo ""
echo "--- Posting Status ---"
posting_pending=$(echo "$status_after" | grep -o '"pending":[^,}]*' | head -1 | cut -d: -f2)
posting_posted=$(echo "$status_after" | grep -o '"posted":[^,}]*' | head -1 | cut -d: -f2)
posting_confirmed=$(echo "$status_after" | grep -o '"confirmed":[^,}]*' | head -1 | cut -d: -f2)
posting_failed=$(echo "$status_after" | grep -o '"failed":[^,}]*' | head -1 | cut -d: -f2)

echo "  Pending: ${posting_pending:-0}"
echo "  Posted: ${posting_posted:-0}"
echo "  Confirmed: ${posting_confirmed:-0}"
echo "  Failed: ${posting_failed:-0}"

# Test 6: Transaction query
echo ""
echo "--- Transaction Query ---"
if [ ${#tx_hashes[@]} -gt 0 ]; then
    sample_hash="${tx_hashes[0]}"
    tx_response=$(curl -s "$BASE_URL/tx/$sample_hash")
    if echo "$tx_response" | grep -q '"tx_hash"'; then
        check "Transaction query" "true"
    else
        check "Transaction query" "false"
    fi
else
    warn "No transaction hashes to query"
fi

# Test 7: Metrics endpoint
echo ""
echo "--- Metrics ---"
metrics=$(curl -s "$BASE_URL/metrics")
if echo "$metrics" | grep -q "l2_uptime_ms"; then
    check "Metrics endpoint" "true"
    uptime=$(echo "$metrics" | grep "l2_uptime_ms" | awk '{print $2}')
    echo "  Uptime: ${uptime}ms"
else
    check "Metrics endpoint" "false"
fi

# Summary
echo ""
echo "========================================"
echo "SUMMARY"
echo "========================================"
echo -e "${GREEN}Passed: $passed${NC}"
echo -e "${RED}Failed: $failed${NC}"

total=$((passed + failed))
if [ "$failed" -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
elif [ "$passed" -gt "$((total/2))" ]; then
    echo -e "\n${YELLOW}Most tests passed (some failures)${NC}"
    exit 1
else
    echo -e "\n${RED}Too many failures${NC}"
    exit 2
fi
