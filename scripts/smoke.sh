#!/usr/bin/env bash
# IPPAN-L2 Smoke Test Script
# Runs basic smoke tests to verify the system is working.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)); }

# Check if a command exists
check_cmd() {
    if command -v "$1" &> /dev/null; then
        log_pass "Command '$1' found"
        return 0
    else
        log_fail "Command '$1' not found"
        return 1
    fi
}

# Check if a file exists
check_file() {
    if [[ -f "$1" ]]; then
        log_pass "File exists: $1"
        return 0
    else
        log_fail "File missing: $1"
        return 1
    fi
}

# Run a command and check exit code
run_check() {
    local name="$1"
    shift
    
    if "$@" > /dev/null 2>&1; then
        log_pass "$name"
        return 0
    else
        log_fail "$name"
        return 1
    fi
}

# Check HTTP endpoint
check_http() {
    local name="$1"
    local url="$2"
    local expected="${3:-200}"
    
    if command -v curl &> /dev/null; then
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        
        if [[ "$status" == "$expected" ]]; then
            log_pass "$name (HTTP $status)"
            return 0
        else
            log_fail "$name (HTTP $status, expected $expected)"
            return 1
        fi
    else
        log_warn "curl not found, skipping HTTP check: $name"
        return 0
    fi
}

log_info "Starting IPPAN-L2 smoke tests..."
echo ""

# ============================================
# 1. Prerequisites
# ============================================
log_info "Checking prerequisites..."

check_cmd cargo
check_cmd rustc
check_file "$PROJECT_ROOT/Cargo.toml"
check_file "$PROJECT_ROOT/rust-toolchain.toml"

echo ""

# ============================================
# 2. Build Check
# ============================================
log_info "Checking build..."

cd "$PROJECT_ROOT"
run_check "Cargo check (workspace)" cargo check --workspace

echo ""

# ============================================
# 3. Test Check
# ============================================
log_info "Running tests..."

run_check "Unit tests" cargo test --workspace --all-features

echo ""

# ============================================
# 4. Clippy Check
# ============================================
log_info "Running lints..."

run_check "Clippy" cargo clippy --workspace --all-targets --all-features -- -D warnings

echo ""

# ============================================
# 5. Format Check
# ============================================
log_info "Checking formatting..."

run_check "Rustfmt" cargo fmt --all -- --check

echo ""

# ============================================
# 6. Binary Check
# ============================================
log_info "Checking binaries build..."

run_check "Build fin-node" cargo build -p fin-node
run_check "Build oracle daemon" cargo build -p ippan_eth_oracle_daemon

echo ""

# ============================================
# 7. Config Files
# ============================================
log_info "Checking config files..."

check_file "$PROJECT_ROOT/configs/local.toml"
check_file "$PROJECT_ROOT/configs/dev.toml"
check_file "$PROJECT_ROOT/configs/prod.toml"
check_file "$PROJECT_ROOT/integrations/eth-oracle/configs/devnet_sepolia.toml"

echo ""

# ============================================
# 8. Documentation
# ============================================
log_info "Checking documentation..."

check_file "$PROJECT_ROOT/README.md"
check_file "$PROJECT_ROOT/docs/DEV.md"
check_file "$PROJECT_ROOT/docs/CONFIG.md"
check_file "$PROJECT_ROOT/docs/OPS.md"
check_file "$PROJECT_ROOT/SECURITY.md"

echo ""

# ============================================
# 9. CI Files
# ============================================
log_info "Checking CI configuration..."

check_file "$PROJECT_ROOT/.github/workflows/ci.yml"
check_file "$PROJECT_ROOT/.github/dependabot.yml"
check_file "$PROJECT_ROOT/deny.toml"

echo ""

# ============================================
# Summary
# ============================================
echo "============================================"
echo "Smoke Test Summary"
echo "============================================"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo ""

if [[ $FAILED -gt 0 ]]; then
    log_error "Some smoke tests failed!"
    exit 1
else
    log_info "All smoke tests passed!"
    exit 0
fi
