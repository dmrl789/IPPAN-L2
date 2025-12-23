#!/usr/bin/env bash
# IPPAN-L2 Local Development Runner
# This script starts the local development stack.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    cat <<EOF
Usage: $0 [COMMAND]

Commands:
    build       Build all components
    fin-node    Run FIN node demo
    oracle      Run oracle daemon (requires env vars)
    dump        Dump oracle scores (one-shot)
    all         Run all components (requires docker-compose)
    help        Show this help

Environment variables:
    IPPAN_RPC_URL      IPPAN CORE RPC URL (default: http://127.0.0.1:8080)
    ETH_RPC_URL        Ethereum RPC URL (for oracle)
    ETH_PRIVATE_KEY    Ethereum private key (for oracle)
    CONFIG             Config file path (default: configs/local.toml)

Examples:
    $0 build
    $0 fin-node
    IPPAN_RPC_URL=http://localhost:8080 $0 oracle
EOF
}

check_rust() {
    if ! command -v cargo &> /dev/null; then
        log_error "Cargo not found. Please install Rust: https://rustup.rs/"
        exit 1
    fi
}

build_all() {
    log_info "Building all components..."
    cd "$PROJECT_ROOT"
    cargo build --workspace --release
    log_info "Build complete!"
}

run_fin_node() {
    log_info "Running FIN node demo..."
    cd "$PROJECT_ROOT"
    
    local config="${CONFIG:-configs/local.toml}"
    local batch_id="demo-batch-$(date +%s)"
    
    if [[ -f "$config" ]]; then
        cargo run -p fin-node -- --config "$config" --batch-id "$batch_id"
    else
        log_warn "Config file not found: $config, running with defaults"
        cargo run -p fin-node -- --batch-id "$batch_id"
    fi
}

run_oracle() {
    log_info "Running oracle daemon..."
    cd "$PROJECT_ROOT"
    
    # Check required environment variables
    if [[ -z "${ETH_RPC_URL:-}" ]]; then
        log_error "ETH_RPC_URL environment variable is required"
        exit 1
    fi
    
    local ippan_url="${IPPAN_RPC_URL:-http://127.0.0.1:8080}"
    local config="integrations/eth-oracle/configs/devnet_sepolia.toml"
    
    export IPPAN_RPC_URL="$ippan_url"
    
    log_info "IPPAN RPC URL: $ippan_url"
    log_info "ETH RPC URL: ${ETH_RPC_URL}"
    log_info "Config: $config"
    
    cargo run -p ippan_eth_oracle_daemon -- watch --config "$config"
}

dump_oracle() {
    log_info "Dumping oracle scores..."
    cd "$PROJECT_ROOT"
    
    local ippan_url="${IPPAN_RPC_URL:-http://127.0.0.1:8080}"
    local config="integrations/eth-oracle/configs/devnet_sepolia.toml"
    
    export IPPAN_RPC_URL="$ippan_url"
    
    cargo run -p ippan_eth_oracle_daemon -- dump --config "$config"
}

run_all() {
    log_info "Starting all components with docker-compose..."
    cd "$PROJECT_ROOT"
    
    if [[ ! -f "docker-compose.yml" ]]; then
        log_error "docker-compose.yml not found"
        exit 1
    fi
    
    docker-compose up --build
}

# Main
check_rust

case "${1:-help}" in
    build)
        build_all
        ;;
    fin-node)
        run_fin_node
        ;;
    oracle)
        run_oracle
        ;;
    dump)
        dump_oracle
        ;;
    all)
        run_all
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        log_error "Unknown command: $1"
        usage
        exit 1
        ;;
esac
