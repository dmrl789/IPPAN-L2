# IPPAN-L2 Dockerfile
# Multi-stage build for minimal production images
#
# Build targets:
#   - fin-node: Main FIN node binary
#   - oracle-daemon: Ethereum oracle daemon
#
# Usage:
#   docker build --target fin-node -t ippan-l2/fin-node:latest .
#   docker build --target oracle-daemon -t ippan-l2/oracle-daemon:latest .

ARG RUST_VERSION=1.83

# ==============================================================================
# Build stage: Compile all workspace binaries
# ==============================================================================
FROM rust:${RUST_VERSION}-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency manifests first for better layer caching
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/l2-core/Cargo.toml ./crates/l2-core/
COPY crates/l2-storage/Cargo.toml ./crates/l2-storage/
COPY crates/l2-batcher/Cargo.toml ./crates/l2-batcher/
COPY crates/l2-bridge/Cargo.toml ./crates/l2-bridge/
COPY crates/l2-leader/Cargo.toml ./crates/l2-leader/
COPY crates/l2-node/Cargo.toml ./crates/l2-node/
COPY crates/ippan-rpc/Cargo.toml ./crates/ippan-rpc/
COPY hub-fin/Cargo.toml ./hub-fin/
COPY hub-data/Cargo.toml ./hub-data/
COPY fin-node/Cargo.toml ./fin-node/
COPY integrations/eth-oracle/daemon/Cargo.toml ./integrations/eth-oracle/daemon/

# Create stub files for dependency resolution
RUN mkdir -p crates/l2-core/src && echo "pub fn stub(){}" > crates/l2-core/src/lib.rs && \
    mkdir -p crates/l2-storage/src && echo "pub fn stub(){}" > crates/l2-storage/src/lib.rs && \
    mkdir -p crates/l2-batcher/src && echo "pub fn stub(){}" > crates/l2-batcher/src/lib.rs && \
    mkdir -p crates/l2-bridge/src && echo "pub fn stub(){}" > crates/l2-bridge/src/lib.rs && \
    mkdir -p crates/l2-leader/src && echo "pub fn stub(){}" > crates/l2-leader/src/lib.rs && \
    mkdir -p crates/l2-node/src && echo "pub fn stub(){}" > crates/l2-node/src/lib.rs && \
    mkdir -p crates/ippan-rpc/src && echo "pub fn stub(){}" > crates/ippan-rpc/src/lib.rs && \
    mkdir -p hub-fin/src && echo "pub fn stub(){}" > hub-fin/src/lib.rs && \
    mkdir -p hub-data/src && echo "pub fn stub(){}" > hub-data/src/lib.rs && \
    mkdir -p fin-node/src && echo "fn main(){}" > fin-node/src/main.rs && \
    mkdir -p integrations/eth-oracle/daemon/src && echo "fn main(){}" > integrations/eth-oracle/daemon/src/main.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release --workspace 2>/dev/null || true

# Copy actual source code
COPY crates ./crates
COPY hub-fin ./hub-fin
COPY hub-data ./hub-data
COPY fin-node ./fin-node
COPY integrations ./integrations
COPY docs/openapi ./docs/openapi

# Build release binaries
RUN cargo build --release --workspace

# ==============================================================================
# FIN Node production image
# ==============================================================================
FROM debian:bookworm-slim AS fin-node

# Security: Install minimal packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Copy binary
COPY --from=builder /build/target/release/fin-node /app/fin-node

# Create data directories
RUN mkdir -p /var/lib/ippan-l2/{receipts,fin_db,data_db,policy_db,recon_db,audit_db,bootstrap_db,snapshots}

# Create non-root user with specific UID/GID for consistency
RUN groupadd -g 1000 ippan && \
    useradd -r -u 1000 -g ippan -s /bin/false ippan && \
    chown -R ippan:ippan /app /var/lib/ippan-l2

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/fin-node", "l1", "check"] || exit 1

# Security hardening
USER ippan

# Labels for container metadata
LABEL org.opencontainers.image.title="IPPAN-L2 FIN Node"
LABEL org.opencontainers.image.description="IPPAN L2 Finance Hub Node"
LABEL org.opencontainers.image.source="https://github.com/dmrl789/IPPAN-L2"
LABEL org.opencontainers.image.vendor="IPPAN"

# Use tini as init process for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--", "/app/fin-node"]
CMD ["run"]

# ==============================================================================
# Oracle Daemon production image
# ==============================================================================
FROM debian:bookworm-slim AS oracle-daemon

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

COPY --from=builder /build/target/release/ippan_eth_oracle_daemon /app/ippan_eth_oracle_daemon

# Create non-root user
RUN groupadd -g 1000 ippan && \
    useradd -r -u 1000 -g ippan -s /bin/false ippan && \
    chown -R ippan:ippan /app

USER ippan

LABEL org.opencontainers.image.title="IPPAN-L2 Oracle Daemon"
LABEL org.opencontainers.image.description="IPPAN L2 Ethereum Oracle Daemon"
LABEL org.opencontainers.image.source="https://github.com/dmrl789/IPPAN-L2"

ENTRYPOINT ["/usr/bin/tini", "--", "/app/ippan_eth_oracle_daemon"]
