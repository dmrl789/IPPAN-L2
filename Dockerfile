# IPPAN-L2 Dockerfile
# Multi-stage build for minimal production images

# Build stage
FROM rust:1.83-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/l2-core ./crates/l2-core
COPY hub-fin ./hub-fin
COPY hub-data ./hub-data
COPY fin-node ./fin-node
COPY integrations ./integrations

# Build release binaries
RUN cargo build --release --workspace

# FIN Node image
FROM debian:bookworm-slim AS fin-node

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/fin-node /app/fin-node

# Create non-root user
RUN useradd -r -s /bin/false ippan && \
    chown -R ippan:ippan /app

USER ippan

ENTRYPOINT ["/app/fin-node"]

# Oracle Daemon image
FROM debian:bookworm-slim AS oracle-daemon

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/ippan_eth_oracle_daemon /app/ippan_eth_oracle_daemon

# Create non-root user
RUN useradd -r -s /bin/false ippan && \
    chown -R ippan:ippan /app

USER ippan

ENTRYPOINT ["/app/ippan_eth_oracle_daemon"]
