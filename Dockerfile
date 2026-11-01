# syntax=docker/dockerfile:1

ARG CHEF_IMAGE=docker.io/lukemathwalker/cargo-chef:0.1.78-rust-1.99.1-slim-trixie

FROM ${CHEF_IMAGE} AS builder-base
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config cmake make g++ libzmq3-dev \
    libboost-system-dev libboost-thread-dev libboost-chrono-dev \
    ca-certificates python3 binutils git \
    && rm -rf /var/lib/apt/lists/*
RUN rustup component add --toolchain 1.99.1 llvm-tools-preview
ENV RUSTUP_TOOLCHAIN=1.99.1 RUSTC_WRAPPER="" CCACHE_DISABLE=1 CARGO_BUILD_JOBS=2
WORKDIR /build

# Cache fetched sources, not unified-workspace compilation. Each retained graph
# must compile with its own metadata, features and native symbol namespace.
FROM builder-base AS cacher
COPY core core
COPY protocol-bundles protocol-bundles
RUN cargo fetch --locked --manifest-path protocol-bundles/executor-first/Cargo.toml && \
    cargo fetch --locked --manifest-path protocol-bundles/executor-second/Cargo.toml && \
    cargo fetch --locked --manifest-path protocol-bundles/node/Cargo.toml

FROM cacher AS protocol-bundle-qualification
COPY . .
CMD ["python3", "tools/protocol-bundles/qualify_node.py", "--output", "/evidence", "--profile", "release", "--offline"]

FROM cacher AS builder
COPY . .
RUN python3 tools/protocol-bundles/build.py --build-node --offline \
    --profile release --output /build/protocol-output --install-node /build/bin/kontor

# ---------------------------------------------------------------------
# Runtime — minimal Debian slim with only the runtime .so deps and
# the compiled binary. No toolchain, no source, no package-manager
# state.
# ---------------------------------------------------------------------
FROM docker.io/debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libzmq5 \
    libboost-system1.83.0 \
    libboost-thread1.83.0 \
    libboost-chrono1.83.0t64 \
    libpcre2-8-0 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1000 kontor && \
    useradd --system --uid 1000 --gid kontor --create-home --home-dir /home/kontor kontor && \
    mkdir -p /data && chown -R kontor:kontor /data

COPY --from=builder /build/bin/kontor /usr/local/bin/kontor

USER kontor
WORKDIR /home/kontor

ENV DATA_DIR=/data \
    API_PORT=9333 \
    ZMQ_ADDRESS=tcp://127.0.0.1:28332 \
    NETWORK=bitcoin \
    STARTING_BLOCK_HEIGHT=946452
# No default BITCOIN_RPC_USER / BITCOIN_RPC_PASSWORD — operators must
# supply them; the indexer fails loudly at startup if they're missing.

EXPOSE 9333
VOLUME ["/data"]

# Health check — hits the indexer's /api root once it's serving.
# 60s start period covers cold boot: DB init, mempool sync, first
# fee projection.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl --fail --silent "http://127.0.0.1:${API_PORT}/api" || exit 1

ENTRYPOINT ["/usr/local/bin/kontor"]
CMD ["run"]
