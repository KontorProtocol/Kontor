# syntax=docker/dockerfile:1

# Pinned Rust + cargo-chef base image. Used for every Rust stage so
# cargo-chef is preinstalled and all builder stages share one image.
# Bumping is deliberate: chef version must match recipe.json format,
# rust version must match rust-toolchain.toml.
ARG CHEF_IMAGE=docker.io/lukemathwalker/cargo-chef:0.1.77-rust-1.95.0-slim-trixie

# ---------------------------------------------------------------------
# Planner — generates recipe.json from Cargo.toml / Cargo.lock.
# Cheapest stage; its output drives the cacher.
# ---------------------------------------------------------------------
FROM ${CHEF_IMAGE} AS planner
WORKDIR /build
COPY core core
WORKDIR /build/core
RUN cargo chef prepare --recipe-path recipe.json

# ---------------------------------------------------------------------
# Builder base — apt deps shared across every Rust build stage below.
# No wasm32 target or Binaryen: test-contracts compilation was moved
# to testlib's build.rs, and testlib is a dev-dependency that never
# gets pulled in by a `cargo build --release -p indexer` production
# build.
# ---------------------------------------------------------------------
FROM ${CHEF_IMAGE} AS builder-base

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    cmake \
    make \
    g++ \
    libzmq3-dev \
    libboost-system-dev \
    libboost-thread-dev \
    libboost-chrono-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------
# Cacher — builds the full dependency tree once from recipe.json. As
# long as Cargo.lock is unchanged, this whole layer is a cache hit and
# the stage is skipped entirely in subsequent builds. This is the
# mechanism doing the real caching work — sccache would add overhead
# here without contributing; BuildKit cache mounts don't persist
# across CI runs, so per-rustc-call caching has nothing to hit.
# ---------------------------------------------------------------------
FROM builder-base AS cacher
WORKDIR /build/core
COPY --from=planner /build/core/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# ---------------------------------------------------------------------
# Builder — copies real source, builds the indexer binary. Inherits
# pre-compiled deps from the cacher stage.
# ---------------------------------------------------------------------
FROM builder-base AS builder
WORKDIR /build

COPY --from=cacher /build/core/target /build/core/target
COPY --from=cacher /usr/local/cargo /usr/local/cargo

COPY . .

WORKDIR /build/core
RUN cargo build --release --package indexer

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

COPY --from=builder /build/core/target/release/kontor /usr/local/bin/kontor

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
