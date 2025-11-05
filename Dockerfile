# syntax=docker/dockerfile:1

# Tool builder stage - builds and caches cargo tools
FROM rust:alpine AS tool-builder
RUN apk add --no-cache musl-dev g++ gcc make
RUN cargo install cargo-chef --locked
RUN rustup target add wasm32-unknown-unknown
RUN cargo install wasm-opt --locked

# Planner stage - generates dependency recipe
FROM rust:alpine AS planner
RUN apk add --no-cache musl-dev
COPY --from=tool-builder /usr/local/cargo/bin/cargo-chef /usr/local/cargo/bin/
WORKDIR /build
COPY core core
WORKDIR /build/core
RUN cargo chef prepare --recipe-path recipe.json

# Builder base - builds dependencies once and caches them
FROM rust:alpine AS builder-base

RUN apk add --no-cache \
    musl-dev \
    zeromq-dev \
    boost-dev \
    openssl-dev \
    pkgconfig \
    cmake \
    make \
    g++ \
    gcc \
    perl \
    linux-headers \
    bash \
    brotli \
    sqlite-dev \
    git \
    tcl \
    curl \
    wget \
    unzip \
    pcre2-dev

# Copy pre-built cargo tools instead of building them
COPY --from=tool-builder /usr/local/cargo/bin/cargo-chef /usr/local/cargo/bin/
COPY --from=tool-builder /usr/local/cargo/bin/wasm-opt /usr/local/cargo/bin/

# Install wasm32 target directly instead of copying
RUN rustup target add wasm32-unknown-unknown

WORKDIR /build

# Cacher stage - builds dependencies (cached separately from source code)
FROM builder-base AS cacher
WORKDIR /build/core
COPY --from=planner /build/core/recipe.json recipe.json
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN cargo chef cook --release --recipe-path recipe.json

# Builder stage - builds actual code
FROM builder-base AS builder

WORKDIR /build

# Copy cached dependencies from cacher stage
COPY --from=cacher /build/core/target /build/core/target
COPY --from=cacher /usr/local/cargo /usr/local/cargo

# Copy source code (including pre-built sqlean binaries)
COPY . .

# Build only the indexer (dependencies already built)
WORKDIR /build/core
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN cargo build --release --package indexer

# Runtime stage
FROM alpine:latest

RUN apk add --no-cache \
    zeromq \
    boost-libs \
    ca-certificates \
    libgcc \
    libstdc++ \
    pcre2

RUN addgroup -g 1000 kontor && \
    adduser -D -u 1000 -G kontor kontor

RUN mkdir -p /data && chown -R kontor:kontor /data

COPY --from=builder /build/core/target/release/kontor /usr/local/bin/kontor
RUN chmod +x /usr/local/bin/kontor

USER kontor
WORKDIR /home/kontor

ENV DATA_DIR=/data \
    API_PORT=9333 \
    ZMQ_ADDRESS=tcp://127.0.0.1:28332 \
    NETWORK=bitcoin \
    STARTING_BLOCK_HEIGHT=921300 \
    USE_LOCAL_REGTEST=false \
    BITCOIN_RPC_USER=rpc \
    BITCOIN_RPC_PASSWORD=rpc

EXPOSE 9333
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/kontor"]
