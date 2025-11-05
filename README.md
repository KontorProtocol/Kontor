# Kontor

The Kontor project is split into two workspaces: `core` and `contracts`.

The `core` workspace contains the application and its tests, while `contracts` contains the native contracts. This separation exists because contracts compile to `wasm32-unknown-unknown`. In `cargo`, compile targets can only be set at the workspace level, not at the crate level ([yet](https://github.com/rust-lang/cargo/issues/9406)).

## Getting Started

Install build dependencies:
```bash
brew install binaryen
brew install brotli
```

Add wasm compile target:
```bash
rustup target add wasm32-unknown-unknown
```

Install cargo expand
```
cargo install cargo-expand
```

Set `core` as the working directory:
```bash
cd core
```
Continue with `core` [README.md](core/README.md).

## Docker

Build the Alpine-based image:
```bash
docker build -t kontor-indexer .
```

Run with environment variables:
```bash
docker run -d \
  -p 9333:9333 \
  -v kontor-data:/data \
  -e BITCOIN_RPC_URL=http://your-node:8332 \
  -e BITCOIN_RPC_USER=your-username \
  -e BITCOIN_RPC_PASSWORD=your-password \
  -e ZMQ_ADDRESS=tcp://your-node:28332 \
  -e NETWORK=bitcoin \
  kontor-indexer
```

Or pass CLI arguments directly:
```bash
docker run -d -p 9333:9333 -v kontor-data:/data kontor-indexer \
  --bitcoin-rpc-url http://your-node:8332 \
  --bitcoin-rpc-user your-username \
  --bitcoin-rpc-password your-password \
  --network testnet \
  --api-port 9333
```

Available networks: `bitcoin`, `testnet`, `signet`, `regtest`

