# Kontor

## Development

### Install build dependencies:

MacOS:
```bash
brew install cmake pkgconf libevent boost zmq brotli
```

Ubuntu:
```bash
sudo apt install cmake pkgconf libevent-dev libboost-all-dev libzmq3-dev brotli
```

If rust tooling is not installed follow steps from [rust-lang.org](https://rust-lang.org/tools/install/)

Add wasm compile target:
```bash
rustup target add wasm32-unknown-unknown
```

Install cargo components
```bash
cargo install cargo-expand wasm-opt
```

### Compile Bitcoin

A local copy of `bitcoind` is required to run all tests successfully.

Install dependencies for compiling Bitcoin:

Clone Bitcoin:
```bash
git clone https://github.com/bitcoin/bitcoin.git
cd bitcoin
git checkout v30.0
```

Compile Bitcoin:
```bash
cmake -B build -DENABLE_WALLET=OFF -DENABLE_IPC=OFF -DWITH_ZMQ=ON
cmake --build build
```
Compiled binaries including `bitcoind` are located in `build/bin`. **This directory must be on your `$PATH` when running tests.**

### Run Tests

```bash
git clone https://github.com/UnspendableLabs/Kontor.git
cd Kontor/core
cargo test
```

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

Available networks: `bitcoin`, `testnet`, `testnet4`, `signet`, `regtest`
