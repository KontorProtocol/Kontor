# Kontor

## Bitcoin

Install dependencies for compiling Bitcoin with [ZeroMQ](https://zeromq.org/download/):
```bash
brew install cmake boost pkgconf libevent zeromq
```

Clone Bitcoin:
```bash
git clone https://github.com/bitcoin/bitcoin.git
cd bitcoin
git checkout v29.0
```

Compile Bitcoin:
```bash
cmake -B build -DENABLE_WALLET=OFF -DWITH_ZMQ=ON
cmake --build build
```
The binary is now located in `build/bin/bitcoind`

It is recommended to store Bitcoin data in a custom directory, ideally on an external volume i.e. `/Volumes/ExternalDrive/bitcoin-data`
Additionally, a `bitcoin.conf` file should be created in the Bitcoin data directory with the following content:
```bash
rpcuser=rpc
rpcpassword=rpc
server=1
txindex=1
prune=0
mempoolfullrbf=1
dbcache=4000
rpcthreads=11
rpcworkqueue=32
zmqpubsequence=tcp://127.0.0.1:28332
zmqpubsequencehwm=0
```
You can set `rpcthreads` to a higher or lower value depending on your system's resources.

Bitcoin can be run with:
```bash
build/bin/bitcoind -datadir=<path to your bitcoin data dir>
```

Bitcoin should be running and synced before running the application.

## Development TLS

Create TLS certs for local development with [mkcert](https://github.com/FiloSottile/mkcert). In the project (`Kontor`) directory run:
```bash
mkcert -key-file key.pem -cert-file cert.pem localhost 127.0.0.1 ::1
```

## Run

To run the application, your `.envrc` should include the following environment variables:
```bash
export BITCOIN_RPC_URL="http://127.0.0.1:8332"
export BITCOIN_RPC_USER="rpc"
export BITCOIN_RPC_PASSWORD="rpc"

export ZMQ_PUB_SEQUENCE_ADDRESS="tcp://127.0.0.1:28332"

export API_PORT="8443"

export DATABASE_DIR="../"

export CERT_DIR="../"

export NETWORK="bitcoin"
```
`../` for when files and directories are in the root workspace folder instead of the `kontor` crate folder.

```bash
cargo run
```

## Test

To run tests, **in addition to the environment variables above**, your `.envrc` should also include the following:
```bash
export SEGWIT_BUYER_KEY_PATH="../segwit_buyer.key"
export SEGWIT_SELLER_KEY_PATH="../segwit_seller.key"
export TAPROOT_KEY_PATH="../taproot.key"
```
`../` for when files and directories are in the root workspace folder instead of the `kontor` crate folder.

```bash
cargo test
```

## Regtest Testing
Some tests are setup to run against regtest.

```bash
cmake -B build -DENABLE_WALLET=ON -DWITH_ZMQ=ON`
cmake --build build
```

Make a data dir for regtest.
```bash
mkdir -p "<path to your bitcoin data dir>/regtest"
```

Copy over the bitcoin config created earlier and put it in the `regtest` folder and add these two options:
```bash
regtest=1
fallbackfee=0.0001
```

Run:
```bash
/build/bin/bitcoind -regtest -datadir="<path to your bitcoin data dir>/regtest
```

Test:
```bash
cargo test --test regtest_commit_reveal`
```

## Testnet4 testing
Some tests are setup to run against testnet4
Running these tests currently requires running a testnet4 node locally

Make a data dir for testnet4 and copy over the bitcoin config created earlier.
```bash
mkdir -p "<path to your bitcoin data dir>/testnet4"
```

Run:
```bash
/build/bin/bitcoind -testnet4 -datadir="<path to your bitcoin data dir>/testnet4
```

Test:
```bash
cargo test --test testnet_commit_reveal
```

## UI

### Run

The main Kontor application must be running first.

```bash
cd ui
cargo run
```

UI runs at localhost:3000

### Development

Add environment variables to `.envrc`:
```bash
export VITE_ELECTRS_URL="https://api.unspendablelabs.com:3000"
export VITE_KONTOR_URL="https://localhost:8443"
```

```bash
cd ui/frontend
npm install
npm run dev
```

Dev server runs at localhost:5173
