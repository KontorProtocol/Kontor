# Testing

## Test Categories

- **Standard tests**: Unit and integration tests (~138 tests)
- **Property tests**: Proptest-based tests in `*_prop.rs` files (3 tests)
- **Load tests**: Performance tests in `*load_tests.rs` files (2 tests)

## Requirements for Regtest Tests

Regtest tests require Bitcoin Core in `PATH`:

```bash
# Clone and build Bitcoin v30.0
git clone https://github.com/bitcoin/bitcoin.git --depth 1 --branch v30.0
cd bitcoin
cmake -B build -DENABLE_WALLET=OFF -DENABLE_IPC=OFF -DWITH_ZMQ=ON
cmake --build build

# Add to PATH
export PATH="$HOME/dev/bitcoin/build/bin:$PATH"
```

## Running Tests

Standard tests (debug mode):
```bash
cargo test --workspace
```

Property and load tests (release mode recommended):
```bash
cargo test --release --workspace --test '*_prop' --test '*_load_tests'
```

## CI Configuration

CI runs two parallel jobs:
- **Standard**: Debug mode on Ubuntu and macOS
- **Optimized**: Release mode on Ubuntu only, filters to `*_prop` and `*_load_tests` binaries

Property and load tests always run with optimizations for reasonable execution time and meaningful performance data.
