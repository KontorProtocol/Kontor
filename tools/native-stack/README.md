# Native Wasm stack qualification

`qualify.py` invokes the ignored indexer test in a fresh process at each depth. The test publishes the `stack-probe` component through the normal user contract path and then executes it through `Runtime::execute` or `Runtime::execute_system_view`. A process per depth lets the driver distinguish a Wasmtime trap from a process signal or timeout.

Build the fixture with the repository's pinned test-contract build, then compile the indexer test binary for each profile:

```sh
./tools/kontor build test --runtime podman -j 2
cargo test --locked --manifest-path core/Cargo.toml -p indexer --lib --no-run -j2
cargo test --locked --manifest-path core/Cargo.toml -p indexer --lib --no-run --release -j2
```

Pass the resulting test executable to the driver:

```sh
python3 tools/native-stack/qualify.py --binary path/to/indexer-test --output path/to/evidence
```

The driver finds the last successful depth and first failing depth for plain recursion, recursion with 32 live `u64` values per frame, and nested calls through distinct contracts. It also runs one fixed 256-value frame. Each JSON observation includes the component hash, stack settings, fuel usage, outcome, persisted receipt, and state marker. A failed paid or Core procedure must leave its marker at zero and record the matching `Trap` or `OutOfFuel` receipt. View calls must not record a procedure receipt.

The GitHub Actions workflow collects Linux x86-64, Linux ARM64, and macOS ARM64 results in development and release profiles. `compare.py` fails if any report is missing, the component hashes or effective stack settings differ, or any sampled boundary, outcome, fuel, receipt, or state marker differs. The fixed single-frame check and the host reentry cap are bounded probes; a passing result does not prove that larger frames or deeper host chains are safe. A native stack trap below the fuel ceiling is evidence of an execution boundary that must not be treated as platform-independent without cross-target agreement.
