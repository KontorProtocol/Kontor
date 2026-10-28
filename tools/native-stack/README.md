# Native Wasm stack qualification

`qualify.py` invokes the ignored indexer test in a fresh process at each depth. The test publishes the synchronous `stack-probe` component through the normal user contract path and then executes it through `Runtime::execute` or `Runtime::execute_system_view`. A process per depth lets the driver distinguish a Wasmtime trap from a process signal or timeout.

Build the fixture with the repository's pinned test-contract build, then compile the indexer test binary for each profile:

```sh
./tools/kontor build test --runtime podman -j 2
cargo test --locked --manifest-path core/Cargo.toml -p indexer --lib --no-run -j2
cargo test --locked --manifest-path core/Cargo.toml -p indexer --lib --no-run --release -j2
```

Pass the resulting test executable to the driver:

```sh
python3 tools/native-stack/qualify.py --binary path/to/indexer-test --cell Linux-ARM64/dev --output path/to/evidence
```

The driver finds the last successful depth and first failing depth for plain recursion, recursion with 32 live `u64` values per frame, and nested calls through distinct contracts. It also runs one fixed 256-value frame. Each JSON observation includes the component hash, stack settings, fuel usage, outcome, persisted receipt, and state marker. A failed paid or Core procedure must leave its marker at zero and record the matching `Trap` or `Other` receipt. View calls must not record a procedure receipt.

The GitHub Actions workflow collects Linux x86-64, Linux ARM64, and macOS ARM64 results in development and release profiles. `compare.py` requires the exact six cells, successful qualification jobs, matching source and lockfile hashes, the approved Wasmtime revision, the Pulley target, the effective stack settings, adjacent repeated stack boundaries, and matching observations. It also checks the root-inclusive 64-Store success and 65-Store rejection in the stack probe. The workflow runs the paid, view, and Core chain fixture separately. The fixed single-frame check is a bounded probe; a passing result does not prove that larger frames are safe.

Run the comparator's negative controls with `python3 -m unittest discover -s tools/native-stack -p 'test_*.py'`. The historical results in `qualification-results.md` use the earlier async guest fixture and are context only. The synchronous fixture requires a fresh six-cell qualification before S2 can merge.

The synchronous probe's compressed SHA-256 is `e396317b4eb14c9a29d47acbe8a9f7b0e29770d47e7df53e4bed12d5c5bfce50`. Its exact encoder inventory is `encoder-inventory/inventory-s2-stack-probe.tsv`, with three embedded modules and zero core or component starts.

S2 replaces S1's default Wasmtime feature selection with the explicit production features in `core/Cargo.toml`: `anyhow`, `async`, `backtrace`, `component-model`, `component-model-async`, `cranelift`, `gc-copying`, `gc-drc`, `gc-null`, `pooling-allocator`, `pulley`, `runtime`, `std`, `threads`, `wat`, `wave`, and `wit-parser`. Cargo additionally resolves `gc`, `once_cell`, `wasmtime-jit-icache-coherence`, and `wasmtime-unwinder` through these features. `call-hook` appears only in the indexer's development dependency graph. The `threads` compile feature provides `wasm_threads(false)` for the nine-setting capability check; the runtime disables guest threads. This feature change and the new synchronous binary require fresh target and profile qualification, so S1's earlier measurements cannot be reused.
