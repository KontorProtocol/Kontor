# Test contract fixtures

These committed `.wasm.br` files are loaded by `testlib::ContractReader`.
Rust tests use them directly, including on macOS, without compiling Wasm.

```sh
./tools/kontor build test
./tools/kontor build test --check
```

Run from the repository root and commit regenerated binaries and `build.json`.
CI verifies them with the same [shared pinned build](../../tools/BUILD.md) as
native contracts and SDK outputs.
