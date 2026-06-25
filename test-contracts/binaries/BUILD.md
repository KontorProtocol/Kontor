# Test contract fixtures — committed, reproducible

These `.wasm.br` are the compiled test contracts that `cargo test` loads
(`testlib::ContractReader` globs them here). They are **committed and
reproducible** rather than built on the fly, so:

- `cargo test` compiles no wasm — no wasm32 toolchain or wasm-opt on the host,
  and the macOS CI runner (which can't run Docker) just reads these bytes.
- they're built by the same pinned image as the genesis contracts, recorded in
  [`build.json`](build.json), and the `reproducible-build` CI job rebuilds and
  diffs them on every PR.

After editing a test contract, regenerate and commit:

```sh
tools/build-contracts.sh
```

See [`../../native-contracts/binaries/BUILD.md`](../../native-contracts/binaries/BUILD.md)
for the full provenance / reproduce / bump details — the model is identical.
