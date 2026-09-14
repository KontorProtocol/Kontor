# Genesis contract binaries

These committed `.wasm.br` files are loaded by every node at genesis. CI checks
that the current source reproduces their bytes using the shared pinned build.

```sh
./tools/kontor build native
./tools/kontor build native --check
```

Run from the repository root. Commit regenerated binaries and `build.json`.
The metadata records the actual image, platform, and tool versions; the input
pins live in `tools/build.json`. The configured platform is used on every host.

See [the shared build guide](../../tools/BUILD.md) for SDK/test builds,
bootstrapping, toolchain upgrades, and failure recovery.
