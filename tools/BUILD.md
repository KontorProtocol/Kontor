# Reproducible contracts and SDK

From a checkout, with Rust and podman or Docker installed:

```sh
./tools/kontor build                 # native contracts, test contracts, SDK
./tools/kontor build native test     # selected outputs
./tools/kontor build sdk --check     # compare without rewriting the checkout
./tools/kontor build --runtime docker -j 2
```

An installed `kontor` exposes the same `build` subcommand. The repository
bootstrap compiles only `core/kontor-build`, a small Rust library and executable
with no node or generated-output dependency. Both entrypoints call that library.
Run the bootstrap from the checkout when changing the build implementation.

## Platform and tools

[`build.json`](build.json) pins the actual published container by digest and the
canonical platform, currently **linux/arm64**. Local generation and CI use this
same platform regardless of the host architecture. Other hosts need container
emulation or a runtime on that platform; builds never silently switch the pin.
Podman is preferred when both runtimes are installed.

The image supplies Rust, wasm-opt, and brotli. SDK generation additionally uses
checksum-pinned Node, wasm-tools, and WASI SDK archives. WASI SDK supplies clang
and llvm-ar for the SDK's C cryptography dependencies; the SDK still targets
`wasm32-unknown-unknown`. JCO is an exact package version, installed
with `npm ci` from the SDK lockfile into a separate cache. Host Node, C compilers,
wasm-tools, and `sdk/node_modules` do not participate in generation.

Every Cargo invocation uses `--locked`. Containers use fixed `/build` paths and
`CARGO_HOME`, with dependency source paths remapped. Generated `build.json` files
record the image and observed tool versions; SDK provenance also includes tool
archive pins, the JCO version, and the npm lockfile hash.
The generators format their own output; there is no second formatting pass.

To change the base toolchain, update `kontor-build.Dockerfile`, publish through
the Build Image workflow, and pin its resulting digest in `tools/build.json`.
Changing SDK tool versions requires updating their archive checksums. A platform
change also requires matching SDK archives. Regenerate all outputs and commit
them with the pin changes.

## Outputs and failure handling

The command builds into `.build-cache/generated` before replacing any committed
output. It manages native/test `.wasm.br` files and provenance, the entire
`sdk/src/component` tree, and `sdk/src/bindings.d.ts`. Contract `BUILD.md` files
are preserved. Cargo artifact messages select current workspace outputs, so
stale target files cannot resurrect a deleted contract.

API bindings are exported by the complete `indexer-types` library test suite.
Ordinary Rust tests instead export into an ignored directory under that crate;
a filtered test run cannot truncate the SDK's checked-in bindings.

`--check` compares bytes, including new and removed files and nested SDK
interfaces. It leaves checkout outputs untouched and retains candidates for CI
upload or inspection. A compilation/generation failure also leaves them intact.
Replacement keeps backups until every requested output is installed and rolls
back if a later replacement fails. This is not crash-atomic across directories:
after a process or machine crash, `.build-cache/backup` is retained and the next
build refuses to overwrite it; restore those backups before proceeding.

Only one shared build runs per checkout. Caches live under `.build-cache`;
remove that directory when no build is running for a clean build, after checking
that it contains no recovery backup. CI runs the same bootstrap and `--check`
on a matching native runner. Node tests on other platforms consume the committed
outputs and do not need this build toolchain.
