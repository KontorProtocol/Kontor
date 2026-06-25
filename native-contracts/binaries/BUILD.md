# Genesis contract binaries — build provenance

The `.wasm.br` files here are the **genesis contracts**: every node loads these
exact bytes at genesis, so they are consensus-critical and committed to the repo.
They must be **bit-for-bit reproducible** from source — CI rebuilds them on every
PR (`reproducible-build` job) and fails if a single byte drifts.

## Self-describing builds

Contract wasm bytes are a function of the build environment, not just the source:
cargo bakes the build path and host CPU architecture into each crate's metadata
(`StableCrateId` / `-C metadata`), and `wasm-opt` / `brotli` output depends on
their own versions. So the committed set carries its own provenance in
[`build.json`](build.json) — there is no project-wide "canonical" arch, just a
record of what produced *these* bytes:

```json
{
  "platform": "linux/arm64",
  "image": "kontorprotocol/kontor-build:1.96.0",
  "rustc": "1.96.0",
  "wasm_opt": "binaryen version_130"
}
```

`build.json` is the single source of truth. CI reads `platform` and verifies the
bytes on a matching native runner (`linux/arm64` → `ubuntu-24.04-arm`,
`linux/amd64` → `ubuntu-latest`). Builds on a *different* arch produce different
bytes (cargo's arch-dependent metadata); the multi-arch build image lets anyone
reproduce whichever platform the record names.

The remaining inputs are pinned by [`../../tools/kontor-build.Dockerfile`](../../tools/kontor-build.Dockerfile):
rustc by the base image tag, wasm-opt by binaryen version + sha, brotli by an
exact apt version, and the build path by the fixed `/build` WORKDIR.

The test fixtures in `test-contracts/binaries/` are committed and verified the
exact same way (same image, same `build.json` shape, same gate) — `cargo test`
loads those committed bytes instead of compiling, so the macOS CI runner (no
Docker) needs no wasm toolchain.

## Regenerate (after changing a contract)

```sh
tools/build-contracts.sh
```

Rebuilds **both** native and test contracts in the pinned image and stamps each
`binaries/build.json` with *your* arch. ~30s on a native host; commit the
resulting `.wasm.br` + `build.json`. Needs `docker` or `podman`.

## Verify without rebuilding the image

The in-image build script takes the workspaces to rebuild as arguments:

```sh
docker run --rm --platform "$(jq -r .platform native-contracts/binaries/build.json)" \
  -v "$PWD:/build" -w /build \
  kontorprotocol/kontor-build:1.96.0 \
  bash tools/build-in-image.sh native-contracts test-contracts
git diff --exit-code native-contracts/binaries/ test-contracts/binaries/   # no diff == reproduced
```

## Bumping rustc or wasm-opt

All inputs are pinned in one file, `tools/kontor-build.Dockerfile`: rustc by the
base image tag, brotli by its exact apt version, wasm-opt by `BINARYEN_VERSION` +
sha (the build runs in the image, not against a host toolchain). To bump, edit
those pins there and regenerate with `tools/build-contracts.sh`; `build.json` is
re-derived from the installed tools automatically, so there's nothing to mirror.
