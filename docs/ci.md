# CI selection and compilation reuse

CI chooses checks from the complete PR diff or main push range. Missing history
and unrecognized events select broader coverage. Renames include both the
removed and added path. Unknown filenames retain ordinary checks but do not
automatically select expensive qualification.

| Change | Checks |
| --- | --- |
| Documentation | No compilation |
| CI selector, tooling tests, diagnostics, node report comparison | Tooling tests and lint, plus applicable diagnostics smoke |
| SDK client | SDK checks |
| Contract, WIT or shared SDK build inputs | Rust, SDK and reproducibility checks as selected |
| Ordinary API handlers or integration tests | Ordinary Rust and SDK checks |
| Pricing, tokens, staking, storage accounting, ordinary queries and transaction logic | Ordinary relevant checks; no qualification solely for these changes |
| Engine, call transitions, ownership, resource limits or stack fixtures | Stack qualification, plus ordinary checks |
| Activation/recovery, executor adapters, retained bundles or native graph machinery | Linked-node qualification, plus ordinary checks |
| Compiler settings, native libraries or dependency files in covered build trees | Applicable stack and linked-node qualification |
| Stack evidence implementation | Stack qualification; no linked-node qualification solely for this change |
| Unknown ordinary source path | Ordinary checks; use manual qualification when needed |

The two qualification selectors are independent. Runtime ownership and native
libraries can select both, but a change to upgrade coordination does not also
select stack-boundary discovery. Contract execution and runtime-construction
API files remain stack inputs. Canonical/certified recovery state, migration
interfaces and the database adapters used by linked executors remain linked-node
inputs. General database, reactor and protocol directories are not blanket
triggers. Existing ordinary workspace tests retain bounded ownership, resource
and call-chain checks without adding jobs or repeating ignored boundary sweeps.

Dependency selection uses paths, without parsing package changes:

| Dependency/build files | Qualification |
| --- | --- |
| `core/**`, including shared workspace manifests/locks and native build inputs | Stack and linked-node |
| `native-contracts/**` and `test-contracts/**` | Stack and linked-node |
| `protocol-bundles/**`, including retained executor manifests/locks | Linked-node |
| Existing stack or native-crypto qualification tool directories | Their respective qualification |
| Dependency files in unrelated standalone SDK/workspace directories | Neither, unless another relevant file changes |

The build-file rules cover `Cargo.toml`, `Cargo.lock`, `build.rs`, Rust toolchain
files and Cargo configuration. Repository-root build configuration selects both
matrices. The `core/` rule intentionally includes SDK crates in that shared
workspace and tooling used by the executor/qualification builds. Updating an
unrelated package inside a shared lockfile still selects qualification.

Adding a dependency or crate within a covered build tree needs no selector
change. A new workspace outside the covered paths needs a rule if it becomes
an executor or qualification input. Source-path selection still uses the full
PR diff or push range, including removed paths, with conservative missing-history
fallback and manual overrides.

The authoritative paths and tests are in `core/kontor-build/src/ci_scope/`.
When a change affects an execution or upgrade boundary outside those paths,
use the manual Native Wasm stack qualification or Protocol bundle qualification
workflow and extend the selector. Their default runs release qualification
plus applicable smoke coverage; exhaustive dev qualification stays manual.

## Shared compilation

`ci.yml` selects a union of test consumers and calls `rust-tests.yml`. Ordinary
Rust tests use Linux x64 and macOS ARM64 release cells. When stack qualification
is selected, the same cells also run stack checks, with Linux ARM64 release and
three dev smoke cells added. `native-stack.yml` is now a manual entry point into
that same workflow, including optional exhaustive dev qualification.

Each cell owns one Cargo target directory. The compiler and runners are pinned
to the qualification configuration: Rust 1.99.1, Ubuntu 24.04 and macOS 15.
Compatible dependencies compile once. Ordinary tests retain sccache support.

When a release cell runs both suites, it builds all workspace test targets
once with `cargo test --locked --release --workspace --no-run`. Stack checks
select the indexer library test executable from that build's original Cargo
JSON and retain the executable and Wasmtime feature validation. Ordinary tests
then run `cargo test --locked --release --workspace`, reusing those outputs
and preserving other packages, binary targets, integration tests and doctests.
Both compilation steps use the same toolchain, profile and sccache wrapper.

This deliberately selects the workspace feature configuration for shared
cells. It includes additional dependency features such as serde_json's
`unbounded_depth`, while the indexer and Wasmtime feature sets match the
package-only build. Stack-only cells still build `-p indexer --lib` so they
do not compile unrelated workspace targets. Qualification compares outcomes
across these configurations; it does not assume their binaries are identical.

This uses steps in the same job rather than uploading test binaries into new
jobs. It avoids artifact transfer, relocation and repeated runner setup. It
does not claim that all compilation has been eliminated or that adding stack
steps will shorten each individual job. The main benefit is reduced duplicated
work across the selected jobs. Full qualification remains a separate workload.

Contract tests retain their shared regtest network and process-wide engines.
The intentionally isolated file-storage and lifecycle tests remain isolated.
Tests are not sharded into additional processes or networks.

## Caches

- Tooling caches have source-sensitive save keys and compatible dependency
  restore prefixes, so a manifest-only cache does not permanently retain an
  outdated CLI.
- Test compilation caches are separated by hosted image, architecture,
  compiler, profile and build configuration. Cargo validates freshness even
  after an exact cache hit.
- Linked-node caches retain graph-specific target directories under the
  existing namespaces, never a unified executor/consensus target directory.
  Linux restores them into the directory mounted at `/evidence`, so the
  container can reuse compilation. Reports and staged audit results are not
  restored as cached verdicts. All qualification and ownership checks rerun.
  Cache preparation removes the final node package's Cargo fingerprints so
  its compiler and linker regenerate audit records on the next build. It
  preserves dependency fingerprints and all graph namespace boundaries.
- Linux qualification image layers also cache fetched dependencies and the
  tooling bootstrap. Main writes the image cache; PRs restore it.
- Compiled target caches are saved only after successful main runs. PRs can
  restore main caches without repeatedly uploading large branch-only caches.
  Incremental directories are excluded. Uploads above 10 GiB uncompressed for
  a test cell or 12 GiB for a linked-node cell are skipped. These are per-upload
  ceilings, not additional GitHub storage allocation. Repository cache quotas
  still apply; eviction or a skipped upload must never affect correctness.

There is no scheduled cache-warming matrix. Missing platform caches populate
during the next necessary main run. Fresh-build/reproducibility and native
crypto controls retain their existing behavior.

## Production images

The **Production images** workflow publishes `kontorprotocol/kontor` only on
`v*` tag pushes or manual dispatch. Main pushes and PRs do not publish images.
Select a reviewed ref in GitHub's **Run workflow** menu, or run:

```sh
gh workflow run docker-image.yml --ref main
```

Both Linux architectures build natively in parallel, with 90 minutes allowed
per build. The manifest is published only after both builds succeed. Every
publication retains the `sha-<short-sha>` tag used by deployments. Valid semantic
version tag pushes also publish the version without its `v` prefix; only stable
releases update `latest`. Prereleases and manual builds do not update `latest`.
Deployments should continue pinning the selected image digest.
`latest` follows the most recently published stable tag, even if that tag is
for an older release line. Rebuilding the same commit can also move its
`sha-<short-sha>` tag to a different digest; the tag is not an immutable pin.

This workflow is publication, not an additional test gate: select a revision
whose relevant CI checks have passed before tagging or dispatching. Ordinary
tests and linked-node qualification still check their selected production
inputs. Dockerfile, Docker context, build-tool, dependency and linked-node
changes retain qualification coverage. That coverage does not guarantee the
final runtime image or registry publication succeeds, and qualification enables
additional node features. Image publication remains the check of the exact
production Docker build.

The redundant dependency-fetch prejob and full production registry-cache
exports are removed. Occasional release builds may be cold. Custom prebuilt
cache images and sharing outputs between production and qualification builds
are deferred. Cache work prioritizes routine tests and protocol qualification;
there is no extra scheduled or exploratory image build.

## Validation and rollout

Validate selectors and matrix construction locally with the standalone tooling
tests. Validate workflow expressions with actionlint and changed scripts with
ShellCheck. Exercise a restored Cargo target and a source-change rebuild before
landing cache changes. These checks do not establish hosted cache permissions,
macOS performance or a particular speedup.

Prepare the complete change locally before publishing it. Do not use successive
PR matrices or repeated manual dispatches to benchmark the cache implementation.
Observe the first necessary main runs and subsequent relevant PRs instead.

Superseded PR runs are canceled across CI, bundles, mobile, native crypto,
diagnostics and Docker cache checks. Relevant main validation is retained:
the existing selectors do not have trustworthy evidence that a successful PR run tested the exact merged inputs. Removing that
validation without such evidence would leave direct pushes and changed merge
inputs unchecked. No new cross-run evidence service is introduced here.

Local implementation validation included 190 tooling library tests, nine real
native ownership controls, matrix and aggregate-gate cases, workflow lint,
ShellCheck and a Cargo test proving final-node rebuild with fresh dependencies.
A standalone CLI cache probe measured 19.37 seconds cold, 0.05 seconds after
restore, and 2.12 seconds after changing source. The archive was approximately
126 MB, with 10.94 seconds to create and 1.51 seconds to restore locally. This
validates cache behavior, not hosted node-build performance. Historical
tooling-only commits `8b4f4a99` and `2bbeec22` select tooling checks without
Rust, SDK, stack or linked-node jobs under the new policy.

Shared-binary validation used a local Linux ARM64 release workspace build with
Rust 1.99.1. Its Cargo JSON passed the unchanged stack provenance validator.
Bounded paid and Core recursion probes passed using its indexer test executable.
A subsequent filtered workspace ownership test passed using the same executable;
Cargo reused all 957 artifacts, preserved the 28-test-executable inventory, and
finished its build phase in 0.23 seconds. This local check used no sccache and
did not run the full workspace suite or cross-platform qualification matrix.

Narrowed qualification selection was checked with local tooling and CLI tests,
including covered and unrelated dependency-file locations, dependency additions,
PR merge bases, renames/deletions, missing history, manual overrides and continued
ordinary test selection. The required-check gate rejects missing or unsuccessful selected
jobs. Historical replays include selector/documentation-only commits that skip
both matrices, and node-building commits that select linked-node qualification
without stack qualification. No hosted runs were used to validate this policy.
