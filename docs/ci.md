# CI selection and compilation reuse

CI chooses checks from the complete PR diff or main push range. Missing history,
unrecognized events and unclassified execution/build inputs select broader
coverage. Renames include both the removed and added path.

| Change | Checks |
| --- | --- |
| Documentation | No compilation |
| CI selector, tooling tests, diagnostics, node report comparison | Tooling tests and lint, plus applicable diagnostics smoke |
| SDK client | SDK checks |
| Contract, WIT or shared SDK build inputs | Rust, SDK and reproducibility checks as selected |
| Ordinary API handlers or integration tests | Ordinary Rust and SDK checks |
| Runtime, protocol, database, native graph or compiler inputs | Stack and linked-node qualification as applicable, plus ordinary checks |
| Stack evidence implementation | Stack qualification; no linked-node qualification solely for this change |
| Unknown execution/build inputs | Conservative qualification |

Some API files, including contract execution, signing and runtime construction,
remain execution inputs. The authoritative paths and tests are in
`core/kontor-build/src/ci_scope/`. Do not broaden a skip prefix without checking
its callers and build inputs.

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
diagnostics and Docker cache checks. Main publication is not canceled. Relevant
Rust or Docker changes select main image publication; documentation-only and
tooling-only changes no longer rebuild and publish images. Relevant
main validation is retained: the existing selectors do not have trustworthy
evidence that a successful PR run tested the exact merged inputs. Removing that
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
