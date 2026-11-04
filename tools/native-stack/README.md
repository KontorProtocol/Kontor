# Native Wasm stack qualification

## Automatic qualification scope

Stack sweep parsing and fresh-control comparison now use
`tools/kontor verify-stack-evidence` (`parse_sweep` and `sweep_pair` JSON requests).
Capture and archive comparison use `tools/kontor qualify-stack` and
`tools/kontor compare-stack`; the temporary Python adapter is removed.
Bootstrap uses the existing tooling
lockfile and respects Cargo's offline environment. It requires the pinned Rust
toolchain, including when comparing downloaded reports. Parsed observations and
report formats are unchanged; integer evidence explicitly rejects booleans and
floating-point substitutes. The former sweep unit tests now run with the Rust
tooling tests. Capture retains the worker, fresh-control and owned-control
process sequence, preserving partial logs and reaping failed or timed-out
children without retries. A failed rerun removes its stale qualification report.
No stack-boundary or performance runs are added by this migration.

Every PR runs the lightweight `Stack qualification change scope` job. Full
release qualification and bounded dev smoke run when the Git diff touches runtime/ownership, retained protocol
code, storage or canonical execution, pooled contract/signer entrypoints, shared
execution crates, native/test contracts, protocol bundles, or qualification tools.
Cargo manifests/locks, build scripts, Cargo configuration and Rust toolchain files
also trigger it. The authoritative selection is
[`tools/kontor ci-scope stack`](../../core/kontor-build/src/ci_scope.rs), with
the path policy in [`ci_scope/paths.rs`](../../core/kontor-build/src/ci_scope/paths.rs).

Unrelated documentation, client/mobile code, read-only API presentation, logging,
metrics and advisory-exception changes retain ordinary CI without the stack qualification
matrix. This is a change-scope decision, not a reuse of old reports as new
qualification. Extend the selector when execution inputs move to a new location.

Selection compares the complete PR diff from its merge base (or the full push
range on main), including removed paths and both sides of renames. Missing Git
history selects release qualification plus dev smoke. A failed selection job cannot
produce a successful aggregate comparison. Release cases and strict semantic
comparisons remain unchanged. There are currently no GitHub required status
checks configured on main; if added, require the scope job and aggregate comparison,
allowing the aggregate's intentional skip for unrelated changes.

Automatic runs fully qualify release builds on Linux x86-64, Linux ARM64 and
macOS ARM64. Dev builds on those platforms run the eight existing tests listed in
`core/kontor-build/src/stack_evidence/smoke.rs`, covering paid-call settlement, inherited yield policy, nested
cancellation, canonical drainage, Store admission and shared memory accounting.
They do not discover stack boundaries or run deep-chain sweeps. The eight tests
run sequentially in one process, sharing the fixture's compiled native contracts
while retaining independent test databases. The entire group has a 15-minute
timeout and must report exactly eight passing tests. Evidence
binds the source, lockfile, compiler host, binary and Cargo/feature/test logs.
Ordinary `ci.yml` tests use release mode and do not substitute for this dev smoke.
Smoke is regression coverage, not proof of dev/release boundary equivalence.

Run `tools/kontor stack-smoke --binary <dev-test-binary> --cell <platform>/dev
--output <evidence-directory>` after writing the Cargo JSON build log to
`<evidence-directory>/cargo.json`. Paths are relative to the checkout root unless
absolute. The Rust runner retains the eight tests, writes their combined output
to `tests.log` (smoke report schema 2),
removes stale `smoke.json` before reruns, preserves partial failure logs, and
checks that source, lockfile and executable stayed unchanged. The informational
`host` field now uses `uname -a`; compiler host validation is unchanged.
`verify-stack-evidence` also accepts `build_provenance`, `smoke_test`,
`smoke_report` and `smoke_set` requests (use absolute archive paths). The archive
validators reject evidence links outside their directories. The former Python
dev-smoke runner and tests have been removed; release qualification uses the
same Rust Cargo/feature validator directly.

Release ownership lifecycle checks likewise run in one sequential process via
`tools/kontor stack-ownership-controls --binary <test-binary> --log <log-path>`.
The five exact tests must all pass within a 10-minute whole-process timeout.
Stack-overflow and deep-chain probes retain separate processes and their existing
timeouts because a native abort must not take down unrelated tests.

The aggregate requires an explicit profile policy: exactly three release reports
plus all three dev smoke reports, or exactly six full qualification reports.
Missing artifacts, failed upstream jobs and incomplete smoke logs fail the gate.
It never infers required coverage from the reports that happen to be present.

Use the workflow's **Run workflow**, profiles **full**, for exhaustive dev/release
qualification when a compiler, engine or other relevant change warrants it.
Profiles **release** runs normal release qualification plus dev smoke. Full dev
qualification remains manual. These checks establish bounded correctness and
cross-platform agreement, not throughput acceptance.

## Retired prelaunch resource certification

The separate S2 discovery, guard, chain and final workflow, Python capture and
verification suite, synthetic report tests, schemas and source manifests were
retired after the protocol-upgrade initiative. Their last complete source is
[commit 9a286b68](https://github.com/KontorProtocol/Kontor/tree/9a286b68883517cf7871e9c6d5e22ac640d0be5b/tools/native-stack).
The workflow is archived at the same commit under `.github/workflows/native-stack-s2.yml`.
Use that revision to interpret or verify its historical reports. The historical
S2 proposal and amendment documents describe that experiment, not a current
instruction to rerun its prelaunch acceptance campaign.

This is retirement of a separate certification claim. Ordinary release checks
do not replace its archived memory envelopes, reviewed boundary-depth selection,
measured phase/provenance evidence, or 41-case cross-cell certification. The old
comparator itself returned `qualification_status: missing` even after successful
case-semantic comparison. No historical result is upgraded to acceptance by this
cleanup, and future changes needing those claims require an explicitly scoped
investigation.

The retained boundaries are:

- Rust release capture/comparison, owned chain and cancellation checks, and the
  eight bounded dev smoke tests. Their cases, protocol limits and required cells are unchanged.
- Runtime regression assertions and manual diagnostics in `native_stack_resource`,
  `native_stack`, `sequential_chains`, and the ownership tests. This includes
  logical-stack preservation and fresh-process measured worker-capacity checks.
  Ignored diagnostics remain manual; their presence is not evidence of execution.
- `ThreadObservation`, shared by the Linux/macOS diagnostic producers. Retired
  report validators and source-archive CLI plumbing are no longer maintained.
- The frozen workload fixture/schema/manifest checks below, which have an
  independent Rust replay caller.

The scope job tests the Rust tooling, including frozen-workload validation,
through `setup-kontor-tools`. The separate Python controls job is removed.

## Local macOS VM-map diagnosis

The existing Rust hook can still emit baseline and peak maps for local diagnosis.
Set `binary` to the indexer test executable for the revision being investigated,
with no other `KONTOR_*` overrides:

```sh
KONTOR_FINITE_STACK_CASE=pending_host_io \
KONTOR_FINITE_STACK_ROLE=target_observed \
KONTOR_RESOURCE_MODE=production \
KONTOR_RESOURCE_TEARDOWN_PROBE=on \
KONTOR_SUSPENDED_64_VMMAP=1 \
"$binary" --ignored --exact \
  runtime::call::tests::native_stack_resource::finite_stack_worker_case \
  --nocapture > suspended-64-vmmap.log 2>&1
```

`SUSPENDED_64_VMMAP:` records contain base64-encoded stdout/stderr and hashes.
Each `/usr/bin/vmmap` call is bounded to 45 seconds; this direct diagnostic has
no overall driver deadline or certification claim. No CI job runs it.

## Retained frozen workloads

Frozen replay calls `kontor_build::workload::verify` directly. The same Rust
validator is available from the existing CLI:

```sh
tools/kontor verify-workload "$PWD/capture/manifest.json" --sha256 <reviewed-sha256>
tools/kontor assemble-workload "$PWD/capture"
```

The validator preserves exact monetary arithmetic, closed document shapes,
archive containment and hashes, receipt ordering, rollback and pruning checks.
Its tests run in the existing tooling setup, without a separate CI job.
Assembly creates an unapproved `candidate-manifest.json`, refuses an existing
file and removes a newly created candidate if verification fails. It does not
approve a workload or replace replay at the captured source revision. Newly
assembled JSON can have different key ordering and therefore a new digest;
existing frozen manifests retain their original bytes and pinned hashes.
Replay output now reports `document_validator: "kontor-build"` instead of the
former informational `python_version` field.

The Linux cgroup performance supervisor and Python external Bitcoin, arrival and
view services were previously retired. Their source and usage are preserved at
commit `84ac9c7213e5d932951b1a4fc6123da9d5e86f46` under this directory.
Rust correctness workloads retain frozen-input identities, independent database
restores, checkpoints, accounting and rollback assertions. Ordinary local runs
use regtest and in-process arrivals/views. Leave `KONTOR_WORKLOAD_BITCOIN_RPC_URL`,
`KONTOR_WORKLOAD_ARRIVAL_SOCKET`, `KONTOR_WORKLOAD_VIEW_SOCKET` and
`KONTOR_WORKLOAD_TRIAL_MEMORY` unset unless deliberately using an external test client.
