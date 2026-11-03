# Protocol upgrade implementation ledger

This is a chronological evidence record. Dated entries describe their state at
that time, not the current status. See the latest entries at the end and the
[current delivery checkpoint](implementation-plan.md#current-delivery-checkpoint-2-november-2026)
for the current architecture, merged phases and remaining gates.

Current scope override, 1 November 2026: oversized-certificate paging and its
greater-than-10-MiB proof acceptance tests are deferred outside this goal by the
operator. Earlier entries describing those as unfinished requirements are
historical. See the latest scope-correction entry and certified-history plan.

## K2b local checkpoint, 31 October 2026

At this historical checkpoint K2b was unmerged. Its implementation and outstanding
phase gates were summarized in [the implementation plan](implementation-plan.md) and
[the agreed production boundary](k2b-production-boundary.md). This entry and the dated entries below
are historical evidence, not the current phase status.

The local production worktree now builds both real independently locked executor
graphs and links them into the node. The bounded ARM64 dev run matches eighteen
scenario groups across both graphs. The separate preserved-input comparison
matches all eleven pre-extraction logical-state stages. No cross-platform result
is inferred from that local run.

Recent local implementation checkpoints:

- `697a2410`: real transaction publication, fees/deposits, failure and replay cases.
- `0044003d`: preserved pre-extraction baseline through the linked node.
- `7850ead2`: audited production node installation and Docker build route.
- `deef86aa` and `f0f09445`: explicit release3/full6 comparison and CI scope selection.
- `aeaa83cf` and `53bb95a0`: actual-library compile controls and their evidence bindings.
- `a7807439`: actual linked-node callback, cursor, admission and panic ownership cases.

The compile controls accept the shared structural factory signatures and reject
cross-graph Wasmtime Engine and Tokio Handle values and private Runtime imports.
All five controls passed against actual staged libraries. The builder/comparator
test suite passes 94 tests; the CI helper suite passes 24 tests. Missing dependencies
and unrelated compiler failures cannot satisfy a negative compile control.

The linked-ownership task was integrated after lead source review and validation
of its actual node report against the integrated source. Its ARM64 dev executable
hash is `53db1247acffef7e01983a2aeceb7d7e4ae1ac58fb070ea53c15e3ed131524d2`.
The five added groups check pending callback cancellation, ordinary callback
failure versus panic quarantine, a guest-held cursor during cancellation, shared
capacity/shutdown with both graphs, and direct export panic classification.
The run also passed the five actual-library compile controls. Evidence is retained
under `.build-cache/linked-ownership-qualification/aarch64-unknown-linux-gnu/dev/executors`
in the parent workspace. This does not establish the remaining raw guest panic
payload or missing-context publication/provenance behavior.

The Daybreak implementer is addressing that remaining clause under bounded task
`kontor-k2b-panic-parity`. A source patch or running build is not a passing result.
The production release container built successfully from runtime source
`a7807439`. Image `a1da95362b4735bb8a9dbb3ad894852e4fe042ce942aaac4a2a60f2301421e96`
contains the exact audited executable with SHA-256
`1fc5d8b0a0cf5168e428b07ec9bd44d6caed6ebffbcdb6c76f22724ff24795ef`.
Non-root CLI help passed and the qualification-only command was rejected.
Preserved ownership reports, build log and linker-input inventory match their
recorded hashes. Evidence is in the production worktree's
`.build-cache/production-release-image-v1-evidence` directory. This local Podman
OCI image omits Docker healthcheck metadata; the Dockerfile healthcheck is
unchanged. These packaging checks do not qualify execution across platforms.
Final platform qualification, consolidated lead/two independent reviews, PR CI
and merge remain pending.

The node compiler wrapper now preserves Cargo's inherited jobserver descriptors.
The original wrapper closed them when spawning `rustc`, producing a bad-descriptor
warning and losing access to Cargo's shared compilation budget. A real inherited
pipe regression fails before the fix and passes after it. All 94 builder/evidence
controls pass with compiler caching disabled. The release image above predates
this builder-only correction; final candidate qualification must use the corrected
wrapper rather than relabel the earlier image evidence.

The consolidated integration review found a gap in that native ownership audit:
the node's dependency archives were added to the common reference inventory.
An unnamespaced retained reference could therefore resolve against a node native
library and pass the check. The preserved graph references do not show an actual
blst, secp256k1 or ring fallback, but the audit did not enforce the required
isolation. Its correction must separate final node-symbol attribution from the
restricted common reference inventory and reject node-copy fallback through a
negative control. Earlier successful audits are not evidence that this gap is fixed.

The focused guest decoder test passes with the exact root-cause payload
`host panic: deliberate host panic for testing` and infrastructure classification.
An attempted linked observation after the view returned failed: pooled-root
quarantine prevents that return. The failed probe was removed. Decoder behavior
is checked through the existing in-tree test path; the actual linked scenarios
check quarantine, session discard and separate export-unwind classification.
These are distinct observations, not a claim that a quarantined pooled call
returns its decoder payload. The new provenance test also passes, preserving
prior writes until rollback after missing-context misuse. Final test integration
and the audit correction are pending at this checkpoint.

No K2b broad CI campaign has been launched. Comparator-only changes select focused
controls; execution/build changes retain the required platform matrix. Before
launching CI, inspect prior runs and preserve equivalent merge-tree evidence to
avoid unnecessary post-merge qualification. The operational performance gate was
superseded by the operator's explicit prelaunch acceptance, not by relabeling the
earlier extreme-workload failures as passes.

## Plan approval

PLAN-1 records the explicit two-party approval of DRAFT-4 content hash
`e08a3a8e3903d800e73d306d0992fd67202932e9994c72df1ad53aff04085eb1`.
Reviewer: Interlink session `64900b0a-c524-49d4-889a-138292b608db`.
Task: `kontor-upgrade-plan-v1`. Approval receipt:
`ccdf27c803fafe9291ab1ffd2bacfc4e`.

The native GDB registration exclusion was subsequently agreed under task
`kontor-upgrade-f1-native-owner`, receipt `4f2da3f765c0db29d6a4518b5957a570`.
The plan records its required K1/K2b enforcement and compatibility evidence.

## F1: merged

Repository: wilfreddenton/wasmtime, target branch function-lifting-metering.
Isolated worktree: `/home/wilfred/Documents/Kontor/wasmtime-protocol-isolation`.
Implementation branch: `kontor/protocol-bundle-isolation`.
Base: `bfdee9ba9a483915dc95432708cf7db8281adbc1`.
Initial review head: `7f05b4392a4ec27c6d66cb8a490cc41339872963`.
Follow-up head: `9944b89928cab6d5eb68bedfbbd9c29d94c6a867`.

Validation completed on Linux ARM64 with Rust 1.99.1:

- Minimal independent dual-VM graph, release profile: distinct lifting charges
  4/16, memory/stack traps, async fuel yielding, alternating and concurrent calls.
- Final link has distinct, defined libunwind helper symbols and no GDB globals.
- Rust fixture formatting, Python syntax, workflow YAML parsing and diff whitespace.

Commands and evidence:

```sh
CCACHE_DISABLE=1 python3 ci/test-bundle-isolation.py --offline --output target/bundle-isolation
rustfmt +1.99.1 --edition 2024 --check tests/bundle-isolation/bundle.rs tests/bundle-isolation/host.rs
```

`target/bundle-isolation/report.json`, `symbols.txt`, and per-graph Cargo locks/logs
are local evidence. The first attempt failed because host ccache could not write
inside the sandbox; disabling that compiler cache resolved the environment failure.

The full Kontor configuration also passes at follow-up head 9944b899 on Linux
ARM64: actual node engine options, synchronous and async components, distinct
portable charges 1026/1028, 100 iterations per concurrent thread, memory/stack
traps and async fuel yielding. The minimal configuration also passes at this head.
Five native-audit regression checks pass, including a real weak-symbol collision
that links successfully but fails the pre-link audit.

Both initial reviews are complete. Follow-up reviews are requested for 9944b899.
Initial findings and disposition:

- Mach exception-port collision: adapters preserve Kontor's existing false setting;
  macOS CI must demonstrate Unix signal-handler chaining. No P1 configuration delta.
- Native audit too narrow: now inventory current Cargo rlibs/build-script archives,
  retain input hashes/symbol maps, reject unowned/intersecting native definitions
  before link and unowned final globals. Explicit compiler runtime exceptions only.
- Unused cache/zstd dependency: accepted review amendment excludes Wasmtime cache;
  K1 enforces and K2b qualifies together with debug-builtins exclusion.
- Test engine differs from node: full case now mirrors Runtime::new_engine options,
  except the deliberately different P2 lifting rate and test hostcall accounting.
- Reused baseline version: docs reserve 51.0.0-dev to exact bfdee9ba; K1 must reject
  source/version identity reuse and normalized suffix collisions.
- Stale/unlocked facade resolution: copy source lock each run, fetch source locked,
  resolve offline and check every package identity against source lock; build locked
  offline and assert identical before/after lock hashes.
- Concurrency too brief: 100 iterations per thread, opposite call order, start barrier.
- Action references: confirmed checkout v7, setup-python v6, upload-artifact v7 and
  Rust 1.99.1 references exist remotely.

The feature branch is pushed. Six-platform/configuration CI is running:
https://github.com/wilfreddenton/wasmtime/actions/runs/40459207093
This is pre-PR evidence collection, agreed with the reviewer. No PR or merge yet.

## Remaining work

F2 is implemented and under final qualification, not yet merged. F3 and K1-K11
(including K2a/K2b) remain unimplemented. The owner-only dark Site now opens with PLAN-1 and implementation status, with
all thirteen original chapters clearly marked as archived research proposals.
Deployment appgdep_6ae0413164808191831c25596ac807d2 succeeded from source
057b9a9476eb19fcdf9e7834b59dc2abdd66cbb6. The final implemented-system
documentation and replacement of archived machinery remain outstanding. Full goal completion requires every approved
phase, both reviews per PR, current-head green CI, verified merges, and integrated
acceptance evidence. F1's VM test is not evidence for the full node dependency closure.

### F1 follow-up review at 9944b899

Independent subagent found C++ legacy mangled symbols were incorrectly excluded
by the Rust symbol filter. Accepted and fixed in ca04b651 with a real C++ weak
global regression; six audit checks and the full Linux ARM dual-VM test pass.
The second finding is x86-only ittapi via unused profiling. Explicit exclusion
is proposed to the Interlink reviewer; no ownership exemption has been added.
Follow-up review and current-head CI remain required before PR creation.

### First platform CI outcome and fixes

Run 40459207093 at 9944b899 completed with Linux ARM minimal/full and Linux x86
minimal green. Both macOS jobs failed the final audit on the exact Mach-O
linker-created executable-header symbol; fixed in 80d40d30 with a final-only,
macOS-only allowance and input-rejection regression. Linux x86 full failed on
166 colliding ITT native definitions per graph. The downloaded native input map
confirmed this is the unused profiling feature, not a linker infrastructure issue.

Reviewer explicitly approved excluding profiling and the narrow Mach-O exception
in receipt c289a78411b46d06a5bbbebc9ae7fc47. Implementation explicitly agreed.
PLAN-1 records cumulative K1 enforcement and K2b feature parity requirements.
The revised full configuration is building locally before the combined push.
No green macOS runtime evidence exists yet, because the audit correctly stopped
before execution. Seven native-audit regression checks pass locally.

### Current candidate fc71db2d

Head: fc71db2d8b473424d0a4c528d2a72dbe27986de7. Independent subagent
follow-up review completed with no remaining material findings. It independently
ran seven audit regressions and checked feature rejection, symbol classification,
Mach-O exception scope, engine configuration and documentation. All prior findings
were accepted and fixed. No finding was declined. Current-head execution and
platform CI remain acceptance gates. The Interlink reviewer requests all six green
jobs plus this disposition for its final exact-head review.

The exact candidate fc71db2d full Kontor configuration passed on Linux ARM64,
including the resolved-feature rejection and both native audits. It is pushed.
Current-head six-job CI is in progress:
https://github.com/wilfreddenton/wasmtime/actions/runs/40460693192
All previous run jobs are terminal; macOS full also failed only on the fixed
executable-header exception. No PR or merge is claimed.

### F2 preparation during F1 CI (not a phase implementation)

A disposable native probe under /tmp/kontor-blst-namespace-probe compiled the
registry blst 0.3.17 C and assembly for Linux ARM/x86 and assembly for macOS
ARM/x86. The union contains 311 global definitions, including internal assembly
helpers and CPU-detection state, so prefixing only public blst_* functions would
be insufficient. A generated macro header namespaces all observed definitions.
No unprefixed definitions remained in those six object outputs. One existing
x86 portable SHA alias redefinition needs careful treatment in the real build.
The combined ARM link exposed a conditional-compilation collision in vect.c: defining internal function names
as rename macros also enables its #ifdef fallback implementations, producing
duplicate assembly exports. The real patch must preserve those conditions;
no passing dual-library execution is claimed yet. This is feasibility evidence,
not F2's required dual-Rust graph, concurrent signature, feature or platform tests.
macOS C compilation cannot be qualified locally without its SDK; use actual CI.
No production F2 files or dependency selections have changed.

The F2 probe's subsequent post-preprocessing token rewrite preserves both
conditional-compilation and token-paste behavior. Original and namespaced ARM
C/assembly objects now link in one executable and derive identical compressed
public keys. This supports using cc's configured preprocessor first, then exact
symbol-token rewriting and normal compilation. Full BLS vectors, malformed inputs,
concurrency, dual Rust graphs and actual platform qualification remain F2 gates.

### F1 candidate acceptance evidence

Run 40460693192 completed successfully on fc71db2d: all six jobs green. Reports
confirm actual aarch64-apple-darwin, aarch64-unknown-linux-gnu and
x86_64-unknown-linux-gnu execution, each minimal/full. Downloaded evidence under
/tmp/kontor-f1-fc71-evidence includes independent locks, current native inputs,
final native maps and runtime reports. Checked unchanged before/after lock hashes,
forbidden feature absence and distinct helper addresses in every report. Final
Interlink exact-head review requested in message 651b2f1469fa0b394f5e33593c696b9b.
No PR exists until that review is completed and addressed.

### F1 final review approval

Interlink reviewer explicitly approved exact head fc71db2d, receipt
5463eaacf940bd74c44a7c48c0a754a3, task kontor-upgrade-f1-review. It independently
verified clean worktree, all six green jobs, distinct helper addresses, unchanged
lock hashes and all prior fixes. Both required reviews are now completed and
addressed. No findings declined. Carry forward to K1: intersect Rust-mangled and
compiler-anonymous symbols too to catch metadata mistakes, and enforce the
version/source guard in code. Carry forward to K2b: real canon-lift-async contract
coverage; F1's async API call uses a sync-lifted component function.

F1 PR opened after both reviews: https://github.com/wilfreddenton/wasmtime/pull/1
Head remains fc71db2d; base remains bfdee9ba. PR-triggered six-job run
40461985893 is in progress, so no merge yet. Previous current-head push run
40460693192 is green.

### F1 merge verified

PR https://github.com/wilfreddenton/wasmtime/pull/1 merged at
2026-10-27T06:46:26Z into function-lifting-metering. Merge commit:
525ffedef9bc8babdd9c0b3bd703a5ba5793fcb8. PR run 40461985893 passed all six
jobs on reviewed head fc71db2d. Fetched target branch and verified its tree is
identical to that tested head. Both required reviews and all findings are recorded
above. Portable lifting source is unchanged. No advisory exception was added.

## F2: native crypto isolation, beginning implementation

Kontor origin/main revalidated at 2c5cff0ddc3eada52f143f61109b6360d3732c6f.
Isolated branch feature/protocol-native-crypto in protocol-upgrades worktree.
F1 dependency is now merged. The approved scope amendment and conditions C1-C5
are recorded in the implementation plan, receipt 7f362ce63833d9e90868fe0e71aeddac.
All phases after F1 remain unmerged and require both reviews plus current-head CI.

### F2 initial implementation evidence (not review-ready)

Pristine crate archives verified against core/Cargo.lock checksums and recorded in
tools/native-crypto/sources.json, including upstream VCS metadata. ring's archive
reports a dirty VCS tree, so the published archive checksum is the source identity.
Vendor scripts verify each tree equals its pinned pristine archive plus recorded
patch. A shared owned kontor-native-build crate validates namespace identifiers,
rejects bundle builds missing a namespace, and rewrites tokens after preprocessing.
Its three lexical/namespace tests pass.

Initial hooks are implemented for all three crates, with namespaces opt-in and
ordinary build branches preserved. A standalone Rust smoke executable using all
three patched crates verifies BLS signing/verification, SHA-256 and ECDSA. Native
archive inspection on ARM found 289 blst, 80 ring core, 3 ring test and 65 secp
definitions, all carrying the requested namespace. This is single-graph smoke
evidence, not the required dual-graph or instruction-equivalence proof.

The first smoke link exposed ring's packaged generated-prefix headers; namespaced
builds now copy packaged assembly into OUT_DIR and generate matching headers.
No new assembler generator dependency is introduced. Default builds use their
original packaged path. Vendored secp's upstream cfg names are explicitly declared
for rustc check-cfg, since path dependencies no longer receive registry lint caps.
Its four Rust exports and C references use the same prefix.

The default `cargo test -p bls-crypto --lib` command compiled successfully but
ran zero tests; record this only as compilation evidence. No default-output parity
or complete default test coverage is claimed. Remaining F2 work includes durable
fixtures/harness, full vectors, malformed inputs, dual graphs and concurrent calls,
upstream/default/namespaced instruction and data comparison, platform and SDK
regressions, CI integration, documentation, both reviews and green PR/merge.
No F2 commit or PR exists yet.

F1 automatic post-merge run 40463102230 also completed successfully on merge
commit 525ffedef9bc8babdd9c0b3bd703a5ba5793fcb8. The independent Interlink merge
verification is receipt 7d36262afe311385088860de4135d81a.

### F2 native equivalence and dual-graph checkpoint

The durable harness `tools/native-crypto/qualify.py` passed on Linux ARM with
Rust 1.99.1. Current evidence is `target/native-crypto-evidence/report.json` in
the isolated worktree. Its source manifest records exact input-file SHA-256s and
the harness rejects source edits during qualification. Current Cargo messages
identify archive inputs; independently pruned locks are checked against the core
lock and consumed unchanged by the builds. Native compiler invocations are
retained in each graph's build-script logs.

Six builds passed: pristine, patched default and patched namespaced, each under
portable blst + low-memory secp + recovery, and platform blst + ordinary secp +
recovery. All native archives matched pristine loadable instruction/data bytes,
zero-fill sizes, alignments, symbol properties, relocations and relevant COMDATs
after symbol-name normalization. Debug metadata is excluded; data bytes are never
namespace-normalized. The complete comparator is a pinned, independently locked
Rust tool using the object parser for ELF/Mach-O.

Fixtures cover full SHA-256 and RFC 8032 Ed25519 vectors, BLS signatures and
aggregation, ECDSA signatures/recovery, Schnorr signatures, malformed encodings
and wrong-message rejection. Deterministic output bytes matched pristine under
both feature configurations. Both independently built namespaced rlib graphs
linked into one executable and passed 800 exercises on four threads with
first-use races and opposite call orders. Prelink native/Rust-rlib ownership,
zero cross-graph native intersections and final-link ownership checks passed.
Required live crypto entry points have distinct addresses. All three actual
build scripts rejected a protocol bundle with no namespace for the expected
reason.

The recovery fixture found five missed FFI link attributes in secp's optional
`recovery.rs`; they are fixed in the recorded vendor patch. Five comparator test
groups pass, including deliberate instruction/data/relocation/binding/alignment
mutations and Linux ARM/x86 plus Mach-O ARM/x86 object fixtures. The cross-format
fixtures validate the comparator, not full crypto builds on those targets.
Object-tool Clippy with warnings denied, core/tool/fixture formatting, Python
syntax checks, and vendor byte/type/executable-mode reproduction checks pass.

The new native-crypto CI matrix targets Linux x86, Linux ARM and macOS ARM.
Mobile CI now also triggers on vendor-only changes. Cross-platform qualification,
SDK/mobile parity evidence, required phase reviews, PR CI and merge are still
pending. No F2 completion is claimed, and later phases remain unimplemented.

### F2 first remote matrix and review corrections

Checkpoint commit 88ce3300a05faace5ba0117fc52092c6935e6981 is pushed on
feature/protocol-native-crypto. Native qualification run 40468574927 passed Linux
x86 and Linux ARM. macOS failed the pristine/default ring comparison. Downloaded
reports show only two provisional `__eh_frame` section-address differences;
instruction/data/unwind bytes, symbol properties and relocations were identical.
The comparator now uses section-relative symbol offsets and ignores provisional
relocatable section placement. No unwind bytes or relocations are excluded.
An ARM Mach-O debug-layout regression covers this case. x86 unwind bytes can
encode provisional PC-relative values; differing bytes remain a strict failure.

Both the independent subagent and designated Interlink reviewer reviewed 88ce3300.
Interlink receipt e54539b392e4c52af4428cefdc5ef125 requested changes. Both reviews
identified the material undefined-reference gap: a missed bare reference could
bind to the ordinary node's crypto copy while definition audits and vectors pass.
The implementation now audits undefined references, rejects bare crypto-family
references in the object reporter, records per-symbol namespace coverage, and
links a third ordinary node graph alongside the two namespaced graphs. A negative
control demonstrates the silent cross-binding and rejects it with both audits.
The three-graph host passed 1,200 concurrent exercises locally, with all six
pristine/default/namespaced builds and native comparisons passing. Evidence is
`target/native-crypto-three-graphs`; subsequent comparator/parser changes were
rechecked against those current-source archives. Fresh exact-head remote evidence
is still required before phase acceptance.

An apostrophe in an assembly comment no longer lets the lexical rewriter consume
following lines. Four namespace-helper tests and seven comparator groups pass.
ring uses the already validated namespace value throughout its build path.
No Unix system/prebuilt-library escape exists in these ring/secp versions; ring's
Windows preassembled-object path is already rejected for namespaced builds.
Source reproduction was already run inside qualify.py; it is now also an explicit
named CI step. The reviewer C5 finding was therefore a visibility issue, not an
absent verification gate. No correctness finding was declined.

Ordinary node/SDK builds, Wasm native object parity, mobile CI, the corrected macOS
matrix and follow-up reviews remain open. There is still no F2 PR or merge.

### F2 corrected platform matrix

Commit 6371bdcefabfd885ce40c0ce5546f940e6562649 passed native qualification run
40470692823 on Linux x86, Linux ARM and macOS ARM. Downloaded reports in
`target/f2-ci-6371bdce` match every recorded source SHA-256 against the current
checkout. Each platform completed all six builds, native equivalence checks,
three-graph linking and 1,200 concurrent exercises. Owned definition counts are
446/446/446 on ARM platforms and 508/508/488 on Linux x86, reflecting the different
feature configurations. All graph intersections, cross-graph references and
unowned definition checks passed.

The independent subagent follow-up found no new material issue in 6371bdce and
independently reran seven comparator groups, vendor reconstruction and the
three-graph executable. Interlink follow-up is requested with exact-head remote
evidence. Its full phase approval remains pending.

The ordinary `kontor-sdk-native` build and its existing numeric bridge unit test
pass locally. That single test does not demonstrate crypto parity. The repository's
pinned `tools/kontor build sdk --check` is now running to validate the actual Wasm
generation path. Wasm native object comparison, SDK crypto parity, ordinary node
CI, mobile CI, and final review/PR/merge remain required F2 work.

The pinned SDK generation completed and its 64 binding-export tests passed.
`--check` failed because only `sdk/src/component/kontor-sdk.core.wasm` changed;
generated JavaScript, interfaces and provenance matched. Candidates remain under
`.build-cache/generated`, and committed SDK artifacts have not been replaced.
The new `compare-sdk.mjs` executed both actual Wasm builds with pinned Node
24.22.1: key generation, EIP-2333 derivation, public keys, signatures, aggregation,
verification and six malformed-input error cases matched exactly. Local evidence
is `/tmp/kontor-f2-sdk-crypto-parity.json`. This does not establish native-object
equivalence or every SDK behavior. WAT inspection shows function/data placement
differences, so the changed artifact is not being dismissed as debug-only.

An isolated detached baseline worktree, `protocol-sdk-baseline`, was created at
2c5cff0ddc3eada52f143f61109b6360d3732c6f. It will build the pristine SDK under the
same pinned container/tool paths for direct Wasm C-object comparison. Only source
and tool download caches are reused; build outputs are independent.

The pristine baseline SDK build reproduced its committed outputs byte-for-byte.
Both full Wasm C archives, including all bytes and archive structure, are identical
between pristine and patched default builds: blst SHA-256
`f679a3233a39a8cbd330da92bfbd5e799df7e65e656381c14a03df6519c6f6cb`
and secp256k1-sys
`5efd109af0e848cc4a19becb1804e76a5f9cd6883797cf6a13fe4315cfe6f23d`.
The combined local record is `target/sdk-compatibility.json`.

Pristine Wasm crypto vectors are recorded with their reference commit and Wasm
hash. A new native SDK integration test passed against these bytes and errors,
including Kontor's actual min_sig API. The comparison script verifies that its
baseline is the recorded pristine artifact, avoiding accidental self-comparison.
The SDK Wasm was then regenerated through `tools/kontor build sdk`; only
`kontor-sdk.core.wasm` changed (1,696,861 to 1,696,805 bytes). Candidate and pristine
native C code are byte-identical; the full Rust-linked artifact has different
function/data placement. Final reproducibility, SDK CI and mobile CI remain open.

Checkpoint 4d902e7b89679475136caa62099f8de72c5c2c91 passed native matrix
40473648429. Full CI 40473709440 and Mobile 40473716091 were explicitly started
on that head before PR creation. The iOS and Android Rust cross-builds passed;
binding/binary packaging and full CI are still running at this checkpoint.
Core Clippy found a new test-helper lint (`chunks_exact_to_as_chunks`), not an
advisory failure. The helper now uses `as_chunks` with an explicit complete-byte
assertion, and targeted SDK Clippy with warnings denied passes locally. A fresh
head will validate that correction. The actual Wasm crypto comparison is also
being added to reproducible-build CI, with the pinned pristine artifact extracted
from its recorded Git commit and a report retained with generated outputs.

Mobile run 40473716091 completed green on 4d902e7b: iOS and Android Rust
cross-builds, native binaries, binding regeneration/type checks and web/React
Native SDK bundles all passed. The same head's SDK and reproducible contracts/SDK
jobs passed; core test jobs remain in progress while the lint correction is
prepared. The new CI extraction/comparison step was exercised locally with the
recorded pristine Git files and pinned Node, and the corrected native crypto
integration test passed again.

The owner-private dark Site was updated from source b82bb8dba505d9edeff8f74241ca3fa43cd10d12,
deployment appgdep_6ae0636244c88191898240fa85e11529 (succeeded). Its implementation
chapter now distinguishes verified three-graph native/SDK evidence from remaining
phase gates and later protocol work. Access remains owner-only, with no external
visitors. Static structure, internal anchors and evidence downloads were checked;
no new browser-based visual verification was performed for this text-only update.


### F2 final review and PR preparation

Interlink reviewer approved ea7ae9ea4d35bdfaf5fc56d895746bc4bf23952d against
base 2c5cff0ddc3eada52f143f61109b6360d3732c6f for PR creation, receipt
`216b0b253636a6fa55a4b90350355557`. F2-1 through F2-4 are fixed; F2-5 is
inapplicable because secp has no external-symbols path and blst rejects its
prebuilt path when namespaced. The independent subagent also reported no material
findings through ea7ae9ea, including the new CI reference extraction/comparison.
Merge remains conditional on the exact PR head's CI, native qualification and
mobile checks. No review approval substitutes for these checks.

Native qualification run 40475297184 passed all three platforms on ea7ae9ea.
Full CI 40475342328 has passed lint and all security audits, with core tests, SDK
and reproducible builds still running. No advisory exception was added by F2.
Mobile is green on 4d902e7b; the PR must supply current-head validation.

The reviewer requested investigation of embedded panic-location strings. WAT
inspection confirms the pristine SDK includes the 84-byte path
`/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/secp256k1-sys-0.10.1/src/lib.rs`,
where the candidate embeds the 31-byte `vendor/secp256k1-sys/src/lib.rs`. This
confirms changed source-location data and explains 53 fewer path bytes. It does
not by itself prove the cause of all 56 fewer Wasm bytes or the full changed
function placement. The byte-identical C archives and recorded actual SDK
compatibility checks remain the acceptance evidence; no claim of full linked
binary equivalence is made. K2b now explicitly checks vendored-path panic-location
strings in host error-text parity, including native execution paths.

### F2 merge and container correction

PR #604 merged as 28789f61e1622a5c631ef7acecbab9ffbd532577 after full CI
40476490470, native qualification 40476490171 and mobile 40476490159 passed
on reviewed head 26be2a72884fd7536b331d0efaa6eb3c2f5b49bd. The fetched
merge tree equals that reviewed head. All 747 source hashes in each of the three
native platform reports matched the reviewed files. Each platform completed
1,200 concurrent crypto exercises with the same vector hash. Both reviewers
approved the final behavior; the Interlink reviewer independently confirmed the
merge and CI evidence in receipt 5649e3ebb1383b0ff48a711fac4b4aa5.

Main CI 40479610372 then exposed a container integration regression in job
122106308843. Docker jobs previously ran only after merge. Cargo Chef regenerated
the workspace helper as a stub after the cacher copied the real vendor sources,
so ring's build script could no longer import `kontor_native_build::Namespace`.
This is an implementation defect, not an infrastructure or advisory failure.
Post-merge native and mobile runs 40479610314 and 40479610145 passed.

The corrective branch excludes the helper from the workspace, preserving its
source as an ordinary path build dependency. Its own committed lock, exact
`cc = 1.8.0` pin, formatting, Clippy and unit-test CI replace the lost workspace
coverage. A lock check compares dependency identities and verifies that all
three native vendors still use the helper. The core lock is unchanged. A new
PR-time job builds the actual planner and cacher on Linux ARM64 and AMD64 without
publishing images or requiring registry write credentials. This gate covers all
core source changes, including future path crates, plus the Docker build inputs.

Local standalone helper tests pass (four tests), along with locked Clippy for all
targets with warnings denied, formatting, and the lock-parity check. A deliberately
changed helper `cc` version is rejected. Core metadata confirms the helper is not
a workspace member, with the core lock unchanged.

The pinned Chef image's skeleton negative control replaces the member helper with
an empty file, while the excluded helper remains byte-identical. The full actual
Dockerfile planner and cacher then completed locally on ARM64, using two Cargo
jobs. Release compilation took 8m06s and compiled the real helper, ring, blst and
secp256k1-sys successfully. Completed cacher image:
`699a24b5362647e27a1c0575134d0b5a33f7d7e0b6ad19e51d2fc30b7e8f7375`.
The helper source inside that image and in the reviewed checkout both hash to
`4634e2c388755d98c7f7d5669644a90e53b205d565579f869d938acad09b086f`.
Logs: `/tmp/kontor-f2-chef-cacher.log` and
`/tmp/kontor-f2-chef-skeleton.log` on the implementation host.

Independent subagent review found no material issues in base
28789f61e1622a5c631ef7acecbab9ffbd532577 through corrective implementation
5ba82a5d2ccffc3787aae763784f485756cc43a7. It checked the Docker/Cargo
integration, retained helper CI coverage and unchanged dependency resolution,
and independently ran the lock-parity check. It confirmed review carryover to
documentation head 8326a69058075d2411ef0a75214f608047e5c7a1 after inspecting
the completed build log.

Interlink approved the full correction through 8326a690 for PR creation in receipt
`4bede2fded3fab76b8b7b074f6f72283`. Its maintenance note about updating the
helper pin alongside core's `cc` is now explicit in the README. Multiple core
`cc` versions are deliberately rejected today; a future graph with multiple
versions must instead verify the exact native vendor edges. Both new Docker
cache jobs must pass on the PR head. The post-merge main image build must also
succeed before F3 commits proceed. F3 implementation and tests remain isolated.


## F2 corrective merge and post-main closure

PR605 merged as `6504523fa674211d8781c26905961da090f94efb`. Main run40489996759,
native40489997143 and mobile40489996758 all passed. Main includes both architecture
cache/image builds and multiarch publication. No dependency advisory exception.

## F3 source and platform qualification, not yet merged

Malachite worktree `malachite-protocol-lifecycle`, head
`cdc0ea41776bdf2135f0267ccbf2e3ea05e39785`. Both source reviews and follow-ups
complete. Production changes own the engine runtime, actors, WAL threads, metrics
and interface watcher, retain ordinary WAL errors across actor teardown, and keep
ownership after timeouts. No F3 PR yet. Fork CI prerequisite PR2 must merge first;
F3 then rebases/re-signs and requalifies the actual final head and PR policies.

Platform run40501837563 passed all three platforms, each with one real lifecycle
fixture and 54 engine unit tests. Linux x86 fixture54.12s, worst watcher17.302us;
Linux ARM54.13s/52.89us; macOS58.06s/702us. Watcher bound is500ms. Linux diagnostic
runs exposed a joined owner thread still visible after address-space release.
The observer waits <=1s only for identified PF_EXITING/vsize0 entries, freezes
initial live counts and captures FDs immediately. A mixed negative control proves
live workers cannot disappear into an unrelated exit wait. The x86 current-head
run observed a real owner exit requiring two re-polls42.008us; synthetic-control
waits are recorded separately in fork documentation.

The initial observer approval77c48f41e9f2f3b05f2b373471467cc7 was withdrawn after
independent review found live-observation loss during full re-enumeration. The fix
was reviewed by both, Interlink superseding approval15533d850d739eba00bd1068d1ffb9f0.

## Fork CI bootstrap prerequisite, PR2

https://github.com/KontorProtocol/malachite/pull/2
Current head `5985ce345cfe04f1c492b3bba02c0aa7bb88e017`, no merge yet.
Both reviews complete. Public runners, compiler1.99.1 qualification with separate
MSRV verification, original pinned path/title actions, direct fail-closed Clippy,
coverage failure propagation, and retained substantive suites. Quint0.27.0 matches
MBT; semver0.51.0 supports current rustdoc format. No production algorithm/API,
dependency, lockfile or specification changes.

Current-head CI evidence: unit756pass/3existing skips; maelstrom discovery22pass/
1ignored and application215pass/5ignored; MBT5pass0skips; Quint47files typecheck and
89cases across16files pass at max-samples100. Semver CI succeeded for the nine
selected crates; local full analysis records202passing/58inapplicable checks each.
Clippy, fmt, no_std, MSRV, standalone, spelling and workflow validation passed.
Coverage and Rust CodeQL are still running and remain merge gates.

Only upstream PR policies309324264/309324265 were temporarily disabled for the
bootstrap, at11:37:54.933867Z and11:37:56.050199Z on2026-10-27. Re-enable immediately
after merge, verify active states, and require passing policies on the F3 PR.
No test/security workflow is disabled. Superseded9d4a Rust/Coverage runs were
canceled after current-head Rust passed; cancellation is not qualification evidence.

The private dark Site was updated from source429d696e8fde840e1f1e5a8aae65956247cb15b8,
deploymentappgdep_6ae095934a74819188416894ae975125 succeeded. Static structure,
anchors and downloads verified; no new browser visual QA for this text-only update.

## K1 preparation

Isolated worktree `protocol-bundle-build`, branch `feat/protocol-bundle-build`,
base verified main6504523fa674211d8781c26905961da090f94efb. Plan/evidence preparation
only so far. Release-path clarification is recorded in the implementation plan.
The full K1-K11 system remains outstanding.

F3 resident-timer documentation was independently reviewed and approved by Interlink
in receipt558607a501a8b37c048f08e29465b558. It distinguishes asynchronous removal
of canceled timer records from destruction of engine futures and authority. The
named per-graph helper is not a permission to detach per-engine workers.

## F3 PR 3 qualification follow-up

Bootstrap PR 2 merged as 0821ca5ebbe29d538a2e7edbd49990010da8326d after
exact-head substantive CI passed. Its merge tree equals reviewed/tested head
5985ce345cfe04f1c492b3bba02c0aa7bb88e017. Both temporarily disabled policy
workflows were restored immediately and independently verified active. PR 3
subsequently passed the collaborator, title and commit-signature policies.

Bootstrap main Rust run 40505982903 nevertheless failed the pre-existing WAL
concurrent-crash test. The test truncates through an uncooperative raw handle
during a live multi-write append, which can correctly produce a CRC error.
F3 carries a separately committed test correction: 284 torn-tail cut offsets
preserve the complete prefix and support subsequent append/reopen; deterministic
mid-append external truncation remains InvalidData. No production WAL changes.
Full final-head F3 CI and its post-merge main run replace this outstanding gate,
per Interlink agreement 697dc0d355c0b39970ca7069b531bbfe. Main red is not accepted
as green. Nextest process isolation is required for the existing process-spawn
test to avoid inherited advisory-lock interference under concurrent libtest.

F3 PR 3 is open at https://github.com/KontorProtocol/malachite/pull/3. Initial
head 754e918df9d603de1175614c2bf3dbd72542058d passed the dedicated platform
lifecycle jobs but failed workspace resource observation and semantic versioning.
The corrected Linux observer waits only for initially terminal PF_EXITING tasks
with a one-second bound, freezes initially live counts and captures FDs before
waiting. Linux can wake pthread_join before clearing task->mm, so requiring zero
vsize was too strict. Tokio native joins remain intact.

The lifecycle API intentionally changes NodeMsg (variant and unwind traits) and
wal::Args. The fork now declares 0.9.0-kontor.1 consistently across all 30 own
packages; every third-party lock record is identical. Future bundles must pin
the exact revision and explicitly accept the prerelease requirement. Fork semver
CI checks the PR's merge base and derives an explicit numeric release policy.
Unchanged numeric versions allow additions but reject breaking API changes,
including suffix-only bumps. Real checker controls: removed function fails one
of 202 checks; retained plus added function passes 202; both report 58 skips.
The intentional 0.8.2→0.9.0 major transition runs zero checks and skips 260 per
crate, which accepts its version declaration but does not prove API compatibility.

Both reviewers approved these follow-ups. Local lifecycle 54.25 seconds, watcher
worst 23.876 microseconds, workspace Clippy and six WAL crash tests pass. Full local workspace passed 761 tests with three existing skips and no retries.
Final PR/main qualification remains pending. K1 is not started
in production; this worktree contains only plan and evidence preparation.

The final follow-up head is 6a3917201875f49d28016cbfa18ee6b8393cbf46, with
both committed-head approvals (Interlink 4c53aff9d818ec77149587a6a17dd8f5).
The separate WAL test-only commit is 12e36a41c82c8f5782377a43c5181751630c8ce2.
Exact-head Rust run40510810713 passed all jobs, including761 workspace tests
with3 existing skips. Dedicated platform run40510810370 passed Linux x86
(54.15s fixture,26.169us quiet watcher), ARM(54.12s,30.817us), and macOS
(56.91s,423.666us), plus54 engine units on each. Semver run40510810622 passed
with all nine explicit-major0/260 results printed. Policies, CodeQL, MBT and
Quint passed. Coverage run40510810318 is still pending. No merge yet.

## K1 resolution and ownership preflight

Temporary files only, no production bundle implementation yet. A combined real
Wasmtime/F3/crypto manifest resolves 464 reachable packages on Linux ARM64 from
the seeded node lock, including itoa 1.0.14 and Tokio 1.53.3. Native-build
candidates are blst, ring, secp256k1-sys, Wasmtime, its fiber crate and jit-debug;
AWS-LC, libsql and zstd are absent from this resolved closure. Metadata is not a
native archive audit, and the checked-in final graph must consume F3's actual
verified merge. A single Cargo graph with exact itoa 1.0.14 and 1.0.15 aliases
fails resolution, confirming that the intended patch conflict is meaningful.

A standalone locked Tokio 1.47.1 Linux probe observed four cold descriptors,
then six after each of forty runtime creation/drop cycles. The identified pair
is retained in Tokio's Unix signal OnceLock per graph, while each runtime drops
its own duplicate receiver. Interlink approved this named ownership class and
the required node control-signal/child-reaping proofs in receipts
5e476ff359000469af853d342588b208 and 3aac0eadc7a134f7a5501daf623fdbd3.
A separately reviewed F3 documentation follow-up will name the existing resource;
K1 must still demonstrate cold-start and repeated combined-graph behavior on all
required targets. No runtime signal subscribers or child-spawn call sites may be
introduced in bundle Kontor/fork sources. VM trap handlers retain their distinct
F1 ownership policy.

## F3 merged; post-merge test race under correction

PR3 merged as be93c1bc4668bb83e7fef023376079fd664ed6c6, with tree
c349bd43a2450b46ab4da76a04efa259c9a96809 identical to reviewed head6a391720.
All final-head checks passed, including coverage40510810318: 998 passed,
nine existing skips, no second attempts. The restored policies passed.

Post-merge Rust40515844978 then failed an unchanged test-app configuration test:
both lib.rs and main.rs compile config.rs, and nextest runs both test binaries
against the same /tmp/config-test.toml. The bin finished first; the lib's cleanup
failed NotFound. The managed lifecycle fixture and all other 760 unit tests
passed. Dependent K1 implementation paused while the race is corrected, with
no blind CI rerun. A local 50-cycle concurrent lib/bin reproduction produced
six failures out of 100 invocations, including missing files and a partially
rewritten configuration. The proposed fix uses a unique tempfile directory per
test invocation, preserving .toml parsing and explicit checked cleanup.

Both reviews approved the Tokio-resource documentation at a5fe0858, based on
be93c1bc (Interlink23993cb5ab864eb84e41292673665d1f). The new test correction
will be separately committed and reviewed in the same small followup PR.
Post-merge F3 closure remains outstanding; K1-K11 remain unimplemented.

## F3 corrective PR4 merged; combined K1 proof first passes locally

Corrective PR4 https://github.com/KontorProtocol/malachite/pull/4 merged as
c9a313bd6d37b7489933db9f0bde3de9ec77e667. Its tree
0702e87017b4bf3c08c785ef4ece021d4315ba11 equals reviewed head5985d492.
Both reviews approved the separate TempDir correction, including Interlink
056f08889216c0edda84a28654941cf7. Local formatting, full workspace Clippy and
761 workspace tests passed (three existing skips, no retries). Actual lifecycle
fixture54.236s. All applicable final PR checks passed. Coverage40518721144:
998 tests passed, nine existing skips, no retries, artifact12743515357.
Quint's PR jobs were correctly path-skipped; they run on main. All fork policies
remain active. Corrected main qualification is running, so F3 closure is pending.

K1 now has two independently locked manifests and an initial builder and proof.
Both real Wasmtime/F3/crypto graphs compiled. Their initial input inventories each
contained about99,000 global definitions; only DW.ref.rust_eh_personality shared
across graphs. This includes Rust and anonymous definitions, not only C symbols.

An explicit target build revealed that Cargo leaves host proc macros outside
RUSTFLAGS. Their identities collided at final metadata load. A checked-in rustc
wrapper applies graph metadata to host and target units while retaining Cargo's
unit metadata. Review agreements de0179cf051240bbe66a88f6f73462d6 and
f756fee5e13f753f31eaa31d97aebc93 require transparent probes, no additional wrapper,
recorded wrapper/flags/cache identity, proc-macro SVH controls, and no compiler
plugin in runtime dependencies. These final hardening checks remain underway.

The first combined Linux ARM64 executable passed 40 real single-validator
consensus decisions across20 same-port replacement cycles, std callbacks,
wrong-graph Any rejection, node SIGTERM/SIGINT and child exit23 while both engines
were live, stable workers/descriptors, concurrent VM/crypto exercises, lifting
charges1026/1028 and compile-time rejection of cross-graph Tokio Sender values.
Cold descriptors4 became8, exactly one Tokio socket pair per graph. Final native
Wasmtime and crypto helpers had distinct addresses. The executable hash was
11d899cb28bded9e13f4a785a27a01c2a1924f44318eae4fbf7204d45781ab67.
This is preliminary local evidence, not final K1 acceptance: complete provenance,
negative controls, Linux Docker/other-platform CI, both reviews and merge remain.
The node still uses its original P1 path; this proof does not implement upgrades.

## F3 corrected main qualified

All applicable workflows on corrected main c9a313bd6d37b7489933db9f0bde3de9ec77e667
passed. Coverage40524021458, Rust40524021486, managed lifecycle40524021402,
Quint40524021918, MBT40524021630, documentation, workflow validation, spelling
and Push on main succeeded. TODO tracking was expected to skip. This closes
the F3 and bootstrap post-merge gates. K1 remains in implementation, with its
early review findings being addressed before final qualification and review.

## K1 ownership and provenance follow-up

The next local Linux ARM64 proof passed with executable hash
39c4ff28916d1ae79d440e646831cbd6647d616db9921f54dbc152a44d5d21c1.
Its audit checks undefined references as well as definitions, concrete host and
pinned sysroot ownership, exact staged inputs, and before/after source stability.
Compiled negative controls reject foreign native imports, weak shared Rust-shaped
definitions, unknown final Rust definitions and strong undeclared unwind imports.

Cold workers/descriptors were 1/4. Each crypto graph added eight blst workers;
each VM graph added eight compilation workers. Both stopped engine graphs left
two timer workers and four Tokio registry descriptors, giving 35/8. Repeated
workloads and twenty replacement cycles kept those counts stable. This measures
one ARM machine; it does not prescribe a universal CPU count.

The independently resolved locks use Tokio 1.53.3 and futures-timer 3.0.4, rather
than F3's 1.47.1 and 3.0.3. Independent review checked the updated blocking-pool
join and lazy SIGCHLD behavior. Timer global.rs and timer.rs are unchanged;
delay.rs adds overflow-safe deadline construction/reset. These are proof graphs,
not a claim of original-P1 semantic equivalence. K2b still owes that comparison.

The targeted follow-up review accepted the original four fixes and identified
two further provenance gaps: alternate Cargo compiler configuration and omitted
inherited workspace manifests. The builder now fixes the exact compiler path
for Cargo, the wrapper and host linkage; it fingerprints complete git dependency
trees and inherited manifests/configuration, and rechecks resolved metadata.
Darwin undefined imports use the attribute-preserving nm format. Nineteen local
Python controls, core builder Clippy and four builder tests passed. Both refreshed
bundle security audits passed with existing core exceptions; no new advisory
exception was added. The exact revised CLI build and platform CI remain pending.

## K1 found a managed shutdown ordering defect

The revised CLI built and linked both graphs, passed ownership and metadata
controls, then failed during the second graph's cold engine stop. Consensus
reported `wal_flush before PublishConsensusMsg` against an already closed WAL
actor. The old manager broadcast stop to every child before awaiting any child;
an active consensus handler could still need its WAL provider. Publication fails
closed, but this shutdown-induced supervision fault would prevent handoff.

K1 qualification is paused for a corrective Malachite PR. Interlink agreement
13a640d2b404ff98fccc6139a39cf089 fixes scope on main c9a313bd: sequential reverse
dependency shutdown, preserving supervisor barriers, mandatory terminal waits,
runtime destruction and final WAL worker joins. No public API, WAL format,
signing or dependency-lock change is intended. The isolated branch is
fix/managed-engine-stop-order in the malachite-stop-order worktree.

A deterministic dependent's final RPC fails on the old manager and succeeds with
the correction. A real TCP peer test verifies network events still reach a live
observer after another subscriber has stopped, including direct replay to a
closed subscriber. The complete existing lifecycle fixture passed in 54.59s,
including blocked WAL work, faults and shutdown panics. Final reviews and CI
remain outstanding. The original failing WAL and logs are preserved locally in
the bundle output's failed-stop-order directory. No success attestation was
emitted for the failed run.

Corrective Malachite PR5 is open:
https://github.com/KontorProtocol/malachite/pull/5
Final reviewed head is 7dd018a1c11af944a54ae841d59e0764fc78b56d, based on
c9a313bd6d37b7489933db9f0bde3de9ec77e667. Both reviewers approved the final
head; Interlink carry-forward receipt 2cced268e892b808b0520a511862070a covers
the final comment/documentation amendment. All 997 remaining workspace tests
passed in 570.434s, with nine existing skips and no retries, in addition to the
separate 54.59s complete lifecycle fixture. Full workspace Clippy and formatting
passed. The signed commit is verified by GitHub. Exact-head CI is running;
merge, main verification and corrected-pin K1 qualification remain pending.

## Corrective shutdown order merged; K1 qualification resumes

PR5 merged as 6d99c0a43a21ff48ff3f69a5f9e834310d0b0b09 after all exact-head
checks passed, including Coverage40537565575, Rust40537565492 and all three
managed lifecycle platforms in40537565497. The fetched main tree
5ce0ddde4b49767d45917aed803ddac3caed50b2 equals reviewed head7dd018a1 exactly.
The squash message is a single line, with no authorship trailer.

Post-merge main CI is running under a fail-fast monitor. The local K1 candidate
build can overlap that CI after verifying the merged tree; this does not close
the post-merge gate or permit final K1 acceptance while main remains unqualified.
Both independent bundle manifests and locks are being moved to this exact merge,
including if-watch, with a check that all other package identities remain unchanged.
The original failing cold-engine test and all ownership/provenance controls must
pass on the corrected pin. Earlier successful binaries are not substitute evidence.

The initial targeted Cargo update also changed prost-build's petgraph selection
from0.7.1 to0.6.5 and removed fixedbitset0.5.7. The pin-preservation check rejected
that unrelated resolution change. The original first lock was recovered from the
existing local qualification image and matched its recorded SHA256 exactly;
the untouched second lock also matched its recorded hash. Only the Malachite
revision strings were then replaced in both locks. Locked offline Cargo metadata
accepted both; all464 resolve nodes, dependency edges and features compare equal
apart from the git revision. The pinned public CLI is rebuilding the candidate.

The corrected-pin first graph compiled. The second graph's ring C compilation
then failed because GCC could not write a temporary assembly file under /tmp
(`Disk quota exceeded`). This was an observed infrastructure failure, not a
teardown or ownership failure. Logs were preserved under .build-cache/pr5-evidence;
the completed coverage log was moved there to relieve the temporary quota.
Qualification resumed with TMPDIR under the workspace filesystem and the same
source, locks and existing compiler cache. No source change or CI rerun was used
to hide the failure. The new run still must complete every qualification check.

## Corrected-pin combined bundle qualification passed locally

The public CLI completed successfully under Rust1.99.1 on Linux ARM64, release.
Both graphs pin6d99c0a43a21ff48ff3f69a5f9e834310d0b0b09. Executable SHA256:
3f2b377f311b61307284e4ff06a09f0c189ae49ce86ac064c5f8ff1135f1a76d.
The builder emitted qualification.json only after all linkage, native/common
ownership, metadata controls, staged input and final source/compiler checks passed.

The original cold shutdown reproducer now passes for both graphs. The run made
42 real decisions, including two cold warmups and20 two-engine replacement cycles.
It also passed host callback panic containment, std callbacks, Any-owner rejection,
cross-graph Tokio compile rejection, signal/child-status checks and concurrent
VM/crypto repetition. The two deliberate callback panics are contained controls.

Cold workers/descriptors1/4 became9/4 and17/4 after each crypto graph,25/4 and33/4
after each VM, then34/6 and35/8 after each engine stopped. Repeated workloads and
replacement cycles retained35/8. Portable lifting results remain1026/1028.
The Linux node-builder image now runs the full qualification separately. Main CI
has passed everything except coverage, which remains active. Container/platform
qualification, final K1 reviews and merge are still required.

## K1 final review and immutable-source correction

Signed K1 head2f00bf37979d03891113a4def80c122c47ce0ee3 is based on6504523f.
The full node-builder ARM container qualification passed on that source, producing
495d289810a409c4f8760275915e379cdffe258a805c82628f861e6df06a13ad and the same
42-decision/resource results as the host run. Its report attests Rust1.99.1,
the compiler, compiler libraries and pinned sysroot inside the builder-base image.

Interlink receipt0cb36ac271f441aa418785b0ba2a55fe approved that exact head with
remaining main/platform CI gates. Its K2b negative-control requirement is recorded:
node dependency definitions must never let bare bundle crypto imports resolve
through the common inventory. The duplicate linker-runtime list entry is removed.

Independent review requested changes for one material source-identity gap: a
pre-existing edit in a cached Git checkout could preserve the revision label
while passing before/after source hashes. The correction verifies raw Git blob
contents, modes, symlinks, index and submodule revisions against pinned objects,
including files marked assume-unchanged. Extra ignored/untracked files are rejected
apart from exact Cargo administrative markers. Registry extraction bytes are also
checked against archives whose SHA256 matches the lockfile. Missing archives fail.

All31 Python controls pass, including12 new identity controls. Both actual graphs
passed verification of2 Git roots and410 registry archives each. The previous
host/container results remain evidence for the earlier source; the corrected
builder must be requalified and receive both follow-up reviews before the PR.

The c08cc7f2 correction passed host qualification and received Interlink approval
in d20657a69435da670f8bd789269b0238. Independent follow-up reproduced a remaining
Git-replacement-ref bypass, so final approval stayed open. All verification Git
commands now disable replacement objects. Graft files are rejected, and raw pinned
commit/reachable-tree objects are rehashed as well. New controls cover replacement
refs, grafts and corrupt commit/tree objects. Git on this host rejects a corrupt
tree during ls-tree itself; the control accepts that native fail-closed result.
All35 controls now pass, and both real source inventories pass the stronger check.
Both reviewers must approve the final correction and qualification must be rerun.

Malachite post-merge verification is complete: all applicable jobs on6d99c0a4
passed, including Coverage40543559798, Rust40543559658 and lifecycle40543559692.
The reviewer independently confirmed this in ac7b8aa6e92ad3987f968cbe6d8fd8b7.

## K1 PR606: Linux x86 linker-anchor correction

Both reviewers approved ca095073f0f603f77b11aa1ed45bed004383509d. Its complete
ARM host and actual node-builder container qualification passed after the final
source-identity correction, with the executable hashes recorded above unchanged.
Both bundle audits reported zero unignored vulnerabilities. PR606 opened at that
head; Linux x86 CI failed in the weak-unwind Python control before bundle builds.
The C compiler added an undefined `_GLOBAL_OFFSET_TABLE_` reference, which the
ownership checker had not attributed to the ELF linker. ARM and macOS CI continued.

The correction requires that exact anchor to exist as a local data or absolute
symbol in the final Linux executable and records its actual address and kind.
It grants no bundle-definition exemption and does not waive unknown imports or
an absent anchor. The weak-unwind control now links its real Linux fixture and
uses the actual linker inventory. Two additional controls cover absent, global,
wrong-kind and non-Linux anchors, unknown imports, and forbidden bundle definitions.
All37 Python controls pass. A cross-compiled x86 object and LLD-linked executable
reproduce the GOT reference, pass with its real local anchor, and fail without it.
The native ARM GNU linker emits a local absolute anchor; LLD emits local data.
Follow-up reviews and corrected-head platform CI remain required before merging.

Both reviewers approved the GOT correction48d20169, including Interlink receipt
ba822bc7ecf0a25dc0014b23772ae307, and it was pushed to PR606. Corrected x86 CI
passed the previously failing Python control and advanced to real qualification.

A separate CLI integration defect was then reproduced: tools/kontor enters core,
and its Python child inherited that directory. Relative --output therefore landed
under core, while macOS CI uploads from the repository root. The existing binary
confirmed the mismatch. The child now starts at the discovered checkout root;
relative outputs are documented accordingly, and absolute outputs remain unchanged.
macOS CI explicitly checks the expected qualification.json before artifact upload.
Linux Docker already passes absolute /evidence and is unaffected. This correction
requires root/core/absolute-path checks and both follow-up reviews before push.

The full local qualification passed with the GOT checker, including42 decisions,
20 replacements and stable35-worker/8-descriptor warm counts. Its actual ELF
GOT owner is local absolute data at000000000382b398. The explicit relative output
in that diagnostic run exposed the CLI bug, so its report is under
core/.build-cache/protocol-bundles/aarch64-unknown-linux-gnu/release rather than
the normal root cache. No qualification source or bundle code changed during it.

Both reviewers approved the CLI correction393d0c73 (Interlink8170c77bf6f5a026fa153723d2c347ad).
All four builder tests, Clippy, formatting and actionlint pass. The real public
CLI was invoked from both root and core, each with relative and absolute outputs,
using a recording Python child rather than duplicating bundle compilation.
All four invocations selected the exact builder script and root working directory;
the relative output resolved to root/.build-cache/pr5-evidence/cli-relative and
the absolute output stayed root/.build-cache/pr5-evidence/cli-absolute. The child
created markers at those destinations. This is CLI routing evidence, not a
substitute qualification result. Records: cli-output-before.txt,
cli-output-after.json and cli-path-tests.log in .build-cache/pr5-evidence.
Corrected-head platform CI remains mandatory before merge.

## Darwin standard-library bitcode reader correction

The retained48d CI matrix passed both Linux node-builder container runs. Its
macOS run compiled both graphs and linked the host, then failed when platform nm
could not inspect Rust1.99.1's libaddr2line Darwin sysroot archive. stderr was
captured but omitted from the subprocess exception. This is an actual qualification
failure, separate from the already-corrected output-upload path.

The exact downloaded Darwin archive contains LLVM23 bitcode. The pinned compiler's
llvm-nm reads it successfully and reports addressless definitions; the older local
LLVM22 plugin fails decoding its attributes. All27 Darwin sysroot archives are
readable with the matching tool, including their undefined references. The previous
hex-address-only parser would have silently omitted bitcode definitions even after
a reader upgrade, so that parser also needed correction.

The builder now uses the llvm-tools-preview reader from Rust1.99.1 for all symbol
inspection, records its path/hash/version, retains addressless bitcode definitions
in ownership/collision inventories, and requires concrete final executable addresses.
Unexpected reader output and nonzero exits fail with their diagnostic; partial
output is never accepted. CI and the qualification Docker stage install the pinned
component. All41 Python controls pass, including bitcode collision/common-shadow,
final-address, malformed-output and partial-reader-failure controls. Complete local
qualification and both follow-up reviews remain required before push.

Reviewer0b056655ada51a8eaa68adf552ccabc0 confirmed the Linux full gate is the
node-builder container, with bare ARM host qualification as additional evidence.
No separate bare x86 run is required. Reviewerc2e389583d3328dc553e895e9bd0afb5
confirmed current compiler/native-environment/runtime/output evidence is sufficient
for K1; it does not include an explicit linker-backend hash. Accurate driver/backend
attestation is recorded as a K11 release item. A default cc-selected ld hash alone
could misidentify Rust's actual backend when linker flags override that selection.

The full local ARM host qualification with the pinned reader passed all41
controls and the real42-decision/20-replacement proof, including ownership and
final source/compiler verification. Executable SHA256:
3f2b377f311b61307284e4ff06a09f0c189ae49ce86ac064c5f8ff1135f1a76d.
The report records the pinned llvm-nm hash/version. Darwin archive inspection
is direct reader evidence, not a claim that the macOS runtime proof has passed.


## Darwin iconv platform declaration

Head 287fef1e passed ordinary CI (including macOS tests) and both Linux bundle
container qualifications. Its Darwin bundle run passed symbol inspection, then
rejected the executable's `/usr/lib/libiconv.2.dylib` dependency. The actual
locked libc 0.2.191 declares `link(name = "iconv")` on Apple unless built with
`rustc-dep-of-std`; both graph inventories show default/extra_traits/std instead.
A pinned-compiler cross-compiled staticlib using this exact crate reports
`-liconv -lSystem -lc -lm`; the sysroot-only control reports System/c/m. The
provenance evidence is in `.build-cache/pr5-evidence/iconv/libc-native-static-libs.log`.

The common platform inventory now includes that exact Apple library path.
Symbol resolution, bundle-shadow rejection and runtime provenance remain active.
All 42 Python controls pass, including acceptance of the actual Darwin linked
paths and rejection of Homebrew, @rpath, a changed iconv soname and an unknown
system library. Both follow-up reviews and current-head platform CI remain
required; this cross-compile probe is not native Darwin runtime qualification.
The previous head's local ARM host and actual node-builder container full
qualification both passed, including 42 real decisions and 20 replacements.

## Corrective aggregate verification classification, 2026-10-27

The agreed correction is isolated from K2a on main `9d4da679`. It addresses
local database failures in three verification paths: public-key identity
resolution/creation, signer-ID BLS resolution for calls, and signer-ID public-key
resolution for registration. The current catch-all verification branch converts
all three into per-operation rejection results. Publisher identity resolution
after successful verification already returns an outer error and must remain so.

Deterministic shape, signature and missing-signer errors retain their existing
classification and complete formatted rejection text. Infrastructure errors must
reach the enclosing block transaction, which explicitly rolls back before
returning the failure. Batch execution also propagates errors before commit, but
its current cleanup relies on the fatal reactor exit and connection teardown;
this correction does not claim immediate batch rollback.

On unchanged production main, the four signed-aggregate fault cases all failed
at the committed-as-rejection assertion with `Ok(())`. The five deterministic
rejection cases passed. After the correction, the focused suite passed all five
tests in 1.20 seconds. Faults are one-shot; each returned error identifies
transaction execution, not the later lifecycle. The nonce-insertion case observes
signer and public-key insertion before the denied write. Every fault restores
the table/checkpoint snapshot and tip, then retries the unchanged signed input.
Registration retries install the expected key and advance nonce once; the Call
retry requires the matching mint receipt to have status `Ok`.

Both source reviews found no material issues after the fixture strengthenings.
Interlink approval is recorded in `5e7f95a07b24de71d20841c5de3f7731`, conditional
on final validation and commit/CI verification. The complete release REGTEST
workspace run passed 967 tests, zero failures and 16 existing ignores across
39 suites, including all 129 real-node integration tests. The first run passed
the library tests but exposed a local test setup error: the new worktree lacked
the ignored `core/target` link required by the regtest harness's node-binary
path. Adding that link to the already built shared target fixed the setup;
no production workaround was added. The complete rerun passed.

Full-workspace release Clippy with tests and warnings denied passed in 69 seconds.
Committed-head and CI confirmation are pending. No dependency, schema or
advisory-exception change is included.

## K3 local acceptance candidate, 1 November 2026

The consolidated independent review of `766ffa454640a47dcc754635363fa2cdfdc7a03d`
found no confirmed material code regression. It identified a caller-coverage gap:
the historical reactor oracle intentionally has unavailable lineage, while the
migration fixture constructs its journal directly. A new bounded scenario starts
from fresh genesis and calls the real reactor block, batch and rollback paths.
It checks empty and fully excluded batches, block/lifecycle ordering, persistent
atomicity when the lifecycle journal append fails, preservation of anchor-height
entries, and exact lineage on replay. The focused in-tree test passed in 29.73
seconds. The reviewer inspected this addition and found no material issue,
preserving the original consolidated review. Feature-enabled library/test Clippy
passed with warnings denied. The rebuilt linked executable passed all 23 scenarios
through both real graphs in 101.42 seconds, including the unchanged historical
semantic oracle. Its SHA-256 is
`12e02b534496b318bc13313cd6d49c296258d2e2e509e937fcb028e56d11bf4d`;
raw evidence is retained in `.build-cache/k3-linked-v4-evidence/`.
The historical oracle and its fixture remain unchanged, and this adds no new CI
matrix or job. The v3 evidence below remains the record for the earlier candidate.

Base: `aad23bccdaa300ed207bb328abc8c124e68efbe9` (PR 618), also verified as
GitHub's current main during candidate preparation. This is unmerged K3 work,
not completion of the protocol-upgrade system. The operator's latest delivery
policy requires lead review plus one combined independent Codex review per
grouped PR. No routine Daybreak assignment or additional review round is involved.

The candidate records witness-inclusive ordered input commitments, reversible
application lineage, exact migration retry keys/results, and genesis stages.
Migration effects, marker, work and cursor share the owned writer transaction.
The dedicated read-only input snapshot remains pinned while same-height writes
occur; cleanup revokes its capabilities before settlement and quarantines failures.
Populated legacy databases preserve ordinary operation with unavailable authentic
lineage. They cannot migrate by inventing history. Live authorization and activation
remain K6/K7, including the real P2 migration and engine handoff.

Execution references bind retained sources, independent locks, resolved features,
effective inherited package properties and an immutable StorageV1 requirement.
Node-only coordinator/ownership/pool changes remain artifact provenance rather
than redefining retained execution. Missing, unknown, changed or duplicate storage
requirements are rejected before executor construction. The current SQL adapter
and shared database dependencies require compatibility with the retained contract;
the requirement is not regenerated from whatever implementation ships next.

Local Linux ARM64 dev build and native ownership audit passed. Executable SHA-256:
`6af6134e32a43390bbea9b53ca91b53c2276589a63a01e9218f9d4c23f6b1a26`.
Both real graphs passed all 22 linked qualification cases in 54.65 seconds,
including migration rollback/retry, immutable input, production registry isolation
and storage-requirement rejection. The unchanged historical semantic oracle and
preserved full SQL-state/receipt/checkpoint comparison passed for both graphs;
the latter took 27.11 seconds. The four new journal tables are checked separately
before exclusion from the old-table comparison. The original semantic fixture and
oracle remain byte-for-byte unchanged. A new module supplies complete typed SQL
snapshots. Raw logs and build/source/audit records are retained locally under
`.build-cache/k3-linked-v3-evidence/`.

The final focused in-tree run passed 62 tests in 0.38 seconds. Its one ignored
helper is explicitly launched by the passing process-crash test, which kills child
processes after effects and after commit, reopens the database and verifies retry.
The pool-saturation addition postdates the linked binary and changes only a test
module excluded from retained semantic identity. It is not claimed as linked-binary
coverage. The node/build/comparator controls passed 26 tests, execution-reference
controls passed nine, and ordinary CI-scope controls passed 38. Default indexer
library/test Clippy with warnings denied passed after the pool-test extension.
Clippy required explicitly dropping the view object acquired at the end of that
test; this changes no production behavior or tested assertion.

The previously observed main CI cluster/WIT failure did not reproduce locally:
the focused cluster lifecycle test passed in 129.29 seconds with the earlier
audited dev node. Its first local attempt could not create sockets in the sandbox.
The successful rerun used local networking and preserved the failure log. The
test now reports the actual WIT error when it fails; this is diagnostic detail,
not a claimed fix for an unestablished cause. No new CI campaign has run for K3.
Final release-platform checks and merge verification remain
required. Local dev samples do not establish all-platform or all-input correctness.

## K3 merged, 1 November 2026

[PR 619](https://github.com/KontorProtocol/Kontor/pull/619) merged as
`fdf6a65d3a14cf88af7271d666bf13b001849d2f`. Its final head was
`c5481a2f168eb45407052eebfdde6f3e96b6f68e`, based on
`aad23bccdaa300ed207bb328abc8c124e68efbe9`. GitHub tested synthetic merge
`168510224e7310f742269b4e8c5ff2f94fd14601`. Both that tree and the actual merged
tree are `32b14250524f795904b736cfd605da3bb934147b`; equality was verified before
requesting cancellation of duplicate post-merge qualification.

The lead and sole independent reviewer completed the consolidated review and
accepted the real-reactor caller follow-up. Later corrections were confined to
legacy test fixture initialization, generated source bindings, and reproducible
migration fixture metadata. The lead inspected those corrections and preserved
review coverage for unchanged production behavior. No material finding remains
for K3. This is completion of K3, not completion of the protocol-upgrade goal.

Two fixture problems were reproduced and fixed without weakening comparisons.
Synthetic legacy fixtures now initialize unavailable canonical history consistently
on first use and reopen; all 27 formerly failing ordinary tests passed on both
platforms. Separately, independent migration qualification runs had random
node-local receipt-stream epochs. The original test copied one seed database to
both graphs and therefore missed the cross-run difference. The strengthened test
uses independent seeds and failed before the correction. The qualification seed
now fixes that metadata before execution, while production still creates random
epochs. The test passed after the change and continues to compare every table.

Final required evidence:

- [Ordinary CI 41287408200](https://github.com/KontorProtocol/Kontor/actions/runs/41287408200)
  passed, including Linux/macOS tests, lint/security, SDK and reproducible outputs.
- [Stack qualification 41287408254](https://github.com/KontorProtocol/Kontor/actions/runs/41287408254)
  passed all three release platforms, eight bounded dev smoke tests on each of
  three platforms, and the explicit cross-platform comparison.
- [Linked-node qualification 41287408362](https://github.com/KontorProtocol/Kontor/actions/runs/41287408362)
  passed both actual retained graphs on Linux x86-64, Linux ARM64 and macOS ARM64,
  including all 23 required scenario groups and the historical semantic baseline.
  The final common observation digest is
  `b32bd8ba109f9ffa8e169b866e3e4d8dc2b7ce8d9ba10df6fdd877bc107906a2`.
- [Docker cache qualification 41287408495](https://github.com/KontorProtocol/Kontor/actions/runs/41287408495)
  and [diagnostics 41287408246](https://github.com/KontorProtocol/Kontor/actions/runs/41287408246)
  passed. Expected unselected image/S2 jobs remained skipped.

Raw final evidence is retained in the `protocol-migrations` worktree under
`.build-cache/k3-ci-c5481a2f/`. The lead independently reran both comparators over
those downloaded artifacts, validating source/lock/compiler/component identities,
raw log hashes, native ownership, type boundaries, exact cases and preserved
historical observations. The reproduced stack comparison equals CI's output.
The linked comparison agrees on all platforms, observation digest and compiler;
only local report paths differ from CI's artifact paths.

Earlier failed or incomplete evidence remains bound to its original source.
The superseded `653ad035` linked run was canceled after its fixture mismatch was
identified. It was not relabeled as a successful final-candidate comparison.
Post-merge qualification runs 41290216054 and 41290216114 duplicate the verified
successful tree; cancellation was requested only after retaining final evidence
and verifying the actual merge. Main CI remains separate because it includes the
production image path absent from PR CI. Both duplicate qualification runs were
subsequently verified as completed with conclusion `cancelled`.

## K4 implementation entry

K4 begins in isolated branch `feat/protocol-certified-history` from verified merge
`fdf6a65d3a14cf88af7271d666bf13b001849d2f`. The lead and sole planning reviewer
already agreed [revision 2 of the concrete plan](certified-history-plan.md),
including restartable closure stages, historical registration provenance, two
explicit executor link sets, and bounded proof paging in K4 rather than deferring
all recovery transport to K9. No repeated planning review is needed for these
unchanged decisions.

A pre-implementation source relocation experiment reproduced the original first
and second definition bytes and IDs from a copied source root using locked offline
resolution. It did not establish compilation or link acceptance. A framing preflight
used actual existing Bitcoin/protobuf/stream/GossipSub encoders with maximum and
many-small transaction inputs. It passed, with a minimum 7,977 bytes of headroom
for the existing signed message. It did not qualify the final K4 schema or complete
RPC aggregation. Both limitations remain explicit implementation acceptance work.

K4 production changes and final acceptance remain unfinished. Publication stays
at the end of the full goal. The Daybreak agent has no new assignment.

The first packaging implementation now freezes the K3 executor input closure from
the exact merged commit in `protocol-bundles/retained/k3`. Its 1,264 recorded files
include local packages, semantic includes, inherited manifests, build support and
unused path patches that Cargo still reads during resolution. The snapshot digest
is `fc85d7f7479662012faef9bc43e3efaf7c9299ddc940ffd5ef5865abe5667592`.
Both definitions reproduce byte for byte after locked offline resolution. Their
IDs remain `a69902e230dfa7ae50079838c5d90cf33c6a00de9fc901bf2c26e363449e19e4`
and `0565ceaf03d95097c02f86ad4bfb6f0c352900ecdfcf071960a408404a81bc48`.

Build recipes can now select a separate, inventory-checked source root. Local
dependencies and semantic symlinks cannot escape that root; inherited local
manifest discovery stops at the explicit boundary even without a Git marker.
Current compiler tooling is recorded separately from historical source inputs.
The 119 local build-tool controls pass, including source substitution, mutation,
added-file, escape and cycle rejection, and reference self-exclusion for newly
named executors. The first test invocation encountered a read-only ccache directory;
disabling ccache allowed the C-object controls to run successfully. This is not
relocated compilation/link acceptance. CLI link-set selection, observer exports,
node integration and the rest of K4 remain outstanding; no new CI was launched.


## K4 frozen replay input checkpoint

From base checkpoint `5e3a2fd00d5e406194e6b73a2953473eae028094`, replay work now
binds exact per-batch frozen inputs and the actual batch execution/source validator
consumes them. The lead traced plan publication, subset validation before effects,
owned rollback, stage failure/retry, immutable branch eligibility and recovery.
An occurrence-identity gap found during inspection was fixed by recording dropped
positions in addition to the exclusion txid sets. Shared retained executor sources
and released definitions are unchanged. The unreleased coordinator definition is
`d2d49f6fc726d723969fb660c7022c15e7a77d6fe6994c5571370d879e9c999e`.

The final local `certified_callbacks` run passed both tests, zero failures, in
59.73 seconds (39.33-second build). Raw evidence is
`.build-cache/k4-frozen-positions.log`, SHA-256
`b57e4982919e8704849c778b5fb55ae1635f8e6082ca3202ce70188aa9d7f2a7`.
This is focused production-library integration coverage, not the broad unit suite
or final independent-graph qualification. The test supplies its own replay verdict;
automatic bounded verdict generation, full live driver, startup recovery and old
unit-fixture adaptation remain. Consolidated independent review remains at the
complete K4 group, with no additional microreview, push or CI campaign here.

## K4 automatic finality checkpoint

From checkpoint `a6f4ba1d9bbcc5409df30a738b5993afb802ed34`, bounded planning now
captures overdue direct seeds, freezes branch-specific replay subsets with indexed
availability, seals the verdict into the work identity, and publishes seeds and
work atomically with the owned finality stage. A new driver consumes those saved
items and reevaluates finality before closure completion. The lead traced staging
rollback, publication atomicity, pre-state binding, historical interval selection,
exact-subset consumption, descendant attribution and completion ordering.

The actual parent/child fixture, including injected seed-write and publication
failures and reopened-connection planning, passed with the existing branch check:
2 passed, 0 failed, 75.36 seconds, 29.83-second build. Raw log:
`.build-cache/k4-finality-final.log`, SHA-256
`eb7a5ce6bb39920c2dcdeeae00f7bef0ece32a96db8ae192553dd6a95d0d053c`.
The unreleased coordinator definition is
`a01ccde289e4df99d46654136f252b19a921292a0bba7b56b04cdaf3339168cc`.
Retained executor sources and definitions are unchanged.

An oversized async qualification poll frame caused a debug host-stack overflow.
Local GDB evidence is in `.build-cache/k4-finality-gdb.log` and
`.build-cache/k4-finality-frames.log`. Splitting the test into sequential phase
helpers resolved the failure without raising thread or guest stack limits. The
first split was insufficient; the final split passed twice, with the second run
also covering transactional planner-write failure. These are correctness checks,
not a renewed Pulley performance or stack qualification campaign.

Live consensus still uses the old volatile finality driver, and startup still
rejects an unfinished closure. Both require integration before K4 is complete.
Broader replay cases, proof transport, old unit-fixture adaptation, independent
graph qualification and the one consolidated review remain. No push, PR, remote
CI run or new Daybreak assignment accompanies this intermediate checkpoint.

## K4 live closure integration checkpoint

From `2a98f6851465fedc394670f70ec10087bf31c167`, the live reactor advances durable
certified closure work instead of an in-memory replay queue. Finalized verifies the
saved decision and retains its callback until completion; repeated callbacks cannot
repeat committed effects. The lead checked Decided/Finalized ordering, historical
committee selection before Next, post-commit notification timing, cancelled reply
handling, local candidate versus certified input separation, and obsolete volatile
replay removal. Optional observer tracking does not control canonical finality.

Both focused tests passed in 75.36 seconds (29.13-second build), including live-stage
failure/retry, a conflicting local block, cleared proposal cache, callback redelivery,
execution before Finalized, and one empty-batch heartbeat. Raw evidence:
`.build-cache/k4-live-final.log`, SHA-256
`eda706f0c076b58f07bf1a510120897fcc4687586286f4acf23835060f44a46b`.
Unreleased coordinator definition:
`6e791a6c5478a918f74c13bfc960dda8ad81de66a3c2904dd54cfaefefc4f3d0`.
The earlier live test also passed; the final run adds proposal cancellation at the
durable decision and removes an obsolete unbounded history helper.

No broad unit-suite pass, full engine restart, cluster run or independent linked
qualification is claimed. Old fixtures require adaptation, and the compiler still
reports unused legacy executor resolution/redelivery capabilities awaiting removal.
Startup recovery remains unimplemented. The sole planning reviewer explicitly agreed
to the shared engine-independent canonical execution context, with one owner of
execution state, bounded progression, settled ownership, committed outcomes separate
from notifications, and pruning/tip reconstruction before engine startup. The detailed
conditions and recovery acceptance are recorded in the certified-history plan. This
is planning agreement, not an implementation verdict. Consolidated review and CI
remain at the complete K4 group. No
push, PR, CI run or Daybreak assignment was made for this checkpoint.

### K4 shared execution context and startup recovery

Extracted engine-independent ownership of canonical execution from Reactor, moved
actual owned block/batch/rollback handlers onto that context, and made both live
execution and startup recovery consume the same bounded closure step. Startup
loads pruning bounds and validates/replays saved work before mempool recognition
and engine creation, then moves the recovered context into Reactor. Notifications
consume committed results; rollback reads its new tip before committing.

Lead inspection covered unique mutable session/tip ownership, retained-input
selection, original owned transaction boundaries, stage-before-notification ordering,
prune-watermark loading with pruning disabled, baseline H0 scheduling, recovered
mempool selection and successor authority. The agreed planning boundary is retained.
Consolidated independent K4 implementation review has not yet been requested.

Focused local qualification: 2 passed in 87.91s, build 41.05s, terminal exit 0.
Evidence `.build-cache/k4-recovery-test3.log`, SHA-256
`d875160300c64ceca2ef9523662b67493a4f5e671518c36199bdadc227a8ecd5`.
Source definition `f38d0deeee0199208889046c695bf02e1e2eab10d2c110305e8b78f7da657016`.
The new scenario stops Malachite, reopens executor sessions around a replacement
rollback, injected block/lifecycle and finality-publication failures, and verifies
recovered position, lineage, cursor and historical successor committee without
Bitcoin RPC. Shutdown and persisted pruning rejection are covered. Full startup
supervisor/cluster behavior and interrupted multi-page/batch replay parity still
need acceptance coverage. Existing broad fixtures still require K4 API adaptation.
No remote CI or new performance work was launched.

### K4 interrupted planning/replay equivalence

Added a frozen-input comparison of uninterrupted closure recovery against fresh
executor sessions reopened after planning pages, rollback and replayed batches,
including a failed replay-stage publication. All persistent SQL tables must match;
closure identity, applied position and ownership settlement are checked separately.
The test uses the same production step/recovery methods as the live reactor.

Focused qualification passed: 2 tests, 115.15s, 40.67s build, terminal exit 0.
Log `.build-cache/k4-replay-parity.log`, SHA-256
`212aeeb8bce16da71c31a33c6d049305fe20f6a5f6c387e7cc9961aa8e69bd10`.
Definition `346ff34104c8241da63abc0661945a72d55831b8f793e06b47cf81bddc1d54ef`.
Separate broader unit compile (`.build-cache/k4-unit-fixtures-build.log`) failed
with 136 errors in old fixtures and moved test accessors. This is an outstanding
integration task, not a skipped acceptance gate. No CI campaign or review round
was started for this intermediate checkpoint.

### K4 existing fixture migration (in progress)

Routed existing test access through the shared execution context. Updated isolated
stream, proposal-signature and replay-model fixtures to construct exact values
with explicit era context. The mempool verdict fixture now carries its original
value. Retained-row witness tests use the database API after removal of the old
reactor resolver.

Removed the obsolete test-only volatile-queue persistence implementation and its
self-test. Added a certified-journal regression that persists an unexecuted
witness-bearing decision, reopens the database, checks exact input retention
without canonical batch rows, and rejects a different witness at the same
consensus height. This new regression has not yet executed.

The broad unit compile progressed from 136 to 30 errors, then to 12 errors
(terminal exit 101, `.build-cache/k4-unit-fixtures-build3.log`). Remaining errors
were old synthetic block constructors, an obsolete rollback-cache method and
volatile-queue assertions. After that compile, the archived deadline fixture was
updated to expect completed durable replay without Bitcoin redelivery, and the
frozen block fixture was changed to use its retained raw Bitcoin body. Those last
edits have formatting/diff validation only. No passing broad-suite claim is made.

Next: migrate real Reactor setup to authenticated genesis and signed exact-input
decisions, including the mock Bitcoin chain and handoff/fault/storage fixtures.
Do not restore synthetic-input acceptance or fabricate certified history for
legacy runtime snapshots. Then compile and run the affected regressions before
consolidated K4 review. No remote CI, performance workload or new review round
was launched for these intermediate edits.

### K4 authenticated handoff fixtures and empty successor authority

The full indexer unit-test executable now compiles. Handoff fixtures use the real
native genesis/session setup, signed certificates and exact Bitcoin bodies,
including witness commitments. They exercise immediate and delayed decided input,
execution before Finalized, early proposals, publisher authentication and bounded
buffer admission. The witness-retention regression now starts with a certified
block, respecting the rule that a batch cannot precede the first Bitcoin block.

Aggregate database faults and synthetic storage-penalty tests now use an explicit
execution-only fixture. It requires unavailable canonical history, starts no
consensus engine and fabricates no certified records. It exercises the shared
block transaction and owned execution/rollback operations. Its coverage is
accounting and failure behavior, not authenticated consensus or recovery.
The production block transaction helper now receives the decision height and
certificate explicitly; its live caller supplies the same validated decision.
Archived workload setup still needs authentic history migration.

Before the observer correction, the focused run in
`.build-cache/k4-fixture-regressions7.log` passed all 11 tests in 274.26 seconds
(build 56.13 seconds, session 16435, exit 0). It covers witness retention,
aggregate failure/retry and positional errors, normal handoff/early proposals,
and storage settlement, rollback, reopen and last-validator penalties.
Log SHA-256: `4db9ac60cc7f8bbec26fcd20126d56d915c0e2d3fdcf52a11b6439a3a3c1eb17`.
This result is bound to the source before the observer correction below.

The real certified last-validator exit test exposed a regression: the observer
called nonempty committee derivation inside the block transaction and rolled back
the valid exit. The sole planning reviewer explicitly agreed that the existing
unreleased K4 observer should accept an empty observed set while continuing to
validate every watched holder. Frozen P1 committee derivation and frozen K3
sources/references are unchanged. The existing authority constructor still
rejects emptiness, so publication halts after execution commits. This was a
targeted architectural agreement, not consolidated K4 implementation approval.

The observer reference was explicitly refreshed to definition
`cc6739c0387a9a5cf2eda7b82c668598ebc7d16c8b6d644d90683f231939d194`.
The refreshed draft coordinator definition is
`fc1ca26f92899f065d90effedcb6bb47aa4cd3f68f929ee4296142eea16e5b07`.
No existing database identity was rewritten. The focused post-correction run in
`.build-cache/k4-exit-recovery8.log` passed 2 tests in 82.17 seconds (build 67
seconds, session 40950, exit 0). It verifies the unchanged nonempty projection
with public view gas set to zero, and immediate/delayed certified exit flows:
durable empty staking state and observation, absent successor committee/closure,
withheld Next, reopen through executor startup and engine-free recovery,
unchanged canonical lineage/stage/observation after retry, and zero live roots.
An injected observation-persistence failure rolls back the exit before a
successful retry. Authority failure is checked by its typed error.
Log SHA-256: `8c4a04f5c2e091a03362288661589a2e9bc672af99e934ad24a190dc2357bddf`.
Ten execution-definition tooling tests and three coordinator-definition tooling
tests also passed locally. Formatting and diff checks passed for the changed files.

K4 remains incomplete. Database/closure fixtures that still start with an
uncertified batch need migration, as do the broader reactor/mock-cluster/archive
fixtures. Broader replay cases, bounded proof transport, consolidated lead and
independent review, and scoped final-candidate CI/merge remain required. This
checkpoint does not establish a passing full unit suite or linked cross-platform
qualification. No remote CI or additional review round was launched.

### K4 journal fixture repair and certified A-B-A replacement

The journal fixture check on checkpoint `1f77e52e` reported 4 passing and 10 failing
tests, all failures caused by fixtures beginning with a batch before the first
certified Bitcoin block (`.build-cache/k4-journal-fixtures9.log`, 17.04 seconds).
The common database fixture now starts with an exact block. Closure fixtures
record both the block-transaction application and its lifecycle application, and
the owned-stage fixture checks the block selection envelope. Their rollback,
corrupt-record, stale-ticket, substituted-input and invented-work assertions
remain. One negative control initially failed too early because its substituted
lifecycle used a different storage height; it now remains structurally valid so
the closure's semantic check must reject it.

The corrected journal/owned-stage family passed 14 tests in 17.24 seconds,
session 36031, exit 0, `.build-cache/k4-journal-fixtures11.log`, SHA-256
`4011ac2e6570ab4044fbde612bd95f3515ae58041ba55eb22be87cb34bac2743`.
This evidence precedes the additional branch-restoration test and resulting draft
coordinator identity update.

Added an actual executor/reactor callback test of certified A-B-A replacement at
the initial Bitcoin height. Each decision has a real signature and retained raw
Bitcoin body. The test awaits Next after each completed closure, then reopens
through executor/consensus startup. It checks all three immutable closure records,
each decision's historical Bitcoin branch, the final authenticated/closed frontier,
equal canonical lineage/cursor for the two A executions, and equal token supply
(no duplicate emission). The first and third closure IDs remain distinct despite
equal canonical output. This is baseline replacement coverage with empty user
transaction bodies, not cross-upgrade or all finality-replay acceptance.

That test passed in 41.83 seconds, build 57.72 seconds, session 43062, exit 0,
`.build-cache/k4-branch-restoration12.log`, SHA-256
`7396e6529fdcebc302cbced96feb05c1fecc6763272db6559f96c51464c031f3`.
The tested draft coordinator definition is
`360a32f8e8f58c0b571ef488423f3932436c0ecbdbf1c18d742a9ff20efbe717`.
Formatting and diff checks passed. No production semantic rule was changed by
this fixture work, and no remote CI or additional independent review was started.

The operator asked whether first-block admission was only a test requirement.
Clarified that it is a K4 production startup restriction already recorded in the
agreed plan: the initial H0-1/zero-hash scheduling placeholder is not a Bitcoin
anchor. After the first certified block, multiple batches can anchor to the same
block. This is not a requirement to wait for a new Bitcoin block for each batch.

Remaining K4 work includes migration of older reactor/mock-cluster/archive
fixtures, further finality replay cases (kept batches, parent redeclaration,
reorg healing and many small batches), proof paging and resource admission,
consolidated review, scoped CI and merge. The full unit suite has not passed.

### K4 mock Bitcoin retains complete blocks

The cluster's mock Bitcoin source now emits complete Bitcoin bodies through the
shared certified fixture builder, with actual header-derived hashes, transaction
Merkle roots, unique coinbases and witness commitments. Its generated stub
transactions have non-coinbase inputs and outputs so Bitcoin consensus decoding
is unambiguous. Reorgs preserve the surviving block's actual hash, discard removed
transaction lookup entries, and use a new fork nonce for replacement bodies.
Reset cannot invent a height outside the generated chain. The configured starting
parent remains a fixture boundary, not a claimed certified Bitcoin block.

The lightweight executor ignores coinbases instead of counting the newly retained
coinbase as a counter-contract call. The pending-buffer flood fixture now obtains
complete blocks from MockBitcoin rather than constructing synthetic hash-only
inputs. The mock does not validate proof-of-work, UTXOs or Bitcoin scripts.

Two focused tests passed in 0.02 seconds, build 66 seconds, session 33395, exit 0,
`.build-cache/k4-mock-bitcoin13.log`, SHA-256
`13dd4c14de0fcff506e3f8df8f1b179c3f0ba14c5759f6c91e8cb7eaa2a0f10e`.
They establish exact witness/body round trips through the production certified
codec, rejection of a changed expected block hash, retained late-join events,
surviving-parent consistency, removed transaction lookup cleanup and replacement
at both an interior height and the configured starting boundary. The compiled
draft coordinator definition is
`a760f4715bc4a520bcc9bc809cf8f99d6e49db018776656e9888311cee76a3d4`.
Formatting and diff checks passed.

This does not establish passing cluster integration. LiteExecutor's direct native
and counter-contract seeding still produces unavailable history, and the cluster
readiness barrier still assumes a pre-first-block batch. Both need migration to
authenticated genesis and appropriately ordered real setup inputs. Other reactor
fixtures and the remaining K4 replay/transport/review/CI work are still pending.
No remote CI or new independent review cycle was started.

### K4 cluster authenticated startup and real transaction execution

The preceding goal turn made progress: complete mock Bitcoin bodies were committed
as `44e957de`. This continuation replaces the cluster's synthetic genesis/counter
seeding. LiteExecutor now mocks Bitcoin I/O and configured validation latency only;
transaction recognition and execution use the normal retained operations. Fresh
and restarted nodes run the native genesis journal, then engine-free certified
recovery before Malachite starts. A shared session factory retains the component
cache across nodes without sharing their mutable storage sessions.

The cluster's first mock Bitcoin block carries an actual Kontor issuance and
counter publication transaction. Subsequent generated transactions carry counter
calls. The counter address is `counter_1_1`, after the coinbase. Replacing the first
block repeats its setup input so state comes from ordered execution, not fixture
seeding. The mock still does not validate Bitcoin scripts, PoW or UTXOs. The old
readiness barrier that expected an empty Batch(0) has been removed. Test readiness
means reactors initialized; each test must explicitly supply its first block.

The migrated three-validator case establishes first certified Block(1), then two
batches anchored to Bitcoin 1 without intervening blocks. It verifies each batch's
persisted certificate/input and the first decision's block command, reads counter
value 6 through the normal selected view path on all three nodes, confirms those
transactions in Bitcoin 2 and checks the value stays 6, then restarts one node on
its existing database and reads 6 again. The final local run passed in 46.00s,
session 73927 exit 0, `.build-cache/k4-cluster-startup17.log`, SHA-256
`b9f567a11b98be19b78a9a300e2255959efd4b8dd11e787ad89a12232b045111`.
The same binary's two mock-body/reorg regression tests passed in 0.00s,
`.build-cache/k4-mock-bitcoin18.log`, SHA-256
`f8a81a380aeb2ae5be77f2061821ca7e56fccfc315ce0d32198243710672c71a`.
Draft coordinator definition:
`d76e2709c9b5fd3e18c111014a0df2900ea45116e22b9913a92d5e43ddbb2688`.
Formatting and diff checks passed. Earlier run15 passed the smaller notification
case; runs14 and16 exposed fixture compilation errors corrected before run17.

This is not full cluster acceptance. Other cases still assume Batch(0), synthetic
counter funding, or volatile rollback/replay behavior and require migration with
their assertions preserved. The existing fixed-delay node-stop helper also needs
an explicit task-completion handshake for reliable restart evidence under faults.
The ordinary successful restart above is limited evidence, not a teardown-race
qualification. Remaining K4 finality/replay, bounded proof transport/admission,
consolidated review and scoped CI/merge remain required. No PR, push or remote CI
was started for this checkpoint.

### K4 explicit initial anchors and node task completion

Continuing from `bcb7460e` (a progress turn), migrated ten cluster cases that
expected Batch(0): each now explicitly processes setup Block(1), with subsequent
Bitcoin heights and anchors shifted while preserving transaction counts and
assertions. The stuck-validation case also establishes its anchor before starting
the delayed I/O job. The dropped-startup-proposal fixture supplies Block(1) after
its existing round-zero readiness barrier. No production ordering rule changed.

Cluster restart now waits for the old node future's completion signal before
reopening its database, replacing the fixed 500ms delay. Timeout or premature
channel closure fails the test. This checks node-task completion, not the future
K5 engine-handoff timeout/signing qualification.

Seven selected local tests passed, 335.12s, session 18418 exit 0:
anchor transition; blocks progressing during stuck validation; happy finality;
missing transaction rollback with complete and partial submission; actual counter
state/confirmation/restart; dropped initial proposal with a delayed retry proposer.
Evidence: `.build-cache/k4-cluster-migration19.log`, SHA-256
`30c148b135ecf9c07865bd6deeb0519ec42e852d3c3307cab42836b009c05ca8`.
Draft coordinator definition:
`34aeafc15480afc156004a584c66031a575e81040eaab6f6782f2aa8bd3e6656`.
Formatting/diff checks passed. Other migrated cases still need execution evidence.

Remaining old reorg cases incorrectly expect a local Bitcoin rollback notification
to immediately undo canonical state. They must preserve their assertions while
applying them after certification of the replacement block. The simulation case
still uses an ambiguous empty Bitcoin encoding and should execute a real counter
call with a no-state-leak assertion. Full cluster, late-join/deep recovery, remaining
K4 transport/admission and final review/CI remain incomplete. No remote run or PR
was created for this local checkpoint.


### K4 certified reorg, simulation and catch-up fixture migration

Continued from `060a058c`, a progress turn. Cluster reorg cases now submit and
await the certified replacement block before asserting rollback. The combined
wait retains each node's rollback and replacement events. A real counter proves
that a reorg below a batch anchor removes its effects, preserves its certificate,
and permits re-submission under a later decision. Reorg at the anchor preserves
its effects and still delivers the original batch's finality verdict. Every old
certificate and completed closure remains verifiable after branch replacement.
Simulation executes a real counter increment and proves no state leak, including
agreement of the following block's checkpoints.

Cluster startup now obtains its ordered committee from `certified_startup` after
recovery, as the production node does. Separately constructing a genesis set gave
the four-validator fixture a different member order and correctly failed the
existing authority check. No production authority check was relaxed. Deep-reorg
catch-up compares every retained decision and exact input and verifies the joining
node's completed closures while its Bitcoin feed contains only the surviving
branch. Ordinary catch-up selects the checkpoint at the requested height and
checks the joining node's real counter state.

The reward test preserves emission arithmetic, stake totals, empty reward pools,
rollback/restart and late-join equality. Its deposit assertion is now scoped to
lifecycle writes (`tx_id IS NULL`), since real contract publication creates user
deposits. Inspection uses an existing read-only database connection rather than
rerunning schema initialization beside the active writer. Sampling waits for the
source's authenticated consensus height to close locally: Bitcoin height alone
can transiently match while the joining node replays an abandoned branch.

Local evidence, all logs under `.build-cache/`:

- `k4-cluster-reorg20.log`: session 5171 exit 0, four passed in 214.67s:
  batch rollback/re-submission, receipt-stream rollback boundary, immutable
  decisions/closures across reorg, and real simulation. SHA-256
  `f10349a8500f674aaf40f46e40cd8c9f6789583e0171ddc0b74070c4dd30958a`.
  Draft definition `88692a8597e5bb893590e6e603d99b467ad68bebd876c4ac518588a4f1972082`.
- `k4-cluster-catchup21.log`: same binary, session 11721 exit 101,
  retained-anchor finality passed; three startup committee-order failures.
  SHA-256 `682da7fd8a34f7fd5cb6a2dde0107eaa238af04c8cf84b15cee2dabdf4e7b7c1`.
- `k4-cluster-catchup22.log`: session 81937 exit 101, deep-reorg catch-up passed;
  reward deposit assertion and wrong-height checkpoint selection failed.
  SHA-256 `b7952888d483ffa1407afb12404976957c8e2fae2676f059c63f38471b784303`.
  Draft definition `84587596342d7eaa760910b3957bb568d12b602ecfaed9a8eb61ff9e60f358f0`.
- `k4-cluster-catchup23.log`: session 24115 exit 101, ordinary catch-up passed;
  reward inspection hit schema-initialization lock contention.
  SHA-256 `f44493bc654221bccc60fc57cd5847843598330d694b07a6ff9f3bc7fcac28e8`.
  Draft definition `9f8a4418e3028a8caaa3ffd8088788099910ef06fd186fd848464aca487aa2f8`.
- `k4-cluster-rewards24.log`: session 33425 exit 101, reward arithmetic, rollback
  and restart passed before late-join sampling crossed a rollback stage.
  SHA-256 `cdb6a1c89f3828e84178ac71015c476c9a9f46a0afb030d246c7ccced4ea5b33`.
  Draft definition `c58140ec81b1aaabe69f2a1e363a0d97c3d91cf6307c056a2ef40a9a5f54c215`.
- `k4-cluster-rewards25.log`: session 69315 exit 0, reward rollback, restart and
  late-join case passed in 129.26s with the certified-closure barrier.
  SHA-256 `b7453ea4a188c118d2849761fa545a3141bfe60440275069179738289842f72a`.
  Draft definition `9873c85ac4cdd37d3f0dddab1982bf86aaf2c5b35104dc71e8cac63b48de96e5`.

These are scoped results at the listed source definitions, not a complete suite
pass at the final checkpoint. Follow-up runs targeted explained failures and
preserved prior evidence. Formatting and diff checks passed. The obsolete
shutdown-during-replay gate still intercepts unused `replay_blocks_after`; migrate
it to an active owned closure stage and retain the shutdown/drain assertions.
Remaining cluster cases, bounded proof paging/admission, real-graph integration,
lead and consolidated independent review, and final CI remain incomplete. No PR,
push or remote CI campaign was launched.


### K4 active rollback ownership and remaining finality regressions

Continuing from `7811b2ff`, moved the cluster's obsolete replay pause from the
unused poller replay method onto the real executor maintenance call. The fixture
pauses after rollback work but before the owned closure stage settles. Before
shutdown it verifies all three nodes have one active root, a non-autocommit SQL
connection, and a pending certified Rollback(0) stage. Shutdown must remain pending
until release; afterward the drivers join, transactions settle, batch rows are
removed, and no active, quarantined or fatal roots remain. The expected subsequent
root-admission-closed errors are retained rather than hidden.

`k4-cluster-shutdown26.log`: session 24082 exit 0, one passed in 56.65s.
SHA-256 `5ee6f4e8451ee142c43c9c149b1349ae1e1b7b7cae2d27a505f7d9cd892e1c67`.
Draft definition `362d47fb6fa8368c6dab27a1e23ba66b4efee06bd25b7cd062c501fcb448af73`.

Fixed the pre-anchor preservation setup to confirm the earlier batch in Block(2),
so only the later batch is missing. Its rollback assertion now compares the exact
checkpoint captured after the earlier batch, rather than merely requiring some
checkpoint. Five local regressions passed in one subsequent group: delayed
validation with mempool removal, cascade invalidation, cross-block cascade,
restart inside the finality window with receipt recovery, and exact preservation
of the earlier checkpoint.

`k4-cluster-finality27.log`: session 22034 exit 0, five passed in 307.68s.
Draft definition `7080540f26ea843de0f9cbd5c48c54b5b24d3246274fa4344139f5b58fa664c2`.
These scoped results preserve the prior source bindings; only the pre-anchor test
changed between runs 26 and 27. Formatting and diff checks passed. Remaining
cluster/old unit fixtures, obsolete executor capabilities, bounded proof paging
and admission, real-graph integration, consolidated review and CI remain pending.
No remote CI run or PR was created.

### K4 missing-local-input recovery and pre-anchor proposal deadline

From `dd2be2b6`, replaced the obsolete regression that merely kept a lagging node
alive with a four-validator recovery check. Node 3 receives no local Bitcoin
BlockInsert events for blocks 1 and 2. All four must nevertheless process them
with matching checkpoints. The test reads node 3's own certified journal, compares
retained decision IDs and exact inputs with the source, and requires completed
closures. Blocks 3 through 5 then prove continuing execution/checkpoint agreement.
The target is a captured authenticated consensus frontier, not Bitcoin height:
empty anchored batches may occupy intervening consensus heights.

The first run exposed a real startup liveness defect. Node 3 was the initial
proposer but had no local block and no certified anchor. `try_fulfill_pending_proposal`
kept its GetValue sender even after the hard deadline. Malachite's serial connector
was awaiting that reply, so later round/decision callbacks could not reach the
node. The other three validators advanced while the test timed out at only three
block-processing events. The pre-anchor path now drops the pending reply at its
hard deadline. The engine proceeds to the next round without an invalid empty
batch. The dependency connector logs the cancelled reply as `channel closed`,
handles that error, and remains alive; this log is retained in the evidence.
No change to post-anchor batching, gas, Bitcoin ordering or protocol validity.

Local evidence:

- `k4-cluster-ordering28.log`: session 11714 exit 101, five passed and the new
  recovery check failed in 296.39s. Scoped passes cover checkpoint agreement,
  confirmation deduplication, multiple batches at one anchor, bounded pending
  blocks, and progress after stale block redelivery.
  SHA-256 `c811b004a9f054dd8ba78fe04e08bc78ca6b0fd1b1b4706ec6f36e0e36953fb9`.
  Draft definition `ef6a3efac9638e95551124e1a89632f7d0a24e6a549a719ba3294a1021cc587a`.
- `k4-cluster-recovery29.log`: session 55888 exit 0, the focused four-validator
  missing-local-input case passed in 51.38s after the deadline correction.
  SHA-256 `374940439b4ee24cce7f2080edf29a2ee5f4cbdbf168de608a154bbed31a36f5`.
  Draft definition `35bc74c27aacf103c55edb73381a35f333e04483e91e0119549b21f91508c988`.

For the preceding finality group, the retained log SHA-256 is
`383a580327f86847aeb43bb33b38e9bad883609220c623158bffd2d156d63404`.
Removed the unused decided-only wait helper and stale poller-replay commentary.
Formatting and diff checks passed. These are scoped evidence bindings, not a full
suite claim on the new source. K4 still needs the remaining synthetic fixture
migration, obsolete replay interfaces removed, bounded proof paging/admission,
real-graph integration, lead and consolidated independent review, and final CI.
No PR, push or remote CI campaign was launched.

### K4 execution-only state fixtures and certified mempool startup

Continuing from `dc049146`, moved simulation selection, owned simulation execution,
and inspection from `Reactor` to `ExecutionContext`. Reactor entry points delegate
without changing selection, unit ownership, failure handling or result assembly.
The four context-restoration tests now use the existing execution-only fixture;
seeded runtime state is never promoted to certified authority. The pruning test
uses the same fixture and the real runtime maintenance operation, without an
unused consensus engine. Its pruning watermark, injected failure, SQL rollback
and reconfiguration assertions remain intact.

The five mempool tests now construct a real certified fixture, authenticate a
signed first-block decision, finalize and execute its closure, and require the
next global consensus height to be 2. Their proposal anchors use that block's
actual hash. Delayed witness replacement, stale selections after rollback,
retained-recognizer dispatch, and event-loop backpressure assertions remain.
The backpressure test initially failed because the migration accidentally supplied
an empty second block, removing its intended transaction-removal stimulus. Restored
that staged non-Kontor transaction in the second block. It is a synthetic spend;
this test establishes reactor event handling, not Bitcoin UTXO/script acceptance.
The assertion that late recognition cannot restore a removed transaction was not
weakened. No mempool implementation change was needed.

Local evidence (one Cargo/runtime operation at a time, two build jobs):

- `k4-state-fixtures30.log`: session 48099 exit 0, six passed in 142.10s: pruning,
  four simulation-context cases, and real-cluster simulation with unchanged state.
  SHA-256 `8f08de46542610297384763c4719bc91e5d6d460134d7833fc83063e5c74b1ef`.
  Draft definition `33c14ac215b83324b568b79264857acb24045a80ba5c3d5a4b46dfe3e365487e`.
- `k4-mempool31.log`: session 72490 exit 101, four passed and the explained
  block-removal fixture failure in 85.29s.
  SHA-256 `7567b51322c24ad7a4571ecf59597dd8b7b3ab0e5b77fa4adef27fc59db58c92`.
  Draft definition `427330bfeaf49b202bca75db34a63e0a31e0e549468b949f395954076a29bd12`.
- `k4-mempool-removal32.log`: session 15325 exit 0, corrected pending-recognition,
  block/request liveness and channel-backpressure case passed in 17.22s.
  SHA-256 `562980707e90857a5df35737047d572cc5d72e1ec63921c251f9348d0e47aa21`.
  Draft definition `4ee41619d3562b9e508823ccd8570368596f71152319ac5d157303b1f36cab20`.

Formatting and diff checks passed. These are scoped results at the listed source
bindings, not a full final-head suite claim. The only source differences after
run 31 are the corrected block-removal stimulus and field shorthand. Confirmation
position/parity and archive fixture migration, obsolete replay interfaces, bounded
proof paging/admission, real-graph integration, consolidated review and CI remain
unfinished. No PR, push or remote CI campaign was launched.

### K4 certified confirmation and reorg accounting fixtures

Continuing from `f3006af6503c6a73fb99f7ed85d7af8ca3014cf1`, the two automatic
confirmation-position regressions now initialize certified history from genesis,
execute an issuance and publication in certified Bitcoin Block 1, and use signed
batch/block decisions with exact retained inputs. The test advances the production
closure one settled step at a time, allowing inspection immediately after the
replacement block's rollback stage. No seeded runtime is promoted to authority.

Both paths retain successful contract output and gas assertions, raw Bitcoin
position versus recognized-transaction ordinal checks, and actual execution/op
counts. The batched path proves unchanged transaction effects and charges on
confirmation, preserved batch identity after rollback, cleared confirmation,
receipt-stream recovery to the pre-block cursor, and reconfirmation at a different
raw position with zero repeated operations. The batch is now consensus height 2,
after the certified initial block. Its Bitcoin execution height remains 1.

Full certified block processing also runs native lifecycle operations. The effects
snapshot therefore compares transaction-associated state and receipts, all gas
usage and depositor footprints, contract/provenance rows, and the target contract's
current-state projection. Lifecycle-only state and receipts are excluded from the
equality assertion because a new block legitimately changes them. Receipt recovery
uses the captured pre-block maximum receipt ID, including the surviving batch,
rather than the later maximum that can include rolled-back lifecycle receipts.
The fixtures still do not establish Bitcoin PoW, UTXO or script acceptance.

Local evidence: `k4-confirmation33.log`, session 83147, exit 0, two passed in 49.82s.
The existing manual cross-revision parity test was ignored, as intended by its
explicit-run marker; this result does not cover that test or its legacy seed.
Log SHA-256 `4b96ff0149fc635fc9d4a6c92d4ec9f0f720f15ee8d6e758e2acfed73b1b3dcb`.
Draft definition `a0fff15b64e949ce6634b1c6698a864f76fcc607f3318ad3642a24ad6ebb578c`.
Formatting and diff checks passed. Lead inspection traced certificate retention,
closure stepping, rollback and receipt recovery; the consolidated independent
K4 review remains pending. No production execution changes, PR, push or remote CI
were made for this fixture migration. Manual historical parity/archive migration,
obsolete replay interfaces, bounded proof transport/admission and the rest of K4
integration/review/CI remain unfinished.

### K4 obsolete Bitcoin replay plumbing removal

Continuing from `f195f21650213cd31f248bf383c2ae7e22ce42a1`, removed the unused
`Executor::resolve_transactions` and `replay_blocks_after` interfaces and all three
implementations. Certified application/recovery already reads retained exact
inputs. Removed the replay sender from RuntimeExecutor, node startup and session
constructors, the follower's returned channels, and the poller's rewind request
branch. Ordinary Bitcoin polling, ZMQ wakeups, startup hash reconciliation, reorg
rollback and shutdown retain their existing paths. No Bitcoin RPC API was removed.

Removed the now-unreachable mock executor block sender and corresponding cluster
plumbing. The maintenance pause used to test ownership during rollback remains.
The manual deadline archive still checks that certified closure finishes before
advance returns; its obsolete assertion against an unused replay receiver is gone.
Four tests solely for the removed poller replay-request API were removed with that
API. All 25 remaining poller tests were retained and passed, including ordering,
header/witness retention, live/offline reorgs, chain shrink, reorg during catch-up,
and cancellation. This does not claim that the older manual archive setup has
been migrated to certified startup.

Local validation, one Cargo/runtime operation at a time and at most two jobs:

- `k4-replay-removal34.log`, session 38385, exit 0: 27 tests passed in 93.61s.
  In addition to the poller suite, this includes certified A-to-B-to-A replacement
  and the four-validator missing-local-block recovery regression. Both now run
  without an executor or poller replay request interface.
  SHA-256 `f9248e06a5b4b1257726b81315798c1bb3d6160164ff4cc2c6dfcaea11978351`.
- `k4-replay-main35.log`, session 74962, exit 0: locked `indexer` production
  `kontor` binary check with the protocol-qualification feature passed in 9.20s.
- Draft coordinator definition for both checks:
  `c5273daeae767579060ae9579ed4f322b3e068d899ef11b6c6ae65f9a7dd5e1c`.

Formatting and diff checks passed. Lead inspection traced all removed interface
call sites and confirmed certified recovery is independent of local Bitcoin
redelivery. No independent microreview, PR, push or remote CI was started. Remaining
K4 work includes bounded proof transport/admission, required real-graph integration,
historical fixture reconciliation, and consolidated review/CI/merge.


### K4 incremental proof verification and bounded journal reads

Continuing from `0de8855863af41a3965ad2be7fe7db4056b127e0`, replaced the
whole-slice certificate parser with an incremental verifier. Existing contiguous
verification uses the same verifier. It retains one fixed 107-byte wire-field
buffer, the established committee lookup and duplicate-signer tracking. Declared
length is checked against `1024 + 96*N`; field order, minimal varints, round,
value identity, canonical signature records, known distinct signers, signatures
and strict supermajority retain their previous rules. Finishing requires all
declared bytes and a complete field, even after a quorum prefix. A failed stream
cannot be reused to obtain a successful verdict.

Added `load_verified_input` for journal consumers that need authenticated input
and decision identities but not proof bytes. It checks both original and optional
augmentation proofs using SQL slices of at most 1 MiB each, then exposes the
input. Closure planning/recovery/completion, finality/replay validation and the
block/batch retained-input checks now use it. The existing whole-proof load still
serves callers that require proof bytes, with a committee-based length check
before loading those blobs. This bounds the application's proof-read buffers, not
SQLite's page cache or all memory proportional to the historical committee.

Local validation, one Cargo/runtime operation at a time and at most two jobs:

- `k4-proof-stream36.log`, session 32235, exit 0: 22 tests passed in 44.36s
  after a 1m49s test build. This includes all certified-decision and journal tests,
  splitting valid proofs at every byte boundary for rounds 0, 128 and u32::MAX,
  malformed split prefixes, incomplete/failed stream rejection, original and
  augmentation corruption checks, and actual certified A-to-B-to-A recovery.
  SHA-256 `ad08760ab7978dfeb09eb726d8cb61a6032addf7415c7f1a4c01064b11f19d65`.
- `k4-proof-stream-main37.log`, session 80876, exit 0: locked production
  `kontor` binary check with protocol-qualification passed in 9.26s.
  SHA-256 `4dc20531836ac02acc2f95f7d566579d2bdafcc681d872b0df98bf1a0704dd62`.
- Draft coordinator definition for both checks:
  `3c4b9097960fc32e319f0b3e1e2c2160bbc261fbc88331555db62b8b3991fab9`.

Lead inspection compared all parser acceptance checks with the preceding parser,
traced converted journal consumers, checked failure poisoning and bounded field
arithmetic, and confirmed no proof verification is skipped when returning input.
Formatting and diff checks passed. No independent microreview, PR, push or remote
CI was started. The sole planning reviewer was asked to scrutinize the concrete
network/engine integration because the current Malachite app-channel interface
only transports complete native certificates. No engine adaptation was selected
or implemented in this checkpoint.

This is not complete proof paging or K4 acceptance. Network request/page binding,
bounded disk staging and admission, large-proof journal publication and actual
engine integration remain. The native-sync serving path and the execution path
that populates the legacy batch certificate projection still load whole proofs.
Required real-graph integration, historical fixture reconciliation and the
consolidated K4 review/CI/merge also remain unfinished.


### Operator deferral of oversized-certificate paging

The operator explicitly instructed the lead to stop pursuing oversized-certificate
paging as a current need and to update the goal. Appended the refinement to the
existing objective file without replacing the goal or touching its statistics.
Updated the active K4 and implementation-plan requirements. Earlier ledger and
checkpoint requirements are superseded rather than erased.

No proof-page wire protocol, HTTP history source configuration, page staging,
giant-committee test or early engine replacement was implemented. The preceding
incremental-verifier checkpoint b3ba8306 remains, with its 22 passing tests and
production build check. Ordinary bounded native sync and cross-era historical
verification/catch-up remain in scope. This deferral adds no committee cap and
does not claim oversized-certificate support.

The sole reviewer was informed to end the paging-driven planning work. Its source
investigation supports reusing the previously qualified ManagedEngine fork pin
6d99c0a43a21ff48ff3f69a5f9e834310d0b0b09 in K5, with complete join, preserved WAL,
callback fencing and no replacement after timeout or lifecycle faults. The
reviewer agreed that dependency choice, but no node dependency or engine change
was made. Preserve that research for K5 instead of treating it as a new K4 gate.

This is an operator-directed scope change, not an assertion that K4 is complete.
Remaining K4 work includes historical fixture reconciliation, real retained-graph
integration, ordinary framing/admission checks, consolidated review, scoped CI and
merge. No new test or CI campaign is needed for these documentation-only edits.


### K4 retained and certified acceptance harness repair, 1 November 2026
The sole planning reviewer explicitly agreed the split against 8d59b615:
retained first/second/observer execution and journal adapters retain per-graph
qualification; the current K4 certified baseline runs separately using the actual
observer factory. The original first lacks registration observation and cannot
honestly serve as the current certified baseline. No certificates or committee
history are manufactured for the old graphs.

The old history fixture failed locally at consensus startup with missing
certified_history_state. It now exercises the production block transaction,
lifecycle, linked root/ownership, maintenance and journal adapters without a
consensus engine. Empty/all-excluded synthetic batch applications check journal
integration and surviving anchor prefixes, not current Reactor construction.
The existing fifteen-decision certified fixture retains the real caller checks
for admission, empty/excluded batches, closure, finality/replacement replay,
atomicity and engine-free recovery. It runs separately in k4-node before the
node-capacity check shuts down the shared owner service.

Both execution and cross-platform comparison gates require this separate result,
including all completion assertions and observer definition/manifest/protocol/era
bindings. Legacy qualification cannot claim this coverage. The case formerly
named reactor-canonical-history is now retained-canonical-history-adapters.
The semantic oracle fixture was restored byte-for-byte to K3; the new issuance
helper lives in the certified fixture instead of invalidating historical evidence.

Validation: the pre-fix fixture failed (session55735, exit101); repaired adapter
fixture passed (session51807, exit0, 1 test,29.41s after79s build); Python gates
passed 7+16 tests including missing/altered certified-result rejection; certified
integration passed (session32313, exit0,2 tests,115.50s after27.16s build); node
binary check passed after ordering the certified check before shutdown
(session69411,exit0,4.33s). Draft coordinator definition:
0b4e50018cb248f7b265f0c5d20bc1b14cc307c42bd42f316d6a643ec1df075f.

Local raw logs under .build-cache, SHA-256:

- `k4-history-fixture38-before.log`: `71642b29b16d8886b80eada5d0467d62c917269f623c779a9d3cd47194716f6d`.
- `k4-history-adapters39.log`: `bd4465fa901a651f83a62c4ff9ceb8f5ef098275db40bd83d82bf6c82de24d94`.
- `k4-history-execution-gates39.log`: `9b281161641fb306d267739bbb724e97c30d21afe1248d97f7c24024b1b05ad9`.
- `k4-history-comparison-gates39.log`: `481fc384c2826a04e5a708c778b878b61a1f10ae57860998d7293d1d411e5688`.
- `k4-certified-integration40.log`: `41a2cc29e11827eb7fd98ffa1dfbde994331e1096cc9d5c1812e32ca41833477`.
- `k4-history-node41.log`: `b13cd986951eb77e137539db06ce42225c8e30c5e90a24609b19f59cfd1eab04`.

These results do not yet prove the separately linked k4-node executable passes.
The certified fixture uses supplied signed certificates and a disabled-consensus
engine; it is not multi-validator networking evidence. The combined independent
build/run, manual historical-fixture reconciliation, final K4 review and scoped
CI remain. No PR, push or remote CI was started for this checkpoint. Oversized
certificate paging remains deferred; K5 lifecycle work remains in K5/K6.


### Operator-approved proportional scope, 1 November 2026

Updated the original goal file in place and the active implementation plan after
the operator agreed to reducing/postponing all four identified areas. K6 retains
manual isolated migration rehearsal instead of six-height automation/readiness
expiry. K9 retains verified sequential bounded catch-up without advanced download
machinery. K10 defers a new user transaction format while retaining existing
format discovery and required control codecs. K11 retains distinct correctness
and recovery boundaries under scoped release3/bounded-dev CI, not exhaustive
combinations or stress/performance campaigns. The full core upgrade implementation,
lead plus one independent review and verified green merges remain required.
The private Site will be reconciled at final publication as already instructed.

Before the independent K4 build, inspected the shared Cargo cache with no active
Cargo/runtime and removed only incremental directories whose newest content
predated 1 November. The deletion manifest is `.build-cache/k4-incremental-cleanup.json`;
228 directories, 21.65 GiB logical bytes. Filesystem free space rose from25 to35 GiB
(the filesystem shares extents). Sources, binaries and qualification evidence
were preserved. The observer's immutable execution definition verified unchanged:
cc6739c0387a9a5cf2eda7b82c668598ebc7d16c8b6d644d90683f231939d194.


### K4 linked-node success and preserved archive comparison, 1 November 2026

The actual independent first/observer node at `17172bb7` passed ARM64 dev
qualification (session95197, exit0, runtime192.32s): both graphs matched the
retained semantic baseline, all25 named cases completed, and the separate
observer-certified fixture authenticated and closed15 decisions. Its result binds
the observer definition, manifest, protocol and era. Executable SHA-256:
`18b67b474bab731a156b89e910b711fe13e706c287c8c4de2ed018cab308fe0a`.
Raw reports remain under `.build-cache/k4-bundles/aarch64-unknown-linux-gnu/dev/executors/k4-node/`.
The expected injected callback/constructor/export panics were contained and
verified by the harness. This is one local platform/profile, not the final scoped
platform campaign or multi-validator networking evidence.

Reconciled the older pre-extraction archive comparator with certified history.
It now uses ExecutionContext without starting consensus or fabricating committee
history. Factored the unchanged batch transaction body out of the certified
caller; production retains its exact retained-input, replay-subset, anchor and
closure checks before invoking that private body. The feature-only legacy wrapper
requires unavailable canonical history and owns the usual execution lease and
transaction. Block execution, rollback and simulation use their existing owned
paths. The manual test shares the comparator; baseline recording remains on the
preserved historical source. Removed the duplicated recorder and unused old
consensus fixture, and restricted the remaining test constructor to tests.

The original archive at source `c7554ca8b7a104d28f41eb1e9a0c48200c34d5f1`
was not regenerated. In-tree comparison passed all11 complete state/receipt
stages, including simulation isolation and confirmation/reconfirmation without
reexecution or additional charges (session9032, exit0,6.88s after88s build).
Certified callback integration then passed both tests, including15-decision
closure/recovery (session76987,exit0,115.21s after23.41s build).
The first compile caught an omitted test import, which was fixed. An initial
library test filter selected zero tests; it provides no acceptance evidence and
was corrected to the actual certified_callbacks integration target.

Lead inspection compared the extracted body ignoring indentation, traced its
production/qualification callers and root lifecycle, and checked that original
archive hashes and exact expected observations remain enforced. The in-tree
archive result is not yet both-independent-graph evidence. The linked archive
comparison, remaining ordinary framing acceptance, consolidated K4 independent
review and scoped final-candidate CI remain. No PR, push or remote CI was started.

Raw local evidence SHA-256:

- `k4-linked-node42.log`: `637b8e24fd1bdcc33a3141beab32211b0e45f980254a248a893ac9f8b311e03a`.
- `k4-historical-parity44.log`: `17d62e210fc2ccf1208c4d670fadd37b253402283d5db196b33522d89f862117`.
- `k4-historical-parity44.json`: `323276dc7ea5bd56f71b0e860559863153004df005a06be31479bad5d08c62aa`.
- `k4-certified-batch-regression46.log`: `45cbc8a765bfb7c009e3bf0fbc9c0b70ae3a931972ce2230cc8fe0641492086a`.


### K4 linked archive and signed gossip acceptance, 1 November 2026

The actual independently linked first/observer node at `e9033433` matched all
11 preserved archive stages in each graph (session55533, exit0, 11.11s execution).
The original archive was not regenerated. The build and comparison records are
under `.build-cache/k4-archive-bundles/`, including `archive-comparison.json`,
`archive.stdout.json` and `archive.stderr.log`; the full build log is
`.build-cache/k4-linked-archive47.log`. Executable SHA-256:
`1824912eaa44378b2cff9422fe9cc11f78696c0f1133b64e772127725572351b`.
The comparison record binds the source, build report, binary and raw outputs.
This closes the earlier linked archive comparison gap; it is not evidence of
committee authority for the uncertified old archive or of other platforms.

Added actual two-peer signed GossipSub delivery to `certified_value_wire` using
the production engine/network configuration. Both maximum framed batch shapes
(one maximum-size transaction plus filler, and many small transactions) cross
the transport and retain exact encoded bytes and authenticated publisher identity.
The readiness barrier observes a small message on the same channel before sending
each large message once. Peers use temporary WAL directories and ephemeral ports;
normal teardown stops and joins each engine. No framing limit or fork changed.
All six wire tests passed (session68750, exit0, 3.27s; 13.90s compilation), recorded
in `.build-cache/k4-gossip50.log`. Attempt48 caught a PeerId type mismatch. Attempt49
incorrectly awaited mesh membership for persistent peers; the corrected fixture
uses bidirectional persistent connections and actual message delivery. Neither
failed attempt is acceptance evidence.

Clippy53 passed the indexer tests with `protocol-qualification` and `-D warnings`
(session45355, exit0, 27.84s), after removing unused test adapters, redundant borrows
and test-only lint issues. Ordinary workspace formatting exposed remaining
formatting differences in two fixture files, subsequently formatted. These are not execution
rule changes. Removing the unused runtime test helper nevertheless changes the
unreleased observer source definition to
`7026414e4530a26af9768253beea0e4bd426d28d6bcccec15d494c2014d1a82a`.
Historical first/second definitions and frozen sources remain untouched. The
updated draft coordinator definition is
`c918d397b03749c18d0de2aafe9c9aa50adebbffaeaae9788304a87e1446e6b5`.
Earlier linked results remain bound to their tested sources; final candidate CI
must rebuild and qualify the current definitions.

Lead inspection traced durable append before acknowledgement, retained input use
at Finalized, closure completion before next-height publication, and atomic
successor committee/closure/frontier persistence. The framing test deliberately
isolates transport from consensus authority; signed certificate/closure tests
cover that distinct invariant. The cleanup removes only unused test paths or
changes borrow/formatting structure. Prior scoped recovery, accounting and cluster
results remain recorded above with their source bindings. Full grouped independent
review, final-candidate scoped platform checks and merge remain outstanding.

The focused source-root, coordinator-definition, node comparison/build/execution
tooling checks also passed: 41 tests in 6.70s (session98795, exit0). Final local
workspace formatting and diff whitespace checks passed. Raw evidence SHA-256:

- `k4-linked-archive47.log`: `a659f65f14144698d15d70d92bc95bc6e558215a8b25b5d334570c70b5a6199c`.
- `k4-gossip50.log`: `24a00863e09f187cb0f4bdc99384a9e90e55b346e2449131e268142a756334b3`.
- `k4-clippy53.log`: `c49257ed31e9632265ab9ff69b1e1ccfe86f95f97b189e21947c623d14d09ebd`.
- `k4-build-tools54.log`: `5c64aa92104b4181fcfe809af823004f10eb651068548acf863e9de67860fc83`.


### K4 normal workspace configuration, 1 November 2026

The CI-default `cargo clippy --locked --workspace --tests -- -D warnings` exposed
helpers that qualification-feature builds legitimately use but normal builds do
not. Scoped those committee adapters and reactor fixture wrappers to their actual
test/qualification configurations. Definition-specific session dispatch remains
compiled for real linked nodes. The historical committee operation stays in the
export ABI; its local adapter field has an explicit dead-code allowance only in
builds that do not exercise historical qualification. Live authority still comes
from trusted registration observations.

Clippy55 identified eight unused items; Clippy56 identified two wrappers used only
by qualification, rather than ordinary unit tests. After the corresponding cfg
corrections, the complete default workspace Clippy57 passed (session27614, exit0,
25.95s). No execution rule or retained bundle definition changed in this follow-up.
The draft coordinator reference is now
`a49ebd6b121d1cdc40d9cf264dbbd537db13357e6c339dc51abf15ee4680b3d7`.
The source-only correction will be included in the consolidated review, not sent
through a separate independent review campaign.

Raw `k4-default-clippy57.log` SHA-256: `0a8f51e7cd08db8e6e474c64fcc36b46becfb5015f74f413932cbddf8bf3bfbd`.


### K4 consolidated review and original-bundle acceptance, 1 November 2026

The single independent reviewer examined the complete K4 group from merge-base
`fdf6a65d3a14cf88af7271d666bf13b001849d2f` through `f6d1b320` (including the
normal-build cfg corrections). Remote main was independently checked and remained
that K3 merge; no K4 PR existed. Review covered durable acknowledgement, exact
input/proof bindings, genesis/unavailable legacy state, stage/observation atomicity,
closure/Next ordering, historical authority, branch replacement, frozen replay
intervals/exclusions, recovery, ownership, factory mapping and qualification gates.
The reviewer compared all 1,264 frozen entries against the K3 source with no
mismatches and inspected prior linked evidence hashes. No runtime work was rerun
by the reviewer.

One material finding was accepted: proposal reassembly had stream/part count caps
but no aggregate raw-body byte admission before proposer authentication. Five
unfinished near-4-MiB Data streams exceed the agreed 16-MiB budget. The post-completion
early-proposal limits do not cover those streams. The bounded correction is
assigned as `K4-REASSEMBLY-BOUND` to the existing defensive implementer in an isolated
worktree; integration, lead review and focused independent follow-up remain
required. This is an identified resource-bound failure, not a new paging project.
No other material state, authority or compatibility regression was found.

The reviewer also identified repeated full-batch decoding and membership scanning
in finality seed validation, quadratic in transaction count when many transactions
fail in one batch. The lead confirmed the source path in `finality::seed`, `probe`
and `capture`. Practical latency has not been measured. Retain this scalability
limitation without adding a performance campaign or merge gate, consistent with the
operator's performance disposition. It is not a claim of acceptable worst-case
throughput or a reason to change gas or ordering.

The explicit `legacy-qualification` link set then built both relocated original
executors at `f6d1b320`, passed native ownership/interface controls and executed all
25 existing qualification cases (session45836, exit0, 99.91s runtime). First and
second matched each other and the preserved semantic baseline; no current K4
certified-history result is claimed by this legacy link set. The original execution
definitions remain `a69902e230dfa7ae50079838c5d90cf33c6a00de9fc901bf2c26e363449e19e4`
and `0565ceaf03d95097c02f86ad4bfb6f0c352900ecdfcf071960a408404a81bc48`.
Artifacts are under `.build-cache/k4-legacy-bundles/aarch64-unknown-linux-gnu/dev/executors/legacy-qualification/`.
The lead independently verified the build report, stdout, stderr and installed
binary hashes. Executable SHA-256:
`09d63f7fb9d33aafa9fc4628aebec9b11fafb375f33eaf58b563b11d67fe5915`.
This closes relocated original-second linked execution, not final production
platform CI. Existing first/observer evidence and pending final candidate checks
retain their distinct scopes. The reviewer will inspect this evidence and the
buffering fix in a focused follow-up, preserving the rest of the completed review.

Raw `k4-linked-legacy58.log` SHA-256: `c30380665c360a466203081cc629a07b2cbab1dbc5507bf21f2116f2d83ace90`.

The independent follow-up verified the legacy build/output/binary and ownership
report hashes, checked all 536 qualification source entries against `f6d1b320`,
and confirmed both original definitions, the 25 cases, the semantic baseline and
explicitly absent certified-history claim. It accepted this acceptance gap as
closed. The reassembly correction and final-candidate CI remain outstanding.


### K4 proposal reassembly review correction, 1 November 2026

Integrated the bounded defensive implementation `e696f75b` as `9a48cb91` after
lead source inspection and terminal validation. The changed files are the proposal
reassembly map, its export and the reactor caller. Admission now limits aggregate
retained stream IDs, descriptor/body bytes and a conservative 256-byte per-part
allowance to 16 MiB. The existing stream and part count limits remain. Duplicate
sequences do not recharge, refusal leaves no empty stream or seen sequence, and
completion or explicit discard releases the stream's exact accumulated charge.
Impossible Fin sequence values are refused before sequence arithmetic. Local
saturation maps to the existing no-completed-proposal reply, not invalid consensus
work. Round changes do not clear live streams.

Lead review traced Value::size_bytes, the stream-ID ownership path, accounting
before retention, completion/removal and the handler's reply classification. The
budget is not total RSS: decoded transactions and transient decoding add memory.
Abandoned streams remain bounded but can stay until completion, explicit discard
or map destruction. There is no new production discard caller, eviction policy,
transport retry protocol or guarantee of fair admission under a flood.

The implementer ran the exact source without edits during execution: 11 reassembly
unit tests passed in0.54s (after2m25s compilation); the maximal proposal encoding
test passed in1.66s; the real reactor early-proposal/committee handoff regression
passed in69.47s; package Clippy for lib/tests with warnings denied passed in42.73s.
The lead inspected the raw logs and unchanged three-file cherry-pick. Formatting
and whitespace checks pass. These bounded checks address the identified regression;
they do not replace the pending final-candidate platform campaign.

The observer execution definition remains unchanged. Refreshed only the unreleased
draft coordinator source reference, now
`3d06eb32c3a3b61ccbe9b3a7c56910b7ec52a84d1771bafd1366bdfa1365f3a4`.
No historical definition or frozen source changed. Focused independent review of
this delta is required before opening the PR; the remainder of the consolidated
K4 review and its evidence remain valid within their recorded source scope.

Raw evidence is in the main workspace `.build-cache/`:

- `k4-reassembly-part-streams.log`: `8bcb9f6ca112c8e1c1f4ddd4f5bfba2d5e6f53309ae2044016809689df63a5c3`.
- `k4-reassembly-max-wire.log`: `495266944574e1531b9179de0a2b42abff33dde334a403838912d448eb05dc12`.
- `k4-reassembly-ingress.log`: `f9c9eb7594dd9e4ee5473b6d995ec29d53cf48f88d772b5cd5e1addab13fedea`.
- `k4-reassembly-clippy.log`: `8897a241bfc3ba545619877250003ba2c8df5d7ef8b2cb22ab4579a397cfa9fa`.

The sole independent reviewer closed the reassembly finding at `34bd03ea` and
approved K4 source review, retaining the completed consolidated coverage and
legacy-link-set acceptance. It verified admission ordering, duplicate handling,
checked accounting, completion/discard release, Fin bounds, local reply semantics,
the identical cherry-pick, raw test results and exactly three updated coordinator
source hashes. No further workloads were run and no new material finding remained.
Final-candidate CI is still required. Before the first push, remote main remained
`fdf6a65d` and GitHub reported no existing K4 PR or branch workflow runs. One scoped
candidate campaign is needed for the changed coordinator, observer and linked-node
builds, retaining the automatic release-three/bounded-dev policy.

### K4 first-campaign qualification-control correction

PR620 first candidate `e3bcef78` failed native-stack evidence controls in run
41334668424 before executing the platform matrix. The sole source-registry drift
was the indexer build-script hash: K4 declares the `kontor_observer` check-cfg,
but the generated resource manifest still named the earlier bytes. Refreshed
that one input hash and its dependent v2, boundary and suite-registry hashes.
No source code, case policy, measured result, frozen executor or historical
qualification artifact changed. The comparator correctly rejected skipped jobs.

The exact CI control command now passes locally: 235 tests in 23.127 seconds,
exit zero, `.build-cache/k4-ci-evidence-controls60.log`. The initial sandboxed
check passed the manifest controls but six local Unix-socket tests could not bind;
the complete check then passed with local socket access. Lead inspected the four
generated-file diffs; this nonmaterial metadata correction retains the completed
source-review coverage. No new runtime tests or performance campaign were added.

Push the consolidated correction promptly so workflow concurrency cancels the
superseded active candidate, rather than paying for both full campaigns. The
corrected candidate still requires its own passing CI, including the stack matrix
that did not execute in the first campaign.

### K4 regtest first-block startup correction

SDK job 124933441505 in CI run 41335140236 failed while starting the real
`kontor regtest` devnet. Its harness waited for `/api` availability before mining
height 102; K4 now needs the first certified block before publishing chain-state
availability. Move the existing one-block mining operation immediately after all
active node processes spawn and before the availability barrier. Keep the seed
listen-address barrier, quorum, readiness predicate and later height check intact.
This is a harness ordering correction, not a consensus-rule change.

Lead traced the CI log and caller flow. The sole reviewer checked the focused
diff and accepted the correction. Local dev binary build passed in 55.29 seconds
(`k4-regtest-startup-build61.log`). A real `kontor regtest` process then reached
its SDK readiness marker with eight funded identities in 18.676 seconds, served
`/api` at height 103 and exited zero on SIGTERM. Evidence:
`.build-cache/k4-regtest-startup63.json` and `.log`; binary SHA-256
`17dc82ea029bdce22a77a1ec27161cd02c2fef4081e89cf09409fd2457109ebd`,
log SHA-256 `2404d654c57fdbe38e2d23c2b91076f24e50328ad3c4e235332fa4b21879d670`.
The first local probe reached readiness but its checker used the wrong API JSON
envelope; correcting the checker to read `result.height` produced the recorded
pass. This focused startup check is not a claim that the complete SDK suite ran
locally. The corrected candidate still requires CI. No executor definition or
coordinator reference binds this harness file, and none was regenerated.

### K4 ordinary-CI test representation and startup corrections

Both ordinary release CI jobs at `bd3b3b78` reported the same twelve failures:
eleven replay tests still inspected the certified value as if it were the filtered
execution body, and the delayed-proposal test bypassed certified genesis setup.
Correct the assertions to inspect `execution_txs()` while retaining the original
certified-body assertions. Correct the repeated-filter fixture to keep its full
original body in `value`. The startup fixture now uses the real executor session,
certifies and applies block 1, then delays the height-2 GetValue callback by five
seconds and still requires a round-zero decision within the original proposal
deadline. No production execution or consensus rule changed.

The initial replay check passed 21 tests. The sandboxed startup attempt could not
listen on its local socket and timed out; with socket access it passed. A broader
local dev reactor run was deliberately stopped after a SQLite lock failure in
the rollback cluster test. Isolating that test also exposed its unsupported
assumption that two separately recognized transactions enter one batch. The
fixture now submits and observes each transaction separately, checks preservation
of both certified decision IDs across branch replacement, and verifies fresh
higher-height execution plus counter state `2 -> 0 -> 2` on all three nodes.
Its read helper opens and uses the pool in a blocking task so SQLite's synchronous
busy handler cannot freeze the current-thread test runtime driving writer commits.
The failed and stopped attempts remain recorded, not counted as passes.

Final bounded local regression: 24 passed, zero failed or ignored, 1031 filtered,
61.75 seconds, exit zero (`k4-ci-regressions69.log`). This covers the 21 replay
cases, both startup tests and the rollback cluster case. Lead review and the sole
independent review accepted the corrections and retained the prior consolidated
K4 approval. The unreleased coordinator reference changes exactly the hashes of
these three test source files; dependency fields, retained executor definitions
and the observer definition are unchanged. Current-head CI remains required.

Evidence record: `.build-cache/k4-ci-test-correction.json`. Raw log hashes:
- `k4-replay-ci-correction64.log`: `6c423fcb76977f79ef798077fd9e9ca446ff72c8ed34730611e216b4dc3ab700`.
- `k4-startup-deadline65.log`: `1407fd4cccde43488fe04cf669ab84345ff026d469031b6ea8c5d6e91028dc53`.
- `k4-startup-deadline66.log`: `8ec0532d8a0b6e459837e9e692cce147b33b93c46b2315443d309d286a865e06`.
- `k4-reactor-ci-correction67.log`: `e56ec29d76fca026edc4002185f35acece29dd42d8e32ef9a8f3fd846a37e5e3`.
- `k4-rollback-lock-isolation68.log`: `543cced63e12dd26ca246c218ce17e8f8ff4c7604b6e881071adf08c83f6576d`.
- `k4-ci-regressions69.log`: `a6c48471f9b9f6bfc5a0402209fd2829a40d5148b8ccc14e4fd3253c7b8e8960`.

### K4 merge and final qualification, 1 November 2026

PR [620](https://github.com/KontorProtocol/Kontor/pull/620) merged as
`0a2cbd89e8ebdd8acc74b514e6d5e85e4c9466dd`. Its tree
`00391db8c5665c82c0601a8a749253d4f37e569f` exactly matches candidate
`25fee2f6d56afdb20d72f5dbb4180b398704e7a7` and the qualified PR test merge
`364a3d4776778536d332c6e52241c257e73038a3`. Lead and sole independent
review coverage includes the final regression-fixture corrections above.

All four final-candidate workflows completed successfully: ordinary CI
`41339806743`, native stack `41339806784`, linked-node qualification
`41339806858`, and Docker cache qualification `41339806748`. Both comparison
jobs and `CI required checks` passed. The lead downloaded the raw release and
dev-smoke evidence, validated it against the checked-out source and artifacts,
and reproduced both CI comparisons locally without rerunning workloads.
All three linked-node release platforms produced the same observations digest,
`2dff48679c667cfe78a8db2076a6a0139435a69e03f1aab586af416f5915b2cc`.
This qualifies the recorded cases, not all possible executions or throughput.

Evidence is retained in the preceding worktree under
`protocol-certified-history/.build-cache/k4-final-25fee2f6/`, including raw
reports, comparison records, ordinary CI logs, terminal workflow checks and the
merge response. Duplicate post-merge stack and linked qualification runs
`41343775884` and `41343775867` were requested cancelled only after verifying
tree equality. Main CI `41343775846` remains responsible for its unique image
publication. No SDK or Site publication was performed.

The next grouped phase, K5/K6, starts from this verified merge in the isolated
`protocol-upgrade-control` worktree. Its agreed revision-2 plan preserves the K4
development baseline without silently relabeling existing databases, introduces
independently locked real managed consensus graphs, and implements durable
signing, engine coordination and explicit upgrade authorization. Actual
after-H activation and cross-boundary recovery remain in K7/K8.

### K5/K6 baseline preservation, 1 November 2026

The extended existing snapshot tool captured K4 from the exact merge, using locked
offline node and observer metadata under the shared Cargo lock. It verified both
definitions before and after relocation. Snapshot
`protocol-bundles/retained/k4/snapshot.json` has SHA-256
`9359c0b7cdca0d9e2852262337061ce43a0856b32e36c173a41c4b874ba1ebf9`.
It preserves coordinator definition
`f02def02f91e190b72103d6d2a77c9521d86c0c1b7d814b9b792415fd8f9b4af`
and observer definition
`7026414e4530a26af9768253beea0e4bd426d28d6bcccec15d494c2014d1a82a`.
The selected historical executor reference is included; its complete existing K3
snapshot remains separately hash-bound rather than copied again. This preserves
development-baseline interpretation, not a claim that an old K4 live engine is
linked into the managed baseline.

Focused source-root and coordinator-definition tests passed (7 and 3 tests).
They check the frozen inventory, every coordinator source digest, historical
executor reference, and baseline composition/lock inputs. The original snapshot
checks still reject mutations, extra files and substituted inventories.
No Rust build or runtime workload was started. Managed consensus adapters,
durable signing and upgrade control remain to be implemented and reviewed as one
group before its final-candidate CI campaign.

### K5/K6 real consensus graph foundation, 1 November 2026

Added independent `consensus-first` and `consensus-second` workspaces pinned to
managed Malachite `6d99c0a43a21ff48ff3f69a5f9e834310d0b0b09`. They compile the
production Kontor context, validators, certified values, proposal/vote types and
protobuf codecs. Their local protocol subset includes the exact descriptor/body
validation and identity codecs. Neither resolved graph contains Wasmtime, libsql
or Malachite's TestContext crate. The production signing module in these graphs
contains public-key/address types only; private keys are available solely to tests.

The first wire codec preserves the existing protobuf framing. The second wraps
all codec messages in its distinct versioned envelope. A representative real
Kontor block value keeps its certified identity across round-trip, and the two
wire formats reject each other's input. This does not change historical value or
certificate encodings. The wrapper also accounts for envelope bytes in sync
response length reporting.

Each independently locked graph passed 24 library tests, including inherited
certificate, committee arithmetic, descriptor/body, identity and work-accounting
checks, plus wire incompatibility. The first check encountered a read-only ccache
configuration; disabling ccache allowed the build to proceed. Isolated resolution
exposed Serde's previously indirect `rc` feature, now explicit in both manifests.
An explicit test-module path enables reuse of the production certified-input
tests from the new crate. Earlier failed attempts remain logs, not passes.
Evidence: `.build-cache/k5-consensus-graph-foundation.json`, with raw log and lock
hashes. New Rust files pass formatting checks.

This is an intermediate local checkpoint. The crates are not yet linked into the
node, and managed lifecycle, node event/reply bridge, durable signer and authorized
control remain unfinished. Unused-code warnings reflect that unwired state and
are not suppressed. The existing live baseline reference remains unchanged;
its replacement and old-database preflight belong to the managed-baseline
integration, so this checkpoint is not a final-candidate node build.

### K5/K6 private consensus event bridge, 1 November 2026

Added the graph-private adapter for the real Malachite application messages and
proposal-publication channel. Events cross the intended boundary as owned bytes
with generation, operation and one-use reply token. The private registry keeps
Tokio reply senders inside their resolved graph. Retirement closes both delivered
and queued requests, and rejects subsequent event delivery and publication.
Nonblocking channel polling and publication preserve bounded queue backpressure.

The adapter preserves actual Kontor value encoding, decision certificates,
committee order, height parameters and separate peer-fault/local-transient sync
outcomes. It checks reply positions, history ranges and trailing adapter bytes.
Vote extensions remain disabled. Finalization misbehavior evidence remains a
diagnostic string, matching its existing logging-only reactor use. Network wire
envelopes remain separate from the in-process adapter encoding.

Reply results distinguish stale generation, unknown token, wrong operation,
malformed payload and ordinary receiver expiry without text comparisons. A
malformed addressed reply consumes its capability and retires the bridge; normal
GetValue expiry does not fault it. The lifecycle owner must act on bridge faults
and retain engine ownership until join, which is still pending integration.

Both independent locked graphs passed 39 library tests (zero ignored or failed),
including real-value/certificate translation, delayed and duplicate replies,
retirement of buffered requests, bounded publication, malformed framing,
committee-order retention and unsupported extensions. Formatting and whitespace
checks pass. Raw logs and source/lock bindings are recorded in
`.build-cache/k5-consensus-bridge.json`. No CI was launched for this intermediate
local checkpoint.

These tests exercise the real graph types and channels, not a live managed engine
or the node reactor. Managed owner/start/join, node adapter, linked graph
provenance, the new baseline/preflight, durable signing and upgrade authorization
remain unfinished. This is progress within the agreed K5/K6 group, not its
acceptance or a production integration claim. Consolidated review remains pending.

### K5/K6 managed owner lifecycle, 1 November 2026

Added a graph-private owner around the fork's actual `ManagedEngine<Ctx>`, using
Kontor's real context and each graph's wire codec. The owner is non-Send so it
stays on the calling control thread. It retains the managed engine on startup or
shutdown timeout, retires reply/publication channels before shutdown, preserves
faults through join and makes repeated join queries stable. Drop retires pending
application replies before the managed engine's blocking destructor runs.

Channel availability is explicitly `ChannelsReady`, not consensus readiness.
The node adapter must separately await the actual `ConsensusReady` event before
exposing a running engine, with a bounded deadline that keeps ownership on timeout.
An initial occupied-port test incorrectly expected all listener failures to
surface as immediate managed-start errors. The fork can instead leave channels
available without that readiness event. This is a required case for the node's
readiness deadline, not evidence of successful startup and not a reason to start
a competing engine. A separate invalid-WAL-path test establishes actual partial
startup failure after network construction, joined cleanup and sticky fault state.

Both independently locked graphs pass 42 library tests, zero failed or ignored.
The new lifecycle cases exercise real follower engines, the real Kontor codec,
WAL reopening, the same TCP listening port, deterministic startup/shutdown gates,
retired callbacks and partial-start failure. A test-only verifier rejects all
signatures and followers have no consensus signer; these are lifecycle tests,
not cryptographic acceptance or multi-validator consensus evidence.

The first sandboxed run could not bind localhost and failed the three lifecycle
tests. Running with local socket permission passed the ordinary lifecycle and
timeout cases; the occupied-port assertion above was then investigated and
corrected. Raw failed attempts are retained. Final-source logs and hashes are in
`.build-cache/k5-consensus-owner.json`. Formatting and whitespace checks pass.
No CI, PR or publication was triggered.

The owner is not yet connected to the node reactor or a public linked factory.
Node-side durable signing/generation revocation, authorization, immutable managed
definitions and build/link integration remain pending. The node coordinator must
revoke signing independently of this owner's potentially blocking join. The
operator's discussion clarified that linking does not require IPC or a generic
serialized internal RPC layer; typed per-bundle adapters are possible. Keep the
interface narrow and do not infer a requirement to serialize every operation.

### K5/K6 typed consensus facade refinement, 1 November 2026

The sole independent reviewer explicitly agreed the interface refinement against
`de7a03d35c4afe07dc2c38232495726791ee606b`, before implementation. Each consensus
bundle owns public Rust DTOs composed only of standard-library types. The node
will translate between their distinct types without casts or a shared semantic
crate. This replaces the unmerged generic operation-code and outer-byte encoding;
it does not change network codecs, signing bytes or the merged executor API.

Events now carry named request variants and an optional generation-bound reply
token whose fields are private to the bundle. Responses carry named variants;
the private registry checks the response kind before consuming a token. Canonical
value, proposal, proposal-part, certificate and sync payloads retain their existing
codecs in distinct byte wrapper types. Heights, rounds, timeouts, roles and committee
parameters pass directly as typed data. Parameter conversion still validates
committee order, membership uniqueness and voting-power arithmetic. Existing
u32 collection/byte ceilings remain checked, with bounded queues and pending replies.

Both independent locked consensus implementations pass 45 library tests, zero
failed or ignored. These retain the real managed-engine lifecycle cases and add
coverage for malformed inner payload retirement, history range/order checks and
synced verdict height/round/proposer checks. Formatting and diff checks pass.
Source/lock/log hashes are in `.build-cache/k5-consensus-typed.json`; no remote CI
or publication was triggered. Lead inspection traced all ten application event
variants, internal disabled-extension handling, one-use response ownership,
receiver expiry, stale-generation rejection, malformed-response retirement and
owner shutdown. No material regression was found in this intermediate scope.

Public factory configuration, typed public errors/callbacks, node integration and
actual independently linked facade type controls remain part of K5/K6, not proven
by these library tests. In particular, the real-node readiness deadline must still
cover a listener that never produces ConsensusReady, and signing revocation must
remain callable independently of blocking join. The final grouped implementation
review and required CI remain outstanding.

### K5/K6 typed factory and readiness ownership, 1 November 2026

Added typed engine configuration and a concrete non-Send engine facade. Public
operations return bundle-owned errors and standard-library data. The internal
factory maps settings to the private Malachite configuration, derives a separate
network peer identity and preserves follower mode without a consensus signer.
Invalid settings fail before engine construction or WAL creation. No consensus
private key is accepted by the configuration.

The facade distinguishes starting, initializing, running, stopping and joined.
Private channel availability is insufficient for running: the actual ConsensusReady
event and successful initialization reply are both required. Polling and replies
check a bounded readiness deadline; expiry retires pending callbacks and requests
stop while retaining the owner. Publication requires the current running
generation. Public stateful operations contain unwinding panics, retain a sticky
failure and request stop without giving up join ownership. A failed joined engine
still reports its failure, separately from the joined state.

Both independently locked graphs passed 50 library tests, zero failed or ignored.
New real-engine cases establish follower settings, readiness acknowledgement,
occupied-listener failure without false readiness, initialization timeout,
panic containment with joined cleanup and configuration refusal before WAL
creation. These run alongside the existing timeout, WAL/port reopen and typed
reply tests. Raw logs and source/lock bindings are recorded in
`.build-cache/k5-consensus-factory.json`. Formatting and whitespace checks pass.
No CI or publication was launched.

The internal start function still accepts the graph-private consensus context.
Its public authority-based entry point awaits the bounded durable-signer callback
integration; the node control thread and reactor wiring also remain unfinished.
The lifecycle tests continue to use a reject-all verifier, so they establish no
signature acceptance claim. Actual independently linked type controls, durable
node transitions, signing fences and combined group acceptance remain required.

The operator-designated Daybreak implementer confirmed availability and accepted
an explicitly bounded security-sensitive durable-signing assignment. It owns new
authority API/adapter and node durable-signer files in its isolated worktree. The
lead retains ordinary factory/coordinator work and final integration. The agreed
callback carries typed roles and canonical preimages, never the consensus key;
node signing state validates and persists before returning signatures. Proposal
and proposal-part signatures share a value commitment, and generation fencing
remains independently callable during control-thread joins. The single Cargo
slot was released after both local suites exited successfully. Delegated work
still requires lead review and the one consolidated independent group review.

### K5 consensus build integration, tooling checkpoint

The builder now has an explicit `--build-consensus` mode for the independently
locked `consensus-first` and `consensus-second` production graphs. Their identity
binds the managed Malachite revision, manifest, lock and source root without
inventing a Wasmtime identity or execution settings. Resolved consensus graphs
reject Wasmtime and node storage dependencies, require the pinned Malachite
closure and patched native crypto, and inventory the shared crate, imported
production types and protobuf sources outside each manifest directory.

The native input audit accepts explicitly identified VM-free graphs while still
rejecting shared namespaces, colliding definitions, unowned native symbols and
process allocators. Mixed final-link attribution retains each Wasmtime helper's
actual graph owner. The source ownership tripwire distinguishes certified-input
`Command::Block`/`Batch` variants and read-only PID access from process control.

Consensus staging also compiles interface controls against its actual libraries:
explicit typed DTO conversion and engine operations must compile; implicit
cross-bundle DTO/engine conversion, private consensus/owner access, private Tokio
type exchange and moving the engine owner across threads must be rejected for
their expected compiler errors. Missing dependencies cannot count as successful
negative controls. Report bindings preserve the library hashes and diagnostics.

Local tooling validation passed 74 focused tests covering consensus recipes,
sources, ownership and interface inputs together with existing executor recipes,
dependency checks and node build/ownership controls. The log is
`.build-cache/k5-consensus-build-tooling-tests.log`. The initial native fixture
run could not write the default compiler cache; rerunning with `CCACHE_DISABLE=1`
passed. No Rust bundle build, actual consensus interface compilation, node link,
CI or handoff qualification ran in this checkpoint. The durable-signing agent
has the reserved Cargo/runtime slot in its isolated worktree; source-only
tooling tests do not establish production integration. Actual staged builds,
linked node adapters, signer integration and grouped acceptance remain open.

### K5 typed node adapter checkpoint

Added node-owned coordination messages and explicit adapters for both production
consensus facades. Each adapter moves canonical payload bytes without decoding
or re-encoding them, preserves request generation, round distinctions, committee
order and timeout fields, and maps typed errors without matching their text.
Reply tokens retain their originating bundle tag; a token from the other bundle
is rejected before invoking either engine. The selected owner remains non-Send
and exposes poll, respond, publication, readiness diagnostics and stop/join
operations for the upcoming control-thread integration.

The maintained `tools/kontor protocol-bundles` command now forwards
`--build-consensus`. Consensus staging compiles the actual node adapter sources
against both independently staged libraries and runs seven focused conversion
tests. The checker requires both bundles' named tests to execute with no failures
or ignored tests, and records source, library, executable and log hashes. Node
adapter sources are included in the staging provenance inventory.

Formatting/whitespace checks and 75 focused Python/C tooling tests passed
(`.build-cache/k5-node-adapter-tooling-tests.log`). After the signer agent returned
the slot, the maintained CLI compiled and the local staging run built both real
consensus graphs, passed their native input ownership audit, and passed all seven
actual-library type/privacy checks. The stored interface report was verified
against the staged graph reports and raw diagnostics.

The subsequent adapter test compile failed with E0583: importing the parent module
through an external `#[path]` changed Rust's child-module lookup directory. The
harness now explicitly imports the actual adapter and DTO files. Seventeen focused
tooling checks passed after this fix. The next compile exposed publication's
borrowed argument requirement. Publication now returns the original owned payload
on full, closed or failed delivery, allowing retry without copying or loss.

A focused rerun verified the staged library hashes, compiled the actual adapters,
and passed all seven adapter tests, with zero failed, ignored or filtered out.
The payload retry test checks the original allocation is retained. Evidence and
source/library/binary/log bindings are in
`.build-cache/k5-node-adapter-validation/result.json`; raw output is under its
`node-adapter` directory. The earlier partial runs remain failures, not relabeled
passes. No full node handoff qualification marker is claimed by this focused run.

The node module is gated by `kontor_managed`; the production builder does not
enable it yet. Production reactor wiring, control-thread implementation, managed
baseline activation and a successful linked handoff remain part of this grouped
implementation, followed by the consolidated review and required CI.

### K5 durable signer and public authority startup

Integrated delegated signer commit `55df953b` after lead inspection of its six
files and the canonical codecs and ownership paths they depend on. The journal
records bounded message commitments and signatures, preserves exact retries and
cross-generation conflict history, and serializes durable signing and fencing.
Proposal and proposal-part Fin share a value commitment. The node retains the
validator key; each bundle receives only typed signing callbacks. The network key
is separate. The journal lives outside reversible canonical state.

The inspected delegated node log records 12 passing signer tests. Both integrated
consensus graphs now pass 54 tests each through the public authority-based startup
path, including actual follower/validator startup, invalid configuration before
signing, signing failure and panic before WAL creation, readiness and stop/join.
Local evidence is `.build-cache/k5-authority-factory.json` and its two raw logs.
The older sandbox owner/readiness timeouts remain recorded; these complete runs
succeeded with localhost networking available. No new CI campaign was started.

The lead review is recorded in `.build-cache/k5-durable-lead-review.md`. Torn
journal frames fail closed; deleting or rolling back the entire signing directory
cannot be detected without an external monotonic anchor. Journal history grows.
These are limitations, not claims of automatic repair or bounded total history.
The node must still connect generation selection, independent revocation,
control-thread lifetime and reactor replies. The new public startup entry point
and component tests do not establish a working protocol activation yet.

The node now has explicit startup adapters for each bundle's configuration and
signing request/error enums. The actual node library and test executable were
compiled with both independently staged consensus libraries. Eight focused tests
passed, including startup through the real node durable signer for both bundles,
Ready delivery, independent node fencing, stop/join, releasing the old signing
owner, and reopening the same journal under the next generation. Seven existing
adapter conversion/backpressure tests also passed in that executable.

The first local test build failed because `testlib`, a reverse dependency of the
node, lacked the separate library search paths. Correcting the local compiler
wrapper resolved E0463; the retry reused verified staged artifacts instead of
rebuilding or reauditing unchanged dependencies. Raw successful evidence and
source/library-wrapper/binary/log bindings are in
`.build-cache/k5-node-authority-test-rerun.json`. This check uses the real node
sources with `kontor_managed` enabled, but does not enable the production builder,
change the preserved K4 baseline, execute a consensus decision, or establish the
remaining live reactor handoff. No PR or CI run has been launched for this group.
The same linked test executable also passed all 12 durable-signer tests locally,
including conflicting retries after reopen, fencing races and failed writes.
This reused the compiled binary without another Cargo build; its hash and raw log
are recorded alongside the adapter result.

### K5 node control-thread checkpoint

The node now constructs the selected non-Send engine on a dedicated control
thread. Bounded node-owned event and command queues carry typed messages and
reply tokens; bundle Tokio and Malachite types remain private. The node can
request stop and revoke signing independently of that thread. Node async tasks
poll for thread completion without blocking on a running thread's join.

The engine slot is released only after an explicit successful join. A timeout
retains its handle and slot. An abandoned handle requests stop, but leaves the
slot unavailable; failed startup or teardown also fails closed. The worker
retains and drains the actual engine. Pending commands are rejected before
blocking teardown, returning publication buffers where non-publication is known.
A lost acknowledgement after admission is represented as unconfirmed, rather
than incorrectly reported as a definitely unsent publication. Readiness expiry
is enforced even when the event queue is full.

Twelve focused managed-node tests passed in the actual node test executable
linked to both independently staged consensus bundles. Four new tests cover
ordinary control-thread startup/replies/listener discovery/stop for both bundles,
a blocked real engine startup while node signing is independently revoked,
timeout retention and rejected competing startup, failed and abandoned owners,
and unacknowledged Ready expiry. These tests run on the node's single-threaded
async test runtime, so the blocked control thread does not occupy that runtime.
The existing startup and adapter tests also passed. Evidence is
`.build-cache/k5-control-test.json` and `.build-cache/k5-control-test.log`.

This is still component integration. The reactor must adopt these events/replies,
reject stale generations before applying work, persist the selected managed
baseline/generation, and use the stop/revoke/join sequence for live handoff. The
production builder and K6 control path remain unfinished. No new CI or independent
microreview was requested; the grouped PR still needs its consolidated review.


### K5 reactor reply bridge checkpoint

A node-owned reactor bridge now converts managed bundle events into the existing
handler types, retaining canonical payload codecs. Reply futures and any response
already being submitted remain owned by the bridge across cancellation of a
reactor poll. Pending replies are bounded. Dropping a handler reply explicitly
abandons its private engine sender; abandoning startup fails the engine instead
of acknowledging readiness. Stale-generation cancellation cannot consume another
generation's reply. Finalized evidence remains diagnostic text and the existing
certificate/finalization handler remains authoritative.

The actual node test executable, linked with both independent consensus bundles,
passed 15 managed tests. The three new tests cover delayed replies across canceled
polls for both bundles, retained outgoing response futures, and dropped startup
replies followed by engine join. Both bundle suites passed all 56 tests, including
explicit cancellation, stale and repeated cancellation, and abandoned readiness.
Evidence is `.build-cache/k5-reactor-test.json` and
`.build-cache/k5-abandon-tests.json`, with their raw logs. The initial role-name
compile mismatch is preserved in `.build-cache/k5-reactor-initial-compile.json`.

This checkpoint does not switch production startup or complete K5/K6. The live
reactor loop, durable generation selection, proposal signing, managed baseline
identity, production build wiring, authorization and final grouped review remain.
No PR or CI campaign was launched for this checkpoint.

### K5 live reactor transport checkpoint

The reactor now receives consensus events, publishes proposal parts, discovers
the listener, signs proposal Fin messages and stops the engine through a
node-owned transport. Managed engines use the same durable signer for Fin and
engine signatures. Publication backpressure retains the original buffer;
shutdown retires callbacks, independently fences signing and awaits the worker.
Construction failure also requests engine shutdown. Legacy startup remains
selected until managed protocol identity and durable ownership are integrated.

The actual node linked with both independent consensus bundles passed 18 selected
tests (zero failures or ignored tests, 72.09 seconds): 15 managed component tests,
a new real signing/publication/decision test through each bundle, existing
validator agreement, and the delayed-proposal deadline regression. The new test
authenticates reassembled proposal parts and verifies the decided precommit
signature. Evidence and lead review are in
`.build-cache/k5-live-transport-test.json` with its raw log. Subsequent formatting
only changed whitespace in three fixture files, verified and recorded there.
This local driver did not record the test binary checksum; final grouped
acceptance must retain complete candidate provenance.

This does not establish full managed database application or activation. Managed
startup/identity, persistent generation ownership, production build wiring, K6
authorization and operator dry run remain unfinished. No CI or independent
microreview was requested; consolidated grouped review is still required.

### K5 persistent ownership and managed lifecycle checkpoint

The node now has an exclusive persistent generation owner, separate network
identity, and per-validator signing history. Reserving a generation appends and
syncs its identity before use. Restart advances the generation; within a process,
only successful engine join releases the active reservation. Follower mode retains
the same ownership lease without receiving a signing capability. Managed startup
checks the reserved generation, network seed, validator/follower mode and exact
signer ownership. Unowned control/reactor startup helpers are test-only.

Both the control handle and worker retain the lease. Dropping the public handle
while construction or teardown is blocked does not release the OS lock. A timeout
does not permit another reservation or engine. The real two-bundle transport test
now uses this persistent owner and verifies that node and both bundle graphs
derive the same network peer identity from its seed.

Lead review found that opening an existing journal with a missing lock could
create a replacement lock before rejecting the inconsistent state. Both the
generation owner and signer journal now check presence before lock creation.
Regressions remove each lock while its original owner remains live and verify
that repeated attempts fail without recreating it. These fixes were integrated
from the delegated ownership work and reviewed by the lead.

The combined actual-node suite passed 39 tests, zero failed or ignored, in
2.45 seconds after a 1m28s build. Coverage includes signer conflicts and retries,
crash/reopen generation advance, stale tokens, exact owner admission, missing and
truncated state, independent revocation during blocked engine startup, dropped
follower-handle lock retention, reply cancellation, and real proposal/decision
signatures through both bundles. `.build-cache/k5-owned-control-test.json` records
source, binary, wrapper, link specification and log hashes, plus lead review.
The prior 37-test result is retained separately as evidence before the lock fixes.
The delegated ordinary non-managed signer target also passed 20 tests before
those two fixes; it is not represented as final-source coverage.

Limitations: wholesale deletion or complete-prefix rollback of local authority
history requires an external monotonic anchor to detect. Missing/truncated state,
including a header-only journal after interrupted first initialization, fails
closed rather than being automatically repaired. Production managed baseline
admission, coordinator startup, builder wiring, K6 controls and dry run remain
unfinished. This is not final handoff/activation evidence. Consolidated independent
K5/K6 review and final scoped CI remain required; neither was launched here.

### K5 managed identity and database admission checkpoint

The operator clarified that intermediate pre-release implementations do not need
compatibility support. The goal and plan now exclude a K4 live compatibility or
migration project while retaining the final managed P1/P2 historical guarantees.

The managed definition now binds the actual coordinator sources and independently
locked consensus-first graph, including transitive dependencies, resolved features,
dependency aliases/target conditions, local sources and build inputs. Generated
references are excluded from their own source closure. The existing K4 reference
is unchanged. The managed reference is still unreleased and will be finalized
with the complete K5/K6 implementation, before registering its successor.

Daemon startup reads configured genesis once and checks existing protocol state
through a read-only database snapshot before opening the schema-initializing
writer. Supported initialization and restart retain their identity. Unsupported
contexts, changed manifests and populated state without protocol history are
refused without database initialization or relabeling. Pure genesis conversion
and chain derivation are shared with actual bootstrap to avoid divergent startup
identities.

Eighteen focused Python definition tests passed. Generation using the real
locked, unfiltered metadata covered 468 consensus and 493 coordinator packages.
Nine actual-node Rust tests passed, zero failed or ignored, in 17.60 seconds
after a 1m17s build. These cover identity separation, read-only admission,
interrupted genesis, unsupported/malformed state, atomic genesis reservation and
reopening a fully published native genesis through the daemon's admission API
without replaying publication. `.build-cache/k5-protocol-admission-test.json`
binds the source, binary, runner, wrapper, link specification and raw log. The
first run also passed nine tests, but its evidence driver incorrectly expected
ten and exited nonzero. That result is preserved separately; the final rerun
adds the ready-database admission path and uses the correct expected count.

This remains single-managed-protocol K5 startup. K7 must separate original genesis
verification from persisted current-era selection and interrupted activation
recovery. Production engine ownership before canonical mutation, managed engine
startup, final independent-graph node builder, K6 and grouped acceptance/review
remain unfinished. The local library tests do not establish final production
binary or cross-platform qualification. No CI was launched.

### K5 managed daemon startup and ownership checkpoint

The managed daemon now acquires its persistent generation owner and initial
signer before opening the schema-initializing writer. Read-only protocol
admission runs first, and runs again after the exclusive owner is acquired.
Unsupported intermediate databases remain untouched. A competing node cannot
create a second database in the owned directory. Network identity persists
independently of validator identity.

The reactor retains the node coordinator and starts the real first consensus
bundle through its typed adapter. Restart reserves a fresh generation only after
the previous engine has joined. The WAL path is era-specific and stable across
restarts within an era. Production managed startup requires the coordinator;
legacy startup remains available to existing isolated test/qualification fixtures.
There is no new Malachite fork change in this checkpoint.

Twelve focused Rust tests passed, zero failed or ignored, in 53.20 seconds. The
new live test publishes actual native genesis, starts a consensus round, joins
the engine, restarts another round using the same node owner and WAL, joins again,
and verifies the next reservation is generation three. Admission, preserved
network identity, exclusive ownership, bootstrap and owned-genesis shutdown are
also covered. Two earlier attempts failed at initial network readiness inside a
sandbox that denied localhost socket creation, independently reproduced with
`socket.socket()`. Their failed logs are preserved. The successful run used
localhost access without increasing startup timeouts.

`.build-cache/k5-managed-startup-test.json` binds the test source, binary, raw log,
runner, wrapper and staged-library specification. The actual daemon entry point
also compiled successfully with the managed configuration; its final evidence is
`.build-cache/k5-managed-daemon-build.json`. After the tests, only a conditional
import in `main.rs` changed to remove a managed-build warning. The final daemon
build covers that correction; the tested library sources are unchanged.

Lead review traced admission before initialization, owner/signer lifetimes,
reactor startup and shutdown, generation reuse after join, and same-era WAL
selection. This is component integration using independently staged consensus
libraries, not final independent executor-plus-consensus production-link evidence.
The production builder, K6 authorization/rehearsal, activation/recovery and the
consolidated K5/K6 review remain outstanding. Existing warnings for unselected
later-phase helpers remain visible. No PR or CI campaign was launched.

### K5 combined managed-node builder and evidence checkpoint

From base `5721f50f88453a29ca3ec559758b79cbcd22b5a8`, the production builder
now defaults to `managed-node`. It builds retained `first` and current `observer`
executors plus `consensus-first` and `consensus-second` independently, and links
all four into the daemon with managed startup enabled. Role-qualified audit
labels prevent the two `first` graphs from aliasing. Their original identities,
source inventories and staged-library fingerprints remain separate. Node Cargo
resolution rejects accidental inclusion of an executor or consensus facade.
There is no IPC, dependency unification or Malachite fork change.

The builder applies existing common-resource and final native-symbol ownership
checks to the combined graph set. It verifies the managed definition against the
locked all-target coordinator and first-consensus metadata. Qualification now
requires both consensus source inventories, link bindings, interface controls
and actual typed-adapter test logs. Certified-history evidence must match the
selected consensus definition as well as the observer executor. The CI artifact
paths include this evidence in the existing scoped job and comparison; no new
matrix or always-on PR job was added.

Local Linux ARM dev evidence is `.build-cache/k5-managed-node-qualification.json`
and the raw reports under
`.build-cache/k5-node-linked/aarch64-unknown-linux-gnu/dev/`.
The combined build/audits/controls passed in 279.68 seconds. The installed daemon
hash is `cc16228b8eae58b5af8068b38402e402f0282a738a38588c3951926c761c1db0`.
The 25-case executor harness passed in 190.21 seconds, including equality against
the preserved semantic baseline and all 17 certified-history checks, with 15
certified and closed decisions. The current comparator accepted the actual local
cell, including both consensus graphs and seven adapter tests. This is one local
dev cell, not cross-platform qualification or a performance acceptance campaign.

The first local driver omitted `--install-node`, so it stopped after the successful
build with a missing installation record, before executing any runtime cases.
`.build-cache/k5-managed-node-before-install.json` preserves that failure. The
recovery driver used the existing hash-checking `install_node` helper on the same
audited executable, preserved the pre-install report, then executed and verified
it without rebuilding or changing its source evidence. The normal CI runner
already supplies `--install-node`.

Thirty-six node builder/runner/comparator tests passed. Five interface-control
and twelve consensus-input tests also passed. Negative controls cover missing or
substituted consensus graphs, stale interface and adapter bindings, incomplete
adapter test logs, and substitution between K4 and managed consensus identities.
The workflow YAML parses and `git diff --check` passes. Lead review traced the
four graph roles through compilation, audit input sets, source bindings, installed
binary hashes and uploaded evidence paths. Independent review remains consolidated
around the complete K5/K6 group.

The certified-history fixture deliberately retains its isolated legacy engine
path. This result does not turn that fixture into managed-engine startup evidence;
the prior managed startup tests cover that separately. Integrated managed runtime
acceptance in the final independently linked daemon, K6 authorization/rehearsal,
and grouped review/CI/merge remain outstanding. No PR or CI campaign was launched.

### K5 managed startup in the independently linked daemon

From base `64ae83c24ff28b8b69d8e476b13f9a824afaa130`, the existing
managed startup test now shares its implementation with the node qualification
entry point. The installed daemon starts the actual managed first consensus
bundle, answers readiness and round-start requests, stops and joins it, then
starts and joins a second generation using the exact same listener and era WAL.
The test also rejects concurrent generation ownership and a competing database
writer before that writer can create its database. Certified history stays
available and unchanged through the restart. The runner and comparator require
these results to match the selected chain, protocol, era and executor definition.

The local Linux ARM dev run passed. Combined independent builds, ownership audits,
interface checks and typed-adapter checks took 284.24 seconds; the installed
daemon completed the retained 25 executor cases, certified-history checks and
managed startup/restart in 205.62 seconds. Its SHA-256 is
`1cfc3185c7006ce01c5d1ba170b6771d5df608cb09f10d02a15f91832fd3e0da`.
The result is `.build-cache/k5-managed-runtime.json`, with raw build and runtime
logs and the actual comparator result bound to that binary and the tested source
hashes. Thirty-seven focused Python node tests passed, including rejection of
missing startup evidence, changed protocol identity, incomplete joins, listener
changes and incorrect generation counts. `git diff --check` passes.

Lead inspection traced the shared helper through the actual linked runtime,
confirmed that the comparator requires its output, and verified all ten recorded
source hashes after the run. The ordinary Rust test wrapper was not rerun for
this checkpoint; the same helper was compiled and executed in the linked daemon.
The previous builder checkpoint's raw files and executable are preserved under
`.build-cache/k5-combined-builder-checkpoint-64ae83c2` before reuse of the build
output directory. This is one local dev cell and same-era restart evidence, not
cross-platform acceptance or the incompatible-protocol activation handoff.
K6 control integration, K7 activation, and the grouped review/CI/merge remain
outstanding. No CI campaign or fork change was needed for this checkpoint.

### K6 reversible approval and control persistence checkpoint

The operator replaced irreversible upgrade effects with canonical rollback and
fresh validator reapproval. The single independent reviewer agreed
K6-ROLLBACK-PLAN revision 1 after tracing K4 branch intervals, frozen finality
replay and owned rollback. The implementation plan now records the signed-reference
floor, action-ID retractions at the correct historical prefix, and K7/K8's
post-closure protocol selection with fresh engine eras. Existing authenticated
history and signing safety remain monotonic. The superseded uncommitted Bitcoin
high-water draft was archived in `.build-cache/k6-superseded-high-water` and removed.
No merged prerequisite or completed K5 implementation was reverted.

Authorization draft `7288c9c0` was integrated as `98cda5bb`. Its bounded revision
`f89967b8` was integrated as `0065676f`: canonical Bitcoin reference/inclusion
heights replace high-water, a rollback-derived minimum closed reference rejects
old consent after nonce/head restoration, and KUS1 encodes reversible snapshots.
The signed KUA1/KUC1 action/envelope formats are unchanged. All 14 focused verifier
and codec tests passed in the isolated worktree. The three integrated source
hashes match that tested source. Raw log: `/tmp/k6-auth-2-focused-cargo.log`.
This is verifier evidence; callers still authenticate references and committees.

The lead added canonical control application records and snapshots, action-ID
retractions bound to rollback origin/stage, indexed prefix-scoped invalidation
and reference-floor queries, and the retraction call inside the owned reactor
rollback transaction. Canonical-history deletion cannot bypass a retraction.
Reconstruction accepts an original action before its recorded rollback but checks
that rederiving the same retraction produces exactly the same disposition. A
changed signature subset cannot evade invalidation by changing the envelope ID.
Snapshots and retractions roll back together if canonical undo fails. Effects at
the target Bitcoin height survive, matching existing application-suffix rules.

All five new persistence tests passed, including failure injection, reopen,
nonce/state restoration prerequisites, duplicate/retracted action rejection,
historical-prefix reconstruction and a rollback spanning more than one read page.
The combined test build took 2m03s; these tests ran in 0.06s. The same compiled
binary then passed 19 certified-history tests (including those five), eight
canonical-history tests, six canonical-application tests and the actual owned
closure-stage test (16.84s). Evidence and source hashes are in
`.build-cache/k6-control-persistence-validation.json`; regression command/log and
binary bindings are in `.build-cache/k6-control-regressions.json`.

Lead review checked canonical suffix selection, restored snapshots, atomic
rollback/error behavior, action versus envelope identity, prefix-scoped floor
queries and exact reconstruction. Planning agreement is not code approval;
independent implementation review remains consolidated around complete K5/K6.
Live typed control proposals, authorization/application integration, explicit
control replay disposition, operator APIs/rehearsal and K7/K8 activation are still
unfinished. The persistence tests invoke the storage primitive and do not establish
end-to-end control consensus or cross-upgrade recovery. No CI campaign, PR, merge,
publication or new fork change was performed for this checkpoint.

### K6 typed command and reactor rollback checkpoint (1 November 2026)

Local implementation based on `049115e0`, not a completed K5/K6 group or merge.
Upgrade controls now have their own certified command tag and exact KUC1 body.
The execution index and replay selector distinguish Block, Batch and Control.
Controls cannot decode as Bitcoin transactions or enter transaction-exclusion
filtering. Old intermediate boolean-command schemas are refused during read-only
node admission, without relabeling or deleting their data.

Proposal admission and owned application use the same verifier integration:
closed authenticated reference, current inclusion committee, canonical Bitcoin
position, current reversible state, action-ID retraction and historical reference
floor. Application persists its snapshot and canonical lineage with the closure
stage. Finality replay carries controls as explicit commands and records a
RetractedControl outcome after owned undo; it does not reauthorize old envelopes.
Historical stage recovery validates the original envelope/application binding,
not the latest canonical snapshot. The live snapshot check occurs at commit.

The expanded owned-closure test passed (17.21s). It covers signed schedule and
cancel, invalid signature/anchor, interrupted application, atomic retry, restart,
duplicate rejection, typed replay selection and recovery of an earlier control
closure after a later action changes the state. The same production source passed
seven certified-input tests, 14 approval tests, 20 certified-history tests and two
read-only protocol-admission tests. Two additional filters selected zero tests;
they provide no coverage and are excluded from the 44-test count. Commands,
results and binary binding: `.build-cache/k6-control-command-regressions.json`;
owned-unit raw log: `.build-cache/k6-control-inclusion-tests-final.log`.

A new real-executor reactor test then passed (69.07s, build 1m12s). It executes an
unconfirmed issuance batch, applies a schedule, reaches the six-block finality
deadline, and interrupts after owned rollback removes the schedule. A reopened
executor recovers the remaining frozen work. The old envelope and the same
approval reanchored at the current tip are rejected. A new signed action using
the completed rollback decision succeeds. A separate fresh database reconstructs
all the original retained inputs/certificates; closed records and canonical
control state match recovery, including after the fresh submission. The original
schedule's certificate and original application history remain verifiable after
retraction. Raw log: `.build-cache/k6-control-reactor-recovery.log`.

This test uses the real reactor closure/executor/database path and authenticated
fixture certificates, without a live multi-validator network. It does not yet
prove operator submission, live proposal transport, all postpone/cancel undo and
Bitcoin-reorg cases, or cross-activation migration/engine handoff. Those remain
in scope. The focused local build encountered a Rust incremental fingerprint ICE;
only disposable indexer incremental caches were removed before a successful
rebuild. No fork changes, CI runs, PRs, merges or publication were performed.
Consolidated lead and single independent review remain required for complete
K5/K6. Source/binary hashes and limitations are recorded in
`.build-cache/k6-control-command-validation.json`.

### K6 operator submission and proposal production checkpoint (1 November 2026)

Local work based on `1991e61d`, with K5/K6 still incomplete. The daemon now wires
`GET /api/protocol/upgrades` and `POST /api/protocol/upgrades` to the live reactor.
GET reads one deferred database snapshot and reports the closed reference,
canonical Bitcoin position, current control head/nonce/pending plan, reference
floor and next inclusion committee. Heights, nonce and voting powers are decimal
strings. Canonical state/manifest bytes accompany their displayed identifiers.
The endpoint returns unavailable while authenticated history has unfinished work.

POST accepts `{"envelope_hex":"<canonical KUC1 hex>"}` under an explicit body
limit. It does not sign, collect approvals or amend signed fields. A capacity-one
submission channel and one pending approved action bound local queue storage.
Successful responses contain action ID, envelope ID and `status: "queued"`;
this means queued on that node, not consensus acceptance or durable storage.
The queue is volatile across restart. Identical pending submissions are
idempotent; another valid pending action receives a temporary busy response.
An HTTP timeout does not prove that a submission was not queued; retrying the
identical envelope is safe while it remains valid. A rolled-back or otherwise
invalidated action requires fresh approvals as specified by the control protocol.

The proposer reuses live admission on every use and prioritizes a valid control
before a pending Bitcoin block. Unfinished closure temporarily defers the queue;
action expiry, changed state, committee changes or retraction invalidate it.
Malformed or mismatched request context is an ordinary rejection, while database
and history failures remain fatal infrastructure errors. Lead review caught and
fixed a potential unsupported-codec error escaping the ordinary rejection path.
No approval semantics, thresholds, signature domains or rollback rules changed.

Five focused checks passed on the final source: malformed/oversized decoding;
HTTP bounds, backpressure, closed channel and local acknowledgement; real-executor
queue/proposal publication with a local Malachite engine; existing banked-verdict
rollback protection; and pending-recognition/channel-backpressure behavior. The
proposal test covers bad signatures and codecs, duplicate and competing actions,
retention through an unrelated closed decision, priority over a pending block,
exact signed-envelope publication, and rejection after canonical consumption.
It passed in 18.28s. HTTP validation passed in 0.29s; the two existing regressions
passed in 17.19s and 17.18s. The daemon test entry point compiled but its filter
selected zero binary tests, which is not counted as test coverage.

Initial failures were a missing startup-test argument, a disabled-network test
fixture, sandbox socket restrictions, and an HTTP fixture lacking certified-history
schema. The final real-engine run used local socket access. These tests use real
execution/database and proposal publication, but fixture certificates rather than
a live multi-validator quorum. The managed independent-bundle node has not been
rebuilt for this checkpoint. Raw commands, source/binary bindings and results are
in `.build-cache/k6-operator-validation.json` and the referenced logs.

Lead inspection covered input-error versus infrastructure-error handling, queue
bounds and lifetime, revalidation and proposal ordering, and read snapshot
consistency. Remaining K6 work includes approval preparation/signing/assembly
CLI and SDK interfaces, operator migration dry-run/support diagnostics, remaining
postpone/cancel undo and Bitcoin reorg/committee cases, and consolidated K5/K6
integration and review. K7/K8 activation/handoff remains the next dependent group.
No CI, PR, merge, fork changes or publication were performed for this checkpoint.

### K6 unsigned preparation, SDK and control undo checkpoint (1 November 2026)

Local continuation of `33a0116b`. `POST /api/protocol/upgrades/prepare` constructs
unsigned KUA1 action bytes and their ID from one consistent closed-history
snapshot. Callers supply an explicit Bitcoin expiry and Schedule manifest/H,
Postpone H, or Cancel request. Preparation binds current head, nonce, pending
plan and closed reference, then reuses admission with empty approvals: only the
final insufficient-quorum result is expected. Other operation/reference errors
reject preparation. It never changes canonical state, queues work or grants
approval. Heights must be canonical decimal u64 strings. Operators must inspect
and approve the exact returned bytes before submission.

The SDK now exports a separate `UpgradeClient` for state, preparation and envelope
submission. It takes an API URL and optional fetch/headers, without requiring a
Bitcoin wallet identity or signer. It preserves decimal strings and explicit
approved envelope bytes, supports caller cancellation, and does not poll, retry,
regenerate approvals or imply consensus acceptance from a local queue reply.
No SDK release was published.

The real-executor preparation/reorg test passed in 42.56s: it applies Schedule,
Postpone and Cancel, replaces Bitcoin block 3 to undo Cancel and restore Postpone,
then replaces block 2 to undo Postpone and restore Schedule. Old approvals are
rejected against restored state, retained closures remain recoverable, and a
freshly prepared/signed postponement succeeds. Preparation is checked to leave
canonical control state and the certified frontier unchanged. Invalid short notice,
Cancel without a pending plan and Schedule over a pending plan are rejected.
The canonical-u64 preparation test and existing HTTP submission test passed too.
SDK build and eight focused client tests passed with no type errors. The existing
SDK dependency directory was reused only after verifying its lockfile digest
matches this worktree; no dependency or lockfile change was made.

Evidence: `.build-cache/k6-prepare-validation.json`, raw Rust log
`.build-cache/k6-prepare-reorg-test.log`, focused binary report
`.build-cache/k6-prepare-regressions.json`, and SDK build/test logs. These are
focused local checks, not full managed-bundle or live-quorum qualification.
Offline signing/assembly is being implemented separately by the Daybreak agent
under K6-APPROVAL-CLI and is not yet integrated at this checkpoint. Migration
rehearsal/support diagnostics, remaining committee coverage, the agreed pre-K7
activation guard and consolidated K5/K6 review/qualification remain unfinished.
No new independent review, CI, PR, merge, fork change or publication was requested.

### K6 offline approval integration checkpoint (1 November 2026)

Integrated Daybreak task `K6-APPROVAL-CLI`, source commit
`7f60ac3050e1dcc8e7152a089c2abab4ee12922b`, as `2523c388` over `06499d1e`.
The bounded delegation added inspection, explicit-hash file-based approval signing,
and canonical assembly. Lead inspection covered the entire CLI and its tests,
bounded file reads, exact action and registration binding, duplicate rejection,
canonical sorting, safe key error reporting and honest offline verification status.
The shared `Approval::verify_for` helper preserves the previous signature preimage
and consensus verifier ordering; committee membership and generation checks still
precede signature verification. The delegated work remains included in the eventual
single independent K5/K6 review rather than receiving a separate microreview.

The node executable now exposes `kontor upgrade-approval inspect|sign|assemble`.
The real preparation/reorg test now uses the CLI's public file-based sign and
assemble interface for Schedule, Postpone, Cancel and fresh retry. It passed in
42.43s, including both rollback restorations, rejection of stale consent and fresh
postponement. The six CLI and 14 authorization tests also passed on the integrated
test binary. The executable built successfully and a five-command smoke check
matched the independent golden action/signature/envelope, rejected the wrong
expected action ID before reading a missing key, and required the expected-ID
argument. Formatting and diff checks passed. Existing compiler warnings remain.

Evidence is in `.build-cache/k6-cli-integration-validation.json`, the reorg and
focused-test logs, `.build-cache/k6-cli-main-build.log` and
`.build-cache/k6-cli-executable-smoke.json`. The focused checks use the ordinary
local build, not a rebuilt managed independent-bundle node or live multi-validator
quorum. The [operator workflow](upgrade-approvals.md) documents preparation,
inspection, explicit approval, assembly, submission and fresh authorization after
rollback, including the API result wrapper and exact submission object.

K6 still needs migration rehearsal/support diagnostics with failure work accounting,
the agreed scheduled-height guard, remaining committee and cross-language codec
coverage, and consolidated K5/K6 qualification and review. K7/K8 activation and
migration handoff remain subsequent work. No CI, PR, merge or publication occurred.

### K6 scheduled-height guard checkpoint (1 November 2026)

Continued from `e8dcdf9b`. The agreed intermediate guard now rejects ordinary
Block commands at or above a surviving pending activation height. Proposal
selection skips these blocks, proposal validation rejects them without stopping
the reactor, and new certified append rejects before input, certificate or branch
mutation. Owned block application checks again before preparation or execution.
Existing certified retries retain their original historical verification path.
Control commands continue through their separate authorization checks and retain
priority over pending blocks. No activation, executor switch or migration is
claimed by this guard; K7's authorized boundary transition must implement them.

The guard reads the latest canonical control snapshot at or below the block's
parent height. This matches the actual replacement-block rollback order, preserves
all controls at the retained height, and removes later Schedule/Postpone/Cancel
effects from the decision. It neither creates an irreversible schedule nor changes
reference clocks, authorization thresholds or retained certificates.

Six database-control tests passed, including the new exact H-1/H/H+1 and u64
boundary checks, projected surviving snapshots, cancellation/postponement, and
actual rollback restoring or removing the boundary. These are direct persistence
fixtures, not live-quorum authorization evidence. The real preparation/CLI/reorg
test passed in 42.56s with explicit append rejection and unchanged frontier/control
checks. Its boundary candidates also contain a height gap, so the test requires
the specific activation error to distinguish guard execution from branch rejection.
It does not claim a thousand-block approach-to-H run or activation handoff. The
existing local-engine control proposal-priority test passed in 17.32s.

Lead review traced the block proposal, new certified append and owned application
paths; rollback order and target-height inclusion; typed normal rejection versus
infrastructure failures; and the unchanged control proposal path. Validation used
one serialized Cargo/runtime slot with at most two build jobs. Evidence is in
`.build-cache/k6-boundary-validation.json` and its three raw logs. Formatting and
diff checks passed. Managed-bundle qualification and the consolidated independent
K5/K6 review remain pending. Migration rehearsal, failure work reporting, support
diagnostics, remaining committee and codec coverage remain the next K6 work.
No CI, PR, merge, fork change or publication occurred.

### K6 operator migration rehearsal and failed-attempt work accounting

On base `2c610a40389d780f53a1a1370c1654b761153fc8`, added
`kontor rehearse-migration --database ... --network ... --target ...`.
It opens the existing database read-only, makes a consistent SQLite snapshot
including committed WAL contents, verifies closed certified/canonical input
bindings, and runs the exact manifest-bound migration through its registered
executor with a separate storage owner. The temporary writer enables the ordinary
foreign-key and checkpoint-function setup without schema initialization. Source
database bytes and WAL remain unchanged in the real certified-state fixture.

Reports bind the source protocol, era, decision, Bitcoin position, application
lineage and checkpoint to the target manifest and migration definition. They
include budget and charged work on success and failure, with decimal-string
counters. Missing executors and unregistered routines fail explicitly. Reports
are advisory migration results, not consensus-support qualification, authorization
or a prediction about future activation state. No recurring rehearsal service,
live engine, signer or automatic approval was introduced.

The migration boundary now carries consumed work on deterministic rejection and
host failure. Original error downcasts remain available through an anyhow context.
Metering, rejected-charge semantics, state rollback and stored successful receipts
are unchanged. The injected storage failure test verifies partial work, original
host-error classification, rolled-back data and a successful fresh retry.

Validation: 34 focused migration tests passed, with one ignored subprocess entry
point exercised by its passing crash-recovery parent. Coverage includes committed
WAL/uncommitted transaction separation, snapshot writes and source isolation,
checkpoint hashing and foreign-key enforcement, real certified-state rehearsal,
unknown routine/unavailable executor reports, and the existing migration substrate
regressions. `cargo check -p indexer --bin kontor --locked --offline -j 2` passed.
Raw logs, exact source hashes and the test-binary hash are recorded in
`.build-cache/k6-migration-rehearsal-validation.json`. The first compile caught an
old mock error tuple; the new checkpoint fixture initially omitted its referenced
block. Both were corrected before the passing run. An initial CLI check named
the package instead of its `kontor` binary and was corrected without rerunning
the passing tests.

Lead review traced charged-work retention through routine failure, finish and
transaction settlement; typed error preservation; read-only source access and
consistent snapshot acquisition; exact target selection; isolated ownership and
shutdown; checkpoint/foreign-key behavior; and rejection rather than fallback.
This is in-tree evidence, not a rebuilt independent-bundle qualification or an
executed CLI-binary smoke test. The changed structural migration result must be
checked across the independently built graphs before the grouped merge. Installed
support/last-rehearsal diagnostics, remaining committee/codec coverage, consolidated
independent review and final K5/K6 integration/CI remain outstanding. No CI run,
PR, merge or publication occurred for this increment.

### K6 advisory support and cross-language control vectors

On base `7f6d62832df273b1276444be77635a446f152be6`, rehearsal reports now
include the target executor/consensus definition IDs, production-registration
checks, and migration recognition when the attempt can establish it. Executor
lookup uses the actual production factory selector. Consensus lookup uses the
same definition as node admission; the second engine remains qualification-only
until K7 registers its protocol mapping. Migration recognition is nullable when
the attempt cannot establish it. No diagnostic authorizes activation or upgrades
a linked qualification component into a production mapping.

The extended real certified-state fixture passed all four cases: successful
migration, unknown routine, unavailable executor, and successful migration with
an unregistered consensus definition. All preserve source database and WAL bytes.
The last case proves that migration success is not presented as complete target
support. The four rehearsal tests passed in 17.14s. The operator retains the JSON
report as the last-rehearsal record, with its exact target and source bindings.
No node import, automatic refresh, readiness-expiry or persistence service was
added. API-wide diagnostics remain in K10's integration scope.

Added independent JavaScript encoding of KPM1, KUA1, KUC1 and KUS1 fixtures and
SHA-256 domain digests. WebCrypto independently verifies the existing approval
signature and rejects changed action and registration-generation bindings.
Postpone/Cancel fixtures exercise optional plan identity, values beyond 2^53 and
u64::MAX. These wide fixtures establish codec behavior, not semantically valid
upgrade approvals at those artificial positions. Rust encodes, decodes and checks
the same bytes and IDs. No new SDK signing or transaction-format API was added.

Validation passed: 15 Rust control tests; 12 JavaScript vector/operator-client
tests; four vector tests in local headless Chromium. The default browser command
could not start because Playwright's expected revision1248 was absent. A temporary
local config selected the already installed revision1243, and all four tests then
ran and passed. Repository configuration and browser installations were unchanged.
Raw logs and scoped source/evidence bindings are recorded in
`.build-cache/k6-support-codec-validation.json`. The rehearsal test log predates
the test-only vector additions, and its original binary was not retained; it is
not represented as a current full-binary qualification. Final managed-bundle
integration remains required.

Lead review checked the production selector and baseline definition bindings,
unknown versus missing migration recognition, advisory report semantics, wide
integer encoding, byte order, domain separation and browser compatibility. The
single independent review remains consolidated around completed K5/K6. No CI,
PR, merge, publication or new Daybreak assignment occurred. Remaining K6 work is
committee-churn integration coverage, actual linked CLI/bundle evidence, and the
grouped review and scoped final CI campaign.

### K6 real registration continuity through replacement and recovery

On base `3bca59a0`, added a real certified-execution fixture that registers a
validator through the staking contract in block 2 and activates it at block 14.
Two successive replacements of block 14, including restoration of its original
hash, traverse an observed pending-join state before restoring the same active
key, holder, activation height and committee. Each return obtains a fresh
registration generation. The unrelated genesis validator retains its generation
and unchanged approval. An envelope retaining the returning validator's old
approval is rejected specifically as `ControlError::Approval`; a freshly signed
approval for its current generation passes admission without changing the action.
This fixture never applies that scheduling action, so it does not substitute
reapproval of a registration for the separate fresh-action requirement after
rollback of a previously applied control.

The first replacement restarts after the durable rollback stage. Fresh replay
from genesis matches every retained registration stage and completed closure
across all sixteen certified decisions. This exercises intermediate observations
through actual owned closure execution and persistent history, rather than
comparing only the final committee. The test passed in 94.26s. The existing five
registration-history unit tests also passed after adding explicit key A-to-B-to-A
continuity assertions. The added checks required no production behavior change.
Evidence, source bindings, both tested binary hashes and logs are recorded in
`.build-cache/k6-committee-reorg-validation.json`. The integration run predates
only the additional unit-test assertions; its source and production code are
unchanged. No CI or new independent review was launched for this increment.

Lead inspection traced stage finish through the actual registration observer,
atomic observation persistence and successor validation; checked typed stale
approval rejection and the unchanged-signer positive control; and compared
interrupted recovery against stage-by-stage cold reconstruction. The fixture is
an in-tree executor check. It does not qualify a managed engine handoff or a
cross-protocol activation, which remain in K7/K8.

Before the final K5/K6 linked build, source inspection identified an outstanding
interface mismatch: the retained K3 executor exports the old migration result
shape, while the current executor now reports charged work on rejection and host
failure. The node currently expects the latter for both factories. This needs
explicit typed adaptation before linked acceptance; do not mutate the immutable
retained snapshot or invent zero work for an unreported historical failure.
The current production mapping uses the maintained observer executor, which has
the richer result. Resolve the retained interface, regenerate the applicable
unreleased definitions, then run the actual linked build/CLI checks and the
consolidated group review. No PR, merge or publication occurred.

### K6 typed retained migration-result adaptation

On base `fe8bb228`, the session tuple and factory adapter accept an explicit
migration-export type. The maintained callback passes through unchanged; the
retained callback preserves successful work receipts, rejection tags and host
errors while marking unavailable failed-attempt work as absent. No retained
source or dependency snapshot was changed. The current executor reports charged
work as present on its failure paths. The coordinator preserves that distinction
through transaction settlement and error context. Rehearsal serializes unavailable
historical failure work as null, never zero; current execution still reports its
actual work. This adds no intermediate database compatibility obligation.

The focused migration suite passed 35 tests in 17.28s, with one subprocess entry
point exercised by its crash-recovery parent. This includes old-result mapping,
current partial-work failures, atomic rollback, ownership and isolated rehearsal.
An initial test-only mock still used the old nonoptional work payload; compilation
caught it, the mock was updated, and the corrected suite passed. Evidence and the
initial failure log are retained in `.build-cache/k6-migration-adapter-validation.json`
and the adjacent logs. These tests precede generated-definition refresh and do not
claim independent linking or final candidate qualification.

The observer executor and managed consensus definitions were explicitly refreshed
as unreleased definitions. The linked qualification now also checks that the
maintained executor supplies partial charged work and the frozen executor does
not invent it on budget failure. Lead review checked the typed conversion,
unchanged successful receipts and error tags, absence versus zero in diagnostics,
and preservation of old sources. Actual managed build/runtime evidence is pending;
consolidated independent review and grouped CI/merge are still required.

### K6 independent consensus build integration

The combined build exposed missing shared control-decoding dependencies in the
consensus graphs. The graph now imports the control, manifest and certificate
authority modules, declares the already-locked `thiserror` dependency directly,
and uses explicit child-module paths that resolve both in the node and through
the independent graph's `#[path]` imports. Source provenance includes those
modules and their children, including the certificate verifier and test vector;
the process-ownership tripwire also scans imported child modules. The tripwire
recognizes `Command::Control` as an enum variant, preserving its rejection of
process-launch calls.

On base `ae91fc03`, 12 consensus-input, six executor-input, five managed-definition
and ten execution-definition tooling tests passed. Existing mutation checks now
cover the imported child module and control fixture. An initial managed-definition
fixture omitted the new imports and failed; its corrected fixture passes, and the
failure log is retained. The previous linked build and source-inventory failures
remain recorded, not accepted as qualification. The unreleased managed definition
was regenerated after its source inventory and dependency graph changed; frozen
executor snapshots remain unchanged. The next acceptance step is the actual
combined build and runtime, followed by the group's consolidated review and CI.

The next build compiled both consensus graphs and the node, then correctly failed
the old factory-identity positive control: retained and maintained migration
exports no longer have identical result types. The observer link set now requires
direct factory substitution to fail and an explicit typed conversion to compile.
The frozen first/second pair still requires structural factory identity. Actual
staged-library checks passed all six executor controls after correcting the probe's
closure coercion. This is interface evidence, not a successful whole-node build.
The earlier consensus adapter result files were from the preserved prior build
and are not current-candidate evidence.

The managed qualification also now invokes the real rehearsal CLI on its existing
fully closed certified database fixture, after the engine stops. It checks a
registered no-op and an unknown routine, JSON results and process exit status,
advisory authority, source identity, and unchanged database/WAL bytes and logical
state. The verifier requires the explicit managed rehearsal result. Six interface
tooling and ten node-evidence tooling tests passed; the new Rust CLI integration
still requires the rebuilt binary to execute. No new CI matrix or performance
workload was added.

At `e2ec3283`, the complete Linux ARM64 dev managed-node build passed, including
native ownership, six executor interface controls, seven consensus interface
controls and seven actual node-to-consensus adapter tests. The installed binary
SHA-256 is `be4453eab3c2e8deff3e39fab23be5c00cb31ff4e0ecbe559ad3bdd7f74e448b`.
Its real runtime qualification passed in 206.41s: both executor graphs agreed on
all 25 scenarios and the historical semantic baseline; 15 certified decisions
authenticated and closed; engine-free recovery and interrupted replay passed;
managed startup joined both engine generations, retained the listener/WAL and
database service, and rejected a competing writer. Both rehearsal CLI cases
passed with unchanged source bytes and state. Intentional panic-injection output
is retained in the raw log alongside the successful terminal result.

The build, runtime reports, raw output and binary are preserved under
`.build-cache/k6-linked-acceptance-e2ec3283`; the adjacent acceptance record binds
their hashes to the source. This supersedes the earlier missing linked acceptance
for this candidate, not the final cross-platform CI gate or K7/K8 activation work.
The default branch was verified through GitHub as the K4 merge `0a2cbd89`.
Consolidated lead and single independent K5/K6 review, scoped final CI and merge
remain required. No CI, push, publication or new Daybreak assignment occurred.

### K5/K6 consolidated review and final local checks

The lead consolidated review and the single independent review covered base
`0a2cbd89` through `b0548353`, with no unresolved material source finding. The
independent reviewer checked 1,634 frozen K4 entries against the base, all 46
indexed evidence-record hashes, and eight archived linked file/binary bindings.
Coverage included durable signing and ownership, managed lifecycle, control
thresholds and committee generations, reversible snapshots/retractions, ordered
replay and cold reconstruction, and operator API/CLI/SDK/rehearsal behavior.
Actual cross-era activation remains K7/K8 work, not implied by startup evidence.

Final local workspace Clippy exposed unused managed-only code in ordinary builds,
style warnings, and an existing gossip integration fixture still consuming the
old raw startup result. Managed-only declarations now follow their actual cfg;
legacy startup retains raw channels/handle and moves them into the reactor wrapper
through a consuming conversion. No managed ownership is cloned or weakened. Other
corrections preserve lock-file contents explicitly, simplify equivalent conditions
and assertions, and box CLI report values without changing JSON. The unreleased
managed definition was regenerated; frozen references are unchanged. The reviewer
inspected this correction separately and found no material concern.

Core workspace Clippy including tests now passes. All 155 bundle-tool checks,
38 CI-control checks, six certified-value wire tests (including real signed gossip)
and six approval-CLI tests pass. The initial tooling attempt failed because the
host ccache directory was read-only; disabling that wrapper allowed the native
negative controls to execute. Failed lint/tool logs remain recorded. Final local
records and review reports are under `.build-cache/k5-k6-*` and
`.build-cache/k6-final-*`. Previous linked acceptance retains its original
`e2ec3283` source binding rather than being relabeled as this corrected candidate.

GitHub main remains `0a2cbd89`; no prior branch PR or run existed at the preflight
check. The existing selectors require one final release-three-platform campaign
plus bounded dev coverage for the changed execution/build/coordinator inputs.
There is no automatic exhaustive dev sweep or new performance campaign. Required
candidate CI and verified merge still gate K7/K8 implementation.

PR 621 opened at `7c5609b1`. Its first control jobs correctly rejected two packaging
and provenance omissions before starting their expensive matrices. Four frozen K4
sqlean libraries existed locally but were omitted from Git by the shared-library
ignore rules. Each matches both its unchanged snapshot digest and the original
K4 commit bytes. They are now tracked, with narrow retained-sqlean ignore exceptions.
A clean staged Git export verifies all 1,634 entries against the unchanged inventory.
The stack manifests also needed refreshed hashes for the changed indexer build
script and genesis admission sources, plus their dependent manifest hashes. No
resource cases, settings, thresholds or accepted historical results changed.

After these corrections, seven source-root checks and all 235 stack-control unit
tests pass. The first local stack-control retry reached all manifest checks but
six socket fixtures were blocked by the sandbox; the rerun with local sockets
available passed. Logs and the clean-export/hash comparison are retained under
`.build-cache/k6-ci-*`. This is packaging/control evidence, not a new workload or
performance qualification. The original CI lint/security audit passed while the
remaining ordinary tests continued. The correction is batched locally until those
jobs expose any additional failures; the failed control matrices are not blindly
rerun on the unchanged PR candidate.

### K5/K6 CI reader initialization correction

The first PR621 candidate (`7c5609b1`) passed lint/security, SDK, reproducible
contracts/SDK and both Docker-cache jobs. Both standard Rust jobs failed only
`cluster_late_joiner_sync` in their 129-test integration suites. The Linux log
exposed the reactor's original failure: a locked database while inserting the
block batch decision. macOS observed the subsequent closed operation admission.
Two focused local dev runs reproduced that shutdown. Logging the supervisor's
fatal cause before draining prevents test cleanup from hiding it.

Reader-pool creation called the schema-initializing writer constructor. Its
metadata writes could invalidate a canonical writer's deferred transaction
snapshot. A deterministic regression established this failure before the fix:
open/read a writer transaction, open a Reader pool connection, then attempt the
writer insert. Both database and runtime reader pools now open the existing
file read-only, preserving connection timeout, foreign-key and crypto-extension
setup while leaving schema installation to the writer. Existing startup orders
initialize the writer first. Pool fixtures now do so explicitly as well.

The regression and connection checks passed (2), all runtime-pool checks passed
(5, including held/fresh snapshots after contract ID reuse), and the original
late-joiner cluster test passed in 127.18 seconds. These are local dev diagnostics,
not release qualification. Before/after logs and source hashes are preserved in
`.build-cache/k6-ci-reader-correction.json`. The temporary diagnostic binary-path
symlink was removed. Workspace Clippy including tests and formatting passed.
The single independent reviewer traced startup and reader consumers and found
no material concerns in the four-file behavioral/diagnostic correction atop
`98bd1e4a`. The lead verified the failing-before/passing-after regression,
actual cluster recovery and reader restrictions. The unreleased managed
reference and derived stack source bindings were refreshed; retained references
and historical acceptance evidence keep their original source identities.

This fix is batched with the already validated frozen-library/source-pin
correction for the next PR candidate. Current-head CI remains required before
merge. No expensive failed campaign was rerun without diagnosing its failures.

### K5/K6 ownership fixture initialization correction

On candidate `99234cab`, the macOS library suite passed 1,035 tests and failed
ten ownership tests before their assertions: their shared `one_object_pool`
helper opened a nonexistent `owner.db` through the newly read-only pool manager.
The helper now initializes the database through the existing writer constructor
before creating the reader pool. This is a one-line change inside `cfg(test)`;
production ownership behavior is unchanged. Other directly constructed runtime
pools were checked for prior writer initialization.

The Linux library job subsequently reported the identical ten fixture failures,
with 1,041 other tests passing. No additional failure required a separate fix.

All 55 ownership tests passed locally in the dev profile (434.23 seconds),
including all ten failed CI cases. Formatting passed. The four stack manifests
were regenerated and their 22 changed values verified to be source and
parent/group hashes only, with no case or threshold changes. The 235 Python
controls produced 229 passes and six sandbox socket errors; rerunning the two
socket modules outside the sandbox passed all seven tests in those modules.
Raw logs and the exact test-only diff check are recorded in
`.build-cache/k6-ci-owner-fixture-correction.json` and its referenced files.

The lead reviewed this nonmaterial fixture correction; existing independent
production review coverage remains applicable. Running CI evidence is retained
while the correction is validated and remaining failures are collected. These
local results do not replace the final candidate's required CI checks.


### K5/K6 merge and K7/K8 starting point

PR [#621](https://github.com/KontorProtocol/Kontor/pull/621) merged as
`b3e0fc246d7a859e30b836630372e5658f45afb8` on 2 November 2026. Its tree
`f73eb28afe6441fc898e87312768574190dab146` exactly matches the qualified PR
candidate `38df95bd` and test merge `2b0c1cd2`; main was verified at that merge.
The consolidated lead and single independent review, focused reader correction
review, and lead-reviewed test fixture correction cover the final candidate.

Required current-head CI passed: standard workflow `41392126418`, stack
qualification `41392126206`, and linked-bundle qualification `41392126216`.
The lead independently validated the downloaded raw evidence against the source,
lockfiles, compiler/build records, component artifacts and intended test sets.
All three release platforms agreed on stack outcomes and complete linked-node
observations. All 24 bounded dev-smoke executions passed. Linux ordinary CI passed
1,051 indexer tests and 129 integration tests; macOS passed 1,045 and 129,
respectively. The ten previously failing fixture cases and late-joiner regression
passed on both platforms. Ignored tests remain ignored, not claimed as passes.

Evidence and reviews remain in the completed `protocol-upgrade-control` worktree,
including `.build-cache/k5-k6-premerge-38df95bd.json`,
`.build-cache/k6-ci-38df95bd-stack-comparison.json`, and
`.build-cache/k6-ci-38df95bd-bundle-comparison.json`. Older evidence retains its
original source identity. Duplicate post-merge qualification was cancelled under
the verified-tree-equivalence policy; no acceptance gate was waived.

K7/K8 starts in the isolated `protocol-activation-replay` worktree from this
verified merge. K5/K6 provides managed ownership, durable signing and reversible
authorized upgrade controls, but does not yet implement after-H activation or
cross-upgrade migration/engine recovery. Those remain the next grouped phase,
followed by K9 and K10/K11. Publication remains deferred until final review.


### K7/K8 planning agreement and initial records, 2 November 2026

From verified merge `b3e0fc246d7a859e30b836630372e5658f45afb8`, the lead and
`/root/k2b_system_review` explicitly agreed implementation refinement revision 1
under `K7K8-PLAN-1`. The review traced current migration ownership, closure work,
context admission, committee observations, engine startup and native loading. It
corrected the premature next-era commitment and migration-failure incident wording.
The plan now separates reversible activation from monotonic ordering eras and
requires atomic migration/control/stage application followed by atomic completed
closure/authority/handoff publication. It preserves the existing retraction rules.

P2 will add a positive-balance ledger-entry count with an actual metered backfill
from old token state and maintained updates. All holder variants count, with no
amount/rate/gas-constant change. A selected-executor native mapping preserves P1
artifacts and original genesis publication. The reviewer identified the exact
field and value codecs to preserve. This choice is part of the same agreed plan,
not an extra optimization or a new transaction format.

Initial code adds distinct typed activation-descriptor and completed-era records.
It does not enable live activation yet. Focused tests cover the surviving boundary,
schedule removal before completion, historical-protocol restoration with a fresh
era, monotonic consensus heights and malformed persisted records. Planning
agreement is not the final independent implementation review. Raw plan/source
bindings are in `.build-cache/k7-k8-plan-agreement.json`.

Local validation: the first four activation-record tests passed. The broader
coordinator filter then passed 91 tests with one intentionally ignored subprocess
entry point in 44.79 seconds. Raw output and source bindings are retained in
`.build-cache/k7-coordinator-records-test.{log,json}`. These include actual migration,
closure, registration, pool, bootstrap and signing regressions, but do not establish
live activation or multi-bundle handoff.

Block values now commit an optional activation descriptor using a distinct Block
tag; ordinary Block encoding remains unchanged. Descriptor validation binds the
chain/H/hash, and Decision encoding binds the successor to C+1. Source tracing found
that direct streamed certificate admission also needed this height check. Added
it there and ran the focused positive/negative certificate test: one passed, proving
valid signatures over the wrong successor height are rejected while a matching
certificate remains accepted. Its separate current-source evidence is retained in
`.build-cache/k7-certified-transition-height-test.{log,json}`. No CI was launched.
Live expected-descriptor/support admission, activation persistence, migration/stage
atomicity and engine switching remain to be integrated before this group can ship.

### K7/K8 migration-owned activation persistence, 2 November 2026

Extracted `OwnedMigration` from the existing migration coordinator so migration
effects and subsequent activation records can share one canonical root and one
transaction. Finishing an unexecuted or failed migration cannot commit, including
when a caller discards the execution error. Existing cancellation, subprocess
crash, work reporting and retry behavior remain covered.

Canonical activation now references the completed migration application and its
surviving accepted control snapshot. It validates plan, H, migration definition,
protocol and executor identity. The target manifest is retained independently of
reversible activation. Control reads consume the pending plan after activation;
real executor rollback removes migrated state and activation together and restores
the pending plan. Historical signed control snapshots are not rewritten.

Extracted the shared registration-observation and closure-stage recording step
from `OwnedClosureStage`. The activation scheduler will use it inside the
migration-owned transaction. That integration, current-era/control projection,
registry selection and engine handoff are still pending. These changes do not yet
enable live activation or establish complete activation-stage atomicity.

Local evidence is source-bound under `.build-cache/k7-atomic-activation-test`,
`k7-atomic-coordinator-test` and `k7-atomic-history-test` (JSON plus raw logs).
The initial migration filter passed 12 tests. After strengthening the rollback
case and adding wrong-plan and discarded-error cases, the coordinator filter
passed 97 tests with one intentionally ignored subprocess entry point; its parent
crash test passed. Certified-history regressions passed 21 tests. The coordinator
and history checks took 44.41 and 0.16 seconds after compilation. No CI or additional
review campaign was launched. The grouped K7/K8 implementation remains local and
unmerged.

### K7/K8 activation ordering and completed-era publication, 2 November 2026

Activation now has an explicit closure work item. Initial execution schedules it
after H and its due finality; historical reconstruction checks after each Block
and before following batches. A no-activation outcome cannot skip a surviving
due plan. The migration-owned unit records migration, canonical activation,
consumption, registration observation and stage advancement together. Failure
injected at stage insertion rolls back all of them; retry and reopen preserve
the completed stage. Unsupported targets remain unfinished without mutation.

Completion now publishes the closure, successor committee, completed-era handoff
record and ordering frontier in one transaction. Genesis remains bound to its
immutable Bitcoin-boundary context. The successor authority retains registration
generations and old-decision provenance while selecting the new era. Publication
failure leaves the old frontier and no successor committee; retry succeeds.
Missing handoff records are rejected. Exact retries of already retained old-era
certificates remain valid after handoff. Startup checks the completed successor
context, not the preceding decision's context.

Control admission projects the surviving head, nonce and pending plan into the
completed ordering era and canonical active manifest, without rewriting historical
snapshots or approvals. Boundary checking distinguishes a surviving schedule's
original context from the current ordering era. Intermediate pre-activation
development schemas are refused before initialization rather than relabeled.

Evidence is local and source-bound. Before completed-era changes, coordinator
tests passed 99 with one intentional subprocess entry ignored, history tests
passed 21, and the strengthened real replay/restart/cold-reconstruction test
passed with seven ordered activation checks. The earlier five-test control suite
had four passes and one sandbox socket denial; the denied proposal test passed
when rerun alone with local networking permitted. After completion and projection,
the coordinator suite again passed 99 (one ignored); the consensus-state filter
passed 16, including the new reopened-database successor-era startup test.
The focused final next-decision/activation tests passed 2, including acceptance of
the first certificate in the successor era and historical closure verification
after that append. Certified-history tests passed 22, including refusal of the
unsupported intermediate schema before mutation. All five control/replay
regressions passed with loopback networking permitted (96.51 seconds). Raw logs
and source maps are in `k7-era-next-decision-test`, `k7-era-history-test` and
`k7-era-control-replay-test`. The startup evidence is `k7-era-startup-test`;
completion and projection evidence are `k7-era-completion-test` and
`k7-control-projection-test`. These checks cover successive explicitly recorded
source states; unchanged earlier results are retained, not relabeled as a fresh
run of the final source.
The first completion compile had a corrected result-type mismatch and rustc
incremental-cache ICE; only indexer's disposable incremental cache was cleared.
Failed logs are retained, not reported as passing evidence.

This remains an uncommitted, unmerged part of K7/K8, not a live P2 handoff claim.
The activation transaction fixture pre-seeds accepted control state and block
applications, then uses the real registered no-op migration, canonical runtime,
staking observation and closure machinery. It does not establish authorization
notice, full block execution, P2 backfill or independent P2 dispatch. Actual P2
registration/extraction, per-position executor selection, live transition proposal
and replay wiring, managed engine switching, and complete cross-upgrade recovery
remain required. No CI or new independent-review campaign was launched.

### K7/K8 canonical selection and live transition admission, 2 November 2026

The certified execution selector now binds the protocol, immutable executor
definition and canonical application lineage. Owned-root admission rechecks that
selection, and block/batch application records use its protocol execution identity.
Migration selection also resolves the target from the pending canonical plan.
Unversioned fixture preparation remains explicit and does not become certified
history merely because a session exists. The coordinator suite passed 100 tests
with one intentional subprocess entry ignored (48.29 seconds), recorded in
`.build-cache/k7-canonical-selection-test.json` and its raw log.

Block and batch input verification now preserves the original certified era.
Block comparison checks the full retained Bitcoin body and metadata rather than
constructing an ordinary descriptor in the running era. Live transition admission
is not repeated during historical execution: the derived activation stage evaluates
the surviving schedule at that reconstructed position. A focused real block/batch
application test, with a deliberately different in-memory running era, passed and
retained the original certificate and canonical protocol identity. This isolates
input verification; it is not evidence of an actual engine handoff.

Live block proposal construction derives the exact transition from surviving
parent-height control state and the next consensus height. It requires an installed
target before proposing activation. Incoming proposal admission requires that same
descriptor and installed target, with missing, unsolicited, mismatched and
unavailable transitions rejected without treating them as database failures. Exact
local Bitcoin-body comparison preserves the independently validated descriptor.
Authenticated history admission still verifies the descriptor independently of
local installation, so an unsupported node can retain certified work and stop at
activation rather than invent execution support. The earlier ordinary-block-only
boundary guard has been removed.

Focused checks on the source map in `.build-cache/k7-live-transition-sources.json`:

- Surviving schedule, postponement, cancellation, rollback, exact H and C+1:
  1 passed, 0.09 seconds (`k7-transition-admission-test`).
- Migration/activation atomicity and unsupported-target handling, including exact
  descriptor validation: 2 passed, 17.20 seconds (`k7-live-activation-test`).
- Full retained Bitcoin body and transition-bearing input decoding: 2 passed
  (`k7-retained-block-test`).
- Real control, proposal, committee, rollback, restart and replay paths:
  6 passed, 104.82 seconds (`k7-live-control-replay-test`). The proposal case rejects
  an unsolicited transition and accepts the ordinary block without one.

All logs and source-bound JSON records are local under `.build-cache/`. The earlier
original-era-only test passed separately in 17.40 seconds. Its first compile had an
import error and an incremental compiler ICE; the import was corrected and only
the disposable indexer incremental caches were cleared. The failed log is retained.

K7/K8 is still local and incomplete. The registry currently contains only P1, so
positive live installed-P2 admission, actual P2 migration/dispatch and engine
handoff are not established by these checks. Final P1 retention, actual P2 native
mapping, session switching, startup recovery and complete cross-upgrade acceptance
remain. Live proposal callbacks must also follow the completed ordering context
during managed handoff. No PR, CI campaign, publication or additional independent
review round was started.

### K7/K8 P1 preservation and P2 token implementation, 2 November 2026

Local checkpoint `2c26410e8419844bddf3d4967d157ce240f8b9c1` contains the canonical
activation/replay and transition-admission work above. It is not merged or a
completed grouped review. The existing snapshot tool preserved that exact source
under `protocol-bundles/retained/p1`; relocation verified both executor definitions.
Snapshot digest: `4df4b75941b026b19a6dffcf2371afdd4d997e2b8cd33322002c782e3bc36cfc`.
The production build recipe has not yet switched to this snapshot.

The pinned Podman native build produced P2's token artifact, with positive-balance
count at field 5 and all three ledger writes routed through the count-maintaining
helper. P1's retained token and genesis publication remain unchanged. The current
executor now has an explicit P2 factory/version and selects the pinned replacement
at the shared component-byte lookup, so execution, WIT and component-cache inputs
agree. Raw publication bytes remain available separately. Ordinary gas constants,
amount arithmetic and non-token native artifacts are unchanged.

The P2 session migration registry accepts only its exact count-backfill definition.
The fixed migration allowance is 67,108,864 computation steps, 1,000,000 reads,
67,108,864 read bytes, one write and 32 write bytes. These are migration work units,
not ordinary call gas or a block budget. The routine scans the pinned input, rejects
malformed complete keys/balances and an existing count, preserves balances, and
writes the checked count. Exhaustion fails the owned migration rather than retaining
partial state.

Focused local evidence is recorded in `.build-cache/k7-p2-runtime-evidence.json`
with source-manifest, binary and raw-log hashes. The owned backfill test passed
(0.09 seconds), covering positive, zero and negative balances, system/UTXO holders,
malformed and already-migrated input, write-budget exhaustion, unchanged ledger and
rollback settlement. Three P2 codec/native tests passed (35.01 seconds), including
real calls with a shared P1/P2 cache, additive P2 WIT, P1 missing-method behavior,
unchanged publication and repeated issuance to existing holders. The initial test
compile failed on a fixture error conversion and was corrected before these runs.
No CI campaign was launched.

These are component-level checks. The native test seeds the derived count directly;
the backfill test uses the existing owned P1 fixture to exercise the routine. They
do not prove registered P2 activation or independently linked execution. Remaining
work includes the P1/P2 production graph recipe, manifest and session selection,
effective-artifact provenance API, refreshed executor references, actual activation
and rollback, incompatible engine handoff/recovery, and the grouped acceptance and
review. P2 is not yet installed in the node's manifest registry.

### K7/K8 managed graph routing and P2 manifest, 2 November 2026

The managed build recipe now selects the preserved `retained/p1` first executor
and the current observer graph as P2, retaining exactly two conflicting Wasmtime
graphs. Legacy qualification and K4 recipes keep their existing snapshots. Managed
P1 is the default factory; the observer definition explicitly selects the P2
factory/version. Both managed executors expose their originating registration
observer. The node's managed P1 reference points to the same frozen graph.

Added exact P2 manifest construction and managed registry admission. Its commitments
include the independent executor, second consensus definition, predecessor P1,
positive-balance migration, storage schema transition and selected token artifact
digest. User transaction format and canonical certificate codec remain version 1.
The managed-definition generator accepts an explicit first/second graph, and the
node builder checks both references rather than trusting the second graph merely
because it was linked. Generated references remain explicit pre-release outputs;
refresh both managed references after the remaining source changes settle.

The Rust manifest-composition test passed against real retained/current references
(0.09 seconds). This was an unmanaged local test: it checks the commitments and
unmanaged P2 rejection, not managed installation or factory invocation. Focused
Python tests passed for node evidence admission (11), retained source roots (7),
managed definitions (6), node comparison (17), and node compiler-wrapper behavior.
The node evidence gate now rejects the wrong genesis executor even when the supplied
manifest/protocol/era hashes are self-consistent. One comparator attempt overlapped
an observer-reference refresh, invalidating its already-built synthetic fixture;
with reference writes stopped, the same 17 tests passed. Keep reference writes and
evidence tests sequential.

Raw logs, current source and test-binary bindings, and limitations are recorded in
`.build-cache/k7-p2-routing-evidence.json`. No new managed binary, independent-graph
execution, activation/handoff acceptance, CI run or merge is claimed. The next work
is per-position session/view selection, actual managed handoff/recovery, effective
native provenance, qualification-harness updates and the grouped integration run.

### K7/K8 per-position executor and read selection, 2 November 2026

The reactor now resolves each closure action before entering its owned stage,
including the target migration executor. It caches writer sessions by immutable
execution definition, shares the physical writer's admission gate across them,
and changes recognition together with execution. After each settled stage and
startup recovery it restores the surviving canonical executor, including after
rollback. Preparation and simulation use the canonical selector when certified
history is ready. Managed nodes reject non-ready history; unmanaged qualification
fixtures retain an explicit path for absent or uninitialized journals.

Pooled reads select factories by execution definition and retain the configured
view limit. An obsolete idle session is replaced before root admission. Root
preparation and the read callback both check the executor identity against their
pinned snapshot. A cross-protocol change before pinning rejects that request;
automatic retry is not implemented. Replacement construction retains the pooled
object and admission permit until completion even if the requesting task cancels.

Eleven focused tests pass on the current local binary: five linked read/lifecycle
checks (61.25 seconds), and six selection/admission checks (17.18 seconds). They
include cancellation while replacing a reader, pool reuse, read-only SQL, retained
view gas limit, actual views, stale lineage, busy-root rejection and unavailable
target rejection without closure advancement. Thirteen related activation,
closure, selection and mempool regressions passed on the preceding source before
the read-pool changes (69.93 seconds). Source and binary hashes, raw logs and exact
coverage are in `.build-cache/k7-session-routing-evidence.json`.

The first build required a Result type annotation and clearing the affected Rust
incremental cache after a compiler fingerprint error. The first read-test run
identified the absent journal in an unmanaged legacy fixture; the explicit fixture
path fixed it without weakening managed admission. No CI, push or merge occurred.

These checks do not establish independent P1/P2 dispatch. The pool replacement
test uses deliberately obsolete session metadata, not a second linked executor.
Managed-only mapping, actual activation/reorg views, completion-driven engine
handoff, current-era startup/recovery, native artifact provenance and the grouped
linked acceptance remain outstanding. `NodeCoordinator` still assumes its initial
context and first engine bundle; that is the next integration work.

### K7/K8 managed startup and live handoff integration, 2 November 2026

Local implementation now selects the engine from validated completed-era history.
Admission checks immutable genesis separately from current ordering and canonical
execution selection, including an unfinished closure whose canonical executor has
already changed. Signing state opens only after recovery establishes the next
engine's context. The reactor joins the outgoing engine, discards its callbacks and
parsed candidates, retains raw inputs and Bitcoin ingestion, and starts the selected
engine at C+1 on the bound port with its own era WAL.

Focused unmanaged checks passed: three admission tests and four recovery/handoff
regressions (`.build-cache/k7-handoff-local-evidence.json`). These establish their
specific state invariants, not independently linked P1/P2 activation. Twelve build
input tests also pass after including activation descriptor types in the extracted
consensus graph and its provenance inventory.

The real managed ARM64 dev node, both executor graphs and both consensus graphs
compiled successfully. Native ownership, five executor interface controls, seven
consensus interface controls and seven actual node adapter tests passed in the
286-second local build, bound to an unchanged source inventory. Its preserved record
is `.build-cache/k7-transition-build-before-release.json`. The first interface
attempt incorrectly inferred an old migration interface from graph labels. Frozen
P1 already exports failure accounting, so its structural factory matches P2's. The
check now selects expectations from the bound retained source identity, preserves
K3's adapter control, and still rejects foreign Wasmtime/Tokio/private types. Six
focused tool tests pass, as do the controls against actual built libraries.

A new feature-gated `qualify-protocol-transition` command drives a live validator's
real event loop through H, target migration, engine replacement and H+1, checking
P1/P2 views using the same reader pool. It deliberately starts from a fixture
accepted schedule, so it is not authorization/notice or multi-validator evidence.
The sandbox run could not create sockets, confirmed by an independent EPERM probe.
With loopback permitted, the same binary reached handoff and exposed a real resource
lifetime bug: the stopped transport/control handles retained the durable signer,
keeping its journal locked when the new generation opened it. The failed evidence
is `.build-cache/k7-transition-before-release.json`.

The local correction replaces a managed transport with an inert stopped state only
after signing revocation and confirmed join. This drops the old handle references
before replacement; timeout/error paths retain ownership. Stopped transports reject
publication/signing and allow idempotent stop. No signer journal format, fencing
rule or cryptographic operation changes. The corrected linked build passed in
288 seconds and the live transition passed in 27.45 seconds. The preserved record
`.build-cache/k7-transition-pass.json` binds the tested binary and unchanged build
sources. P1 rejects the added view; after activation the same reader pool returns
the migrated count `1`. Decision 1 uses P1, decision 2 uses P2, and the bound listener
is retained. Stopped-engine operations reject signing and permit repeated stop.
The fixture now stops observation promptly on reactor failure instead of waiting
for its deadline after an already-known error.

The fixture extension drops the original reactor, sessions and coordinator,
reopens the same database and starts through the production reactor startup path.
It checks persisted P2 selection, unchanged history before new input, the same era
and listener, and successful decision 3. The extended local ARM64 dev build passed
in 284.59 seconds with unchanged sources, and the full handoff/restart command passed
in 33.81 seconds. `.build-cache/k7-transition-restart-pass.json` preserves the
binary-bound result, raw output/logs and build-source inventory. Archived hashes
were checked after preservation. This is an in-process clean restart, not
process-crash, cold-sync, full HTTP RPC or multi-validator evidence. No additional
production change was needed for the restart to pass.

No CI, push or merge occurred. The older equivalence helper still needs adaptation
because its managed alternate path selects default P1; it cannot establish P2
coverage. Full grouped acceptance still requires actual multi-validator handoff,
restart/reorg and migration recovery, effective native provenance and the remaining
agreed scenarios. The new command does not replace those requirements.


### K7/K8 three-validator managed handoff, 2 November 2026

The linked qualification command now has a `--cluster` mode using three live
validators, independently initialized databases and real managed P1/P2 execution
and consensus bundles. The local ARM64 dev build passed in 289.68 seconds with
unchanged source inputs, including the ownership/interface checks. The cluster
passed in 73.46 seconds. `.build-cache/k7-cluster-pass.json` preserves the binary,
source inventory, raw result and log hashes. All three completed decision 1 under
P1 and decision 2 under P2, kept their bound listener addresses and agreed on the
completed closure, era transition and typed digests of 14 application-state tables.
The same reader pools rejected the added view before activation and returned the
migrated count afterward.

This fixture seeds an accepted schedule before genesis authority is published.
It isolates actual multi-validator migration/handoff and is not an authorization,
notice, HTTP RPC, crash or cold-catch-up test. No CI, push or merge was performed.
Cross-upgrade rollback/replay and the other grouped acceptance requirements remain
open. The grouped review must also assess whether existing ownership/type checks
sufficiently enforce handoff sequencing and whether a small typestate refinement
would remove a concrete risk without unnecessary complexity.


The extended cluster scenario places activation at Bitcoin height 2, executes
height 3 under P2, then certifies a replacement branch from height 1. The earlier
seeded schedule survives, but its activation and migration do not. All validators
restore P1 in a fresh era, and their existing reader pools stop exposing the P2
view. Reaching replacement height 2 reruns migration with a distinct receipt key
and starts a fresh P2 era. A sixth certified decision proves that final engine
can make progress after the last handoff. The three engine boundaries are global
Kontor consensus heights 3, 5 and 6; Bitcoin height rolls back independently.
Original decisions 1 through 3 remain unchanged. All nodes agree on the final
closure, activation, era and 14 compared application-state tables.

The final local ARM64 dev build passed in 279.96 seconds with unchanged inputs;
the six-decision run passed in 114.35 seconds with an unchanged binary. Evidence
is `.build-cache/k7-cluster-reorg-pass.json`, with archived source, build and raw
output/log hashes verified. The earlier five-decision run is retained separately
as `k7-cluster-reorg-five-decisions.json`; it established final migration
publication but not a subsequent decision by the final P2 engine. Neither record
is a new approval, removed-schedule, same-H/hash changed-prestate, process-crash,
HTTP RPC or cold-catch-up test. Those distinct acceptance cases remain open where
not already covered by other evidence. No production change was required for
this surviving-schedule rollback scenario to pass, and no CI/push/merge occurred.


### K7/K8 effective native artifact provenance, 2 November 2026

Contract provenance now returns the original append-only publication claims and
a separate effective-artifact record. The same owned pinned read snapshot selects
the executor and reads the publication. The record reports the selected protocol
and execution definition, SHA-256 of published and effective stored artifact
bytes, and whether a protocol-native mapping supplied the effective bytes. The
P2 hash comes from its independently built executor export and the same native
replacement function used by runtime loading. P1 continues using publication
bytes. No publication row or old provenance claim is rewritten or presented as
an attestation of P2's replacement. SDK `getContractProvenance` exposes both
records; `getProvenance` retains publication-log behavior. Missing full provenance
support produces an explicit SDK error. SDK publication remains deferred.

Rust type/export tests passed (72), regenerating the wire declarations. SDK web
and native bundle builds passed, as did both focused transport tests and changed
TypeScript formatting checks. A direct all-files `tsc` check encountered the
absent optional mobile `@kontor/sdk-native` peer; the repository's web declaration
build excludes those mobile-only imports and passed. Initial Rust setup attempts
used the wrong offline Cargo cache and a read-only ccache location; the corrected
local type/export command passed. The linked build correctly rejected the stale
unreleased P2 definition after adding its export. Regenerating that pre-release
definition fixed the check without changing frozen P1.

The final managed local ARM64 dev build passed in 287.92 seconds with unchanged
inputs. The three-validator six-decision fixture passed in 178.49 seconds. It
checks provenance before activation, after P2 activation, after P1 restoration,
and after reactivation, using the same reader pools. Unaffected staking remains
on publication bytes. Independently comparing raw reported hashes against the
pinned compressed P1/P2 token files passed. Publication claims are equal before
and after; the live state/closure/history assertions also passed. The evidence
record `.build-cache/k7-native-provenance-pass.json` binds source, binary, build,
raw runtime output, artifact files and SDK/type-test logs. This exercises the
actual helper called by the HTTP handler, not a running HTTP server. Seeded
schedule, crash/recovery and cold-sync limitations remain as stated above.

Inactive compiler incremental cache was removed under the shared build lock,
recovering roughly 9 GB of actual filesystem space while preserving source,
binaries and evidence. No CI, push, merge or publication occurred. Grouped review
and remaining K7/K8 acceptance are pending.

### K7/K8 retained-baseline and transition qualification, 2 November 2026

The old managed qualification helper selected the default P1 factory for both
`first` and `observer`. Matching outputs therefore could not demonstrate two
production protocols. Managed qualification now compares only the actual frozen
P1 graph against the unchanged historical semantic oracle. The original fixture
source and oracle hashes remain intact. Legacy two-graph qualification retains
its existing equality checks. Managed P1 view and history fixtures initialize
certified history through normal bootstrap; production admission was not relaxed.
The frozen P1 now exports registration observation and failed-migration work, so
its fixture expectations were updated accordingly. The first runtime attempt
confirmed the latter stale expectation, failed, and is retained as diagnostic
rather than acceptance evidence.

The managed runner separately requires `qualify-protocol-transition --cluster`
from the same audited executable. Its six-decision P1/P2/P1/P2 result must include
three validators, all three handoffs, matching state/closure, retained history,
restored/reapplied migration and the effective native artifact records. The
verifier binds both executor definitions and native artifact hashes to the actual
source files. Original publication claims must remain unchanged. Raw transition
stdout/stderr are hashed into the execution record and checked by the platform
comparator, which also compares the transition observations across required cells.
Missing, altered or failed transition evidence cannot satisfy the managed gate.
The generic shared-capacity test still exercises two independently owned library
roots; it does not claim that its unversioned fixture authorizes production P2.

Focused Python checks passed: transition verifier (1 test with negative cases),
historical semantics (5), node execution (13), and node comparison (18). The
corrected local ARM64 dev linked build passed in 286.53 seconds, with unchanged
source inputs. The complete local runtime runner passed in 274.01 seconds:
P1 matched the preserved oracle, certified history closed 15 decisions, managed
startup joined both tested engines, and the three-validator transition completed
all six decisions. Loading the actual evidence through the full single-cell
comparator also passed, including source inventories, graph/interface checks,
artifact bindings and raw logs. Archive:
`.build-cache/k7-helper-qualified-pass.json`, with ten bound evidence files.

This is one local dev cell, not cross-platform CI. The transition retains the
seeded-schedule scope and does not establish approval flow, HTTP server continuity,
crash recovery or cold catch-up. Other required K7/K8 scenarios and grouped review
remain outstanding. The separate archived unversioned `compare-baseline` command
also needs its managed-versus-legacy invocation scope reconciled; its old archive
must not acquire invented certified authority. No CI, push, merge or publication
occurred.

### K7/K8 actual P2 migration recovery, 2 November 2026

Added `qualify-protocol-transition --recovery`, using the independently linked
P1/P2 factories and production certified-closure driver. The accepted schedule
is a fixture precondition, as in the existing transition test. A real verified
block certificate is persisted before execution. An uninterrupted copy completes
H, its lifecycle, actual P2 token-count migration and closure. A second copy
reopens executor sessions at durable boundaries, injects a SQL failure while
persisting activation after migration execution, and requires exact equality of
every persistent table with the pre-attempt state. It then retries, reopens after
migration commit but before closure publication, and completes to the same full
database and closure as the uninterrupted copy. Successor committee/startup is
unavailable until closure completion. No owner root or writer transaction leaks.

A separate preactivation copy deliberately contains P2's reserved count field.
The real registered migration rejects it with `InvalidOperation` and consumed-work
diagnostics, preserving every table. A fresh session rejects it again after
reopening. This is invalid-input fault injection, not a reachable P1 transaction
claim, operator repair procedure, or authorization to modify production data.

The local ARM64 dev linked build and native ownership/interface checks passed in
290.64 seconds. The focused runtime passed in 44.02 seconds with the binary and
source inventory unchanged. Binary SHA-256:
`f3d826d714a4fd463bc3148a2f6f122d47ef32d4fc04ccdcf62f7df694329334`.
Archive `.build-cache/k7-recovery-qualified-pass.json` binds seven evidence files,
including source inventory, build, node audit, runtime and raw output; archive
SHA-256 `c32ddf2dd1618c5fc5bb4a0b8c17730b8d0074fc7658dd22e79481ad3e231ed4`.
Separate CLI checks verified rejection of simultaneous cluster/recovery options
and the managed build's explicit legacy-archive diagnostic, before archive access.
That resolves the archived command-scope issue noted above without relaxing
production admission or changing the historical oracle.

This evidence covers transaction failure and fresh database/executor sessions,
not abrupt OS-process crashes, engine/WAL recovery, live approval or cold sync.
The command is available for focused qualification; inclusion in the final
grouped acceptance invocation remains to be wired alongside the other remaining
K7/K8 cases. The previous cluster evidence remains bound to its own earlier source
inventory, not relabeled as a rerun here. No CI, push, merge or publication occurred.


### K7/K8 same-H finality and control-effect replay, 2 November 2026

Extended the actual linked-executor recovery command with three seven-block
scenarios. Each executes an unconfirmed issuance batch at H=1, retains the Bitcoin
history, and triggers the ordinary finality expiry at height 7. The surviving
schedule case activates P2 at H=2 both before and after finality reconstruction;
its H hash stays identical while pre-lineage and migration receipt key change.
The other cases apply an actually signed, admission-verified Cancel or Postpone
against the fixture's initial schedule. H=2 originally executes without a
transition descriptor. Finality undo removes the later control effect, records
its retraction, restores the surviving schedule, and derives P2 activation while
replaying that same H. Retained control inputs remain unchanged and their replay
stages explicitly report `RetractedControl`, rather than resurrecting old consent.

All three cases assert P1 execution identity for H's lifecycle, P2 for migration
and subsequent block lifecycle, and equality of every persistent table, closure
and era after fresh-session recovery paused immediately after owned rollback.
They close 8, 9 and 9 certified decisions respectively. The existing actual-P2
migration atomicity/rejection checks still run in the same command. Shared seed,
certificate append, session open and snapshot helpers were extracted without
changing the accepted-schedule precondition or the historical oracle.

The managed qualification runner now requires this recovery command, retains its
raw output hashes and rejects missing/incomplete/altered recovery evidence in the
comparator. Focused Python controls passed: evidence verifier 2 tests, process
runner 14 tests, node comparator 19 tests, including nonzero-exit rejection and
missing/altered/rehashed-but-incomplete recovery data. The actual Rust output also
passed the recovery evidence verifier. The local ARM64 dev linked build and
ownership/interface checks passed in 294.89 seconds with source inputs unchanged.

The initial combined runtime hit its 240-second harness timeout. That result is
retained as failed in `.build-cache/k7-replay-timeout.json`; it is not acceptance
evidence. Its remaining fixture was created near the timeout, consistent with
later scenario setup. One rerun of the unchanged source and binary with a
360-second bound passed in 328.56 seconds. The checked-in runner now allows 420
seconds for this combined correctness suite, with no protocol/runtime limit
change and no performance acceptance claim. This timeout-only runner adjustment
and documentation followed the source-bound execution, so the archive retains
the exact earlier source inventory rather than claiming a later source rerun.

Archive `.build-cache/k7-finality-replay-qualified-pass.json` binds eight evidence
files, including the exact local runner and both build/runtime source bindings.
Archive SHA-256: `7cf815013ae260cbc5bf01e1ad205e6f985ec911e3a5fb98caab70c47ce1a321`.
Binary SHA-256: `8524cf572b0471004ae89bc4860d0f7d0e67fb266936b7c776fa683ca91724e3`.
This resolves the recovery-command gate wiring noted in the preceding entry.
It does not establish initial Schedule approval through activation, schedule
removal after activation, confirmation without recharge, abrupt process/engine
crash recovery, live HTTP continuity, or K9 cold transport. Those remaining
requirements and the grouped reviews/CI/merge are still open. No CI, push, merge
or publication occurred during this work.


### K7/K8 paid confirmation across activation, 2 November 2026

Extended the existing surviving-schedule fixture with a snapshot branch after H=2.
The original P1 batch contains issuance followed by a successful gas-paying token
mint. The branch records Batch(H) under P2, then confirms the original transaction
in H+1. Actual block application reports zero new transactions and zero executed
operations. The original execution height, batch identity, transaction ID, fuel
usage and complete transaction receipts remain unchanged, while the raw Bitcoin
confirmation position is recorded. Database/session reopen preserves every table
and the completed closure. This reuses the accepted-schedule fixture, not initial
Schedule authorization or a live-engine test.

The first runtime attempt failed at canonical Bitcoin validation because the new
fixture used a coinbase-shaped transaction input and omitted the SegWit commitment.
Corrected the fixture using the existing block-test conventions, without changing
production validation. Lead inspection also narrowed receipt comparison to the
transaction, since block lifecycle work produces its own legitimate receipts.
The corrected independent linked-node build passed in 283.80 seconds, and the
complete recovery command passed in 340.38 seconds within its 420-second harness
limit. Existing migration atomicity, same-H finality replay, signed Cancel/Postpone
undo and reopen checks passed in the same run. Source and binary remained unchanged
during validation. The strengthened raw-result verifier accepted the actual output;
35 focused Python evidence/runner/comparator checks passed, including rejection of
missing or false confirmation observations.

Evidence archive: `.build-cache/k7-confirmation-qualified-pass.json`, SHA-256
`b479220e3590eaf84616dd5c9c755407c9adcf59eda5bb78666f8889b6adbf04`.
It binds eight build/source/runtime/raw-output files. Tested binary SHA-256:
`b566e25e7d82624bec03584cfe6a2566aceed636f9fb6ca8f180dab687a9d3d5`.
This is local ARM64 dev evidence, not final cross-platform CI or grouped review.
No PR was pushed, merged or published for this increment. Outstanding K7/K8
requirements remain recorded separately, including removed-schedule replay of a
retained P2 batch, initial authorization through activation, HTTP/ingestion
continuity, engine recovery, zero successor power and P2 balance-count paths.


### K7/K8 signed authorization trace and branch eligibility, 2 November 2026

The local ARM release build passed in 1,380.11 seconds with source hashes
unchanged. Its first authorization runtime failed after 67.30 seconds at the
assertion that an old P2 batch should execute under restored P1. The preceding
real signature, full 1,008-height notice, P2 activation, deep rollback removing
Schedule, and return of the original Bitcoin hashes all completed. Preserve
`.build-cache/k7-authorization-first-failed.json` and its hashed raw records as a
failed run, not acceptance evidence.

Lead investigation and the existing planning reviewer agree that the expectation
was incorrect: the original batch belongs to a superseded branch interval.
Hash equality does not reopen that interval. The updated scenario requires its
certificate to remain exact and its application to remain absent, then submits
a new P1 batch and checks finality replay and reopen equality. The implementation
plan records this acceptance clarification. Production semantics are unchanged.
Corrected runtime acceptance is pending; synthetic verifier tests do not prove it.

The lead also inspected engine handoff ownership in control, reactor transport,
coordinator startup and the closure driver. Generation ownership and the stopped
backend state provide concrete Rust boundaries, while asynchronous stale messages
and durable recovery still require runtime fences. This was intermediate
inspection, not completion of the grouped review. Its source hashes and remaining
RPC/ingestion and crash-recovery gaps are recorded in
`.build-cache/k7-handoff-ownership-lead-inspection.json`.


The corrected ARM release build passed in 237.15 seconds. Its runtime passed in
71.50 seconds with binary/source hashes unchanged, completing 2,028 decisions.
The raw-result verifier confirmed all required fields: actual authorization,
1,008-height notice, H1009 activation, schedule retraction, orphaned P2 batch
exclusion, fresh P1 batch replay, unchanged certificates and reopened-state
equality. Nine archived files bind build logs, source inventory, node build,
runtime, runner, raw output/log and the planning clarification in
`.build-cache/k7-authorization-qualified-pass.json` (SHA-256
`5e23a34407d76c3d71904fc0b308e28eaf1b973cdab8862d4da6e2bd1124afdc`).
This paragraph was added after that source-bound run; it is a documentation-only
status update, not a claim that later implementation was tested.

The managed node runner/comparator now require this scenario's raw evidence,
reject nonzero process exits even with valid output, verify raw hashes and reject
missing or incomplete checks. The 38 focused Python tests passed (3 transition
verifier, 15 execution-gate, 20 comparator tests). The actual full node runner and
cross-platform comparison have not been rerun for this candidate. No new CI run,
push, grouped review or merge occurred. Actual HTTP/Bitcoin-follower continuity,
remaining native count mutation paths and meaningful crash/committee coverage
remain open; do not claim these from this database-recovery trace.


### K7/K8 HTTP and Bitcoin follower continuity, 2 November 2026

The existing three-validator cluster now uses the production Bitcoin follower,
including its poller and initial ZMQ handshake, against the existing in-memory
Bitcoin RPC fixture. It serves the production HTTP router over loopback with the
normal readiness, info and event wiring. Continuous liveness requests run during
all three engine handoffs; contract views and effective-native provenance are
queried through HTTP before activation, after activation and after rollback.

The first runtime failed after 15.18 seconds at a fixed consensus-height
assertion. Follower polling permits ordinary idle batches, so Bitcoin height and
consensus height are not interchangeable. The fixture now finds each exact
Bitcoin block/hash in authenticated branch history, waits for its decision to
close, and checks every handoff at that actual C+1. No production ordering or
engine behavior changed. The failed result remains in
`.build-cache/k7-services-fixed-height-failure.json`.

The corrected ARM64 release build passed in 241.34 seconds. Runtime passed in
36.31 seconds, with six Bitcoin block decisions at consensus heights
`[1, 3, 4, 5, 6, 7]` and handoffs at `[4, 6, 7]`. All three validators agreed on
final application state and closure, preserved original certificates, restored
P1 in a fresh era on rollback, and reapplied P2 with a new migration receipt.
HTTP traffic, views/provenance and the same Bitcoin follower tasks survived.
The actual raw-result verifier passed; 40 focused Python verifier/runner/comparator
checks passed, including incorrect C+1 and missing continuity negative controls.
Cross-platform live comparison validates each actual transcript's positions,
then compares semantic outcomes rather than timing-dependent idle-batch counts.
Fixed-input historical qualification remains separate and unchanged.

Eight source/build/runtime files are bound by
`.build-cache/k7-services-qualified-pass.json`, SHA-256
`09d74d03b584480495aa7d22d89bfbbe15c3327c6f74582fb00a10dce8bace6b`.
This documentation was added after the source-bound run. The fixture seeds its
schedule; it does not use actual Bitcoin Core or prove process-crash recovery or
cold catch-up. No CI, PR, merge or publication was performed for this increment.
Remaining K7/K8 coverage includes actual P2 count mutation paths, meaningful
crash recovery and successor/unsupported committee cases, followed by grouped
lead and independent review and the final scoped CI campaign.

### K7/K8 token mutations and corrected paid-call evidence, 2 November 2026

The full-ledger count scenario initially failed because its raw calls supplied
integer WAVE arguments for decimal-record parameters. Only issuance executed.
The earlier confirmation fixture had the same argument error, and its broad
paid-receipt predicate could accept issuance alone. That earlier evidence still
showed unchanged receipts on confirmation, but did not establish the claimed paid
mint. Those paid-mint claims are superseded by this corrected evidence.

The fixtures now use `to_wave_expr(Decimal)` and require the actual successful
paid `mint` receipt at instruction index 1, both before confirmation and after
fresh authorized P1 replay. No production execution or gas rules changed. The
new scenario checks P1 populated-ledger migration, P2 mint/transfer/self-transfer/
burn, gas escrow refund, UTXO attach/detach, failed transfer consistency and full
database reopen. Seven snapshots independently scan all stored positive balances,
including system holders, and compare them with the maintained field-5 count.

The ARM64 release build passed in 238.00 seconds, recovery and token checks in
26.60 seconds, and signed authorization/finality replay in 72.01 seconds. Both
actual raw-result verifiers passed. Source and binary hashes stayed unchanged.
Thirteen files are archived in `.build-cache/k7-token-qualified-pass.json`,
SHA-256 `6c4014c60f149e197737ad6c35f0130c8ae0533b3b1460f736715b7f97b25ae2`.
The diagnostic failure is retained under `.build-cache/k7-token-decimal-diagnostic-*`.
This ledger entry was added after the source-bound runs.

These are local linked-executor and database-reopen checks, not abrupt process
crash, live consensus transport, cold catch-up or final cross-platform evidence.
Existing migration tests actually kill a subprocess after effects and after commit;
the existing managed-engine restart check instead uses clean stop/join, and the
generation reservation test uses object drop/reopen. Do not conflate their scopes.
Meaningful handoff crash and successor/unsupported-committee cases remain, then
consolidated lead plus one independent review and final scoped CI. No CI campaign,
push, merge or publication was performed for this increment.

### K7/K8 empty successor at activation, 2 November 2026

The linked-executor recovery scenario now covers the last validator leaving at
the upgrade boundary through an actual paid `leave-validation()` call. The call
executes in Batch(H1), confirms in H2 and takes effect after its normal twelve
blocks in H13's P1 lifecycle. The accepted schedule is seeded for this focused
case. Actual P2 migration then commits, but closure publication rejects the empty
successor committee. No C15 authority, new era or consensus startup is admitted.
The authenticated frontier remains C14 and the closed frontier remains C13.

Reopening the database encounters the same typed `InvalidNextAuthority` error.
Canonical state, completed stage chain, inactive registration and retained C14
certificate remain unchanged. This verifies a zero-authority stop at an actual
protocol boundary, not merely the existing same-protocol exit test. It does not
claim automatic repair, a process kill, a live empty-quorum network, or authorization
of the seeded schedule.

The ARM64 release build passed in 234.05 seconds and recovery run in 29.00 seconds,
including the prior token-count, finality and confirmation cases. The raw-result
verifier passed, with source/binary hashes unchanged. Forty-two focused Python
checks passed (7 evidence validation, 20 comparison, 15 node-runner checks), including
missing/false empty-successor observations and incorrect boundary counts.
Nine build/source/runtime files are retained in
`.build-cache/k7-committee-qualified-pass.json`, SHA-256
`b22e985166b491c848aea1a99ed8b5aa8523207aa093eb6b079f734b74dc8445`.
This documentation was added after the source-bound run. Unsupported-target Cancel
progress and focused process interruption remain, then grouped lead plus one
independent review and final scoped CI. No CI, push, merge or publication occurred.

### K7/K8 unsupported target cancellation and process interruption, 2 November 2026

The linked release recovery scenario now starts an actual single-validator engine
with a seeded schedule for an unavailable executor. The production proposal path
does not propose its activation block and rejects a proposal carrying that
transition. A freshly signed Cancel is submitted through the live reactor,
certified before the blocked block, and permits Bitcoin H2 to close under P1.

Five child processes are killed after distinct durable checkpoints: retained
certificate, committed activation, published closure, successor engine readiness
with WAL present, and its first proposal-Fin signature. Each restart matches an
uninterrupted reference state and closure, preserves the original certificate,
starts P2 at C2, and rejects a conflicting proposal signature. Previously bound
listeners are reused. The signed checkpoint retries the identical signature.
Its signature is requested through production managed transport while holding
ConsensusReady, not an assertion that Malachite autonomously produced its first
vote. These cases do not inject inside old-engine shutdown or the migration
transaction; existing lifecycle and migration fault tests cover separate paths
and remain part of the combined review. Cold catch-up remains K9.

The initial sandbox run failed at readiness after 61.24 seconds. A direct socket
probe confirmed socket creation was forbidden. That failure is retained. The
same binary then passed with loopback networking permitted in 47.23 seconds.
The ARM64 release build passed in 238.94 seconds. Source and binary hashes stayed
unchanged through the successful run, and its raw output passed the strict
verifier. Forty-four focused Python checks passed (9 evidence, 20 comparison,
15 runner), including omitted, reordered and false crash checkpoints.

Thirteen source/build/runtime files, including the failed sandbox run, are
archived in `.build-cache/k7-failure-qualified-pass.json`, SHA-256
`b8332aa2fcf96e85561ab10104260f3d5ab0664ded70652293cb6302c7523e89`. This ledger entry was added after the source-bound run.
Next is consolidated lead review of the full K7/K8 change and its coverage,
then the single independent review and final scoped CI. No CI, push, merge or
publication occurred.

### K7/K8 lead review and embedded builder record, 2 November 2026

Consolidated lead inspection traced activation/closure ordering, atomic migration,
canonical rollback versus retained authority, branch-eligible replay, writer/read
executor selection, generation ownership, stale queues and native token accounting.
The detailed scope and limits are in `.build-cache/k7-k8-lead-review.json`, against
base `b3e0fc246d7a859e30b836630372e5658f45afb8` and the current working tree.

Finding LEAD-K7-BUILD-1: the required embedded startup build verification was absent.
The builder now supplies its input record through the content-keyed compiler
wrapper, which checks four role-bound facade/input hashes and the compiler target.
Startup and managed database admission check that record against both installed
executor definitions, both consensus definitions and linked wire codecs before
opening database/signing state. Missing, malformed, mismatched and incomplete
records fail. Compiler/source/lock/facade hashes retain provenance; this is not a
signature by an external authority, nor a self-hash of the final executable.
Final executable/native ownership auditing remains enforced by the builder.

The revised ARM64 release build passed in 241.69 seconds and the
full recovery run in 47.47 seconds. Its build-record negative controls,
live unavailable-target Cancel and five process interruptions passed with unchanged
source/binary hashes. Fifty-seven Python checks passed (12 builder, 10 evidence,
20 comparison, 15 runner). Eleven input/build/runtime files are archived in
`.build-cache/k7-attestation-qualified-pass.json`, SHA-256
`36397e8ffe1b79f815afaa4af47078622b30f0b55f274f2349cac8fb728877a3`. This ledger entry was added afterward.

No independent implementation approval, final cross-platform CI, PR or merge is
claimed by this review. Those are the next grouped delivery gates.

### K7/K8 consolidated independent source review

K7K8-REVIEW-1 reviewed base `b3e0fc246d7a859e30b836630372e5658f45afb8`
through candidate `155ce1091fd5e42141539f1465578b973752055d` with no material
findings. It covered canonical activation/migration, rollback and fresh approval,
branch replay, executor selection, writer/read ownership, engine handoff,
signing persistence, P2 accounting and native provenance. The reviewer verified
all 1,313 frozen P1 inventory entries and the five supplied evidence archives.
The ownership design retains the canonical lease through migration settlement
and requires terminal outgoing engine ownership before replacement.

Builder-record checks compare registry definitions and wire codecs and validate
record structure. Source/compiler/facade hashes are retained builder provenance,
not independently recomputed runtime measurements. The changed-bindings negative
controls do not claim to detect arbitrary substitution of valid provenance hashes.
The first-signature interruption uses production proposal-Fin signing with
ConsensusReady held, not an autonomous first vote.

Remote main was rechecked at the same base; no candidate PR or CI run exists yet.
The post-review source delta only orders a module declaration and regenerates its
two managed references. Ordinary Rust checks and final scoped platform CI remain
pending. K9 cold catch-up and K10/K11 remain separate uncompleted groups.

Final local preparation passed `cargo clippy -p indexer --tests -- -D warnings`,
formatting, and 128 focused Rust tests (102 coordinator, 22 certified history,
three handoff, one session selection). The ignored migration crash child is
invoked by its parent test. The source inventory and four command/log records
are retained in `.build-cache/k7-final-tests.json`; sources stayed unchanged
during the run.

Clippy corrections restrict managed helpers to their callers, document the
unconstructed P2 variant in unmanaged builds, simplify one equivalent condition,
move a test module and remove a needless test borrow. The unreleased observer
reference and both managed references were regenerated; frozen P1 is untouched.
The independent review remains applicable to the unchanged behavior.

The 176 Python build/evidence controls are covered by the full-suite run plus
a focused successful rerun of its 34 native-audit tests with `CCACHE_DISABLE=1`.
The initial audit failures came from ccache attempting a read-only cache write.
The only source correction was adding the required activation input to the
managed-definition fixture and its source-mutation assertion. All three current
references verify. These local results do not replace final platform CI.

### Single-runtime proof started (2 November 2026)

Operator resumed the amended goal. Verified PR622 base
`8c757a8625e8f71f5eceb03c1b3710c849d46207` and created isolated branch
`feat/protocol-single-runtime`. The uncommitted HTTP K9 draft remains untouched
in `protocol-historical-catchup`. K9 now follows the single-runtime proof in the
implementation plan, superseding the previous transport plan. No new build, CI
or proof result is claimed yet. Fork cleanup remains deferred.

The only delegated implementation is security-specific durable per-height signer
authorization (`SINGLE-RUNTIME-SIGNER-1`), assigned to the existing Daybreak agent
in its own worktree. Lead owns reactor integration and final review. One
independent reviewer covers the coherent result; no duplicate planning review.

Initial proof changes remove protocol-triggered stop/start from the reactor's
advance path, retain the live transport, refresh execution preparation at the
next-height gate, and reject stale round/proposal callbacks after certification.
The focused local handoff suite passed four tests (114.22 seconds runtime),
including closure-before-Finalized and the new late-callback regression. This run
preceded the subsequent signer-call integration and is preliminary evidence only.
Log: `.build-cache/single-runtime-handoff-tests.log`. Initial compilation needed
`CCACHE_DISABLE=1` because the sandbox cannot write the user's ccache directory.

The live transition qualification now includes a fresh follower with no injected
history, syncing from an already-P2 peer, plus generation-journal equality and
separate validator/follower WAL assertions. The proof temporarily retains the existing dual-graph
build scaffolding while selecting the first pinned engine for both protocols;
removing that scaffolding and separating semantic identity from build provenance
belong to the coherent refactor only after the bounded proof succeeds.

The integrated signer suite passed 30 tests, including idempotent recovery after
an authenticated height gap. The managed release build then passed locally on
Linux arm64 with both independent historical executors. The live activation,
Malachite catch-up and restart command passed using binary SHA-256
`cd2b10d2e12e056467f155ebe95027ca06fcf2a13e0e69ccbff89c4474eafac8`.
Evidence: `.build-cache/single-runtime-transition-r3.json`, SHA-256
`8f75c4b8fda8de504347f1e3dadaa31a016b89c7d47f04c49082a2b2661c27f0`.
It confirms unchanged engine generation and network owner across activation,
continuous validator WAL, a non-signing fresh follower retrieving the identical
certified prefix and application position through height 2 from an already-P2
peer, and production restart followed by processing Bitcoin height 3. This fixture
seeds the accepted schedule on both nodes; it does not prove upgrade authorization
or follower promotion. Source and follower may advance beyond the checked prefix.

Earlier attempts exposed two harness assumptions about moving consensus tips,
corrected by comparing the same completed height and checking retained records on
restart. A sandboxed attempt could not bind local network sockets; the successful
run used authorized local network access. These were local checks, not CI reruns.
The existing crash/recovery suite also passed against this same binary. Evidence:
`.build-cache/single-runtime-recovery.json`, SHA-256
`ddf91e98e6c9ff389f55d9c99c555c1e5ad1e28262380ed147ed74e7e3c9fbd8`.
All five process-kill checkpoints passed (certified, activated, closed, engine-ready
and signed), preserving certified history, matching recovered state and refusing
conflicting signatures. The signed checkpoint also preserved the exact retry.
Migration failure atomicity, cross-upgrade replay, confirmation without execution,
token accounting, empty-successor gating and unsupported-upgrade cancellation
passed in that suite. Startup authorization recovery is covered; this does not
claim a process kill precisely inside a running engine's Next callback.

The bounded proof supports proceeding with the coherent single-runtime refactor.
K9 remains incomplete: remove dual-consensus build scaffolding, separate semantic
identity from build provenance, complete joining/promotion and targeted historical
sync rejection/resumption coverage, then consolidate lead and independent review
before scoped final-candidate CI. No PR was pushed and no CI launched for this proof.

### Single-runtime build refactor in progress

Protocol manifests now bind `consensus-rules-v1.json`, shared by P1 and P2, instead
of the whole node/runtime build. The runtime reference remains independently
checked by the embedded build record. Protocol registration no longer selects a
consensus implementation. The production recipe links two historical executors
and one pinned consensus runtime, and rejects an extra runtime. Removed the second
consensus manifest/lock/reference, alternate wire-codec feature, dual adapters and
cross-runtime type probes. Generation ownership, signer fencing, shutdown/join
and historical executor isolation remain in place. Tests still exercise successive
runtime generations, including a test-fixture authorization needed by the new
per-height signer.

The ordinary baseline and successor identity checks passed (2 plus 1 tests).
Build-control validation passed 175 of 176 tests before correcting one remaining
four-library attestation assumption; the affected 12-test node-build suite then
passed. Subsequent consensus-input and node-execution evidence suites passed
(12 and 15 tests). Four adapter tests and four interface compilation controls
passed against the previously staged pinned runtime library. The release managed
build subsequently passed with fresh evidence under
`.build-cache/single-runtime-refactor-linked`, reusing only compilation caches.
Its node report confirms two execution graphs and one consensus graph. Executable
SHA-256: `1aac8de22866dbda6fe43e88b8b60e966e97bf04770b81fd87f103567b8c5a14`.
Node source-input digest:
`d71a0a6e133bc6354e0249d18c614b35032afa903385cd00aba91454287759c8`.

The new executable passed the bounded live activation/catch-up/restart command
and the three-validator transition/reorg command. Results are in
`.build-cache/single-runtime-refactor-transition.json` and
`.build-cache/single-runtime-refactor-cluster.json`. The latter passed the existing
transition evidence verifier: matching closure/state, restoration of P1 in a fresh
era, reapplied migration, retained history, RPC continuity and Bitcoin ingestion
continuity. The bounded command again verified unchanged engine generation and
network owner through activation and a fresh follower's exact historical prefix.
No CI has been launched. Joining/promotion and final review remain incomplete.

### Single-runtime startup integration, in progress (2 November 2026)

Base `effa30b7` passed the linked release build and live transition/restart/catch-up
plus three-validator upgrade/rollback checks. Security inspection commit
`1fc4e90b` was reviewed for integration and cherry-picked as `6d0930e9`.
It shares signer-journal validation with ordinary replay and inspects a private
WAL copy with the pinned reader/decoder. The implementer reports three signer
inspection and two WAL integration tests passing. Final consolidated review remains.

Startup policies now distinguish explicit genesis bootstrap, retained-state resume,
and join with a positive verified consensus-height floor. Eight standalone Rust
policy tests pass; integrated Cargo tests and live role-promotion evidence remain
pending. The reactor promotion path is connected after completed Finalized handling,
with follower stop/join before protected-state reinspection and validator startup.
The crash fixture now enters the actual WAL height before its explicit first
signature. Regtest startup selects bootstrap for initial members, resume for
restarts and join for previously unstarted members.

Lead review found a real pre-reservation interruption/refusal window: a header-only
owner journal cannot currently reopen. The Daybreak implementer is investigating
that narrow correction. No CI, publication, merge or completion claim accompanies
this in-progress entry.

Startup integration follow-up: the integrated normal Cargo filter passed all nine
policy/configuration tests. The header-only owner correction is now integrated as
`0352cecc`, following the WAL-copy integrity correction `130cf83a`; the implementer
reports its two focused recovery tests passing. The linked managed release build
is running against this code plus the startup integration. A focused four-member
join scenario now requires the promoted member's vote after an original validator
stops. Live results and consolidated review are still pending. Existing build
caches are reused; no CI run has been launched.

### Startup integration local evidence (2 November 2026)

The linked release build completed with the startup integration and inspection
fixes above. Binary SHA-256:
`b833df3ca0234942ae8d740594aa382357e603bc342e6178533d85927aaeec08`.
Its build report is in `.build-cache/single-runtime-refactor-linked`; transcripts
and results use `.build-cache/single-runtime-startup-*`.

- Four-member join passed. Three original validators reached P2; the fourth
  verified the exact history through consensus height 3, promoted in generation
  2 with separate WALs and the same listener, and signed decision 6 after an
  original validator stopped. The join evidence verifier passed.
- Default transition passed with unchanged engine generation and network owner,
  continuous validator WAL, exact cold-follower history, and production restart
  at Bitcoin height 3 in the same era and on the same listener.
- Recovery passed, including five killed-process checkpoints, rejected conflicting
  signatures, preserved exact retry, atomic migration and three finality replay
  scenarios. The recovery evidence verifier passed.
- All 25 retained executor/node cases passed their semantic oracle and evidence
  checks. Managed startup resumed the same-era WAL and listener, rejected a
  competing writer, and fully joined both engine lifetimes.

The Daybreak implementer ran the full focused durable-signer suite, 36 tests
passing. Its test reconciliation `23397c7c` was reviewed and integrated as
`3acab9fe`. Retained signer artifacts still make header truncation an error;
without those artifacts a lost follower-only reservation is indistinguishable
from interruption before the first reservation and can safely reopen.

The affected Python evidence/comparison suites passed 48 tests, including missing,
tampered and semantically failed join reports. Join runs inside the existing
scoped managed-node qualification, without another workflow or ordinary-PR job.
The comparison fixtures now derive consensus manifests from the single-runtime
recipe rather than referencing the removed second graph.

These live results precede the final test-only recovery reconciliation, evidence
script changes, descriptive scope-string corrections and regenerated build
reference. They are local evidence for the exercised implementation, not an
exact-final-head cross-platform qualification claim. Consolidated independent
review and final-candidate scoped CI remain required; no CI has been launched.

### Consolidated single-runtime review, correction pending

Lead and single independent reviewer examined base/merge base `8c757a86` through
`7b7bd3967d22dbdb12f77defdf11546d01dabbf3`. Remote main was freshly verified at
that base by the lead. Coverage included original-context Finalized handling,
closure/authorization/Next ordering, stale callbacks, nil votes and exact retries,
WAL reconciliation, promotion ownership, semantic identity and build provenance.
The reviewer also checked preserved live evidence against the built binary and
confirmed no changes to retained executor source trees.

One material finding, SR-WAL-1, is accepted and remains open: syntax-only WAL
inspection does not bind stored valid proposals to the context of the height
being resumed. Pinned replay restores their validity without application
revalidation. A valid misplaced same-height WAL could therefore influence
signing outside the authenticated context. The bounded correction passes the
certified next height and context into inspection before generation reservation,
checks height-bearing entries against the WAL header, and compares proposal/value
descriptor contexts when that WAL will actually resume. Older completed WALs must
remain eligible for forward reset without comparison against a successor context.
The Daybreak implementer accepted `SINGLE-RUNTIME-WAL-CONTEXT-1`; focused negative
controls must use valid foreign-context frames and prove unchanged original bytes.
No other material finding was reported. The same reviewer will check this fix.

The full 179-test Python control run had only local ccache read-only filesystem
errors in C fixture compilation. Repeating the affected 34 audit tests with
`CCACHE_DISABLE=1` passed, completing coverage of those controls. Workspace Rust
format checking also passed. Candidate CI and PR submission remain held for the
WAL correction and its focused review.

SR-WAL-1 correction `46412b58` was inspected by the lead and integrated as
`e6fe6f24`. The same reviewer examined its exact diff against `7b7bd396` and
closed the finding, with no new material concern. Four pinned-facade recovery
tests passed, covering valid foreign-context and matching-context inputs, all
four height-bearing input variants, covered older WALs and unchanged protected
bytes on refusal. Ordinary indexer compilation passed in the implementer's
checkout. These checks refuse inconsistent startup state; they neither repair
arbitrary database/WAL combinations nor establish support for swapping backups.
No Malachite fork change was made. Linked compilation of the managed caller and
final exact-head CI remain required.

Final local candidate `b8aff3da53d6cb13f3747bbe3b53bc3cbd341170` completed the
linked Linux ARM64 release build with both executor graphs and one consensus
graph. Installed and audited binary hashes agree:
`17b8d963e3aa8dfb9232fd925e095f0f85a004329abef08f10295eaa1867cf8f`.
The corrected managed caller compiled successfully. Recovery then passed all five
killed-process checkpoints and three finality replay scenarios. All 25 executor
cases passed again, including same-era validator WAL restart, with successful
semantic oracle and evidence validation. Results and transcripts are preserved in
`.build-cache/single-runtime-final-{build,recovery,executors}*`. This closes the
linked-caller validation gap from focused review. No production changes follow
that candidate in this evidence entry; required PR CI remains pending.

### K9 merge and K10/K11 implementation checkpoint, 2 November 2026

PR623 merged as `d671fb8294fe5358e5ad7c5ac900f0f5204b971c` from final
head `75c8cb4a0b08c9d9ad3f1a07261e93d827f01a0c`, after all 26 applicable
checks passed. The substantive lead and single independent review, including
SR-WAL-1 closure, remains the review evidence. Later candidate fixes were the
documented startup-enum lint allowance and a procfs disappearance race in an
evidence-control test. Focused Clippy and all 235 native evidence controls passed.

The successful PR test merge `ee2038d76c41c02852a84eff1b144795488acd5f`
and actual merged commit have identical tree
`02ba878aad6b43ea52fce457808b6efecc32877f`. Duplicate post-merge bundle
run `41548595034` and stack run `41548595238` were cancelled; GitHub reports
both completed/cancelled at the actual merge SHA. Ordinary main CI was not
cancelled. No acceptance campaign was restarted for this bookkeeping.

The combined K10/K11 group starts from that verified merge in
`protocol-client-acceptance`, branch `feat/protocol-client-acceptance`.
The current uncommitted implementation adds snapshot-based protocol/format/ABI
discovery, execution-bound simulation context with the legacy response retained,
typed SDK contextual previews, and reactor-published runtime authority,
committee membership and join-floor diagnostics. It does not change upgrade
authorization, gas caps, transaction encoding or promotion criteria.

Focused local evidence so far: two protocol-discovery tests, five simulation API
tests, five execution-selection tests, the runtime-observation API test, and 12
SDK protocol/result tests pass. SDK web/native builds passed. The first diagnostic
test drafts had invalid fixture setup (missing genesis authority, then a history
status update violating its database constraint); both were corrected using the
real genesis observation and a schema-valid unavailable state. Passing focused
tests are not final managed-node or integrated qualification evidence.

Still required: validate the managed diagnostic publication through the real
runtime, complete remaining integrated acceptance gaps (including two successive
upgrades and linker-backend provenance), consolidate final operator/developer
documentation and the private dark Site, perform lead plus one independent
review, and run the scoped final-candidate checks. The goal remains active.
No publication or additional CI campaign has been started for this draft.

The first K10/K11 managed Linux ARM64 release binary has SHA256
`355c02a07f000cfd6b3855db6c052dbff95659122452d822cb8c23b19703c48c`.
Its linked build and native ownership audit passed. The real authorization run
passed two separately approved upgrades at Bitcoin heights 1009 and 2017, two
distinct migration applications, reopen, and certificate-verified reconstruction
from genesis through 2019 decisions. Only the fresh database's randomly generated
receipt-stream epoch is excluded from cold full-state comparison. Reopen comparison
is exact. The existing control rollback/fresh-retry scenario also passed.

The single independent reviewer agreed to the bounded successive-upgrade fixture:
qualification-only P3 has an exact manifest following P2, reuses P2 execution
semantics, and selects an exact schema-2 no-op migration. Direct P1-to-P3 and
altered-manifest installation are rejected. This is not a third distinct executor
or production support promise, and planning agreement is not final code review.

The same binary passed the three-node activation/rollback scenario with live
protocol discovery and selection-bound simulation contexts at all four observed
states. Its verifier initially rejected SQLite's uppercase checkpoint hashes;
the verifier now accepts either hexadecimal case for that existing field, rejects
malformed and mismatched optional checkpoint coordinates, and accepts the saved
runtime output. No cluster rerun was needed for that correction. The first sandboxed
attempt could not open listeners; the successful local run had loopback permission.

The same binary also passed real validator catch-up from peers already on P2 and
promotion. After an original validator stopped, the joining node's vote was needed
for the next certificate. Its runtime diagnostic reported validator authority,
committee membership and no remaining join floor. The listener and separate
catch-up/validator WAL assertions passed. These are local ARM64 release results,
not evidence for the other required platforms.

SDK contextual HTTP simulation now also checks reservation release after composition,
HTTP, and JSON failures, and after success, without settling or broadcasting funds.
All five focused runtime/type tests pass. A new bounded same-outpoint replacement
case near activation compiles in the managed library, but is newer than the binary
above and has not yet run. Its intended assertions cover original transaction
removal, replayed migration, P2 replacement execution, one canonical charge, and
reopen agreement. The remaining acceptance and final review/CI gates still apply.

### K10/K11 integrated candidate and final committee case

Candidate `81ac06f6db1a717bd21006a49558cb349ffc10a9` was reviewed against
merge base `d671fb8294fe5358e5ad7c5ac900f0f5204b971c` by the lead and the
single independent reviewer `/root/k2b_system_review`. The reviewer found no
material source regression, covering discovery consistency, selected simulation,
rollback, legacy/SDK compatibility and funding cleanup, runtime observation,
P3 registration, migration/replacement accounting, quorum loss and linker bindings.
The reviewer explicitly accepted the bounded composed successor-support fixture;
its final implementation required focused follow-up. Remote freshness and final
platform CI were not established by that source review.

The validation binary SHA256
`aac9826a1c5f3ce11a58ad64d1f41fbd0c5575ea6be5f83b512d94856cbeef98`
passed the linked build/native audit and actual linker recording. Its recovery
suite passed the new same-outpoint replacement case and existing crash/replay
cases. Its join scenario passed an explicit stall without quorum, followed by
promotion and the joining validator's required vote. Logs are retained under
`.build-cache/client-acceptance-validation-runtime/`. Fifty-one focused Python
controls passed, including actual GCC/Clang links with search/selection flags,
response files, failure cases and evidence binding. Five SDK runtime/type tests
cover funding cleanup without settlement/broadcast on all tested outcomes.

The final added support fixture uses real old authority weights 200/100/100 and
a valid 300/400 certificate, then a paid exit of the 200-power member whose delay
expires in H's old lifecycle. The next committee is nonempty, with two 100-power
members. Its real certificate verifier rejects the single-supporter certificate
and accepts both signatures; reopen preserves exact state, committee and frontier.
The missing support of one member is an explicit scenario assumption, combined
with separate actual unknown-target refusal coverage. No live mixed-binary
network or Bitcoin mempool/RBF policy qualification is claimed.

This fixture and shared-helper refactor compile in the managed release library.
All 34 focused evidence/comparison tests pass. The complete linked release build
then passed with installed binary SHA256
`98dde2b70d8442a7a0262e2d0e7a699c9ce159c2f1ea9c6a4d66a03862c46afa`.
The full recovery command and evidence verifier passed against this binary,
including the new committee case and all prior recovery cases. Raw recovery
stdout SHA256 is
`6549bb2d558df51a7315be501a941e9be8d35c6d1cec806a41a179ff2d1e37b0`;
stderr is empty. Build and runtime evidence are retained in
`.build-cache/client-acceptance-final-linked/` and
`.build-cache/client-acceptance-final-runtime/`. These local ARM64 release
results do not replace required current-head cross-platform CI.

Lead follow-up traced the refactored fixture's default single-key behavior,
old/new certificate authority at decisions 14/15, paid lifecycle exit, unchanged
frontier after verification-only probes, and exact reopen comparison. The full
recovery run exercises the previous callers of the shared helpers as well as the
new case. Frozen P1, production protocol authorization, gas rules and engine
ownership behavior are unchanged by this fixture. Final reviewer follow-up,
full controls, documentation/Site review and current-head CI remain pending.

The same independent reviewer approved follow-up
`81ac06f6db1a717bd21006a49558cb349ffc10a9` through
`46bce9c954ab6b7ef41c5d9e36b64e64b873eab3`, with no material findings.
They verified the recovery stdout hash, empty stderr, binary/build-record binding
and semantic verification of the saved result without duplicating runtime runs.
They confirmed the fixture closes the agreed gap and preserves shared-helper
verification. Their documentation correction was limited to stale pending-test
wording in the unpublished Site draft; that wording is updated. All 186
protocol-bundle build/evidence controls and workspace formatting checks pass.
The default branch was reverified at the unchanged PR623 merge before PR
preparation. Current-head CI/platform qualification and merge remain outstanding.

## K10/K11 PR624: macOS post-link provenance correction

Candidate `7c952b3aaa7ad894177933696da56876748dd01e` passed ordinary
Linux/macOS, SDK, reproducibility, stack qualification and Linux linked-node
qualification. Run `41558120201`, macOS job `125662809467`, failed after
compilation and before runtime qualification because the linker output hash did
not equal Cargo's finished executable. The link-spec hash and compiler binding
to the linker record agreed. The invocation requested `-C strip=debuginfo`.
Rust 1.99.1's `rustc_codegen_ssa/src/back/link.rs` runs `rust-objcopy --strip-debug`
after linking on Darwin, so equality across those stages was an invalid assumption.

The correction retains the immediate linker record and captures the same output
path after successful rustc completion in the compiler-object record. The builder
and comparator require the completed output hash to equal the final executable,
while retaining the spec and linker-record bindings. Failed compiler invocations
remove stale success records. A small real Rust compilation with debug stripping
runs before full platform builds; negative controls reject missing capture,
changed output, wrong paths, stale specs and broken compiler/linker bindings.
No runtime semantics or retained P1 sources change. The managed build reference
is regenerated because the compiler wrapper is a tracked build input.

The failed macOS run is not qualification evidence, and the prior Linux/runtime
results retain their original source bindings. The corrected build needs its
focused review and current-candidate CI before merge. No blind CI rerun was made.

The lead and existing single independent reviewer approved correction
`3842cf9cd69708cf5c5667e934fa8d779822115e` against `7c952b3a`, with no material
findings. All 190 build/evidence controls passed locally in 16.8 seconds with
`CCACHE_DISABLE=1`, including the real Rust wrapper test. The regenerated managed
definition verifies. This is compiler/build provenance, not an independent trace
of every post-link transformation. Current-candidate Darwin build/runtime evidence
remains required. The SDK was rebuilt and its packed consumer checks passed for
bundler, Node16 and React Native resolution; publication remains deferred.
