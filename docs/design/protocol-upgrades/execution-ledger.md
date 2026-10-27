# Protocol upgrade implementation ledger

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
