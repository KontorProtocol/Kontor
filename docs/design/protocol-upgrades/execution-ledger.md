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

All F2/F3 and K1-K11 phases (including K2a/K2b) remain unimplemented. The owner-only dark Site now opens with PLAN-1 and implementation status, with
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
