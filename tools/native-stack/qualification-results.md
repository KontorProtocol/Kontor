# Native Wasm stack qualification, original P1 call ownership

Run [40607427518](https://github.com/KontorProtocol/Kontor/actions/runs/40607427518)
measured branch head `d6e1b2606de155bf45224d2c316aa3f5249379e0`, based on main
`ca0e6a768a841a8dfee8a3f8cc3565f4570af97b`. All six Linux x86-64,
Linux ARM64, and macOS ARM64 development and release measurement jobs passed.
The strict comparison job failed as designed because outcomes differ. This is
qualification evidence for the original detached `call_guest` behavior. A later
owned-future prototype changed nested host stack use and needs a fresh matrix.

Every cell used compressed component SHA-256
`f4adbfc04072fa65184e6cb766c7d38d8b3779a34e5ef47779c5207289440ee8`
and reported `max_wasm_stack = 524288` and `async_stack_size = 2097152`.
The pinned Wasmtime fork revision was
`bfdee9ba9a483915dc95432708cf7db8281adbc1`. The table gives the last
successful depth and first `StackOverflow` depth for paid calls. Public view,
system view, and Core calls showed the same wide-frame boundary in each cell.

| Runner | Profile | Plain success / failure | Wide success / failure |
| --- | --- | ---: | ---: |
| macOS ARM64 | dev | 10903 / 10904 | 1720 / 1721 |
| macOS ARM64 | release | 10916 / 10917 | 1722 / 1723 |
| Linux ARM64 | dev | 10903 / 10904 | 1720 / 1721 |
| Linux ARM64 | release | 10912 / 10913 | 1722 / 1723 |
| Linux x86-64 | dev | 10906 / 10907 | 1721 / 1722 |
| Linux x86-64 | release | 10914 / 10915 | 1722 / 1723 |

At paid plain depth 10916, macOS ARM64 release succeeds while both Linux
release cells trap. At paid wide depth 1722, the release cells succeed and
the dev cells trap. A trap rolls back the marker and records a `Trap` receipt
for paid calls. The 256-value fixed frame and distinct-contract re-entry at
depth 32 succeeded in all six cells. Those bounded successes do not establish
a universal safe frame or re-entry limit. The binary search uses one sample
per depth and assumes monotonicity; the per-cell JSON and raw logs preserve
the actual observations.

All seven downloaded CI artifacts, including 793 report and raw-log files,
are retained locally under `.build-cache/native-stack-ci-evidence/`. Their
verified `SHA256SUMS` manifest has SHA-256
`796dc804d68b13ec6c6558907614518dffbba0895d9fdc51a77a3b15d0b7c7f3`.
The strict comparison JSON has SHA-256
`99c8f8c785287975a6f86fb4d46e6ddfd7001008b1b6ed73057c377dbd56487a`.
GitHub retains the uploaded artifacts for 30 days.

## Pulley interpreter qualification on the same guest WIT

Run [40624624979](https://github.com/KontorProtocol/Kontor/actions/runs/40624624979)
measured investigation branch head
`f1f07c0ddf13e3758ac34e04683d3f1eecce8e0f`. All six Linux x86-64,
Linux ARM64, and macOS ARM64 development and release qualification jobs passed.
The strict six-report comparison passed. The Linux ARM64 development runner
also passed the real runtime call suite: 44 passed, 0 failed, 2 ignored.

The diagnostic commit enables Wasmtime's `pulley` feature for the qualification
test and selects `pulley64` only when `KONTOR_STACK_PULLEY` is set in a test
build. It does not change production engine configuration. Every observed
engine target resolved to `pulley64-unknown-unknown-elf`. All reports used the
same compressed component SHA-256 shown above, `max_wasm_stack = 524288`, and
`async_stack_size = 2097152`.

| Runner | Profile | Plain success / failure | Wide success / failure |
| --- | --- | ---: | ---: |
| macOS ARM64 | dev | 8187 / 8188 | 1722 / 1723 |
| macOS ARM64 | release | 8187 / 8188 | 1722 / 1723 |
| Linux ARM64 | dev | 8187 / 8188 | 1722 / 1723 |
| Linux ARM64 | release | 8187 / 8188 | 1722 / 1723 |
| Linux x86-64 | dev | 8187 / 8188 | 1722 / 1723 |
| Linux x86-64 | release | 8187 / 8188 | 1722 / 1723 |

Paid, public view, system view, and Core calls have the same boundaries in
every cell. The strict comparison found identical sampled outcomes, values,
receipts, state rollback markers, and fuel. The fixed 256-value frame and
distinct-contract re-entry to depth 32 succeeded in all six cells. A separate
local Linux ARM64 development probe completed re-entry to depth 64, returning
64 with an `Ok` receipt and 64 child markers. On that same host and test
binary, paid wide recursion at depth 1024 returned the same value, receipt
gas, and user fuel under native code and Pulley. Its complete publish-and-call
test took 15.39 seconds with native code and 19.72 seconds with Pulley. This
single timing sample does not establish a production performance ratio.

The Pulley interpreter uses a virtual Wasm stack with an explicit bounds
check, so the demonstrated guest stack trap does not depend on native machine
frame size. The current 512 KiB setting gives less plain recursion headroom
under Pulley than under the native compiler. Raising `max_wasm_stack` would
require a separate capacity and host stack budget decision. The qualification
kept the existing spawned guest-call path; Pulley alone does not address Rust
future recursion from the separate direct-await prototype.

All seven downloaded Pulley CI artifacts and the locally rerun comparison
are retained under `.build-cache/pulley-ci-evidence/`. The verified
`SHA256SUMS` manifest has SHA-256
`94dc5ef3cb1925141f8600d3b6c8a360220cee1d234c5883ef240b425855962f`.
The uploaded six-runner comparison JSON has SHA-256
`dd0b303ef6e5f7b2c51e89362b3534e557fc7dd8428e42c341784e582fece701`.
Local smoke, re-entry, and same-host native/Pulley logs are retained under
`.build-cache/pulley-local-evidence/`.

This run used the current guest WIT, whose stack-probe exports are async.
Removing async from guest WIT changes the generated contract and its frame
layout. Rebuild the probe and repeat stack boundaries, real-call smoke, and
the six-runner comparison after that change. The current result establishes
Pulley as a viable cross-node guest-stack approach for this tested fixture,
not the final protocol configuration.
