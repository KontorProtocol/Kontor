# Canonical resource error correction evidence

This correction starts from main `13b0d814f7a085d8b84ec88a87ad2682386f2934`, with Wasmtime fork `bfdee9ba9a483915dc95432708cf7db8281adbc1`. The same regression was run on the S2 integration head, with fork `0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7`. The test compiler was Rust 1.99.1 on `aarch64-unknown-linux-gnu`.

## Exact behavior

`call/error.rs` classifies three guest canonical failures after the existing explicit error, allocation, memory, trap and boxed-anyhow host-origin checks:

| Fault | Pinned Wasmtime source | Accepted root cause |
| --- | --- | --- |
| Borrowed handle retained | `vm/component/resources.rs::validate_scope_exit` | `borrow handles still remain at the end of the call` |
| Double drop or invalid handle | `vm/component/handle_table.rs::get_mut` | `unknown handle index {canonical u32}` |
| Guest resource used with another guest resource type | `vm/component/resources.rs::TypedResource::rep` and `ResourceTypeMismatch::fmt` | `handle index {canonical u32} used with the wrong type, expected guest-defined resource but found a different guest-defined resource` |

Both fork revisions have these source forms. The published view-context and proc-context imports empirically emit the guest/guest mismatch text when a handle is sent to the other context's drop function. The formatter's other host/guest mismatch alternatives remain infrastructure errors. Parsing rejects overflow, signs, leading zeros, changed literals and extra text. A genuine host error with any of the same messages remains an infrastructure error.

## Published regression fixture

Tests start with the checked-in `error_test.wasm.br`, SHA256 `8610f85f6abdd1bdeb0d32c0916cf154493535299d2c4d8fa0e053f0ee2df875`. Its decompressed raw Wasm is SHA256 `b45d937af90aa9d68d19e0908f9862030b24a620a02966cbc73dce170ab471e0`. The fixture changes only existing core function bodies, retains the embedded WIT and signatures, validates the raw module, compresses it, then calls `Runtime::publish`. The two proxy contracts use the checked-in binary, SHA256 `e44ced451f07e33041c6f411cf60cd77ba7cc6661ee0e0d996c7eff2ee84a190`.

Patched raw Wasm hashes are:

| Fault | SHA256 |
| --- | --- |
| Retained borrow | `fcbcafd8403a87c5822169955ad43588e999b79caf9fa0269387299ea0a8c4a3` |
| Double drop | `4f0b571b58636d944dbfe49db4c4493091cdeef1201d38353b073ebc3b424b40` |
| Wrong guest resource type | `9f379c6f3ea56f86d3f66d3c15a582e18c9df35599e821617a593b073ad00796` |

For each fault, the test executes a public view twice with no receipt, then funded direct and two-edge proxy calls twice. The paid calls record one root `Other` receipt with gas, settle the normal execution fee, conserve payer, burner and supply accounting, preserve the collateral floor, and roll back the leaf write made before the fault. A later valid view succeeds. A weak reference obtained at the leaf host callback verifies that the leaf call's resource table is destroyed on guest-fault paid runs. The generated-host spoof path does not capture a table reference. The proxy fixtures only read and forward, so this test does not claim rollback of parent writes or observe every proxy and view Store's table.

The host-spoof control uses a test-only message in `Runtime`. The real generated `built_in::testing::HostWithStore::host_error` implementation returns a plain `anyhow` error, leaving generated bindings to attach the host-origin marker. The published guest calls that import this function remain infrastructure failures with no receipt, payment settlement or stored writes. No production diagnostic toggle is added.

## Validation and remaining work

Implementation commit `dc651e0c1556c7256bbcf508c152e99b64916e28` passed all three published regressions on main's pinned engine, with zero failures in 16.69 seconds. The same correction at S2 integration head `34bfb35cd81ddd188fc918d2f9f0af50381c4295` passed all three published regressions, with zero failures in 81.03 seconds. Fuel, gas and payment repeat observations are compared within each engine, not across the two different engine revisions.

From each worktree root, the focused commands and durable logs were:

| Worktree and check | Command | Result and log |
| --- | --- | --- |
| Main, published faults | `cargo test --offline --locked -j2 --manifest-path core/Cargo.toml -p indexer --lib settles_paid_and_nested_calls -- --nocapture --test-threads=1` | 3/3, `native-stack-ce1/.build-cache/canonical-error-audit/ce1-regression-generated-host.log` |
| S2 integration, published faults | Same command with filter `canonical_guest_errors` | 3/3, `native-stack-ce1-s2/.build-cache/canonical-error-audit/ce1-s2-generated-host.log` |
| Main, classification and origin | `cargo test --offline --locked -j2 --manifest-path core/Cargo.toml -p indexer --lib runtime::call::tests::errors` | 3/3, `ce1-current-errors.log` |
| Main, existing generated host conversion | Same test command with filter `generated_host_errors_cannot_impersonate_conversion_failures` | 1/1, `ce1-existing-generated-host.log` |
| S2 integration, classification and origin | Same test command with filter `runtime::call::tests::errors` | 3/3, `ce1-s2-parser-origin.log` |
| Main, non-test library | `cargo check --offline --locked -j2 --manifest-path core/Cargo.toml -p indexer --lib` | Passed in 24.07 seconds, `ce1-production-check.log` |

The runs set `CCACHE_DIR=/tmp/kontor-ccache` and a shared `CARGO_TARGET_DIR` under `native-stack-s2/core/target`; these paths only affect local build caching. Worktree-local logs are ignored by git, and the test names and pinned hashes above reproduce them.

The existing ABI tests cover UTF8, UTF16, char, discriminants, string and list alignment and bounds, return pointers, bad realloc results and typed traps. S2 callback tests cover forbidden imports from realloc and post-return. Other resource errors, including remove-while-borrowed and borrow/own misuse, remain source-only concerns until publication reachability and origin are proven. The separate S2 callback, six-cell, memory, workload and ownership gates still apply before the full upgrade can merge.
