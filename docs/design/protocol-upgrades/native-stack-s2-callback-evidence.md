# S2 callback and CE1 integration evidence, 2026-10-28

## Revisions and scope

- S2 branch: `feat/native-stack-s2`, callback test commit
  `a2384d46a3c3b64cf6eabc6d18db80bcaa60e1fd`.
- Integrated main commit: `9bf5e85d566c66ffa9ce1c72a010ca24315a1fd8`,
  tree `f57e1620c62522fa46b02d648d438e88a341bd0f`, merged into S2 by
  `3ac563713a1f90805e85b82afcd0146afc5ab7e8`.
- S2 retains the Wasmtime `=51.0.0-kontor.2` revision
  `0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7`. The two superseded
  uncommitted classifier experiments were saved outside the branch before
  integration. Neither is in these commits.
- Local test host: Linux aarch64, Rust 1.99.1. All commands below used
  `--offline --locked -j2` and the S2 Cargo target directory.

## Focused results

Run from the repository root with:

```sh
CCACHE_DIR=/tmp/kontor-ccache CARGO_TARGET_DIR="$PWD/core/target" \
  cargo test --offline --locked -j2 --manifest-path core/Cargo.toml \
  -p indexer --lib FILTER -- --nocapture
```

Replace `FILTER` with each row below. Logs are in the ignored local
`.build-cache/native-stack-s2/` directory and are identified by SHA-256.

| Filter | Result | Log | SHA-256 |
| --- | --- | --- | --- |
| `hostile_canonical_callbacks_are_framed_and_clean_up` | 1 passed | `integrated-callback-view.log` | `a4262c087c5649c30d0e82e2248c24a81149798ff5bfb182b5cd4249a6dfee94` |
| `paid_post_return_callback_work_charges_fuel_gas_and_burn` | 1 passed | `integrated-callback-paid.log` | `d0e7d20029c4575360b14e01d1ed5512057124f8466a559f34f8c9494ea11db3` |
| `explicit_guest_resource_drop_invokes_host_callback_and_cleans_up` | 1 passed | `integrated-explicit-drop.log` | `83530948ed71a324759121608ea0e3a355f527247e8e179dec7a2cfa18f99336` |
| `paid_hostile_realloc_charges_one_root_receipt_and_preserves_state` | 1 passed | `integrated-paid-realloc.log` | `c8799566670241b9096f504b4ae7eaf144b4a51190bbe435ca7654367116fa6d` |
| `published_` | 5 passed, including all three CE1 published resource faults | `integrated-ce1-published.log` | `5562af2000cc305f499f1932d3f6520259de21ece10b3abf072cb51c4b4b7feb` |

`cargo fmt --manifest-path core/Cargo.toml --all -- --check` and
`git diff --check` passed. The published CE1 fault test printed the same three
patched raw hashes recorded in the CE1 evidence document.

## Invariants exercised

- The successful `run("ok")` control crosses canonical string lowering and
  invokes the same guest `run` body. The 16 KiB realloc case then traps before
  that body enters: its host body-entry counter does not advance, and the
  forbidden realloc host import's counter remains zero.
- Light and heavy exports have the same guest body and same-length names and
  inputs. Their post-return callbacks both reach the same forbidden host
  import and deterministic trap. Only the heavy callback executes a 16,384
  iteration guest loop first. Fuel is stable across repeats, with heavy minus
  light at least 16,384. The paired paid calls also require strictly greater
  receipt gas and actual payer burn for heavy, with one root receipt per call,
  matching burner credit and rollback of the guest marker.
- The lower bound uses the pinned Wasmtime fork's default operator cost:
  `BrIf` costs one fuel, and the Cranelift translation flushes that cost at
  each branch. `Runtime::new_engine` enables fuel without replacing the
  operator cost table. Each loop iteration executes one `BrIf`. This bound
  does not assume equal cost for other Wasm operators.
- The host marker in the shared export body of the post-return fixture, and
  the explicit resource-drop host callback, capture Weak references to their
  actual invocation resource tables. The tests require those tables to be
  released after success or trap. The paid realloc case
  cannot call a host observer during canonical realloc, so it asserts live
  budget zero, empty frame and savepoint stacks, one receipt, and payment
  accounting. The separate invocation-owner teardown test checks that Store
  data drops before its capacity lease, but does not directly observe this
  paid realloc call's table.

These focused local tests do not close S2's six-cell target matrix, realistic
first-party depth and memory envelope, concurrent-root admission, performance
gate, or cross-node qualification. Those remain separate S2 acceptance gates.
