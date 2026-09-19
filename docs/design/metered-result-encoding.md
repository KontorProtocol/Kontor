# Metered contract result encoding

Contract results used to cross Wasmtime's component boundary as a recursively
allocated Rust `Val` tree. Kontor then charged for visiting and formatting that
tree. Those charges bounded the formatter, but came after the engine had already
lifted and copied the original result. In particular, repeated pointers could
amplify a small guest allocation into a large host result.

This change encodes ordinary results in metered Wasm before they cross that
boundary. It applies to views, procedures, nested calls, and fallback exports.
It does not change published contract bytes, stored WIT, SDK signatures, or the
WAVE representation of results. It changes execution fuel and therefore requires
all nodes to upgrade together.

## Execution path

```text
Published core module + original WIT
                 |
       existing component assembly
                 |
       node prepares execution component
       (compiled and cached per contract)
                 |
       private entry calls original export
                 |
    WIT-generated walker reads contract memory
                 |
    shared Wasm formatter owns its own output memory
                 |
    host sink: charge bytes, then validate/copy UTF-8
                 |
    finish guest execution and canonical post-return
                 |
    settle fixed completion charge, then commit/return
```

The node compiles one pinned formatter module per engine and supplies it through
private linker imports. Each invocation gets an isolated formatter instance.
Generated walkers use `wit-parser`'s canonical sizes, alignments, and flattening
rules. Scalars and structured values use the same formatter. Walkers are generated
once during preparation, not during each result traversal.

The formatter is a small Rust core module, not another component. Preparation
rewrites its two source-read imports into Wasm memory loads and `memory.size`
instructions. Multi-memory keeps its allocator, stack, output buffer, and Unicode
tables separate from the contract's memory. No original complex result is lifted
into a host value tree or transferred to another component.

The host receives `WasmList<u8>`, which exposes a checked slice without eagerly
allocating a Rust vector. It reserves the copy charge before copying or validating
the final UTF-8 bytes. Published modules cannot import the private formatter or
output sink: publication validates their imports against the original restricted
linkers before adding those capabilities. User calls cannot name private entries.

## Async results and cleanup

For synchronous exports, a wrapper encodes the raw canonical result. Its canonical
post-return calls the original cleanup function with the saved raw result. Cleanup
retains Wasmtime's restrictions on calling host functions.

For asynchronous exports, preparation redirects `canon task.return` bindings
through a forwarding table. The handler encodes the original result before the
guest can release its memory, then completes a unit-valued private task. Results
with up to 16 flat values are materialized into a small canonical header in private
scratch memory. List and string payloads still refer directly to contract memory;
indirect results are traversed there directly.

Erasing a result type must not erase validation. An interned structural type ID
checks that the task returns the active entry's declared type. The unit task keeps
the original memory and string-encoding options so Wasmtime continues checking
those identities. Duplicate delivery fails. A trap after delivery still follows
ordinary failed-call handling; staged output is not a committed result.

## Accounting

| Work | Charge |
| --- | --- |
| Original contract execution | Wasmtime instruction fuel |
| Result validation, traversal, formatting, and buffer growth | Same Wasmtime fuel counter |
| Copy and UTF-8 validation of final bytes in the host | `ResultCopyBytes`, currently 1 fuel per byte |
| Successful call completion after post-return | Existing `Result`, 200 fuel |
| Host-owned address returned by `init` | Existing bounded host formatter, explicitly named `InitResultBytes` |

Ordinary results no longer pay the old `WaveValue` traversal or 10-fuel-per-byte
host formatting charge. Input parsing still uses `WaveValue`. The copy tariff is
provisional pending the wider calibration work; it pays for distinct host work,
not for formatting a second time.

The completion charge stays after Wasmtime finishes execution. Wasmtime can defer
a fuel check past its last basic block, so moving every host charge earlier would
allow a call just below its measured budget to succeed. Exact-budget tests cover
this settlement point, nested calls, rollback, deposit release, and payment burns.

`init` returns an owned host `Contract` resource rather than guest data. Its
address projection stays in the host, where its resource is consumed and its
bounded formatting is charged. The former general host result traversal and
fallback formatter have been removed.

## Compatibility and scope

Preparation targets the components produced by Kontor's existing core-module
assembler and supported contract WIT types. It preserves the original imports,
parameter types, callbacks, and cleanup. Public metadata comes from the original
stored component; prepared exports exist only for execution. Prepared byte size
is included in the compiled-component cache weight.

Bounds, alignment, UTF-8/UTF-16, discriminants, inactive variant payloads, and the
64-level active-value depth limit are checked in metered Wasm. Preparation has a
separate defensive type-generation depth limit of 256 and a 65,536-unit schema
budget, counting type nodes, fields/cases, and label bytes across exports. The
preflight runs before code generation, preventing a shared wide type from being
multiplied across arbitrarily many exports. Floats, resources in user
result data, tuples, flags, and experimental component features remain outside the
supported contract interface. Enabling additional WIT types or canonical ABI
features requires extending these walkers and their conformance tests.

This change does not move argument conversion or arbitrary host-import conversion
into Wasm. Existing host-operation charges and Wasmtime allocation allowances
still apply at those boundaries. It also does not pool mutable instances or change
how result persistence is charged.

## Build and validation

`./tools/kontor build encoder` rebuilds the checked-in formatter with the repository's
pinned container and `wasm-opt`. The default build and CI reproducibility check now
include this target. No C compiler, external WAT editing, or Wasmtime patch is
required. Host-side preparation uses versioned Rust parsing/encoding libraries.

The encoder's component tests compare results against Wasmtime's original typed
lifting and WAVE formatting. They cover scalars, Unicode, alternate string
encodings, nested records/lists/options/variants, flat and indirect async results,
malformed memory, inactive payloads, cleanup restrictions, and exhaustion before
output delivery. Runtime tests exercise native contracts, nested calls, profiling,
exact budgets, resource release, and rollback.

Manual performance reproduction:

```sh
cargo test --release --manifest-path core/Cargo.toml -p result-encoder \
  --test component production_encoder_performance -- --ignored --nocapture
```

The benchmark includes fresh invocation setup as well as repeated calls to one
instance. Compilation is excluded. Its old CPU baseline uses ordinary lifting and
WAVE formatting without the former per-node fuel bookkeeping, so it is a
conservative baseline for the previous production path. Old fuel estimates add
the former structural and byte tariffs. Timing is diagnostic, never a CI assertion.

A local Linux ARM64 release run on 2026-09-18 measured these median fresh-call
costs over 31 iterations. These synthetic fixtures isolate the result path; they
are not whole-transaction throughput estimates.

| Result | Old CPU | New CPU | Old fuel estimate | New measured fuel |
| --- | ---: | ---: | ---: | ---: |
| Scalar `42` | 6.3 us | 21.7 us | 272 | 5,379 |
| 128-entry page, 3.9 KB output | 44 us | 58 us | 66,852 | 238,425 |
| 4,096-entry page, 129 KB output | 0.95 ms | 1.08 ms | 2,171,740 | 7,446,797 |
| Async 4,096-entry page | 0.96 ms | 1.09 ms | 2,171,755 | 7,447,251 |
| 1 MiB ASCII string | 8.5 ms | 11.0 ms | 11,534,616 | 85,896,783 |
| Escaped Unicode string, 16 KB output | 173 us | 206 us | 176,408 | 3,014,524 |

The formatter's Wasm is about 25 KB and is supplied once by the node. These
fixtures add approximately 1.2–3.7 KB of generated glue to prepared components;
published contracts gain no bytes. Fresh calls have an extra memory/instance setup
cost. CPU and fuel ratios differ because the previous tariffs did not count the
same work as Wasmtime's instruction meter. The new figures are not a claim that
these prices are calibrated. Large outputs consume materially more of today's
fuel limit, even after removing the overlapping formatting tariffs.
