# Conversion allowance platform checks

Wasmtime's hostcall allowance uses native Rust layout sizes for some charges.
Before considering that allowance as a basis for consensus gas, Kontor needs
evidence that the same conversions have the same allowance thresholds on its
supported node platforms.

`runtime::call::tests::conversion_parity` runs against the node's actual
Wasmtime features, shared built-in types, and `Runtime::new_engine()` settings.
The existing Linux x86-64 and macOS ARM64 CI test jobs run it separately and
preserve its output as `conversion-allowance-<OS>-<arch>` artifacts. The full
workspace test run also includes these tests. No extra node build job is added.

The tests pin native layouts and the minimum successful allowances for small
conversions. Each fixture succeeds at the expected allowance and fails with the
allocation-limit error one unit below it. Each trial uses a fresh Store and
instance. Expected values are literals shared by all targets, so changing both
platforms together does not silently establish a new baseline.

Dynamic results are tested through sync and async exports. Typed values also
cross an async host import; an insufficient allowance must prevent host entry.
The checks cover byte lists, strings, options, records, tuples, variants, enums,
flags, nested lists and the tuple shapes used by native file operations. Actual
shared record types used in proof verification have pinned layout expectations.
Returned and imported values are checked as well as allowance errors.

These are dependency characterization tests, not a new fee schedule. Matching
results support evaluating allowance-based charging for the tested versions and
platforms. They do not prove that all conversion work is metered, guarantee
layouts on future compilers, or test the proposed gas-settlement API. The
existing ABI-error tests separately exercise malformed values and deterministic
failure classification.

A mismatch must be investigated before changing the baseline or relying on
allowance consumption for consensus. Compiler and dependency upgrades must
preserve the expectations or explicitly account for their change. Current CI
tracks Rust stable; the constants deliberately remain fixed across updates.

Run locally from `core/`:

```sh
cargo test --locked --release -j2 -p indexer --lib \
  runtime::call::tests::conversion_parity -- --nocapture
```
