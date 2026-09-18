# Host metadata accounting

Baseline: main `07118ff5` (#579). Follow-up to
[conversion work accounting](conversion-work-accounting.md).

## Missing work

The contract address accessor clones a variable-length name for a fixed tariff.
Repeated context-to-contract resource creation also reads that name from storage.
Call preparation looks up a supplied name and may include it in an error message;
WAVE expression bytes do not include the target address.

Native file imports have operation charges, but do not consistently charge for
metadata. In particular, malformed roots/seeds/peaks can exceed their valid sizes,
file descriptors contain variable strings and nonces, and proof verification
accepts lists of challenges, accepted roots and registry entries. The proof's
fixed verification tariff does not measure those lists. An invalid first item
does not undo ABI lifting of the remaining arguments.

## Charges

Use the existing Store fuel and optional FuelGauge, with provisional prices:

- `ContractNameBytes(n)`: 10 fuel per UTF-8 byte, before target lookup and name
  copying; after fetching a context's address but before creating its resource.
- `FileMetadata(n)`: 50 fuel per metadata entry plus 10 per variable byte.
  An entry is a file root, frontier peak blob, challenge descriptor plus seed,
  accepted proof root, or proof registry row. Proof challenge entries also
  include their supplied challenge-ID bytes, even though host verification does
  not use that ID.

These supplement existing operation tariffs, which continue to pay for the
hashing/verification operation. Byte counts use string/vector lengths without
walking contents or encoding another representation. Fixed-size numbers belong
in the entry charge. Container lists are charged entry by entry and stop when
fuel is exhausted. Empty entries still cost fuel.

Charge all supplied native metadata before validating it, allocating derived
collections, cloning descriptors, or resolving a proof resource. This ensures an
early validation error cannot skip accounting for later arguments already lifted
by Wasmtime. No generic walk of every import argument or second fuel balance is
introduced.

## Limits

This is accounting at the host-body boundary. Wasmtime has already lifted input
arguments, so it is not a pre-conversion allocation bound. The context-address DB
read also precedes its name-byte charge; charging before resource creation does
not prevent the DB driver's allocation. A type-informed conversion guard remains
separate work.

Proof preparation and cryptographic verification have their existing tariffs plus
metadata units here. This does not establish calibrated prices for Poseidon
hashing, tree shape, registry-map comparisons, or SNARK verification. The native
file interface remains privileged. Names and metadata retain their existing
validation rules; no arbitrary length cap is added.

Top-level preparation failures still precede token escrow/fee settlement. Nested
preparation retains its existing shared fuel balance. Fee-settlement rules, deposit pricing, contract
interfaces, and checked-in contract/SDK components are unchanged. Execution gas
usage increases by the new charges, so tightly budgeted calls may exhaust sooner.

This advances #462 but does not close it or supersede #445.

## Validation

Six regressions failed against the baseline before implementation. Eight focused
host/runtime tests now cover every variable descriptor field, malformed roots
and seeds, UTF-8 byte counts, repeated calls, metadata after an invalid first
entry, exact and one-fuel-short budgets, resource preservation/cleanup, valid
challenge IDs, and equivalent aggregate/frontier roots. The full runtime suite
passes 188 tests (14 manual benchmarks ignored), including native proof settlement,
rollback, nested preparation, fee accounting, and resource lifecycles. Release
Clippy with warnings denied and formatting checks pass.

## Whole-call check

Linux ARM64 release builds, using the unchanged ignored `wave_call_costs` harness
from #579 on main and this implementation. Twelve serial runs, six per version,
in the order main/head/head/main/main/head then head/main/main/head/head/main.
Each run uses seven rotating batches and warmed components; the table gives the
median of the six run medians. All 25 workloads succeeded in every run at their
unchanged default budgets. No builds ran concurrently with measurements.

| Workload | Main latency | New latency | Execution gas, main to new |
| --- | ---: | ---: | ---: |
| Scalar view | 34.59 µs | 32.59 µs | 8 to 8 |
| Storage view through two proxies | 226.37 µs | 228.09 µs | 66 to 66 |
| Token transfer | 747.78 µs | 753.67 µs | 31 to 31 |
| Add stake | 1,353.74 µs | 1,363.63 µs | 287 to 287 |
| Storage write through two proxies | 952.89 µs | 956.57 µs | 63 to 64 |
| SHA-256 with a 64 KiB input | 3,597.69 µs | 3,667.34 µs | 6,561 to 6,561 |

These ordinary-call medians show small timing changes, not a large slowdown.
Across all 25 workloads, the rounded execution-gas difference is zero or one gas.
This suite checks ordinary-call overhead and budget headroom; it does not benchmark
native proof verification or calibrate metadata tariffs.

Bulk balance queries remain noisy. The 512-holder aggregate median rose from
1.93 ms to 2.32 ms, but the individual run medians range from 1.85–2.87 ms on main
and 1.85–2.69 ms on the branch. The 16-holder medians changed in the opposite
direction, from 258 µs to 114 µs, with overlapping ranges. These samples do not
establish either a reliable bulk-query speedup or a slowdown. The changed code on
these calls only adds a single 50-fuel target-name charge, outside the query.

[Full measurements](measurements/host-metadata-costs-2026-09-17.csv) retain the
ranges and exact fuel/gas counts. Fuel includes deposit reservations; execution
gas excludes them. View gas is budget use, not a token fee. Setup/JIT, enclosing
test rollback, networking, Bitcoin confirmation, and final durability are excluded,
as in the [original methodology](conversion-work-accounting.md#whole-call-latency-charges-and-default-limits).
