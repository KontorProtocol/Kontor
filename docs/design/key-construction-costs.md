# Temporary buffers in paths and covering projections

Investigated on 2026-09-10 at main
`6a64d4653b5c9015d9274dea0852a5a9cd3204f7`. This follows the numeric-codec
microbenchmark and tests whether a simpler buffer implementation helps actual
contract operations. Production sources and binaries were restored after
building the experimental executable. The direct-to-destination cleanup is now
included on `feat/key-range-queries`; the measurements below isolate that cleanup
and do not measure the broader query changes.

## Prototype

Two existing sites encode into a temporary allocation and immediately copy it:

- `KeyPath::push_element` calls `element.encode()`, then copies the result into
  the new path. `push_interned` does the same for a two-byte structural segment.
- The covering projection generator in `core/macros/src/index_decl.rs` emits
  `projection.extend_from_slice(&field.encode())` for each included field.

The prototype calls `encode_to` directly on the destination buffer. For interned
segments it calls the existing `encode_dict` function. Path boundary offsets are
still updated after each complete element. There are no new APIs, codec changes,
index-layout changes or altered storage-call sequences. The numeric encoder
itself is unchanged. The source diff is nine added lines and three removed lines.

This deliberately leaves ownership unchanged: an appended `KeyPath` still clones
its existing byte vector and boundary-offset vector, and those destination
vectors may grow. It only removes scratch encodings that are immediately copied
and discarded. An ownership/builder redesign would be a separate experiment.

## Allocation evidence

A separate native counting-allocator executable measured the following shapes:

| Work | Before allocations / reallocations | Prototype allocations / reallocations |
| --- | --- | --- |
| Append membership `(agreement_id, node_id)` and a field to an existing map path | 6 / 6 | 4 / 6 |
| Encode the six included active-challenge projection fields | 7 / 8 | 1 / 4 |

The challenge fields were an agreement ID, creation height, challenge count,
32-byte seed, prover ID and deadline. The allocation probe used a zero-filled
seed, exercising byte escaping. Exact growth counts depend on contents and
capacity; removal of the per-field temporary buffers does not.

The probe checked identical output bytes and path segment boundaries. Allocator
instrumentation was not enabled during full-contract timings.

## Full-contract comparison

Both executables use the existing ignored
`reward_costs_across_membership_and_file_counts` test. The baseline embeds the
committed native binaries; the candidate embeds native contracts rebuilt with
the pinned build image using the prototype. Test-contract fixtures are unchanged.
The runtime also uses its respective path implementation.

Five full runs per executable alternate baseline/candidate order, sequentially
with no concurrent build. Every run covers the same six population shapes:
3/9/32/128 members with one file, plus three members with 16/64 files. Every
scenario checks payout equality, membership removal and completion of bounded
exhaustion cleanup. Fixture setup warms contract execution before measured calls.
Random signer keys are regenerated between runs, following the existing harness.

The table below records medians; cleanup sums all calls required to finish a job
within a run. Timing includes host instrumentation and ordinary fee handling.
This is local evidence, not a production throughput result or a formal
statistical significance test.

| Members | Files | Operation | Baseline median (ms) | Prototype median (ms) | Change |
| ---: | ---: | --- | ---: | ---: | ---: |
| 3 | 1 | claim | 7.171 | 7.192 | +0.29% |
| 128 | 1 | claim | 7.204 | 7.214 | +0.14% |
| 128 | 1 | leave | 149.455 | 149.018 | -0.29% |
| 128 | 1 | join | 158.348 | 157.644 | -0.44% |
| 128 | 1 | cleanup | 397.292 | 397.216 | -0.02% |
| 3 | 64 | cleanup | 510.655 | 509.958 | -0.14% |

All ten runs passed (60 scenarios, 540 measurement rows). Each paired row had
identical host-operation counts, including storage reads/writes and cursor calls.
The displayed timing changes are all under 0.5%, have mixed signs, and the
baseline/prototype ranges overlap for every displayed operation. These results
do not establish a meaningful end-to-end performance improvement.

The reward workload is a good check of frequent path construction. It does not
isolate a projection-heavy listing or challenge-creation workload: in particular,
challenge creation is fixture setup rather than a timed operation. The challenge
projection allocation result therefore establishes reduced allocation work, not
a measured end-to-end speedup for that endpoint.

## Recommendation

Treat direct encoding into the destination as a small allocation cleanup, not a
demonstrated reward-performance improvement. It uses less machinery and may be
reasonable alongside future path/query work, but does not justify delaying query
changes that eliminate scans and point reads. Do not expand this into a buffer
pool, custom allocator or new path-builder framework without a measured need.

The prior standalone numeric-encoder speedup also remains a microbenchmark
result; this investigation neither implements it nor establishes its overall
contract benefit.

## Validation and retained evidence

The candidate passed the five existing KeyPath tests and the allocation probe's
byte/boundary parity checks. Full reward-run outcomes and host-operation counts
are recorded with the final results above. This is experimental coverage, not
merge validation: generated macro snapshots, broader index/rollback tests and
both rebuilt contract sets would be needed before shipping the prototype.

Source before/after copies, native contract binaries, separate executables,
allocation probe, logs and the summary script are retained locally in
`/tmp/kontor-path-probe/`. The experimental executables are local evidence; current branch validation is
documented separately in the query work.
