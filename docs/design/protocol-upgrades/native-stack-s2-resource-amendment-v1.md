# S2 resource qualification amendment v1

Status: proposed, 2026-10-28. Requires explicit lead and independent reviewer
agreement on this revision before implementation. This changes the native
stack measurement method in S2 proposal v7, not the invocation cap, production
stack sizes, guest semantics, six-cell requirement, or merge gates.

## Claim and replacement

Replace v7's requirement to measure exact native fiber and OS-thread stack
high-water with a paired, finite-workload experiment at production and reduced
native stack capacities. The accepted claim would be: the declared workloads
completed with half-sized native stack allocations in all six cells, with
identical execution observations. This is not an exact peak-use measurement or
a proof that every admitted contract fits half the production stack.

The ordinary production engine remains on immutable Wasmtime `.2`, commit
`0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7`, with 512 KiB logical Pulley stack
and 2 MiB native async fiber. The reduced diagnostic uses 1 MiB native async
fiber and the same 512 KiB Pulley stack. No diagnostic Wasmtime fork, canary
painting, production environment toggle, guest capability change, new gas
rule, or concurrency-policy change is required or authorized here.

## Source argument and limits

The pinned Unix fiber allocator rounds the requested writable size to host
pages, allocates a separate inaccessible guard page, and excludes that page
from `FiberStack::range` (`crates/fiber/src/unix.rs`, `FiberStack::new` and
`MmapFiberStack::new`). The normal on-demand allocator passes the configured
size to it. Fixed switch records consume some of the writable region; 1 MiB
does not mean 1 MiB exclusively available to host callbacks. Custom stack
allocators and sanitizer-specific allocation paths are outside this
experiment and must not silently enter a cell.

Pulley allocates its logical VM stack separately in
`crates/wasmtime/src/runtime/vm/interpreter.rs`. Each child invocation keeps
the existing spawned task and separate Store/fiber; no direct-await recursive
owner is introduced. Store-local fiber caching and destruction remain intact.
The same logical stack limit preserves the guest overflow boundary in the
paired experiment.

Tokio's requested worker stack size can be enlarged by platform requirements
and does not resize the caller of `block_on`. Current-thread tests alone
cannot establish worker coverage. A guard page is also not a complete record
of stack-pointer excursions: an unprobed large adjustment can skip it. Record
compiler/target probing configuration and unresolved native-code limitations.
Do not turn successful finite tests into a universal stack-safety claim.

## Paired execution and evidence

1. Run production and reduced configurations in separate child processes for
   Linux x86-64, Linux ARM64, and macOS ARM64, in dev and release. Pin the
   source, compiler, lockfile, features, artifacts, fixture manifest and
   runtime settings. The only intended engine difference is native fiber
   capacity. Diagnostic selection exists only in test code.
2. Use an explicitly constructed multithread Tokio runtime. Spawn the entire
   measured operation, including preparation, conversions and teardown, onto
   its workers. Request 1 MiB worker stacks in the reduced configuration.
   Record actual usable worker ranges and guard treatment in both runs;
   production usable capacity must be at least twice reduced usable capacity
   for the worker-margin claim. Identify and cover execution on blocking-pool
   threads and the `block_on` caller separately. A requested size or Tokio
   default is not actual-capacity evidence. If the ratio cannot be verified,
   that portion of the gate remains open; do not silently alter production.
3. Attest page size, normal allocator selection, effective fiber capacity,
   actual thread capacities, runtime worker count, and actual measured thread
   categories once per cell/configuration. Keep the production capacity
   assertions in the ordinary qualification. The reduced diagnostic must not
   be mislabeled as a production run.
4. Compare exact results, deterministic error/trap classes, values, fuel,
   receipts, state changes and rollback, reservations and resource cleanup.
   Include fresh Stores, suspension, failure and reuse. A crash, signal,
   timeout, incomplete transcript or semantic mismatch fails the gate. No
   retry converts that attempt into acceptance; investigate and rerun only
   after a recorded correction.
5. Freeze a fixture manifest before measurement: include the existing plain
   and wide Pulley boundaries, large frame, distinct-contract 33/63/64/65
   Store chains, pending host I/O, maximum-gas call, real native Core calls,
   canonical lift/lower and realloc/post-return, generated initialization,
   explicit resource destruction and failure cleanup, SQLite pagination,
   ranges and large values. Include the deepest successful Pulley frame
   calling a host operation. Record hashes and per-case parameters.
6. For type/value recursion, list the actual admitted limits and tested
   shapes. Kontor's WAVE expression depth 64 and string-literal byte limit
   16,384 do not by themselves bound canonical result-type processing.
   Identify legal shapes not covered. Any discovered reachable native stack
   overflow, unsafe stack access, unbounded native recursion, or uncontrolled
   resource growth is a finding requiring resolution, even outside the frozen
   fixture set. It cannot be excluded merely to make this gate pass. Do not
   label finite selected cases the universal worst admitted workload.

## Separate production memory gate

Use uninstrumented production-capacity runs for memory, not reduced-stack
runs or painted stacks. At 64 simultaneously suspended invocation Stores,
record actual live Store/reservation/fiber counts, mapped reservation,
resident memory, and platform-reported committed/private memory with precise
field definitions. Preserve raw OS evidence and both baseline and peak.
Do not call a mapping size resident memory or equate Linux RSS with every
platform's private/committed measurement.

Repeat with eight non-cancelled view roots plus one active reactor root under
the planned reference profiles: conservative 2 CPU / 12 GiB and burst
8 CPU / 16 GiB. The eight-view overlap must remain explicit under the
conservative CPU limit; do not let `available_parallelism` shrink it to two.
Record actual host CPU/OS/storage and resource enforcement separately from
the reference configuration. This is not a claim about live GCP hardware.

Use the source-defined 512 MiB root guest-memory budget and 64-Store cap as
inputs, not as a complete process-memory estimate. Include Pulley allocations,
fiber mappings, host state and resources, compilation/cache and database
memory. Declare the fixture's guest-memory occupancy, cache state and
per-root/per-node allowance before measurement. The separate workload plan
must freeze those allowances and service criteria before this gate closes.

This remains a conditional non-cancelled envelope. Detached tasks are not
freed roots. OWNERSHIP retains cancellation, task drain, storage authority
and global root admission requirements. No S2 resource result waives them.

## Review disposition

Lead source inspection and an independent subagent support the measurement
approach with these limitations. No resource measurements have been made
under this amendment. Independent Interlink agreement and exact-revision
subagent review are pending. All remaining v7 acceptance gates, including
production six-cell equality, actual runtime accounting, finite declared
operational performance and exact-head CI, remain required.
