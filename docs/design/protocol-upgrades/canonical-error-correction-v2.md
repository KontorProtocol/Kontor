# Canonical guest error correction, phase CE1, v2

Status: proposed exact revision, 2026-10-28. Supersedes v1 after exact lead
and independent reviewer agreement. Separate corrective PR on main before
S2. The expanded scope covers three proven published guest resource faults.

## Evidence and resulting behavior

Main baseline is `13b0d814f7a085d8b84ec88a87ad2682386f2934`, pinned Wasmtime
`bfdee9ba`; S2 uses `.2` at `0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7`.
Controlled tests preserve the error-test core module's WIT and function
signature while changing a function body, then publish through
`Runtime::publish`. On main, these guest actions return `NonDeterministic`:

1. Returning without releasing the borrowed context handle.
2. Dropping that handle twice.
3. Passing the view-context handle to the proc-context resource drop import.

Durable baseline evidence:
`native-stack-class-audit/.build-cache/canonical-error-audit/s1-diagnostics.log`
records all three diagnostic tests passing against the faulty behavior. The
lead has read the log and diagnostic source. Those diagnostic assertions are
not the final regression tests: final tests must require the exact corrected
behavior and complete fee/state effects. Leaked-borrow reachability was also
reproduced on S2; all three need final coverage on both engine pins.

These guest faults must become deterministic failures. Views produce no
receipt; paid roots produce the pinned failed status and ordinary fee
settlement; nested propagation rolls back child/parent effects as specified
by existing call semantics. The plain errors are not automatically Wasmtime
traps. Pin actual `Other` receipt behavior and exact class through the whole
call path. Genuine infrastructure and identically worded host errors remain
infrastructure failures.

## Exact adapter change

Extend `core/indexer/src/runtime/call/error.rs` behind its existing error
origin checks. Preserve explicit `ExecutionError`, allocation failure,
guest-memory and typed-trap precedence, then the boxed-anyhow host marker
before text comparison. Do not invert the unknown-error default.

Recognize only these pinned root-cause formats:

- Exact `borrow handles still remain at the end of the call`.
- `unknown handle index {index}`, with canonical decimal `u32` index.
- `handle index {index} used with the wrong type, expected {expected} but
  found {found}`, on one line, with canonical decimal `u32` index and only
  the demonstrated `(expected, found)` pair:
  `(guest-defined resource, a different guest-defined resource)`.

The formatter also has host/guest mismatch branches. Their source presence
does not prove that a published guest can reach them: host and guest handles
route to different tables. Keep those unproven pairs outside the classifier
until a real guest reproduction and origin trace justify a scope amendment.

For formatted messages, parse the complete fixed grammar and reconstruct the
whole string for equality. Reject noncanonical numbers, overflow, unexpected
literals, extra whitespace, suffixes or prefixes. Never match a bare `wrong
type`, substring, or unrestricted prefix. The source is the pinned
`vm/component/resources.rs` `validate_scope_exit`, `TypedResource::rep`,
`TypedResourceIndex::desc` and `ResourceTypeMismatch::fmt`, plus
`vm/component/handle_table.rs::get_mut`. Verify the same source formats on
both engine revisions. Update the stale version-specific classifier comment
to explain the actual pinned-engine maintenance contract.

This preserves the established origin-guarded adapter. No fork or dependency
change, historical lockfile mutation, broad engine-error suppression or new
production diagnostic toggle is part of CE1. A typed engine API can be
considered independently, but is not required for these narrow corrections.

## Acceptance and review

For each of the three faults, require:

1. A real published contract, not synthetic admitted-cache injection, tested
   as an unpaid view, funded paid root, and a nested chain with two foreign
   call edges. Pin the exact error form and corrected deterministic class.
2. Actual receipt count/status/attribution, payer/burner/floor accounting,
   gas charged, rollback of writes made before failure, and successful reuse
   by a following valid call. Distinguish resource-table destruction from
   unrelated outer-runtime table counts.
3. An actual generated host binding that returns the identical message via
   its ordinary anyhow wrapping. This control stays `NonDeterministic`, with
   no deterministic-failure receipt or accidental success settlement.
4. Focused parser negative controls for noncanonical decimal, overflow,
   wrong type literals, unapproved host/guest pairs and trailing/prefixed text.
   Preserve existing allocation and explicit host-error precedence checks.
5. Runtime regression coverage on main's `bfdee9ba` and S2's `.2`. Record
   engine/source/compiler/fixture hashes and durable raw logs. Repeated
   observations must be stable within each engine; do not require equal
   fuel across engines without evidence.

Continue the bounded audit of other resource and canonical-ABI failures,
including pointer/encoding/discriminant validation, bad realloc results,
borrow/own misuse and leave/reentry checks. Record which are already covered,
which have demonstrated reachability and which remain source-only concerns.
Any additional proven defect requires an exact scope amendment and real
regression, not a source-string-only rule. Known unresolved material faults
block S2 merge even if handled by another corrective PR.

The Daybreak-enabled agent implements CE1 in an isolated branch from fresh
main and reports to the lead. Preserve S2 experiments and diagnostic source;
do not include their unrelated changes in this PR. Retain the one local
Cargo operation limit, at most two jobs, until explicitly transferred.
All production changes and tests receive lead, independent subagent and
Interlink review. After addressing reviews, create the PR, fix required CI,
merge the exact green reviewed head and verify the merge tree.

S2 then integrates the merged correction and reruns affected qualification.
Its remaining callback, six-cell, memory, workload and ownership gates remain
required. CE1 alone does not require a six-hour stack matrix. No chain state
deletion or network activation is authorized. The full protocol-upgrade
system remains the goal after these prerequisite fixes.
