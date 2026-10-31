# S2 admission classification clarification, v1

Proposed 2026-10-28. This supplements frozen S2 proposal v7 and its gate
amendment. It requires coordinator and independent reviewer agreement before
implementation. It changes no numerical limit, guest capability, lifting charge,
Store ownership rule, or activation policy.

## Deterministic depth and physical capacity

The consensus-visible depth limit is `MAX_LIVE_INVOCATIONS = 64`, root included.
The immutable parent invocation depth alone determines whether the attempted
child exceeds that limit. Reject such an attempt with the existing deterministic
`InvocationLimitReached` outcome and unchanged inherited fuel, before Store
allocation or target/expression/cycle preparation.

The shared physical Store count is a resource-safety guard. It must never exceed
64, and reservation must still precede allocation. If the parent depth is below
64 but a reservation cannot be acquired because physical capacity is exhausted,
return a distinct infrastructure failure (`NonDeterministic`). Do not manufacture
a deterministic transaction rejection or receipt from physical capacity. The
existing fatal infrastructure path must prevent committing a partial result.
This includes the reservation fallback in `make_store`; an early check alone is
insufficient if the fallback uses the deterministic depth-error type.

The prior v7 instruction that either depth or physical count directly produces
the deterministic limit outcome is superseded. Although admitted sequential,
non-cancelled execution should have matching physical count and path depth,
that invariant cannot justify turning a scheduler-sensitive safety check into a
consensus result. Cancellation ownership remains a separate prerequisite.

## Lifetime and invariant checks

Keep the existing unique lease in the Store owner wrapper. Drop the complete
Store before releasing capacity, including setup failure, spawned execution,
queued results, and detached execution. An impossible lease underflow must fail
in release builds as well as debug builds; do not silently wrap the count.

In non-cancelled execution, test that the live count equals the parent depth at
each admission, and equals the new depth after reservation. Include sequential
sibling calls in a loop, a nested failure followed by another call, and suspension
inside host I/O. These are assertions about those paths, not permission to release
leases early or make detached tasks disappear from the physical count.

## Required regression evidence

- Exact 63/64-Store success and deterministic 65-Store rejection, with unchanged
  expected fuel, receipt classification, rollback and reuse behavior.
- Depth below the limit with artificially exhausted physical capacity produces
  an infrastructure failure, allocates no Store, and cannot commit a receipt.
- The fallback reservation failure has the same infrastructure classification.
- At the depth limit, the deterministic depth rejection retains its specified
  precedence over malformed expression, invalid target and cycle checks.
- Store-before-lease teardown remains covered, including unobserved results.

Record the exact implementing commit and obtain follow-up lead, subagent and
Interlink review. This clarification does not waive six-cell qualification,
resource margins, the declared performance gate, or the remaining v7 fixtures.
