# S2 qualification setup reuse, v1

Proposed 2026-10-28. This supplements v7 without reducing its platform matrix,
probe kinds, boundary repeats, accounting checks, or production acceptance gates.
Coordinator and independent reviewer must agree this exact revision before the
harness changes. No production runtime behavior changes are authorized here.

## Evidence and purpose

The isolated paid reentry depth-63 probe took 284,756 ms: setup 33,006 ms,
funding 4 ms, publication 251,311 ms, execution 366 ms and post-call checks 66 ms.
These are local development-build diagnostics, not reference-node performance
qualification. Real publication already populates the compiled component cache.
Repeated fresh processes therefore repeat costly compilation before measuring
the same warm-cache execution behavior.

## Required harness behavior

Use one worker process per probe kind and platform/profile cell. Create the
fixture through real funding, validation, publication, provenance and init once.
Do not clone contract database rows, bypass validation, serialize compiled code,
or substitute a fabricated fixture. Keep the existing real-publication
paid/view/Core 33/63/64/65-Store matrix unchanged.

For each worker observation, create fresh invocation Stores through production
entry points. Wrap the observation in an outer savepoint and roll it back after
collecting its result, state, fuel and receipts. Before continuing, assert a
deterministic persistent-state digest equals the initialized baseline, together
with restored resource count, zero live invocation leases, restored savepoint
stack, balances, collateral floor and token supply. Reset execution-local
accounting consistently. Reset failure fails the whole kind, not just one sample.

For recursion probes, preserve adaptive adjacent-boundary discovery. For reentry,
sample the specified depths 62, 63 and 64 directly, representing 63, 64 and 65
simultaneous Stores. Require three samples at each required boundary, including
one repeat pass in reverse depth order. Keep the bounded large-frame probe.

For every kind in every cell, run one additional fresh-process control that
builds the same real fixture and exercises both discovered boundary depths.
For the bounded large-frame kind, exercise its bounded case. Require identical
execution observations, including fuel, receipts, return values and state, to
the corresponding worker observations. All samples must have distinct evidence
identities, raw logs and digest coverage. Setup sizes and starting state must
match between worker and control, including any unused published contracts.

A worker or control abort, signal, timeout, reset failure or incomplete transcript
fails qualification. Do not retry, resume, omit observations, or replace failures
with previously successful samples. Retain strict six-cell comparison, actual
build/feature provenance, artifact identity and source/lock checks.

Label samples as warm compiled-cache execution with fresh invocation Stores.
Keep setup/publication/execution/post-call timings as separate diagnostics, not
fields required to match across platforms. Cold compilation, cold loading and
chains touching distinct cold contracts remain required performance-envelope
inputs. This amendment does not establish a service-time bound or close the
hardware, workload, native-fiber or memory gates.

## Implementation review

Choose the simplest bounded worker interface after inspecting the existing
Rust test and Python driver. Agree its report schema between implementers before
editing. Add controls for reset failure, missing/duplicate samples, wrong order,
worker failure, fresh-control disagreement and cross-cell mismatch. Record the
new source hashes and measured end-to-end CI duration. Obtain all three review
perspectives on the resulting implementation before merge.
