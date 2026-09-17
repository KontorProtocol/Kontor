# Contract result encoding budget

Every completed contract call passes through one result encoder before its
savepoint is committed or its remaining fuel is returned to a parent. Procedures,
views, fallback calls, and publication use this boundary. Views consume their
execution budget without creating a transaction fee or persisted result row.

The encoder uses Wasmtime's re-exported WAVE writer and a bounded `fmt::Write`
sink. It does not reimplement WAVE or convert between the project's two WAVE
dependency versions. Fallback moves its already-formatted string through the
same byte budget. Publication projects the returned Contract resource into the
address record and uses the ordinary WAVE path.

## Accounting rule

- Pay 200 fuel before result processing, including calls with no return value.
- Each encoded UTF-8 byte costs 10 fuel, including escaping and punctuation.
- After the base charge, the byte allowance is `remaining_fuel / 10`.
- Reject a write before appending bytes that exceed the allowance. Stop the WAVE
  writer immediately and return typed `Trap::OutOfFuel`.
- On exhaustion, charge the affordable byte prefix. The charge is independent
  of the formatter's write boundaries, including boundaries inside a UTF-8
  character or escape. Fewer than 10 fuel may remain unused.
- Settle the byte charge once after encoding, including failure, rather than
  touching the Store and profiling history on every output fragment.

Successful procedures retain their previous result tariff of `200 + 10 * bytes`.
Views now pay that tariff too. Failed encodings retain the charge for their
affordable prefix, so rollback does not erase execution work. The existing
transaction settlement still refunds storage reservations and unused escrow.
No new persistence tariff is introduced here; result-row persistence remains a
separate procedure-only step whose calibration is future work.

## Boundaries

This bounds emitted output and avoids finishing an unaffordable serialization.
Wasmtime has already lifted the guest result into owned host values. Its earlier
conversion allocation allowance, deterministic ABI error classification, and
conversion/traversal pricing remain separate work. In particular, WAVE can omit
absent optional record fields, so encoded byte counts do not price all traversal.
The bounded sink also does not promise that allocator capacity equals the byte
allowance.

## Validation

Regressions cover exact/insufficient budgets, UTF-8 and escapes, lists, omitted
options, semantic errors, no return value, fallback, and Contract-resource
projection and cleanup. An instrumented WAVE value checks that a large list is
not fully visited after output exhaustion. Contract fixtures exercise nested
views and procedures, profiling parity, rollback, storage floors, fees, and
runtime reuse after failure. The manual `encoding_overhead` test compares the
existing serializer with the bounded sink in release mode.

A local release run on 2026-09-17 measured 1,000 encodings per case:

| Output | Existing writer | Bounded writer |
| --- | ---: | ---: |
| 2-byte integer | 51.6 microseconds | 75.5 microseconds |
| 16,386-byte escaped string | 164.2 milliseconds | 172.1 milliseconds |
| 20,480-byte list | 54.4 milliseconds | 57.0 milliseconds |

The larger cases added about 5% to serialization time; the small case added about
24 nanoseconds per encoding. These are isolated writer measurements on one host,
not end-to-end transaction overhead or a basis for new fuel calibration.
