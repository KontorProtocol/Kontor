# Contract language audit prompted by storage rewards

The initial #554 implementation (`a1836878983bc223447694268abd47c10e8a4fb4`)
exposed gaps in numeric support and opportunities to use existing storage features
more clearly. The follow-up keeps economic policy in contracts and improves
reusable facilities where the contract was implementing representation mechanics.

## Numeric capabilities implemented

- **Consistent Integer range:** parsing, addition, subtraction, multiplication,
  division, and wide multiply/add/divide now share the 256-bit magnitude range.
  The former smaller ceiling belonged to conversion into a Decimal with 18
  fractional digits. Whole-Integer-to-Decimal conversion checks the scaled
  coefficient exactly and rejects overflow; Decimal's range is unchanged.
- **Exact Decimal units:** `Decimal::to_raw_units` and `from_raw_units` preserve the
  signed coefficient without arithmetic, rounding, or an imported host call.
  These are distinct from converting the numeric value to a whole Integer.
  For example, Decimal 1.25 has raw units 1250000000000000000. The TypeScript SDK
  exposes the corresponding `toRawUnits` and `fromRawUnits` methods.
- **Compile-time Integer constants:** `Integer::from_u128` permits exact constants
  without repeated string parsing or calls into the host. The reward scales now
  use it; contract authors need not construct limbs themselves.
- **Wide quotient/remainder arithmetic:** the original PR's shared, metered
  operation retains exact remainders and checks the final result rather than
  rejecting a product that only temporarily exceeds 256 bits. This stays a
  generic numeric capability, with no knowledge of reward accounts.

Reward accounting now uses normal checked Integer addition and subtraction.
Its remaining nonnegative-difference check expresses an accounting invariant,
not a separate arithmetic implementation. Manual limb operations and Decimal
representation conversions have been removed from the economic code.

The range expansion is consensus-visible. The arithmetic implementation is shared
by the runtime and SDK backends, and the browser SDK component is rebuilt with it.
Existing preproduction state must be recreated/replayed with the new contract
layout. This change does not increase Decimal token capacity or validator voting
power limits. The AMM/pool fixtures retain their own conservative amount limits.

## Existing language features used more clearly

Persisted enums already express staged work. The reweight job now uses
`Preparing(preparation)` and `Applied(index)`, so an applied job cannot exist
without an effective index. The enum and its payload remain ordinary versioned
contract state; no new runtime scheduler or independent history is introduced.

Membership cleanup owns forced membership removal and reservation release in
`filestorage/src/cleanup.rs`. Reward accounting owns income and weight changes in
`rewards.rs`. Cleanup exposes an optional weight increase with its effective index; ordinary
reward accounting does not inspect cleanup phases. A single read path settles an
account for both balance queries and mutations. The pure account transition
separates earning from stopped accounts and names the units of every field. Claims
and membership changes compute their final account state before persisting once,
avoiding a settlement write immediately followed by another update. Cleanup uses
generated field setters to update only the phase payload.

Existing sorted indexes and resumable range cursors already provide deterministic
bounded traversal. Existing nested-call savepoints already provide atomic credit
and payout rollback. Neither needs a reward-specific replacement.

## General storage features worth investigating next

Tracing the generated models reveals a more fundamental issue than whole-record
access: **Integer and Decimal are themselves stored as composite records**. Their
`Retrieve` implementations in `core/built-in-types/src/impls/numbers.rs` check
existence and load a generated model. That model reads four u64 limbs and locates
the sign variant. Their derived `Store` writes four limbs and replaces the sign
variant using a matching-path deletion plus a void write.

For a populated numeric value, that is six storage host operations to read and
six to write. Materializing/replacing the four-Integer reward account therefore
expands to 24 such operations in each direction, before container bookkeeping.
Backing database queries can differ because of caching. The contract sees four
ordinary fields; the extra representation work is hidden inside its native types.

The most concrete next language improvement is **native scalar storage for
Integer and Decimal**: one encoded value at one versioned path, handled by shared
type/storage support. Contracts should not pack numbers into byte arrays themselves.
This could benefit token balances, staking and other contracts as well as rewards.
It needs a separate storage change with tests for numeric round trips, generated
indexes, deposits/metering, deletion, and rollback/replay. It changes all stored
numeric layouts, not just this PR's new account records.

After that, bulk-record reads/writes or opt-in packed records could reduce
crossings further when fields are always accessed together. Current generated
`load()` and `Store` visit every field individually. Field setters already avoid
rewriting unrelated fields; complete account transitions instead write their final
state once.

This reward PR retains the existing numeric storage layout. The opt-in
`reward_costs_across_membership_and_file_counts` test measures host calls, host fuel,
and elapsed time for claims, file joins/leaves, and complete cleanup at increasing
membership and file counts. See [measurements](storage-reward-costs.md). Storage
payload/deposit measurements belong with the separate scalar-storage change. A packed record also makes individual field access less
convenient; bulk operations may better support mixed access patterns. Neither
should bypass generated index maintenance, storage deposits, metering, nested-call
rollback, or versioned deletion/replay with opaque contract blobs or native SQL.

The reward reweighting algorithm remains an independent design tradeoff: one job
serializes forced cleanup, and normal joins/leaves update the affected file's
members. Faster storage primitives could reduce that work's cost but do not make
an arbitrary number of entitlement changes constant work. A general numeric or
storage library should not decide when hosts lose eligibility or survivors gain
larger shares.

## Validation

The final full indexer release library run passed 479 tests (one existing ignored
test), including Wasm/native arithmetic parity, eager reward accounting, staged
cleanup, failed payouts, and rollback/reopening. The numeric/type regressions
passed nine tests, native filestorage passed nine, and the SDK main suite passed
73. Token overflow checks passed in both direct and regtest execution; AMM and
pool limit checks also passed. Core indexer/numeric and both contract workspaces
passed Clippy with warnings denied. Pinned contract builds and both SDK bundles
completed.
