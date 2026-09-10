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

## Scalar numeric storage

The original #554 layout stored Integer and Decimal as composite records. A read
checked existence, loaded four limbs and located a sign variant; a write stored
four limbs and replaced the sign variant. That meant six storage host operations
in each direction for one number, and 24 for a four-number reward account, before
parent-container bookkeeping. Contracts saw ordinary numeric fields while their
native types performed this representation work.

The separate [scalar-storage change](scalar-numeric-storage.md) replaces that with
one value at one ordinary versioned path, implemented by shared Store/Retrieve
support. Token balances, staking and rewards all benefit. Numeric map keys and
indexes keep their existing encodings. Tests cover full-range values, indexed
setters and covering projections, deposits/metering, deletion, savepoints and
block-height rollback. The layout change requires fresh state/replay with rebuilt
contracts; it is not an in-place migration.

The opt-in `reward_costs_across_membership_and_file_counts` test measures host
calls, host fuel and elapsed time for claims, joins/leaves and complete cleanup.
See [measurements](storage-reward-costs.md) for the comparison and its limits.

## Further storage possibilities

Bulk-record reads/writes or opt-in packed records could reduce crossings further
when fields are always accessed together. Generated `load()` and `Store` still
visit fields individually. Field setters avoid rewriting unrelated fields;
complete account transitions instead write final state once. A packed record
also makes individual field access less convenient, so further work should follow
measurements rather than adding a new framework speculatively. None of these
facilities should bypass generated indexes, deposits, metering or rollback.

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
