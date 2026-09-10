# Storage reward accounting

Implementation in #554, using the shared numeric foundation extracted into #556.
This enables scheduled storage
rewards, funded escrow and claims; it does not enable validatorless operation.
The [investigation](storage-rewards-investigation.md) records the policy decisions
and comparisons with other networks.

## Eligibility and payment

An activated file divides its frozen weight equally among its current membership
slots. First activation still requires three hosts. Activation and total storage
weight remain monotonic, including after departures; this work does not add the
older proposal's minimum-replication leave restriction or agreement deactivation.

A host need not validate to earn storage rewards. Positive bonded balances remain
eligible even after a penalty leaves reservations undercollateralized. At the
penalty settlement that exhausts its bond, its prior earnings are settled and
its entire earning weight is removed immediately. Its old membership slots stay
in the divisor, with their shares unminted, until bounded cleanup removes them.
Survivors switch to their increased shares together at that removal boundary.
Existing cleanup blocks top-ups and re-entry until the exhausted account's old
memberships and obligations are cleared.

`claim-rewards()` pays the signer's accrued income across all its files to its
spendable token balance. It is available while serving, after leaving, and during
exhaustion cleanup. Claims do not restore bonded stake, create new issuance, or
forfeit fractions. They pay ordinary transaction gas. `reward-balance(node-id)`
reports the currently claimable amount without changing state.

## Exact accounting

All token amounts below are integers in token atoms (10^-18 KOR). Let `Q = 10^36`
be accumulator precision, and `P = 10^18` the additional weight precision.

For a file with frozen Decimal weight `w` (expressed in its raw 18-place units)
and `N > 0` membership slots, each slot has integer earning weight:

```
p_f = floor(w * P / N)
```

The below-unit split remainder stays unallocated. A host's cached weight `h_i` is
the sum of its slot weights. The global eligible weight `E` sums `h_i` for hosts
outside bond cleanup. Empty files contribute no earning weight. The dilution
denominator `D = Ω_raw * P` includes the existing genesis weight and every file
that has activated; consequently `0 <= E <= D`.

For the block's nominal storage budget `S`, advance a global index:

```
step = floor(S * Q / D)
A += step
```

The discarded index-division fraction stays unminted. A host with cached weight
`h`, snapshot `a`, whole-token-atom credit `c`, and fractional remainder `r` settles
at index `A` as follows:

```
(earned, r_new) = div_rem(h * (A - a) + r, Q)
c += earned
a = A
r = r_new
```

Each weight change first settles the old weight. Claims pay `c` and clear it,
retaining `r`. Fractions stay with the same signer across departures and re-entry.
There is no per-block recipient scan and no historical membership snapshot log.

For funding, the exact new liability is `step * E / Q`. Retain a global liability
remainder `R`, independent of when hosts settle or claim:

```
(whole, R_new) = div_rem(step * E + R, Q)
minted = whole + (R_new > 0 ? 1 : 0) - (R > 0 ? 1 : 0)
```

This is the change in `ceil(cumulative exact liability)`. Thus minted tokens cover
all valid whole-atom claims, while funding above exact liability stays below one
atom globally. Other escrow residue consists of owned unclaimed earnings and
their fractions. Since `E <= D`, `minted <= S`. Genesis dilution and stopped
slots do not create unassigned balances.

`mul-add-div-rem-integer` uses a bounded wide intermediate and accepts nonnegative
inputs with a positive divisor. Its quotient and remainder may use the full
256-bit magnitude range. Integer parsing and ordinary arithmetic now use that
same range; only conversion to a whole-value Decimal reserves the 18 fractional
digits. Decimal raw-unit conversions and compile-time Integer constants live in
the shared type implementation. See the [language audit](contract-language-reward-audit.md)
for the numeric changes and further storage opportunities. The account transition
uses explicit `share_weight`, `settled_index`, `claimable_units`, and
`fractional_remainder` fields; balance queries and mutations share the same
settlement calculation, and mutations persist the final account once.

## Membership changes and bounded cleanup

Ordinary joins and leaves recalculate the affected file's slot weights and settle
its members. Work is O(that file's membership), paid by the initiating operation;
it does not scan every file or every host in the network. Claims and block accrual
use a constant number of state operations. No explicit membership cap is added.

Forced removal cannot rely on an unbounded member scan in a core block hook. Files
with at most eight slots are handled directly within one cleanup step. Larger
files use one persisted reweight job, with the existing 32-step cleanup budget:

1. **Prepare:** visit one membership per step using a sorted cursor. Record each
   survivor's weight increase and sum increases belonging to eligible hosts. Old
   shares remain in effect. Further exhaustion removes any prepared increase
   from this future eligible total as well as removing the host's current weight.
2. **Apply:** atomically remove the exhausted membership, set the new slot weight,
   add the eligible increase to `E`, and record the current index. All survivors'
   new weights become effective at that index.
3. **Fold:** visit one prepared host per step, settling the old weight up to the
   apply index and the new weight thereafter. Clear each temporary delta, then
   clear the job. Claims or membership changes in other files can perform a
   host's fold early; exhausted hosts receive no post-cutoff accrual.

Joins and voluntary leaves in that specific file temporarily return an error
while its job is pending. Claims, other files, accrual, and the separately budgeted
penalty loop continue. Only one job is active, so checking an unfurled change stays
constant work; no unbounded list of old reweight periods accumulates.

State consists of cached weights, per-host credits/snapshots, one job with an
explicit persisted phase (`Preparing` or `Applied(index)`), and temporary per-host
deltas. Membership removal and reservation release belong to the cleanup module;
reward accounting handles income and weight changes. It uses ordinary versioned `contract_state` and generated indexes.
There are no new SQL tables or independent rollback histories. Existing production
data would require a migration/replay; preproduction history is disposable.

## Funding boundary and failure handling

`mint-emission` calculates both nominal shares from one supply snapshot and records
the storage budget. The core-only `allocate-storage-emission` consumes that budget
once at the same height, rejects negative or excessive allocations, mints the
allocated amount into STORAGE_POOL, and transfers it to filestorage's own escrow.
Claims use filestorage's existing unforgeable contract signer to transfer from that
escrow; no public pool-spending capability is introduced.

The reactor runs storage accrual beside ordering distribution before penalties,
inside the block savepoint. Exhaustion therefore preserves that block's earnings.
Claim credit updates and transfers share the ordinary contract-call savepoint;
a failed payout restores the credit. Replayed heights cannot mint or accrue twice.

Validation covers an independent eager integer oracle, membership/claim frequency,
empty periods, partial shortfalls, exhaustion during prepare/apply/fold, changes in
other agreements, large token amounts, authorization, failed payouts, rollback,
runtime reopening, and cross-runtime checkpoint equality. Gas calibration and
large-scale simulation remain separate work in #462 and #444.

Validation of the initial implementation on 2026-09-09: the full indexer release library suite with
`REGTEST=1` passed 479 tests (one existing ignored test) in 72.44 seconds after
compilation. Six shared numeric regressions and ten native filestorage unit tests
passed. Core indexer and native-contract Clippy checks passed with warnings denied;
contract binaries were rebuilt with the repository's pinned build image.

## Tracker consequences

After this replacement merges, close #441 as superseded. Its fee and deactivation
proposals remain tracked in #442; their absence here is not completion of that
scope. Check off #442's storage accumulator/emission/payout item, keeping the
economic umbrella open. This does not close #444, #445/#462, #453 or #463.

Refactor validation on 2026-09-10: 481 indexer release library tests passed with
`REGTEST=1` (two ignored, including the new opt-in cost benchmark), in 61.92 seconds
after compilation. The cost benchmark separately passed all six scenarios. Core
Clippy passed with warnings denied. The numeric foundation was validated and merged
separately in #556. See [cost measurements](storage-reward-costs.md).
