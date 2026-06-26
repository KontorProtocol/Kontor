# Storage Deposit: Vault → Floor Migration

Status: IMPLEMENTED on branch `feat/storage-deposit-footprint` (2026-06-22),
INCLUDING refinements R1 + R2 below. The vault machinery is removed; the floor is
enforced as a spendable reserve on token debits (R1) over the frozen per-row
deposit (R2). The body below "(SUPERSEDED) settle-time floor check" describes the
first cut; R1/R2 are what's actually built and tested (338 lib + integration in
both local and regtest modes).

## AS-BUILT NOTE (supersedes parts of the body below)

The migration continued past R1/R2 on `feat/storage-deposit-rebased`:
- **Integer gas, not token decimals.** The per-row deposit is stored as integer
  `deposited_gas` (column on `contract_state`, in the checkpoint), priced to token
  (`× gas_to_token`) only at the read. The floor is therefore exact-integer
  arithmetic end to end.
- **An O(1) floor read (the "R-cache").** `context::storage-floor` reads an
  off-checkpoint `depositor_footprint(depositor, total_gas)` cache, maintained
  incrementally on every write/delete and recomputed per-affected-depositor on
  reorg — instead of summing the depositor's live rows each debit.

### What "dynamic D" means (and doesn't)

`D` is read at write time via `Runtime::deposit_rate(contract_id, path)` and
**frozen** into the row's `deposited_gas`. Consequences for future tuning:

- **Prospective, per-contract (and per-field) — no consensus migration.** Changing
  `D` (e.g. a governance-set or per-contract rate) only affects FUTURE writes; the
  rate is never re-derived for existing rows. The `path` argument is already on the
  seam, so a per-FIELD / per-INDEX rate — e.g. pricing a hot covering-index leaf
  higher than a cold scalar — needs only a `deposit_rate` body that inspects the
  path prefix, no signature or format change. (This is the seam the covering-index
  work will use.)
- **Retroactive re-pricing is NOT a per-contract lever.** Because deposits are
  frozen per row, you cannot raise `D` and have it bite existing rows. The only
  retroactive knob is the GLOBAL `gas_to_token_multiplier`, which re-prices every
  holder's floor at once. Firming up collateral on existing state otherwise
  requires those rows to be rewritten.

---
## Refinements (R1 + R2 — IMPLEMENTED 2026-06-22 — READ FIRST)

### R1 — Enforce the floor UP FRONT as a spendable reserve (DONE; dropped the settle-time check + `defer_finalize`)

The first cut checked the floor at SETTLE (after the op runs), which forced the
op's storage finalize to be DEFERRED from `handle_call` to `handle_procedure` so a
violation could revert the op (the `defer_finalize` flag) — a subtle change to the
consensus commit path. That's gone. `footprint × D` is now a RESERVED (locked)
portion of the balance, and every token DEBIT checks
`spendable = balance − footprint×D`:

- **Gas hold** (up front, in `token::hold`): `spendable ≥ gas_limit`. If it fails,
  the op is rejected before it runs — nothing to revert.
- **Transfers / burns** (inline, in the token debit path): `spendable ≥ amount`,
  a normal contract `Err`.

This is provably sufficient because **growth is gas-bounded, so the hold
pre-authorizes it.** The hold passes only if `balance ≥ footprint_before×D +
gas_limit`; an op can grow footprint by at most `gas_limit/D` (deposit metered as
gas) and the deposit is RETURNED (only `burn` is permanent); so
`balance_after = balance − burn ≥ footprint_before×D + (gas_limit − burn) ≥
footprint_before×D + ΔF×D = floor_after`. The held gas is escrowed out of the
ledger balance, so an in-op transfer can't dip into the gas that funds the growth
(the "transfer-then-grow in one op" case composes). So **no op ever needs a
settle-time floor revert.**

**As built:** `defer_finalize` is gone (handle_call commits/rolls back as before;
`finalize_op` deleted); the token `settle` floor-op + WIT export are removed
(settle → just `release` = burn + refund). The `spendable` check lives in the
token's `transfer` helper (so `hold`/`transfer`/`burn`/`attach`/`detach` all get
it), and the token reads the holder's floor via a new host fn
`context::storage-floor(holder-ref) -> decimal` (`built_in::context::HostWithStore`
in `host_files.rs`; sums the holder's live `deposited_amount`; 0 for
non-signer/system holders). The footprint is now read PER DEBIT (every transfer),
not per settling-op — so the host-side cache (R-cache below) matters more, not less;
it remains the open perf follow-up (each debit currently does a fresh footprint
sum). Placement note: `storage-floor` sits in the common `context` interface, so
every contract can read a holder's (publicly-derivable) floor — tighten to a
native-only interface if minimal surface is preferred.

### R2 — Evolving D: freeze each row's D in the per-row deposit (don't re-price with current D)

The floor must support a `D` that changes over time. With a single global current
`D`, computing the floor as `total_bytes × D_now` RE-PRICES every existing row at
the new rate — a `D` increase retroactively raises everyone's floor and can push
holders under-collateralized through no action of their own. For a refundable
COLLATERAL that's wrong; the deposit should be FROZEN at write-time `D`
(grandfathered), so a `D` change only affects future writes.

That's exactly what the per-row `deposited_amount` column is for: **floor =
Σ (per-row frozen deposit)**, so no historical-`D` lookup is ever needed — each
row carries its own.

**As built:** the floor sums the live per-row `deposited_amount`
(`live_deposit_amounts_by_depositor`), NOT `bytes × D_now` — frozen-per-row, a
behavioral no-op at D=1. `deposited_amount` stays a TEXT decimal (token) summed in
Rust (host `storage-floor` fn + the endpoint). **Deferred** (pairs with R-cache):
storing it as an **integer gas amount** (`bytes × D_at_write`) for exact, fast SQL
`SUM` — a pre-launch column-semantics change worth doing when the per-debit cost
is addressed, not before.

### R-cache — footprint access (open perf follow-up)

Each token debit currently does a FRESH footprint sum (host sums the holder's live
`deposited_amount`). Bounded by the holder's deposited-row count and fine for
correctness, but it's per-debit (every transfer), so a cache is the next perf step.
The intended shape: a host-side, eager-exact counter (a derived index,
reconstructible, NOT a new consensus structure), served via `storage-floor`.
Eager's "fan-out" at delete is cheap host bookkeeping bounded by the already-metered
`Fuel::Delete` — NOT the vault's cross-party TOKEN disbursement — so it does not
reintroduce the vault's attribution problem. Maintaining it needs the per-write
displaced-row read (gated to deposited writes), and the integer-gas column above for
an exact running sum. Persist it (survives restart like the prune watermark),
maintained in the writes' DB txn.

---


## Why

The vault model makes the storage deposit a token that physically moves into a
`VAULT` holder and is **pushed back to the original setter the instant their row
is freed**. Because Kontor storage is contract-mediated (the depositor of a row
is *not* its owner — any permitted caller can overwrite or delete it), that
push-back is an **eager, cross-party fan-out** executed by the core signer inside
*someone else's* gas-metered op. Every hard question we hit — who pays for the
payouts, what order release/disburse run in, how to meter a variable-size
settlement, the fail-late cliff — is a symptom of eagerly settling a cross-party
relationship inside one party's budget.

Every elegant storage-collateral design (Solana rent-exempt floor, NEAR storage
staking, Sui) avoids this because **storage is owned by the party that
collateralizes it**, so there is never a third-party refund. We decoupled payer
from owner and then bolted a refundable per-depositor deposit onto rows the
depositor doesn't control.

## The reframe

The vault conflated two jobs that don't belong together. Separate them:

1. **Bound per-op storage growth** = the gas limit. Keep metering
   `footprint-growth x D` as fuel against the op's gas budget, so a single op can
   lock at most `gas_limit / D` of new collateral. This is the only thing the
   vault's fuel-metering was actually needed for, and it answers the original
   reason we left the floor model: *a user must be able to cap, per op, how much
   of their balance gets tied up in storage — not have a contract lock their
   whole balance.* The cap is the gas they signed.

2. **The collateral itself** = the floor: `balance >= footprint x D`. Nothing
   moves between accounts. Ever.

Under this split, **delete just removes the row, the setter's footprint shrinks,
their floor relaxes.** The "refund" is tokens un-restricting in place. No vault,
no disburse, no cross-party transfer, no settle ordering, no metering-the-refund.

This is strictly better than the *old* floor model we deleted (commit
`85af9919`): that one tracked footprint as a single net byte-delta attributed to
the **op payer** (`settle(footprint_delta: s64, ...)`), so an overwrite credited
the wrong holder and a setter whose row was taken over stayed collateralized for
it. The vault era gave us **per-row `depositor` attribution**, which is exactly
what a correct floor needs. We keep that and drop the vault.

## What stays (and becomes load-bearing)

- **Per-row `depositor` + `deposited_amount` columns** (schema + checkpoint hash).
  Now the *basis of the derived footprint* (sum the live rows a holder is the
  depositor of), not a refund target. The attribution work is the foundation.
- **Deposit-as-fuel metering** in `_set_primitive` (`Fuel::Deposit`). Now the
  per-op growth cap (job 1). The only change: the reservation is **returned** to
  the payer at settle, not locked into a vault (see flow below).
- **Footprint aggregation query** (`find_footprint_by_depositor`) + the
  `/signers/{id}/footprint` endpoint. Now *computes the floor*, not just a UI
  read.
- **`deposit_rate(contract_id)` seam** = the rate `D`.
- **Delete metering** (`Fuel::Delete`) still bounds rows freed per op — but the
  per-row refund prepay term goes away (it pre-priced a payout that no longer
  exists): `Delete = 200 + 200*rows + 10*bytes` (tombstone + bytes only).

## What is removed

- `HolderRef::Vault` and all its wiring: `holder_ref` macro arm, `indexer-types`,
  `from_holder_ref`, the `balances()` filter, `VAULT()` helper, ts bindings.
- Token `settle` (vault version): lock CORE->VAULT + disburse VAULT->setter + the
  `DepositRefund` record.
- The `DepositMeter`'s **refund map / per-setter batching** and every
  `record_refund` call in `_delete` / `_delete_matching_paths`. (The *charge*
  side — the per-op growth total — stays, repurposed as the cap.)
- The per-row refund prepay term in `Fuel::Delete`.

## What is added / changed

- A token **floor check** `balance >= footprint x D`, enforced at **op settle**
  on the payer. The token stores **no** footprint — the host **computes it fresh**
  (sums the payer's live deposited rows) and passes the absolute figure into
  `settle`. The token just compares it to the balance.
- **At op settle**: burn only the execution slice; **return** the deposit-fuel
  (growth) reservation to the payer with the rest of the escrow; then floor-check
  the payer.

## Footprint: computed fresh (decided)

The floor check needs `footprint(H)`. `balance` lives in the token ledger;
`footprint` is derivable only by the host (it scans `contract_state` across
contracts). **Decision: compute it fresh** — at each settling op the host tallies
the payer's live deposited rows and hands the absolute footprint to the token's
floor check. No footprint counter, no eager maintenance, no fan-out, always exact.

This makes the token side *simpler than the old floor model*: no `footprint` map,
no `apply_footprint_delta`, no delta plumbing. `settle(footprint, pending_credit)`
receives the number and checks `balance + pending_credit >= footprint x D`.

The cost we are accepting (and will measure): one footprint tally per settling op
that touched storage or moved balance. If that shows up as too expensive on the
hot path, the *pure optimization* — added later, behind the same `settle`
interface, no model change — is to cache a per-holder running footprint and update
it incrementally. We start without it.

## The new per-op flow

```
hold gas (escrow gas_limit from payer -> CORE)           [unchanged]
  |
execute op:
  |- storage write: charge Fuel::Set (compute) + Fuel::Deposit(bytes x D) (cap)
  |     - NO vault, NO refund recording: just meter growth against the budget
  |- storage delete: charge Fuel::Delete(rows,bytes)   [no refund prepay]
  |     - footprint accounting untouched (it is derived, not maintained)
  |
settle (one core call):
  |- gas = execution fuel consumed (deposit reservation excluded)
  |- burn execution slice -> BURNER
  |- return remaining escrow (incl. the deposit reservation) -> payer
  |- host computes footprint(payer) fresh from the depositor columns
  |- floor check: balance(payer) + pending_credit >= footprint(payer) x D
        else REVERT (deterministic)
```

Two bounds, two purposes, nothing moved between accounts:
- **gas limit** caps *per-op* collateral growth (`growth <= gas/D`) — user intent.
- **floor** caps *total* collateral (`footprint x D <= balance`) — global solvency.

## Where the floor is enforced (v1)

Enforce at **op settle, on the op payer**. This is sufficient for the common
model because the holder whose footprint grows (the depositor) and whose balance
is spent (the signer) is the op payer, and their floor is checked at the op's end
with the post-refund balance. Concretely it catches both directions:
- an op that **grows** the payer's footprint past their balance reverts;
- an op that **spends** the payer's balance below their existing floor reverts.

Per-internal-transfer floor checks and the case of moving a *non-payer* holder's
balance are deferred — revisit only if the token's authorization model lets a
holder's balance move in an op they did not pay for.

## Migration steps (ordered)

1. **Token**: delete the vault `settle` + `DepositRefund` record. Add a core
   `settle(ctx, footprint: decimal, pending_credit: decimal)` that floor-checks
   `balance + pending_credit >= footprint x D` and returns `Err` on violation.
   No `footprint` map, no `apply_footprint_delta`. Keep `hold`; keep a `release`
   for the burn + escrow refund (or fold into `settle` — one core call is fine
   now that there is no disburse). Rebuild binary + bindings.
2. **`indexer-types` / macros**: remove `HolderRef::Vault` and its wiring; regen
   ts bindings.
3. **Host `_set_primitive`**: keep `Fuel::Deposit` as the per-op cap; keep
   stamping the `depositor`/`deposited_amount` columns; **remove** the overwrite
   `latest_deposit_row` read + `record_refund` (no displaced-setter refund).
4. **Host `_delete` / `_delete_matching_paths`**: remove `record_row_refunds`;
   drop the refund prepay from `Fuel::Delete`.
5. **`DepositMeter`** → reduce to the per-op growth **reservation** accounting
   (so the reservation can be returned, not burned, at settle). Drop the refund
   map entirely. May collapse to almost nothing.
6. **Host settle path** (`call.rs handle_procedure`): compute execution gas
   excluding the deposit reservation; return the reservation to the payer; tally
   `footprint(payer)` fresh; call token `settle(footprint, pending_credit)`; on
   `Err`, deterministic revert.
7. **Footprint tally**: host helper summing `find_footprint_by_depositor` for the
   payer (decimal sum), used by the settle path.
8. **Footprint endpoint**: unchanged.
9. **Tests**: rework `storage_deposit.rs` — replace vault-conservation /
   refund-to-setter / multi-setter-disburse with floor tests: write grows the
   floor; a spend that would breach the floor reverts; delete relaxes the floor
   (no transfer, no fan-out); the per-op gas limit bounds footprint growth; a
   cross-party overwrite moves the floor from the old setter to the new one.

## Open questions / risks

- **Footprint tally cost** — the thing we are choosing to measure. One tally per
  settling op. Bounded by the payer's row count; backed by
  `idx_contract_state_depositor`. If it bites, cache later (no interface change).
- **Floor vs the gas hold** — holding gas reduces spendable balance, so the floor
  must be evaluated on the **post-refund** balance. The old model already threaded
  a `pending_credit` for exactly this; keep that argument.
- **`D` dynamic later** — the floor structure `footprint x D` already absorbs a
  dynamic `D`; a change re-prices every holder's floor at once (nothing to
  migrate, it is derived).
- **Checkpoint/consensus** — the depositor columns + hash stay; removing the vault
  changes only token-ledger *contents* (no schema/hash format change).
- **Griefing** — a write attributes the depositor to the *actor*, so an attacker
  can't make a victim the depositor of a row the attacker wrote. Overwriting a
  victim's row only *lowers* the victim's true footprint (their floor relaxes).
  No way to inflate a victim's floor; no solvency risk.
