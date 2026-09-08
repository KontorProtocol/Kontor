# Reactor ⇄ Economic-Contract Integration Spec (v1)

**Status:** wiring spec for the minimal v1, grounded in the design decisions recorded in
`economic-layer-overview.md` §0. The governing constraint: the economic *model* is sound,
and the wiring must be **conserving** — every flow either transfers KOR out of a named
holder or burns it; nothing mints outside `mint_emission`.
**Audience:** the reactor (indexer-proper) owner, and the economic-layer track re-deriving
the closed PRs (#439/#440/#441/#445/#452/#453) against it.
**Scope:** the **minimal v1** — the smallest coherent economic layer that closes issue
#461's acceptance gate — plus the architectural rules every later phase must obey. Phase-2
bonds/ordering-fees are out of scope (see §12) but the seams they will attach to are named.

**Anchor style:** symbols, not line numbers. File:line anchors rot within weeks
(#510/#521/#522/#525 each reworked the reactor), and deleted symbols (`initiate_rollback`,
`ResolveExpiry`) still circulate in older branches and closed PRs. Anchor by function and
event names; they are stable.

---

## 1. The model in one paragraph

The native contracts hold balances and compute deterministic allocations and penalties;
the reactor invokes their settlement hooks at the block lifecycle boundary under the core signer.
Nothing in a contract reads wall-clock, mempool, or optimistic state. Emission is minted
into **dedicated pool holders** and every payout is a **transfer out of a pool** — nothing
in the per-block flow ever mints to a recipient directly, so total supply moves only at
mint_emission and at burns, and conservation is checkable per block. Storage yield is
**stake-proportional by decision** (Decision 2, "honest acceptance"): the emission pool pays
stakers who store, the *guarantee* that files stay replicated comes from permanence + PoR +
slashing, not from emission targeting.

## 2. Value flows — v1 subset

| Flow | Source → Sink | Clock | v1? |
|---|---|---|---|
| Emission mint `ε = supply·μ₀/B` | fresh supply → **ORDERING_POOL** (χ·ε); storage share computed, **not minted** | per block | ✅ |
| Ordering emission payout | ORDERING_POOL → staking holder → stake credits | per block | ✅ |
| Storage proof-failure slash `λ_slash·k_f` | offender stake → **BURNER (100 %)** | per block | ✅ |
| Execution gas (burned slice) | user balance → BURNER | per op | already on main |
| Storage-deposit floor | locked as balance floor, never moves | per op | already on main |
| Storage creation fee `υ_f = 30 bps·k_f` | creator balance → BURNER | on create | ✅ (re-derive from #441) |
| σ_min entry floor (gate, not a flow) | — | on register | ✅ (re-derive from #453) |
| Storage-share payout (accumulator) | STORAGE_POOL → nodes | per block | ❌ Step 5 (§12) |
| Ordering fees `f_ord`, bonds `B_tx`/`B_exp` | — | per batch | ❌ Phase 2 (§12) |
| Equivocation slash + bounty | — | on evidence | ❌ deferred (§6, §12) |

## 3. Money architecture (the conservation core)

The rules here are structural, not advisory — each one makes a class of conservation bug
unrepresentable rather than merely discouraged.

### 3.1 Holders

The token contract's named system holders today are `CORE()` (the per-op gas escrow) and
`BURNER()`. v1 adds two:

- **`ORDERING_POOL()`** — receives the χ·ε ordering share at mint; drained only by the
  per-block ordering payout (§5.3).
- **`STORAGE_POOL()`** — reserved for the Step-5 accumulator payout. In v1 it exists but
  receives nothing (the storage share is computed for supply accounting and not minted —
  see §5.1). Declaring it now fixes the holder namespace so Step 5 is additive.

The implemented identities are `HolderRef::OrderingPool` and `HolderRef::StoragePool`,
with storage keys `ordering_pool` and `storage_pool`. They have no signer variants.
The core-only `token::transfer_ordering_reward` debits the fixed ordering-pool source;
staking supplies its own escrow holder as the destination.

Both pool holders are **floor-exempt** in the same sense CORE/BURNER are: they are system
holders, not depositor balances; the storage-deposit floor logic never counts them.

### 3.2 The three structural rules

1. **Mint lands only in pools.** `mint_emission` credits ORDERING_POOL (and, from Step 5,
   STORAGE_POOL). It never credits CORE, never a user, never a contract holder.
   **Why CORE is banned:** CORE is the gas escrow; `token::release()` sweeps the *entire*
   CORE balance to payees every op, by design. A pool parked in CORE is stolen by the next
   gas refund. With pools in dedicated holders, `release()`'s
   full-CORE-sweep stays correct by construction — do **not** "fix" this with a runtime
   guard on the gas hot path instead of the dedicated holders. (If a belt-and-suspenders
   guard is ever added, it lives with the emission code and classifies a non-empty CORE at
   `hold` as `NonDeterministic`/fail-stop — a broken invariant, not a user error.)
2. **Every payout is a transfer out of a pool.** `token::issue_to` is a **fresh mint**
   (`token/src/lib.rs`, core-context) and is **banned from every per-block flow** — using it
   for payouts double-mints. It remains only for genesis/bootstrap paths.
3. **Pool-move and stake-credit are one atomic seam.** `distribute_ordering_reward` itself
   performs `token::transfer(ORDERING_POOL → staking holder)` for the exact amount it
   credits to stakes (the staking contract already imports token). The reactor cannot call
   a credit without the matching transfer having happened in the same contract call —
   "stake credited with no token behind it" becomes unrepresentable rather than merely
   discouraged.

### 3.3 Standing invariants (checked, not assumed)

| Invariant | Statement | Where enforced |
|---|---|---|
| **Supply** | per block: Δtotal_supply == ε_minted − Σburns | invariant harness (§13) |
| **Staking escrow** | staking holder balance ≥ Σ all validators' stake | invariant harness + debug assert in `distribute_ordering_reward` |
| **Aggregate stake** | `total_active_stake` == Σ stakes of ACTIVE ∪ PENDING_EXIT, across every slash/exit transition | staking contract + harness |
| **Voting-power arithmetic** | total consensus voting power ≤ `u64::MAX / 3`; admission conservatively bounds full Decimal stake, including PENDING_JOIN reservations | staking capacity checks + checked host validator-set construction |
| **Pool solvency** | ORDERING_POOL/STORAGE_POOL balances never negative; drained only by their named flows | token contract (transfer semantics) |

## 4. Two settlement clocks

| Clock | Trigger | Reactor site | v1 settles |
|---|---|---|---|
| **Per Bitcoin block** | block executed | `run_block_lifecycle`, inside the block savepoint (`handle_block` opens it around `execute_block` + `run_block_lifecycle`; commit closes it) | mint, ordering payout, storage slash, validator/epoch transitions |
| **Per batch event** | `FinalityEvent::BatchFinalized` / `FinalityEvent::Rollback` from `check_finality`/`settle_finality` | finality path (`check_finality` in `consensus_state.rs` → `settle_finality` in `batches.rs`) | **nothing in v1** — the seam Phase 2 bonds/fees attach to |

Two points that must not be gotten wrong:

- The batch clock's v1 economic payload is **empty**. Ordering emission pays per *block* to
  the active set (§5.3, Decision recorded), not per batch-confirm to signers — the
  per-batch signer payout returns only with Phase 2's fee/bond economy.
- `initiate_rollback` and `ResolveExpiry` **no longer exist** (deleted in the reactor
  reworks; they still appear in older branches and closed PRs). Batch expiry
  is not a named reactor event today; the finality pass renders a deadline verdict and
  emits `BatchFinalized` or `Rollback { from_anchor, invalidated_batches, missing }`. When
  Phase 2 needs an expiry hook, it must be introduced as a first-class `FinalityEvent`
  variant that survives rollback/rehydration — not rediscovered from deleted symbols.

The privilege handle for every state-changing call remains the core signer
(`Signer::Core(Box::new(Signer::Nobody))`); all methods below are core-context. No user
signer ever reaches these paths.

## 5. Per-block sequence (extends `run_block_lifecycle`)

The ordering slice is on main. The storage-penalty implementation in this branch adds
bounded settlement and zero-bond cleanup inside the same block savepoint. The runtime
sequence is:

```
run_block_lifecycle(block):
  set_context(height)
  eligible = staking::has_reward_recipients()
  e = token::mint_emission(eligible)
  staking::distribute_ordering_reward(e.ordering_minted)
  record_block_root()
  expire_challenges(height)                 // at most 32 due challenges
  filestorage::settle_expired_challenges()   // at most 32 penalties + 32 cleanup steps
  generate_challenges_for_block(height, hash)
  process_pending_validators(height)
  commit()
```

Ordering rewards use the active set at lifecycle entry and are credited before a
penalty can exhaust its last member. Otherwise a reward minted for that set could be
stranded when payout finds no recipients. A same-block penalty can burn the newly
credited reward. Mint, payout, penalty, obligation settlement, and cleanup all roll
back if block execution fails. Epoch snapshot work remains deferred/unimplemented.

### 5.1 Phase 0 — mint

- Only the χ·ε ordering share is minted. The (1−χ)·ε storage share is **not minted in v1**:
  Decision 2 accepted stake-proportional yield, and the storage payout needs the Step-5
  accumulator (§12) — minting into a pool nothing drains would only build an unbounded
  balance and complicate the supply invariant. The emission *schedule* is unchanged; v1's
  realized inflation is χ·ε per eligible block, and zero without ACTIVE recipients.
- `mint_emission` is idempotence-guarded per height (calling twice for one block must be
  impossible or a no-op — it runs inside the block savepoint, so replay-after-rollback
  re-mints correctly with the block itself).

### 5.2 Phase 2 — storage slash

- **Input:** the settlement hook reads the indexed due prefix of challenges that EXPIRED without a
  valid proof. Unsuccessful proof submissions return an error and leave the challenge
  ACTIVE with its original deadline. A bad submission is not attributable evidence of
  storage failure: anyone may relay a proof, and an invalid aggregate does not identify
  which challenged file was unavailable. Only successful verification marks challenges
  PROVEN; unanswered challenges expire even if rejected submissions were attempted.
  Transactions execute before expiry in the deadline block, so a valid proof included
  in that block is still accepted. The branch implementation settles expired challenges
  through `filestorage::settle_expired_challenges`, calling the staking burn primitive.
- **Resolution:** memberships are signer-keyed on main (`(agreement_id, signer_id)`), so the
  prover *is* the staking identity — no side-table (the #452 node_id label is obsolete).
- **Amount:** `λ_slash · k_f`, saturating at the offender's remaining stake, with no
  debt for the uncollected remainder (2026-09-08 decision below). λ_slash is
  genesis-class but uncalibrated — model before locking (Decision 1 note). If calibration
  is not ready when this wires, a flat interim constant is acceptable *only* behind the
  same call shape.
- **Destination: 100 % BURNER.** `distribute_slash` (co-node redistribution) is deleted
  from this path — it paid nodes when a *peer* failed, a direct sabotage incentive
  (§14 row 6), and its two conservation bugs (stranded escrow on INACTIVE recipients;
  aggregate-skip for PENDING_EXIT) die with it. The τ/bounty split machinery is reserved
  for the *equivocation* path, where a bounty is the correct incentive — and that whole
  path is deferred (§6, §12).
- **Terminal state:** a slash that drives stake to zero triggers the §7 unwinding rules.

### 5.3 Phase 3 — ordering payout (v1 interim, recorded)

**Decision (recorded here):** v1 pays the ordering emission **per block,
to the ACTIVE validator set, stake-weighted** — not to batch signers.

- This is an explicitly documented interim: it admits free-riding (a validator earns
  without signing). Accepted for v1 because the recipient sets converge under full signing,
  it requires no per-batch signer plumbing, and the alternative (`distribute_ordering_reward
  (ctx, signers, amount)`) returns naturally with Phase 2's per-batch fee settlement.
- Denominator = the **recipient set's** stake (the ACTIVE set at this height), not
  `total_active_stake` (which spans ACTIVE ∪ PENDING_EXIT — using it would strand the
  PENDING_EXIT share in the pool).
- Exact conservation: last-recipient-absorbs-remainder (the established `distribute_*`
  rule); amount transferred == amount credited, enforced inside the call (§3.2 rule 3).
- Reward credits must pass the same aggregate stake-capacity check as voluntary additions,
  including reserved PENDING_JOIN stake. The 1B voluntary-deposit cap is separate from this
  arithmetic bound; rejecting an unsafe total must happen before committing the block.

### Ordering implementation decisions (2026-09-06)

- Direct payouts use one staking call per Bitcoin block, with one pool-to-escrow
  transfer and a snapshot of ACTIVE stakes in canonical holder-string order.
- There is no validator-count cap. The owner accepts O(ACTIVE + PENDING_JOIN)
  scans during development, plus canonical recipient sorting. Aggregate-capacity
  validation includes the pending joins. This is
  an explicit exception to §5.4, not a claim that the loop has a fixed work bound.
  Measure the real lifecycle and optimize contract/storage plumbing as needed;
  population scale and replay cost remain production-readiness gates.
- With no ACTIVE recipients, mint nothing and mark the height processed. Zero
  emissions also mark the height. Duplicate or older mint/payout heights fail;
  their guards are versioned state and roll back with the block.
- Supply is sampled after block transactions, at lifecycle entry. Compute
  `scheduled_total = ((supply * 5) / 100) / 52560`, then ordering = total / 10.
  Only the eligible ordering share is minted; storage issuance remains deferred.
- Every payout respects the aggregate arithmetic bound, including pending joins.
  An invariant failure propagates and rolls back the entire block.
- All pre-production history is disposable. Deploy these consensus-visible changes
  with a coordinated fresh genesis; this patch does not reset a deployed network.
  Production upgrade/activation machinery is separate work before history matters.

### 5.4 Loop discipline (post-#489, non-negotiable)

- **Bounded work per hook.** Every Phase 0–4 step is O(1) or O(events-this-block); no step
  may scan a population that grows with chain age (files, agreements, historical
  challenges). The #489 chain halt was exactly an O(N) core hook; the Step-5 storage payout
  is deferred *because* its naive form is O(files × nodes) and needs the accumulator.
- **Expected exhaustion is a successful settlement.** Collect only the remaining bond;
  settle the unpaid remainder without debt. Pending zero-bond cleanup resolves the
  account's other obligations without another slash. This is explicit state-machine
  behavior, not an exception swallowed by the reactor.
- **Unexpected failures propagate.** Missing bonded accounts, inconsistent reservations,
  arithmetic errors, or failed token burns must not be converted into a silent skip.
  The block savepoint rolls back all partial effects. The older blanket skip-and-alert
  proposal is superseded by these distinctions.
- Expiry, penalty settlement, and cleanup each have a 32-item budget. Penalties and
  cleanup have separate budgets so a large exhausted account cannot starve unrelated
  penalties. Indexed deadline/key order and the FIFO cleanup queue are deterministic.

## 6. Slashing prerequisites — same-changeset requirements

Storage hosting and consensus validation are independent roles backed by the same
bonded balance. A storage host does not have to register a validator or supply a
consensus key. One native account record holds the balance, optional validator metadata,
and an independent withdrawal request; there is no second collateral ledger.

- `add_stake` creates or tops up a bond without joining consensus. Voting-power
  limits apply when the account participates in validation, not to storage-only bonds.
  `get_stake` reads the bond; `get_validator` returns no record for a storage-only
  account. `get_staking_info.total_stake` continues to report consensus stake only.
- `register_validator` opts into consensus using the existing bond plus any additional
  deposit supplied in that call. A zero additional deposit reuses a sufficient bond.
- `leave_validation` schedules the existing 12-block exit (or cancels a pending
  join). Deactivation removes voting power but leaves the bond and storage memberships
  intact. The host can continue storing, topping up, and later rejoining consensus.
- `begin_unstake` is a separate collateral-withdrawal request. Consensus participation
  must have ended first if that account was also validating. A storage-only host can
  request withdrawal directly. Additional deposits and validator registration are
  blocked while that withdrawal request is pending.

Storage-slash wiring (§5.2) still requires:

1. **`T_unbond ≥ challenge_deadline (2016) + evidence margin`.** The initial
   implementation uses 2,028 blocks (2016 + 12) from the collateral-withdrawal request;
   this remains an initial parameter choice, not completed production calibration.
2. **`withdraw_stake` refused while storage obligations remain.** Live memberships,
   active challenges, and expired-but-unsettled penalties all retain the hold.
   Expiration alone never releases collateral. These checks and both account states
   use ordinary versioned native records/indexes and follow block rollback.
3. **Stake attribution** so penalties apply to the collateral that backed an obligation,
   including after role changes; the epoch snapshot design remains unfinished.

For example, a validator requests to leave consensus at height 100 and deactivates
at 112. It can keep hosting indefinitely. If it requests its collateral back at 200,
its earliest withdrawal is 2228, subject to outstanding obligations. A storage-only
host making the same withdrawal request at 200 has the same minimum height.

Storage admission now requires a positive bond and no pending withdrawal request,
without checking validator participation. The check runs before membership writes
on both first join and rejoin. Requesting withdrawal preserves existing memberships;
leaving agreements and answering their challenges remain available. Ordinary storage
customers can still create agreements without bonding.

Storage admission also checks `reserved + k_f <= bond` before membership or
activation writes. Each agreement stores its weight and positive `k_f` at creation;
future files and activations do not reprice existing commitments. The weight uses
`32 * padded_len` bytes of committed field-element payload, rather than the
caller's `original_size` label (which otherwise permits zero-cost tiny files or
understating a large tree). The deterministic Decimal calculation is:

```
rank = ledger_index + 1000 + 1
weight = log10(32 * padded_len) / log10(1 + rank)
k_f = weight * 1_000_000 * ln(1 + (activated_files + 1) / 1000) / total_weight
```

`total_weight` starts at 1000 and adds the frozen weight once per activation.
`activated_files` is the existing `active(true)` bucket count. Activation remains
one-way on main; future deactivation/cleanup must update both that status and the
weight accumulator. These are the earlier design's initial preproduction scales,
not completed production calibration or an implemented governance window.

One reservation per `(agreement, signer)` is included in the signer's aggregate
`get_node_reservation`. Leaving retains it while any Active, Expired, Failed, or
Invalid challenge for that membership remains. Rejoining reuses the retained hold;
it does not add another copy or forgive an old penalty. A valid proof releases a
departed host's hold only when all its challenges for that agreement are resolved.
Failed and duplicate operations leave the total unchanged. Membership flags, totals,
and the membership/status challenge index use ordinary versioned contract storage.

Reservations account for capacity in the existing bond; they neither move tokens
nor reserve the eventual `lambda_slash * k_f` penalty separately. This branch adds
storage slashing, penalty settlement, and bounded membership cleanup. An expired
challenge retains its hold until settlement; a settled failure uses the `Settled`
challenge status. A departed membership releases its reservation only once all of
its obligations are resolved. Settling an older challenge preserves any newer
challenge that now owns the agreement's active slot.
Native state/API changes assume a fresh preproduction chain; old agreements without
a positive stored requirement cannot accept joins.

### Shared-bond shortfall policy (2026-09-08)

Adam confirmed shared-risk reservations, continued service during a positive-bond
shortfall, and no debt. The [economic decision record](economic-layer-overview.md#shared-bond-shortfalls-2026-09-08)
records the rationale and provenance. Implementation must preserve these rules:

- A slash may reduce the bond below aggregate reservations. Reservations remain
  attached to their commitments; do not clamp them to the remaining bond or use
  them to shield funds from the slash.
- While the bond remains positive, a reservation shortfall alone does not remove
  memberships or cancel proof obligations. Admission still requires coverage of
  all reservations plus the proposed new commitment; top-ups can restore that
  capacity. No mandatory top-up period or cascading eviction is introduced.
- Collect `min(requested_penalty, remaining_bond)`. Final settlement must not retain
  the unpaid remainder as an obligation or retry it against a later top-up. This
  does not forgive separate unsettled challenges.
- A zero bond follows §7. The positive-bond continuation rule does not override
  terminal cleanup or ordinary voluntary departure and obligation settlement.

**Deferred, deliberately:** equivocation slashing. The evidence arrives at
`AppMsg::Finalized { evidence }` (reactor handlers) and is currently logged and discarded;
v1 keeps it that way. Wiring evidence *consumption* without the full verified-evidence →
slash → bounty pipeline is worse than absent (half-built machinery invites both false
slashes and a false sense of coverage). The seam is named; the pipeline is Phase 2.

## 7. Terminal-state machine (mandatory — Decision 4 consequence)

Deleting λ_stake (Decision 4) makes the whole-pool saturating slash the security bound —
which is only sound if a node cannot keep operating with zero stake. These rules are v1
spec, same milestone as slashing:

- **Bond exhaustion applies to every operator**, including storage-only accounts.
  If the operator also validates, zero stake removes that role through the standard
  status machinery and ends ordering rewards. `Inactive` describes consensus
  participation only: an inactive account can still have bonded, slashable collateral.
- An exhausted account's **storage memberships are unwound**, even if it never
  registered a validator: marked defunct in deterministic order (bounded
  per block — an unwind queue processed N-per-block if needed, not a scan), so its
  agreements' replication counts reflect reality and its pending challenges resolve as
  settled failures *without* further slash attempts: the exhausted bond has nothing
  left to collect.
- **Re-entry waits for cleanup.** A versioned pending flag blocks deposits, validator
  registration, and storage joins until the account's old obligations and memberships
  have been drained. Challenge generation excludes pending accounts. This prevents a
  top-up from paying old failures or resurrecting memberships midway through cleanup.
  Afterwards, storage-only operators can bond and join again without validation;
  validators register again under the ordinary admission rules.
- Cleanup removes memberships using their existing active index. Agreement activation
  retains its existing one-way meaning; this slice does not add agreement deactivation
  or alter the activation-weight accumulator.
- The `balance ≥ Σ stakes` invariant (§3.3) holds throughout — a slash burns from both the
  holder balance and the stake record in the same call.

## 8. σ_min gate (Decision 3, recorded)

- `register_validator` requires `stake ≥ σ_min = 5,000,000 KOR`; the genesis set is exempt.
  Re-derivation is ~30 lines against the current staking contract (the closed #453 is the
  pattern; its `feat/ordering-rewards` base and 5M constant carry over, its σ/τ symbols do
  not).
- σ_min is **admin-window class** (Decision 1): price-coupled, tunable during the sunsetted
  calibration window, immutable after sunset.
- This proposed floor concerns validator registration only. Storage-only hosts do
  not need a validator registration or its minimum stake; their collateral requirement
  will come from storage commitments. Ordinary storage customers do not bond. The
  current validator admission floor remains unchanged pending the separate σ_min work.

## 9. Parameter table (Decision 1 — class-scoped governance)

Every constant in this spec, classified by the three-question test (consensus-computable →
formula; price-coupled → admin window; identity → genesis-fixed):

| Constant | Value (placeholder) | Class | Note |
|---|---|---|---|
| μ₀ (emission rate) | ≈ 5 %/yr | **genesis-fixed** | the monetary promise |
| χ (ordering split) | 10 % | **genesis-fixed** | identity |
| B (blocks/yr) | 52,560 | **genesis-fixed** | Bitcoin timing |
| τ_slash (storage) | **= 1 (burn-all)** | **genesis-fixed** | decided (§14 row 6); not a knob |
| λ_slash | ≈ 30 | **genesis-fixed*** | *uncalibrated — model before locking* |
| λ_stake | **deleted** | — | Decision 4: solvency check is plain Σk_f; revisit trigger = Step-5 correlated-failure modeling; if it returns it is genesis-class or a formula, never admin |
| σ_min | 5,000,000 KOR | **admin window** | price-coupled (Decision 3) |
| gas calibration (`gas_to_token_multiplier`) | currently 1e-9 on main; spec φ_base = 2.5e-7 (~250× apart — issue #462 pt. 1) | **admin window** | price-coupled; the known-miscalibrated one |
| c_stake | 1,000,000 | **admin window** | price-coupled (absolute KOR collateral scale) |
| υ_f (creation fee) | 30 bps · k_f | **genesis-fixed** | ratio of on-chain quantities |
| T_unbond | initially 2028 after collateral-withdrawal request; obligations can extend | **genesis-fixed** | security window (§6); production calibration pending |
| n_min, F_scale, EPOCH | per model | **genesis-fixed** | shape constants |
| ε, ω_f, Ω, k_f, storage floor | — | **already formulas** | never governable; O(1)-per-block rule applies |

The admin window (Option C): k-of-n multisig + hard per-parameter bounds + ~1008-block
timelock + **irrevocable sunset** ≈ genesis + 52,560. The *decision* is recorded; the
*build* (Admin-SetParameter) is not v1 (§12) — it must merely exist before genesis.

## 10. Determinism requirements (non-negotiable)

The complete v1 set:

1. No `f64`, no `HashMap` iteration order, no wall-clock in any consensus-affecting path.
   All amounts fixed-point `Decimal`; integer arithmetic where division order matters.
2. Every settlement set iterated in **sorted, canonical order** (including skip decisions —
   §5.4).
3. All economic state lives in `contract_state`, therefore inside the SHA256 checkpoint
   hash-chain — `assert_checkpoints_match` is the standing cross-node fork detector.
4. Per-block work bounded (§5.4). A dynamic value may be a formula **only if** it is O(1)
   per block (accumulators yes, population scans no).
5. (Phase-2 forward rule, kept here so it is not re-litigated: bond amounts are frozen at
   sign into the batch record and replayed, never recomputed; `r_fee` derives only from
   Bitcoin-confirmed state.)

## 11. Contract-side prerequisites (re-derived against current main)

What exists vs. what the v1 build must add:

**Already on main:** signer-keyed memberships; challenge lifecycle
(`expire_challenges`, `generate_challenges_for_block`, `record_block_root`,
`verify_proof`); `ValidatorStatus` machinery + `process_pending_validators`;
`min_stake` placeholder gate in `register_validator`; FLOOR deposit model; `Issuance`
mainnet gate (merged); creation-fee burn e2e (#460 merged — port its assertions).

**Implementation checklist (v1):**
- **§11.1** implemented in this branch: `filestorage::settle_expired_challenges()` —
  indexed expired obligations, saturating penalties, and bounded zero-bond cleanup.
- **§11.2** on main: `token::mint_emission()` per §5.1 (pool-holder destination, idempotent per
  height) + the two pool holders (§3.1).
- **§11.3** implemented in this branch: `staking::slash(signer_id, amount)` — burn-all, saturating, aggregate-correct
  across every `ValidatorStatus`, zero-trigger → §7.
- **§11.4** on main: `staking::distribute_ordering_reward(amount)` — internal pool transfer + credit
  (§3.2 rule 3), active-set stake-weighted (§5.3).
- **§11.5** withdrawal delay and obligation hold on main; this branch adds penalty settlement; epoch snapshot remains (§6).
- **§11.6** σ_min in `register_validator` (§8).
- **§11.7** bounded terminal-state unwinding implemented in this branch (§7).

**Explicitly not prerequisites for v1:** the `bonds`
contract, ordering-fee escrow, `slash_equivocation` wiring, congestion consumers.

## 12. Explicitly deferred (with their triggers)

| Deferred | Returns when | Shape already decided |
|---|---|---|
| Storage-share payout | Step 5 | reward-per-share accumulator: one global `acc += pool_credit/Ω` per block (O(1)); membership snapshots `acc` at join/leave; nodes claim `(ω_f/\|N_f\|)·Δacc` lazily. Mint (1−χ)·ε into STORAGE_POOL starts then. Self-dealing: **accepted** (Decision 2) — no NPV gate; revisit as Phase-1.5 only if explicitly reopened |
| Congestion β(t) | after a per-block utilization signal + a KOR-per-gas fee path exist (#462 pt. 2) | mine #445's `beta_step` + params + proptests |
| Bonds / f_ord / per-batch settlement | Phase 2, after batch-clock determinism (`Expired` as first-class FinalityEvent) + reindex-equivalence harness | `phase2-ordering-economy.md` (annotated) |
| Equivocation pipeline | Phase 2 | evidence at `AppMsg::Finalized`; τ/bounty machinery reserved for it |
| Admin-SetParameter build | before genesis; not v1 | §9 |
| λ_stake reintroduction | only if Step-5 correlated-failure modeling demands | genesis-class constant or formula, never admin |

## 13. Validation

- **Invariant harness (built with v1, Step 4):** per-block Δsupply == ε_minted − Σburns;
  staking balance ≥ Σ stakes; `total_active_stake` == Σ ACTIVE∪PENDING_EXIT stakes across
  slash/exit transitions; pool balances non-negative.
- **#461 acceptance mapping:** (a) validator stake grows by the ordering emission through a
  mined block — §5.1 + §5.3; (b) an unproven-challenge expiry slashes the offender — §5.2
  (expired challenges included). **Note:** #461's "slash is redistributed" assertion
  encodes the rejected co-node rule; it must be updated to assert **burned**.
- **Cross-node agreement:** the checkpoint hash-chain covers all economic state for free
  (§10.3); cluster tests assert `assert_checkpoints_match` through slash and payout
  scenarios, including a zero-stake unwinding (§7).
- **Shared-bond shortfalls:** cover a positive bond falling below reservations without
  eviction or cancellation of obligations; rejected admission until sufficient top-up;
  penalties exceeding the remaining bond; no collection of a settled penalty's unpaid
  remainder after a top-up; and rollback restoring balances, reservations, and settlement
  status together. The branch tests exercise these transitions, including bounded
  cleanup, unrelated-penalty progress, and a departed host's reservation release.
- The determinism-simulation suite (`determinism-simulation-testing.md`) targets exactly
  the §5.4/§10 properties; its reindex-equivalence oracle is the Phase-2 gate.

## 14. Contradictions ledger (resolved here)

*(Contradictions that existed between the protocol spec, the modeling repo, the closed econ
PRs, and main — each row records the resolution this document commits to.)*

| # | Contradiction | Resolution | Where |
|---|---|---|---|
| 1 | `issue_to` used as payout (it is a mint) | banned from flows; pools + transfers | §3.2 |
| 2 | ordering accrual bridge unspecified (per-block vs per-batch) | per-block in v1, recorded interim | §5.3 |
| 3 | recipient: active set vs batch signers | active set in v1 (documented free-riding); signers return with Phase 2 | §5.3 |
| 4 | #452 free-form node_id vs signer identity | signer-keyed on main; node_id obsolete | §5.2, overview §7 |
| 5 | `Σk_f·λ_stake` (spec) vs `Σk_f` (code) | λ_stake deleted (Decision 4) | §9 |
| 6 | slash redistribution: stake-weighted vs equal | moot — storage slashes burn 100 % | §5.2 |
| 7 | 12-block refund vs 2016-block deadline | separate deactivation and withdrawal; minimum delay plus unresolved-obligation hold | §6 |
| 8 | governance immutability vs launch calibration | class-scoped window with sunset | §9 |
| 9 | two demand-side fee channels (gas vs f_ord) never reconciled | deferred with Phase 2; reconciliation note is a Step-6 gate | §12 |
| 10 | `r_fee` source of truth unpinned | Phase-2 open question, carried in the annotated phase2 doc | §10.5 |
| 11 | permanent agreements vs φ_leave | v1 has no leave path for economics; φ_leave deferred with the storage payout | §12 |
| 12 | genesis-dilution-mass sink | resolved by §5.1: unminted storage share simply isn't created; no sink needed | §5.1 |

---

## 15. Ownership

| Piece | Owner |
|---|---|
| §5 reactor wiring + §13 harness | reactor / indexer-proper |
| §11 contract affordances | economic-layer track (re-derivation of the closed PRs) |
| §9 parameter table upkeep + admin build | protocol owner (pre-genesis) |
| Phase-2 seams (§4, §12) | blocked on batch-clock determinism; do not build early |

References: the decision record (`economic-layer-overview.md` §0); issues #442
(rescope target), #461, #462, #463; closed PRs #439/#440/#441/#445/#452/#453 (formula and
test mines); `reactor/{blocks,batches,consensus_state,handlers}.rs`;
`native-contracts/{token,staking,filestorage}`.
