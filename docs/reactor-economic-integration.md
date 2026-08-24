# Reactor ⇄ Economic-Contract Integration Spec (v1)

**Status:** re-derived wiring spec — supersedes the previous draft of this document.
Written against the 2026-07-12 economic design audit (all 8 major findings independently
re-verified 16/16) and the four design decisions recorded 2026-08-24 in
`economic-layer-overview.md` §Decisions. The audit's verdict: the economic *model* is sound;
the previous *wiring* was not conserving. This revision is the conserving version.
**Audience:** the reactor (indexer-proper) owner, and the economic-layer track re-deriving
the closed PRs (#439/#440/#441/#445/#452/#453) against it.
**Scope:** the **minimal v1** — the smallest coherent economic layer that closes issue
#461's acceptance gate — plus the architectural rules every later phase must obey. Phase-2
bonds/ordering-fees are out of scope (see §12) but the seams they will attach to are named.

**Anchor style:** symbols, not line numbers. The previous draft cited `blocks.rs:196`,
`mod.rs:377`, `initiate_rollback`, `ResolveExpiry` — all of which rotted or were deleted
within weeks (#510/#521/#522/#525 reworked the reactor). Anchor by function and event names;
they are stable.

---

## 1. The model in one paragraph

The native contracts hold balances and expose deterministic primitives that *move KOR given
an amount*; the reactor owns the lifecycle and supplies the amounts, under the core signer.
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

This section exists because the previous draft's flow violated conservation twice
(audit findings 1–2). The rules are structural, not advisory.

### 3.1 Holders

The token contract's named system holders today are `CORE()` (the per-op gas escrow) and
`BURNER()`. v1 adds two:

- **`ORDERING_POOL()`** — receives the χ·ε ordering share at mint; drained only by the
  per-block ordering payout (§5.3).
- **`STORAGE_POOL()`** — reserved for the Step-5 accumulator payout. In v1 it exists but
  receives nothing (the storage share is computed for supply accounting and not minted —
  see §5.1). Declaring it now fixes the holder namespace so Step 5 is additive.

Both pool holders are **floor-exempt** in the same sense CORE/BURNER are: they are system
holders, not depositor balances; the storage-deposit floor logic never counts them.

### 3.2 The three structural rules

1. **Mint lands only in pools.** `mint_emission` credits ORDERING_POOL (and, from Step 5,
   STORAGE_POOL). It never credits CORE, never a user, never a contract holder.
   **Why CORE is banned:** CORE is the gas escrow; `token::release()` sweeps the *entire*
   CORE balance to payees every op, by design. A pool parked in CORE is stolen by the next
   gas refund (audit finding 1). With pools in dedicated holders, `release()`'s
   full-CORE-sweep stays correct by construction — do **not** "fix" this with a runtime
   guard on the gas hot path instead of the dedicated holders. (If a belt-and-suspenders
   guard is ever added, it lives with the emission code and classifies a non-empty CORE at
   `hold` as `NonDeterministic`/fail-stop — a broken invariant, not a user error.)
2. **Every payout is a transfer out of a pool.** `token::issue_to` is a **fresh mint**
   (`token/src/lib.rs`, core-context) and is **banned from every per-block flow** — using it
   for payouts double-mints (finding 1). It remains only for genesis/bootstrap paths.
3. **Pool-move and stake-credit are one atomic seam.** `distribute_ordering_reward` itself
   performs `token::transfer(ORDERING_POOL → staking holder)` for the exact amount it
   credits to stakes (the staking contract already imports token). The reactor cannot call
   a credit without the matching transfer having happened in the same contract call —
   finding 2 ("stake credited with no token behind it") becomes unrepresentable rather than
   merely discouraged.

### 3.3 Standing invariants (checked, not assumed)

| Invariant | Statement | Where enforced |
|---|---|---|
| **Supply** | per block: Δtotal_supply == ε_minted − Σburns | invariant harness (§13) |
| **Staking escrow** | staking holder balance ≥ Σ all validators' stake | invariant harness + debug assert in `distribute_ordering_reward` |
| **Aggregate stake** | `total_active_stake` == Σ stakes of ACTIVE ∪ PENDING_EXIT, across every slash/exit transition | staking contract + harness |
| **Pool solvency** | ORDERING_POOL/STORAGE_POOL balances never negative; drained only by their named flows | token contract (transfer semantics) |

## 4. Two settlement clocks

| Clock | Trigger | Reactor site | v1 settles |
|---|---|---|---|
| **Per Bitcoin block** | block executed | `run_block_lifecycle`, inside the block savepoint (`handle_block` opens it around `execute_block` + `run_block_lifecycle`; commit closes it) | mint, ordering payout, storage slash, validator/epoch transitions |
| **Per batch event** | `FinalityEvent::BatchFinalized` / `FinalityEvent::Rollback` from `check_finality`/`settle_finality` | finality path (`check_finality` in `consensus_state.rs` → `settle_finality` in `batches.rs`) | **nothing in v1** — the seam Phase 2 bonds/fees attach to |

Two corrections to the previous draft:

- The batch clock's v1 economic payload is **empty**. Ordering emission pays per *block* to
  the active set (§5.3, Decision recorded), not per batch-confirm to signers — the
  per-batch signer payout returns only with Phase 2's fee/bond economy.
- The old anchors `initiate_rollback` and `ResolveExpiry` **no longer exist**. Batch expiry
  is not a named reactor event today; the finality pass renders a deadline verdict and
  emits `BatchFinalized` or `Rollback { from_anchor, invalidated_batches, missing }`. When
  Phase 2 needs an expiry hook, it must be introduced as a first-class `FinalityEvent`
  variant that survives rollback/rehydration — not rediscovered from deleted symbols.

The privilege handle for every state-changing call remains the core signer
(`Signer::Core(Box::new(Signer::Nobody))`); all methods below are core-context. No user
signer ever reaches these paths.

## 5. Per-block sequence (extends `run_block_lifecycle`)

Current `run_block_lifecycle` (main): `set_context` → `record_block_root` →
`expire_challenges` → `generate_challenges_for_block` → `process_pending_validators`,
inside the block savepoint. v1 extends it as follows:

```
run_block_lifecycle(block):                          [inside the block savepoint]
  set_context(height)                                [existing]

  ── Phase 0 · Mint ────────────────────────────────────────────────
  e = token::mint_emission()
      → mints χ·e into ORDERING_POOL                 [new; §3 rules apply]
      → returns {total: e, ordering: χ·e, storage: (1−χ)·e}
        storage share is COMPUTED (supply schedule accounting) but NOT minted in v1

  ── Phase 1 · Storage audit ───────────────────────────────────────
  record_block_root()                                [existing]
  expire_challenges(height)                          [existing]
  generate_challenges_for_block(height, hash)        [existing]

  ── Phase 2 · Storage slash settlement ────────────────────────────
  for (signer_id, k_f) in filestorage::collect_failed_challenges():   ← affordance §11.1
      staking::slash(signer_id, λ_slash · k_f)       → 100 % to BURNER
      // no distribute_slash on this path — deleted (Decision: burn-all, finding 5)

  ── Phase 3 · Ordering payout ─────────────────────────────────────
  staking::distribute_ordering_reward(χ·e)
      // internally: transfer(ORDERING_POOL → staking holder, amount actually credited),
      // then credit stakes — one atomic contract call (§3.2 rule 3)

  ── Phase 4 · Validators & epoch ──────────────────────────────────
  process_pending_validators(height)                 [existing]
  if height % EPOCH == 0: snapshot staker set        [new; supports T_unbond, §6]

  commit()                                           [existing — closes the block savepoint]
```

### 5.1 Phase 0 — mint

- Only the χ·ε ordering share is minted. The (1−χ)·ε storage share is **not minted in v1**:
  Decision 2 accepted stake-proportional yield, and the storage payout needs the Step-5
  accumulator (§12) — minting into a pool nothing drains would only build an unbounded
  balance and complicate the supply invariant. The emission *schedule* is unchanged; v1's
  realized inflation is χ·ε per block, documented as such.
- `mint_emission` is idempotence-guarded per height (calling twice for one block must be
  impossible or a no-op — it runs inside the block savepoint, so replay-after-rollback
  re-mints correctly with the block itself).

### 5.2 Phase 2 — storage slash

- **Input:** `collect_failed_challenges()` returns challenges that FAILED verification and
  challenges that EXPIRED unanswered (both are proof failures; audit finding: expired must
  slash or liveness-failure is free).
- **Resolution:** memberships are signer-keyed on main (`(agreement_id, signer_id)`), so the
  prover *is* the staking identity — no side-table (the #452 node_id label is obsolete).
- **Amount:** `λ_slash · k_f`, saturating at the offender's remaining stake. λ_slash is
  genesis-class but uncalibrated — model before locking (Decision 1 note). If calibration
  is not ready when this wires, a flat interim constant is acceptable *only* behind the
  same call shape.
- **Destination: 100 % BURNER.** `distribute_slash` (co-node redistribution) is deleted
  from this path — it paid nodes when a *peer* failed, a direct sabotage incentive
  (finding 5), and its two conservation bugs (stranded escrow on INACTIVE recipients;
  aggregate-skip for PENDING_EXIT) die with it. The τ/bounty split machinery is reserved
  for the *equivocation* path, where a bounty is the correct incentive — and that whole
  path is deferred (§6, §12).
- **Terminal state:** a slash that drives stake to zero triggers the §7 unwinding rules.

### 5.3 Phase 3 — ordering payout (v1 interim, recorded)

**Decision (audit finding 4, recorded here):** v1 pays the ordering emission **per block,
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

### 5.4 Loop discipline (post-#489, non-negotiable)

- **Bounded work per hook.** Every Phase 0–4 step is O(1) or O(events-this-block); no step
  may scan a population that grows with chain age (files, agreements, historical
  challenges). The #489 chain halt was exactly an O(N) core hook; the Step-5 storage payout
  is deferred *because* its naive form is O(files × nodes) and needs the accumulator.
- **Per-item error semantics: skip-and-alert, never abort.** A failed slash for one
  challenge (e.g. an already-emptied stake) skips that item with a loud log/metric and
  continues; it must NOT error out of `run_block_lifecycle`, which would roll back the
  whole block and halt every node identically (deterministic content failure ≠ node
  fault — the same discipline the consensus layer applies). Items must be processed in
  sorted, canonical order so every node skips identically.

## 6. Slashing prerequisites — same-changeset requirements

Slashing that can be exited is theater (audit finding 6: 12-block unbond vs 2016-block
challenge deadline means a faulty staker leaves before evidence lands). Therefore the
storage-slash wiring (§5.2) **must land in the same changeset as**:

1. **`T_unbond ≥ challenge_deadline (2016) + evidence margin.`** The current
   `ACTIVATION_DELAY = 12` covers *set-membership* transitions and may remain for joins;
   exits must be governed by the new T_unbond.
2. **`begin_unstake` refused while the signer has any pending challenge.**
3. **Epoch stake snapshot** (Phase 4) so a slash attributes against the stake that stood
   when the offense was committed, not the post-flight remainder.

**Deferred, deliberately:** equivocation slashing. The evidence arrives at
`AppMsg::Finalized { evidence }` (reactor handlers) and is currently logged and discarded;
v1 keeps it that way. Wiring evidence *consumption* without the full verified-evidence →
slash → bounty pipeline is worse than absent (half-built machinery invites both false
slashes and a false sense of coverage). The seam is named; the pipeline is Phase 2.

## 7. Terminal-state machine (mandatory — Decision 4 consequence)

Deleting λ_stake (Decision 4) makes the whole-pool saturating slash the security bound —
which is only sound if a node cannot keep operating with zero stake. These rules are v1
spec, same milestone as slashing:

- A validator whose stake reaches **zero** (slash-exhaustion) enters `Inactive` via the
  standard status machinery: removed from the consensus set at the next
  `process_pending_validators`, earns nothing further (it is not in the ACTIVE payout set).
- Its **storage memberships are unwound**: marked defunct in deterministic order (bounded
  per block — an unwind queue processed N-per-block if needed, not a scan), so its
  agreements' replication counts reflect reality and its pending challenges resolve as
  failures *without* further slash attempts (skip-and-alert; there is nothing left to
  slash).
- **Re-entry** is a fresh `register_validator` (σ_min applies); no resurrection of the old
  memberships.
- The `balance ≥ Σ stakes` invariant (§3.3) holds throughout — a slash burns from both the
  holder balance and the stake record in the same call.

## 8. σ_min gate (Decision 3, recorded)

- `register_validator` requires `stake ≥ σ_min = 5,000,000 KOR`; the genesis set is exempt.
  Re-derivation is ~30 lines against the current staking contract (the closed #453 is the
  pattern; its `feat/ordering-rewards` base and 5M constant carry over, its σ/τ symbols do
  not).
- σ_min is **admin-window class** (Decision 1): price-coupled, tunable during the sunsetted
  calibration window, immutable after sunset.
- The consequence is recorded as an explicit accepted constraint: with unified stake,
  5M KOR is also the entry price to *operate storage* — at genesis supply that caps
  independent participants at ~200. Users never stake (balance + deposit floor only);
  delegation is the designed future add-on if operator breadth is needed.

## 9. Parameter table (Decision 1 — class-scoped governance)

Every constant in this spec, classified by the three-question test (consensus-computable →
formula; price-coupled → admin window; identity → genesis-fixed):

| Constant | Value (placeholder) | Class | Note |
|---|---|---|---|
| μ₀ (emission rate) | ≈ 5 %/yr | **genesis-fixed** | the monetary promise |
| χ (ordering split) | 10 % | **genesis-fixed** | identity |
| B (blocks/yr) | 52,560 | **genesis-fixed** | Bitcoin timing |
| τ_slash (storage) | **= 1 (burn-all)** | **genesis-fixed** | decided (finding 5); not a knob |
| λ_slash | ≈ 30 | **genesis-fixed*** | *uncalibrated — model before locking* |
| λ_stake | **deleted** | — | Decision 4: solvency check is plain Σk_f; revisit trigger = Step-5 correlated-failure modeling; if it returns it is genesis-class or a formula, never admin |
| σ_min | 5,000,000 KOR | **admin window** | price-coupled (Decision 3) |
| gas calibration (`gas_to_token_multiplier`) | currently 1e-9 on main; spec φ_base = 2.5e-7 (~250× apart — issue #462 pt. 1) | **admin window** | price-coupled; the known-miscalibrated one |
| c_stake | 1,000,000 | **admin window** | price-coupled (absolute KOR collateral scale) |
| υ_f (creation fee) | 30 bps · k_f | **genesis-fixed** | ratio of on-chain quantities |
| T_unbond | ≥ 2016 + margin | **genesis-fixed** | security window (§6) |
| n_min, F_scale, EPOCH | per model | **genesis-fixed** | shape constants |
| ε, ω_f, Ω, k_f, storage floor | — | **already formulas** | never governable; O(1)-per-block rule applies |

The admin window (Option C): k-of-n multisig + hard per-parameter bounds + ~1008-block
timelock + **irrevocable sunset** ≈ genesis + 52,560. The *decision* is recorded; the
*build* (Admin-SetParameter) is not v1 (§12) — it must merely exist before genesis.

## 10. Determinism requirements (non-negotiable)

Unchanged in substance from the previous draft; restated as the complete v1 set:

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

**To build (v1):**
- **§11.1** `filestorage::collect_failed_challenges() → [(signer_id, k_f)]` — failed AND
  expired, sorted, bounded per block.
- **§11.2** `token::mint_emission()` per §5.1 (pool-holder destination, idempotent per
  height) + the two pool holders (§3.1).
- **§11.3** `staking::slash(signer_id, amount)` — burn-all, saturating, aggregate-correct
  across every `ValidatorStatus`, zero-trigger → §7.
- **§11.4** `staking::distribute_ordering_reward(amount)` — internal pool transfer + credit
  (§3.2 rule 3), active-set stake-weighted (§5.3).
- **§11.5** T_unbond + pending-challenge unstake block + epoch snapshot (§6).
- **§11.6** σ_min in `register_validator` (§8).
- **§11.7** terminal-state unwinding (§7).

**Explicitly not prerequisites for v1** (previous draft's items now deferred): the `bonds`
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
- The determinism-simulation suite (`determinism-simulation-testing.md`) targets exactly
  the §5.4/§10 properties; its reindex-equivalence oracle is the Phase-2 gate.

## 14. Contradictions ledger (audit §8 — resolved here)

*(Numbering key: inline "finding N" citations throughout this spec refer to the audit's
**8 major findings**; the rows below are the audit's **§8 contradictions list** — a
different, longer list of 12. Row numbers ≠ finding numbers.)*

| # | Contradiction | Resolution | Where |
|---|---|---|---|
| 1 | `issue_to` used as payout (it is a mint) | banned from flows; pools + transfers | §3.2 |
| 2 | ordering accrual bridge unspecified (per-block vs per-batch) | per-block in v1, recorded interim | §5.3 |
| 3 | recipient: active set vs batch signers | active set in v1 (documented free-riding); signers return with Phase 2 | §5.3 |
| 4 | #452 free-form node_id vs signer identity | signer-keyed on main; node_id obsolete | §5.2, overview §7 |
| 5 | `Σk_f·λ_stake` (spec) vs `Σk_f` (code) | λ_stake deleted (Decision 4) | §9 |
| 6 | slash redistribution: stake-weighted vs equal | moot — storage slashes burn 100 % | §5.2 |
| 7 | 12-block unbond vs 2016-block deadline | T_unbond ≥ 2016 + margin, same changeset | §6 |
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

References: 2026-07-12 design audit (findings 1–8, §5–§8) and its 18-agent verification;
decision record 2026-08-24 (`economic-layer-overview.md` §Decisions); issues #442
(rescope target), #461, #462, #463; closed PRs #439/#440/#441/#445/#452/#453 (formula and
test mines); `reactor/{blocks,batches,consensus_state,handlers}.rs`;
`native-contracts/{token,staking,filestorage}`.
