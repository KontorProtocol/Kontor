# Phase 2 — Ordering & Bond Economy: Implementation Design

**Status:** proposal (design only; not yet scheduled for implementation)
**Scope:** the optimistic-consensus economic layer — ordering fees, the three bond systems (expiry, user-griefing, publisher), expiry penalties, and equivocation settlement — and how to realize them across the Kontor contracts and reactor.
**Out of scope here:** storage economy (Phase 1), governance/admin authority, parameter *values* (see the separate calibration note).

---

## 1. Why this is the hard part

The optimistic pre-confirmation guarantee is only worth what's bonded behind it. Without the bond economy:
- a user can grief the network by getting a tx ordered then double-spending it on Bitcoin (no cost),
- a staker can sign a batch and walk away if it doesn't confirm (no liveness pressure),
- equivocation has no teeth.

So Phase 2 is *core security*, not polish. It is also the largest unbuilt subsystem (~30 mechanisms) and the one most exposed to two failure modes: **non-determinism** (any disagreement on a bond amount or settlement forks the chain) and **incentive bugs** (a mechanism that's deterministic but economically exploitable — exactly the `slash_equivocation` self-publication leak the audit just caught).

The design below is organized to make both failure modes *testable up front* (§7–8).

---

## 2. Design principles

These follow the pattern already established by the storage/staking economic primitives:

1. **Contracts hold balances + deterministic primitives; the reactor orchestrates.** A contract method moves KOR (reserve/release/burn/pay) given an amount. The reactor decides *when* (batch lifecycle) and *how much* (frozen at sign). Contracts never read wall-clock, mempool, or optimistic state.

2. **Bond amounts are frozen at sign time and stored in the batch.** `B_tx(t,h)` and `B_exp(t,h)` are computed once by the proposing staker using the deterministic fee signal `r_fee`, written into `batch.tx_bonds[i]`, and thereafter **read, never recomputed** (spec §user-griefing-bonds: "verifiers read the `tx_bonds[i]` value frozen in the batch"). Per-position records, not scalar totals — so a later parameter change can't retroactively alter an in-flight reservation. This is the determinism linchpin; every indexer replays the same amounts from the canonical batch log.

3. **Two settlement clocks.** Storage settles per Bitcoin block (Phase 1, in `run_block_lifecycle`). Ordering settles per **batch-confirmation / expiry / rollback**, in the finality path (`reactor/consensus_state.rs:check_finality` → `mod.rs:377`). These are different code paths with different atomicity boundaries — call it out explicitly (see §6).

4. **`r_fee` derives only from Bitcoin-confirmed data.** The fee-insufficiency signal that sizes bonds must be a deterministic function of confirmed Bitcoin fee state (percentiles), never of the optimistic mempool — otherwise two stakers compute different bonds. It's computed at sign and frozen anyway (principle 2), but the *source* must still be canonical so independent re-derivation (e.g. for an audit) agrees.

5. **The checkpoint oracle is the determinism backstop.** All bond/fee state lives in `contract_state` and therefore in the SHA256 checkpoint chain; `assert_checkpoints_match` across nodes is the ready-made fork detector. Design every new piece of state as contract state so it's covered for free.

---

## 3. State model — where each bond lives

| Mechanism | Home | Rationale |
|---|---|---|
| **User griefing bonds** (`B_min`/`B_tx`) | **new `bonds` contract** | Deposits of *spendable* KOR with per-position reservations + withdrawal delay. Self-contained, not tied to stake. |
| **Publisher bonds** | **same `bonds` contract** | Identical lifecycle to user bonds, keyed by publisher (BIP-340) key instead of user. Share the code. |
| **Expiry bonds** (`B_exp`) | **staking contract extension** | Reservations against *ordering stake* (`σ_avail = σ_s − A_s`); the penalty burns stake. Must live with the stake it encumbers. |
| **Ordering fees** (`f_ord`, `τ_ord`) | **token escrow + staking payout** | Escrow `f_ord` at batch inclusion; on confirm burn `τ_ord` and pay signers via the existing stake-weighted `distribute_ordering_reward`. |
| **Frozen amounts** `tx_bonds[i]`, per-batch `B_exp` | **batch structure (reactor)** | The canonical, replay-stable record of what was reserved. |
| **`r_fee` signal** | **reactor (computed), frozen into batch** | Derived from confirmed Bitcoin fee state. |

A **dedicated `bonds` contract** (rather than bolting onto `token`) keeps the reservation bookkeeping — which is intricate (per-position records, unlock delays, capacity predicates) — isolated and independently testable, and gives the publisher path free reuse.

### 3.1 `bonds` contract state

```
GriefingBond { amount: Decimal, unlock_height: u64, reservations: Map<ResId, Reservation> }
Reservation  { tx_id: String, position: String, sign_height: u64, amount: Decimal }
BondsStorage {
  user_bonds:      Map<Holder, GriefingBond>,
  publisher_bonds: Map<PublisherKey, GriefingBond>,
  min_amount:      Decimal,   // B_min, admin-tunable
  burned_total:    Decimal,   // accounting / invariant aid
}
```

`A_u = Σ reservations.amount`; `σ_avail = amount − A_u`; `HasCapacity ⟺ σ_avail ≥ B_tx`. These predicates are pure functions of contract state — checked at sign by the proposer (using its view) and re-derived deterministically at accounting time from the frozen `tx_bonds`.

### 3.2 staking extension (expiry bonds)

```
ValidatorEntry += { expiry_reservations: Map<ResId, Decimal> }   // A_s = Σ
// σ_avail(s) = stake − A_s ; HasExpiryBondCapacity ⟺ Σ batch B_exp · (σ_s/Quorum) ≤ σ_avail
```

---

## 4. Contract surface (new core-context methods)

All amount-bearing methods are **core-context** (reactor-only); the reactor supplies frozen amounts. User-facing deposit/withdraw are proc-context.

**`bonds` contract**
- `deposit(ctx, kind)` *(proc)* — move spendable KOR (`ctx.signer()` → escrow), set/extend `unlock_height = height + T_bond` on first deposit (top-ups don't extend). `kind ∈ {user, publisher}`.
- `withdraw(ctx, amount)` *(proc)* — require `height ≥ unlock_height` and post-withdraw `amount ≥ A_u`; return KOR to signer.
- `reserve(ctx, owner, res_id, tx_id, position, sign_height, amount)` *(core)* — append a `Reservation`; extend `unlock_height ← max(·, sign_height + W + k)`. Called on batch publication.
- `release(ctx, owner, res_id)` *(core)* — drop the reservation, KOR stays in the bond (refundable). On Bitcoin-finalization, plain expiry, or cascading rollback of *other* users' txs.
- `forfeit(ctx, owner)` *(core)* — burn the **entire** bond, drop all reservations. On attributable Bitcoin-confirmed conflict.
- views: `get_bond`, `available`, `has_capacity`.

**staking contract (extension)**
- `reserve_expiry(ctx, validator, res_id, amount)` *(core)* — reserve `amount` against `σ_avail`; reject if it would drive `σ_avail < 0`.
- `release_expiry(ctx, validator, res_id)` *(core)* — on batch-confirmed or rollback.
- `burn_expiry(ctx, validator, res_id)` *(core)* — on expiry: reduce stake by the reserved amount and burn it (the expiry penalty, 100% burn).

**token / staking (ordering fees)** — reuse where possible
- `escrow_ordering_fee(ctx, payer, amount)` *(core)* — hold `f_ord` into escrow at batch inclusion.
- on confirm: `token::burn(escrow, τ_ord·Σf_ord)` + `staking::distribute_ordering_reward((1−τ_ord)·Σf_ord)` (already built, stake-weighted, exact-conservation).
- on expire/rollback: `token::burn(escrow, Σf_ord)` (100%).

**equivocation** — already built (`staking::slash_equivocation`, now with the self-publication guard); Phase 2 only adds the **reactor wiring** (consume the `AppMsg::Finalized { evidence }` that is currently logged and discarded at `reactor/handlers.rs:234`) and the broader "publisher ∉ signers" check (reactor has the signer sets).

---

## 5. The five flows (end to end)

1. **Ordering fee** — user attaches `f_ord`; escrowed at batch inclusion; on Batch-Confirmed, `τ_ord` (50%) burned, remainder paid stake-weighted to the batch's signers; on expiry/rollback, fully burned.
2. **Expiry bond** — at sign, each signer reserves `B_exp·(σ_s/Σsigners)` against `σ_avail` (per-batch cap `ε_batch=10%·σ_s`); released on Batch-Confirmed/rollback; **burned on expiry** (applied once at `b.expiry`, even if later late-confirmed).
3. **User griefing bond** — user maintains `≥ B_min` deposited; each ordered tx reserves frozen `B_tx`; released on Bitcoin-finalization/expiry/cascading-rollback; **entire bond burned** on attributable conflict.
4. **Publisher bond** — identical to (3), keyed by the bundler's publisher key; the *only* burn path for bundled txs (rolled-back users' `B_tx` released, not burned).
5. **Equivocation** — reactor detects conflicting signed batches at the same `batch_id`, verifies evidence, calls `slash_equivocation(offender, publisher)` (100% slash + eject; 5% bounty to publisher *iff* publisher ∉ signers, else full burn).

---

## 6. Batch-lifecycle integration (reactor hooks)

Mapping to the real reactor (file:line from the lifecycle survey):

| Lifecycle event | Reactor site | Economic action |
|---|---|---|
| **Sign** (proposer) | `batches.rs:make_value` (306) / sign in `consensus_state.rs:stream_proposal` (206) | compute `B_tx`/`B_exp` from `r_fee`, freeze into `tx_bonds`; check `EligibleForOrdering` / `HasExpiryBondCapacity` |
| **Publish / decide** | `batches.rs:process_decided_batch` (142) | `bonds::reserve` per tx; `staking::reserve_expiry` per signer; `escrow_ordering_fee` |
| **Confirm** | `consensus_state.rs:check_finality` (271) → `BatchFinalized` | pay ordering emission+fee to signers; `release` user/publisher reservations; `release_expiry` |
| **Expire** | `batches.rs:ResolveExpiry` (1127 in spec mapping) / finality deadline | `burn_expiry` (signer penalty); `release` user `B_tx` (plain expiry) |
| **Conflict / rollback** | `batches.rs:initiate_rollback` (523); `ResolveExpiry` conflict branch | `forfeit` responsible user/publisher bond; `release` downstream others; ordering fee burned |
| **Equivocation evidence** | `reactor/handlers.rs:234` (`AppMsg::Finalized { evidence }`) | `slash_equivocation` |

**Settlement savepoint discipline.** Confirm/expire/rollback run in the consensus result branch (`mod.rs:377`), outside the per-block savepoint that wraps storage settlement — so each settlement **event** opens its own savepoint and commits atomically. For one batch-confirmation that means paying every signer (emission + fee), releasing every `B_tx`/`B_exp` reservation, and burning the `τ_ord` share **all commit or all roll back** — never a partial payout (e.g. reservations released but fees unpaid). Group the savepoint by *event* (a confirmed batch, an expired batch, a rollback), not per-tx, and process events in canonical order (batch_id, then position). The checkpoint oracle (§7) catches any divergence if the discipline is violated.

### 6.1 Bond amount schedules (frozen at sign)

Both dynamic bonds are computed once by the proposing staker against the deterministic fee-insufficiency signal `r_fee(t,h) ∈ [0,1]` and frozen into the batch (`tx_bonds[i]` for `B_tx`; the per-signer `B_exp` reservation for the batch). They share one shape — the spec writes `B_exp` explicitly and says `B_tx` "mirrors" it; **pinned here** (the spec's stated gap):

```
B_exp(t,h) = min(B_exp,max, B_exp,base · (1 + k_exp · r_fee(t,h)))
B_tx(t,h)  = min(B_tx,max,  B_tx,base  · (1 + k_tx  · r_fee(t,h)))
```

Defaults (params.typ): `B_exp,base=1000`, `B_exp,max=100000`, `k_exp=4`; `B_tx,base=1`, `B_tx,max=10`, `k_tx=4`. Because the amount is frozen and replayed from `tx_bonds`, a later change to any of these constants never alters an in-flight reservation.

---

## 7. Validation & testing strategy *(first-class — build alongside, not after)*

Layered, cheapest-first; each layer targets a specific failure mode.

**L0 — Property tests (economic invariants).** `proptest` is already a dependency but only used for BLS no-panic. Add, on the pure/contract logic:
- *Conservation:* for any random sequence of deposit/reserve/release/forfeit, `bond.amount == σ_avail + A_u`; total KOR is conserved (escrow in == paid + burned + refunded); supply only ever decreases on burn.
- *Reservation integrity:* a reservation always releases/burns exactly the amount it consumed (the frozen-amount invariant), across interleaved parameter changes.
- *Bounds:* `B_tx ∈ [B_tx,base, B_tx,max]`, `B_exp ∈ [B_exp,base, B_exp,max]`, `σ_avail ≥ 0` always, `Σ B_exp per batch ≤ ε_batch·σ_s`.
- *Settlement conservation:* ordering-fee split `τ_ord·F` burned + `(1−τ_ord)·F` paid == `F` exactly (mirror of the existing distribute conservation tests).

**L1 — Lite contract tests.** Per-method, in the `test_runtime_with_genesis` harness (fast, funded identities): deposit/withdraw delays, capacity rejection, reserve→release vs reserve→forfeit, expiry burn reduces stake, self-publication already covered. One adversarial test per flow (the audit caught a real bug this way — make it routine).

**L2 — Consensus determinism (the ready oracle).** Extend `reactor_cluster_tests` (in-process BFT + MockBitcoin) and `RegTesterCluster` with scenarios that drive bonds through the full lifecycle — order→confirm→pay, order→expire→burn, order→conflict→forfeit→cascade — and assert `assert_checkpoints_match` across all nodes per height. Because all bond state flows through `insert_contract_state`, the checkpoint chain already fingerprints it; a single diverging bond balance fails the test. This is the strongest existing tool — lean on it hard.

**L3 — Adversarial / incentive tests.** Encode the attacks the spec names: double-spend grief (bond must burn), expiry grief (penalty must bite), equivocation + self-publication (bounty must be denied), low-fee unconfirmable batch (must be refused), Sybil bond churn. Each is a test that the *economically correct* outcome occurs.

**L4 — Economic simulation (see §8 — new infra).** Property/lite/cluster tests prove the *code* is correct and deterministic; they do **not** prove the *economics* are sound (is honesty the dominant strategy? do the bond sizes actually deter grief at the calibrated values?). That requires simulation.

---

## 8. Validation infrastructure — what exists, what's missing

**The economic model already exists** — `Documentation/modeling/` (the `kontor_v1` Python package): closed-form equilibrium + congestion simulator + Monte-Carlo tail-risk harness, with a pytest/Hypothesis suite and a reproducibility test that re-derives the v1-Parameter-Report numbers. It already pins ~80% of parameters, **including the bond/ordering economics** (`analyses/05_slashing_deterrence`, `06_ordering_bonds`, `07_griefing_bond_calibration`). So Phase 2's economic *parameters* are largely calibrated already; bond sizes (`B_exp,base=1000`, `B_min=100`, `B_tx∈[1,10]`, `ε_batch=10%`, `r_evid=5%`, `λ_slash=30`) come from it. **Do not rebuild this** — extend it.

What's genuinely missing, in priority order:

1. **The model↔implementation conformance bridge — the real gap.** The Python model is tested against `specs/params.typ` (`test_spec_consistency.py`), but **nothing checks that the Rust contract defaults match the spec/model values.** The deployed `staking`/`token`/`filestorage`/`bonds` defaults could silently drift from the recommended numbers. Close the loop: a single source of truth (`specs/params.typ`) and a check, per layer, that the model, the spec, and the Rust contract defaults agree. This is the conformance guardrail (project task #4) and it's what makes "calibrated" mean something at deploy time.
2. **The four un-pinned anchor parameters** (`c_stake`, `F_scale`, `φ_base`, `σ_min`) — the model deliberately leaves these to launch-time anchoring. Extend `modeling/` with analyses that recommend them given the reference assumptions (KOR/USD, target `|F|`, target USD-per-gas, decentralization preference). See the calibration note.
3. **Rust-side property tests** for the bond/settlement conservation invariants (L0) — `proptest` is already a Kontor dependency but used only for BLS no-panic. Cheap; adopt as standard.
4. **Differential / replay determinism oracle** — today only *cross-node agreement* is tested (the checkpoint chain); there's no *reindex-equivalence* (one indexer twice over the same history → identical checkpoint) or golden-checkpoint fixtures. A two-settlement-clock bond economy with frozen-amount replay is exactly where a reindex bug hides. (Fuzzing also absent; lower priority.)

---

## 9. Suggested implementation milestones

1. **Validate on the existing model first** — the bond/ordering economics are already in `Documentation/modeling/` (analyses 05–07); extend it for any new mechanism shape before writing contract code, rather than building from scratch.
2. **`bonds` contract** + property tests (user + publisher griefing bonds, deposit/withdraw/reserve/release/forfeit).
3. **staking expiry-bond extension** + ordering-fee escrow/settle (reuse `distribute_ordering_reward`).
4. **Reactor wiring** — the six hooks in §6, behind the existing finality path; equivocation evidence consumption.
5. **L2/L3 cluster + adversarial tests**; differential replay oracle.
6. **Calibration pass** with the simulator; freeze parameter defaults.

Milestones 2–3 are contract work (this track); 4 is reactor work (coordination with the consensus-engine owner); 1, 5, 6 are validation/analysis (this track).

---

## 10. Open questions

- **`r_fee` source of truth** — exact confirmed-Bitcoin percentile definition; must be pinned so independent re-derivation agrees. (The amount it feeds is frozen at sign per §6.1, so this only needs to be canonical enough that an auditor re-deriving a historical bond agrees.)
- **Bonds contract vs. staking for expiry bonds** — confirmed split here (griefing→bonds, expiry→staking); revisit if the reservation code wants to be shared.
- **Distribute-Equally remainder rule** — reconcile the spec's `H(seed‖id)` ranking with the implementation's sorted-last-absorbs-remainder (carries into ordering-fee payout); pick one canonical rule.

Resolved in this revision: the `B_tx` schedule (§6.1) and the settlement savepoint discipline (§6).
