# Reactor ⇄ Economic-Contract Integration Spec

**Status:** proposal / hand-off spec.
**Audience:** the reactor (indexer-proper) owner. Consolidates the wiring sketched in tracking issue #442 and Phase 2 design (#443 §6) into one boundary contract.
**Scope:** how the reactor drives the native-contract economic primitives — what it calls, when, with what privilege, and under what atomicity and determinism rules. It does **not** redesign the contracts (those are specified per-contract) or the consensus protocol.

---

## 1. The model in one paragraph

The native contracts hold balances and expose deterministic primitives that *move KOR given an amount*. The reactor owns the lifecycle and supplies the amounts. Nothing in a contract reads wall-clock, mempool, or optimistic state; the reactor passes everything in. This mirrors how challenge generation and validator processing are already wired — the economic settlement is more of the same, on two clocks.

## 2. Two settlement clocks

| Clock | Trigger | Reactor site | Settles |
|---|---|---|---|
| **Per Bitcoin block** | block finalized | `run_block_lifecycle` (`reactor/blocks.rs:196`), inside the block savepoint | emissions mint, storage rewards, proof-failure slashing, validator/epoch transitions, equivocation |
| **Per batch event** | batch confirm / expire / rollback | finality path (`consensus_state.rs:check_finality` → `mod.rs:377`), own per-event savepoint | ordering fees + emissions to signers, expiry-bond burns, griefing/publisher-bond release/forfeit |

The privilege handle for every state-changing call is the existing core signer: `Signer::Core(Box::new(Signer::Nobody))` (`blocks.rs:197`), which resolves to `CORE_SIGNER_ID` and bypasses gas. All economic methods below are `core-context`.

## 3. Per-block sequence (extends `run_block_lifecycle`)

```
run_block_lifecycle(block):                         [inside the block savepoint]
  set_context(height)                               [existing]

  ── Phase 0 · Mint ───────────────────────────────────────────────
  e = token::mint_emission()        → {total, storage=(1-χ)·e, ordering=χ·e} to CORE
                                       (new call, before challenges)

  ── Phase 1 · Storage audit ──────────────────────────────────────
  expire_challenges(height)                         [existing]
  generate_challenges_for_block(height, hash)       [existing]

  ── Phase 2 · Storage settlement (new) ───────────────────────────
  for (node, k_f) in filestorage::collect_failed_challenges():     ← affordance #1
      r = staking::slash(node, λ_slash · k_f)
      staking::distribute_slash(co_nodes, r.redistributable)
  for (node, amt) in filestorage::distribute_storage_rewards(e.storage):
      token::issue_to(node, amt)

  ── Phase 3 · Validators (existing + extend) ─────────────────────
  process_pending_validators(height)                [existing]
  for ev in evidence_this_block():                  ← from AppMsg::Finalized, today dropped
      staking::slash_equivocation(ev.offender, ev.publisher)

  ── Phase 4 · Epoch boundary (new, gated) ────────────────────────
  if height % EPOCH == 0: snapshot staker set; process service-unbonding queue
  commit()                                          [existing]
```

## 4. Per-batch sequence (finality path)

Each event opens its own savepoint and is **all-or-nothing** (see §5). Process events in canonical order `(batch_id, position)`.

```
on batch-confirmed   (check_finality → BatchFinalized):
    pay signers: ε_ordering share (stake-weighted) + (1-τ_ord)·Σf_ord ; burn τ_ord·Σf_ord
    release every B_tx (user/publisher) and B_exp (signer) reservation for the batch
on expire            (deadline passed, not confirmed):
    burn each signer's B_exp penalty (once, even if later late-confirmed)
    release the users' B_tx (plain expiry, refundable)
on rollback/conflict (initiate_rollback / ResolveExpiry conflict branch):
    forfeit (burn) the responsible user OR publisher griefing bond
    release downstream other-user reservations ; burn the ordering fee
```

Bond amounts are **read from the batch's frozen `tx_bonds`**, never recomputed (the determinism linchpin — see §6 and #443 §6.1).

## 5. Atomicity & privilege rules

- **Block clock**: Phase 0–4 run inside the existing block savepoint (`blocks.rs:288`–`302`), so they're atomic with the block. A failure in any phase rolls back the whole block.
- **Batch clock**: runs *outside* the block savepoint. Each settlement event (one confirmed batch, one expired batch, one rollback) gets its own savepoint and commits atomically — paying signers, releasing reservations, and burning either all commit or all roll back. Never leave reservations released but fees unpaid. Group by event, not per-tx.
- **Privilege**: every call uses the core signer; no user signer ever reaches these paths. Crediting `token::issue_to` / burning / transferring is the reactor's responsibility — the contracts compute and return allocations (the established `distribute_*` pattern), the reactor moves the KOR.

## 6. Determinism requirements (non-negotiable)

Any divergence here forks the chain. The reactor MUST:
1. **Replay frozen bond amounts** from `tx_bonds` — never recompute `B_tx`/`B_exp` from current `r_fee` at settlement.
2. Derive `r_fee(t,h)` only from **Bitcoin-confirmed** fee state, never optimistic mempool.
3. Iterate every settlement set in a **sorted, canonical order** (the same discipline the contracts now use after the challenge-selection fix).
4. Use **no wall-clock, no `HashMap` iteration, no `f64`** in any consensus-affecting path.

These are exactly the properties the determinism-simulation suite (`docs/determinism-simulation-testing.md`) is built to enforce.

## 7. Contract-side prerequisites (what must exist before wiring)

These affordances don't exist yet; they're contract work (the economic-layer track), and they gate the wiring:

- [ ] **#1** `filestorage::collect_failed_challenges() → [(node, k_f)]` — expose failed/expired challenge results for the slash loop.
- [ ] **#2** node-identity coupling — `filestorage` node ids are free-form strings today; they must map to staking identities for slashing/stake-sufficiency.
- [ ] **#3** `token::mint_emission` callable per-block by the reactor (it already reads supply; confirm the call shape).
- [ ] **#4** `staking::slash` to take `k_f` and apply `λ_slash` internally, or the reactor computes `λ_slash·k_f` (decide where `λ_slash` lives).
- [ ] **#5 (Phase 2)** the `bonds` contract + the staking expiry-bond extension + ordering-fee escrow must exist before the per-batch clock can be wired.

The storage/staking per-block half (§3) is wireable once #1–#4 land; the per-batch half (§4) needs the Phase 2 contracts (#443).

## 8. Validation

The checkpoint hash-chain (`database/sql/checkpoint_trigger.sql`) already fingerprints all economic state, so cross-node agreement is checked for free by `assert_checkpoints_match`. Beyond that, every rule in §5–§6 is a target of the **deterministic-simulation test suite** — see the companion design `docs/determinism-simulation-testing.md`. In particular the frozen-amount replay rule (§6.1) and the two-clock atomicity (§5) are precisely the properties that only a reindex/fault-injection oracle catches.

## 9. Ownership

| Piece | Owner |
|---|---|
| §3–§5 reactor wiring | reactor / indexer-proper |
| §7 contract affordances | economic-layer track |
| §4 ordering/bond clock | needs Phase 2 contracts first (economic track), then reactor wiring |
| §8 determinism suite | shared (testing infrastructure) |

References: tracking issue #442, Phase 2 design #443, `reactor/{blocks,batches,consensus_state,handlers}.rs`, `native-contracts/{token,staking,filestorage}`.
