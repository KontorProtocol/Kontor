# Kontor Economic Layer — High-Level Overview

**Status:** overview / map + **decision record**. A reading guide over the economic-layer
work — the high-level picture the per-mechanism specs assume but don't restate. Revised
against the 2026-07-12 design audit (model sound; wiring re-derived — see
`reactor-economic-integration.md`) and the four design decisions recorded 2026-08-24 (§0).
**Scope:** the *goals* of the economic layer and the *algorithms* that achieve them, plus
where each piece currently lives (main vs. open PR vs. external modeling repo).
**Not scope:** per-mechanism specification (see the linked PRs/docs) or parameter
*calibration* (lives in the separate modeling repo — see §7).

> Status snapshot is **as of this writing**; PR numbers and merge state will age. The
> goals/algorithms are the durable part.

---

## 0. Decisions (2026-08-24) — the four questions that gated the spec rewrite

The 2026-07-12 audit found the economic *model* sound and the *wiring spec* broken, and
named four decisions that had to precede the re-derivation. All four are decided (full
option analysis preserved in the "Kontor Econ v1 — Four Open Decisions" memo):

| # | Question | Decision |
|---|---|---|
| **1** | Parameter governance (#463) — can constants change after genesis? | **Class-scoped (Option C).** Consensus-computable values are formulas (never governed); the three price-coupled constants (σ_min, gas calibration, c_stake) get a bounded + timelocked + **irrevocably sunsetted** admin window; everything identity-shaped (μ₀, χ, τ_slash, …) is genesis-fixed. λ_slash is genesis-class but must be modeled before locking. |
| **2** | Storage self-dealing — junk earns exactly what value earns (ω_f cancels) | **Honest acceptance (Option A, per Adam).** The storage pool pays stake-proportional yield to whoever stakes and stores; ω-weighting is not anti-spam and is no longer described as such. The storage *guarantee* (permanence + PoR + slashing keeps files replicated) is unchanged. An NPV-of-fees gate remains a designed but undecided Phase-1.5 option. |
| **3** | σ_min — 5M KOR entry floor (~200-participant ceiling) | **Keep 5M, classified tunable (Option A).** The ceiling is an explicit accepted v1 constraint: storage operation is validator-gated; *users never stake* (balance + deposit floor only). Delegation is the designed add-on if operator breadth is needed. |
| **4** | λ_stake — spec says `Σk_f·λ_stake`, code says `Σk_f` | **Delete the symbol (Option A).** The security bound is the whole-pool saturating slash, not the join-time hold; the hold rations capacity. Consequence: the zero-stake **terminal-state machine** is a mandatory v1 item. Revisit trigger: Step-5 correlated-failure modeling (returns as genesis-class constant or formula, never admin — it is not price-coupled). |

---

## 1. The economy in one frame

Kontor is a metaprotocol that provides **optimistic ordering over Bitcoin**: transactions
are ordered and pre-confirmed *before* Bitcoin finalizes them. The economic layer has three
jobs:

1. **Pay for the network's work** — storage capacity and transaction ordering. (Per
   Decision 2: storage yield is stake-proportional — emission pays stakers who store;
   *demand* for valuable data is expressed through fees and agreement terms, not emission
   targeting.)
2. **Bond every promise** — so the optimistic pre-confirmation guarantee actually has teeth.
3. **Stay perfectly deterministic** — any disagreement on an amount or a settlement is a
   permanent chain fork.

The **supply side** runs on **one unified stake pool**: a validator's stake is simultaneously
its consensus voting power *and* its storage collateral (there is no separate storage bond) —
storage providers *are* validators. The **demand side** — ordinary users who just want a
transaction ordered — are **not** staked and **not** validators; they keep a plain identity
and post a separate, refundable **griefing bond** per use (§4). Everything shares one identity
namespace (the signer's x-only / BIP-340 pubkey, `Holder`); a validator is that same identity
plus a registered ed25519 consensus key and stake.

The work splits into two phases on two settlement clocks:

| | **Phase 1 — resource economy** | **Phase 2 — ordering/bond economy** |
|---|---|---|
| Settles | per Bitcoin block (`run_block_lifecycle`) | per batch event (confirm/expire/rollback, finality path) |
| Secures | storage, consensus security, blockspace | the optimistic pre-confirmation promise |
| Status | contracts in open PRs; reactor wiring pending (#442) | design-only (#443) |

**The architectural spine of both phases:** native contracts only *compute* allocations
(pure, deterministic, fixed-point `Decimal`); the **reactor moves the KOR** (via the core
signer) at the right lifecycle moment. A contract never reads wall-clock, mempool, or
optimistic state — the reactor passes everything in.

---

## 2. Program structure & status (the map)

The economic layer is a stacked series of **contract-only** PRs (each ships methods + lite
tests, with reactor wiring deliberately deferred), an open **reactor-wiring** tracking
issue, the **Phase 2 design**, and an **external calibration** model.

| Piece | Where | State |
|---|---|---|
| Storage audit (challenges) + validator processing | **on `main`** (`run_block_lifecycle`) | done |
| Storage-deposit FLOOR model + gas escrow | **on `main`** | done — the live economic mechanism |
| token: mint hardening + `Issuance` mainnet gate | **on `main`** (#437; gate merged) | done |
| Signer-keyed storage memberships (identity decision, §7) | **on `main`** | done — obsoletes #452's node_id |
| Creation-fee burn e2e | **on `main`** (#460) | done |
| The six econ contract PRs (#439/#440/#441/#445/#452/#453) | **being closed** per the audit | formula & test mines for the re-derivation — do **not** rebase (they encode the broken spec's conservation bugs) |
| **Reactor wiring — minimal v1** | `reactor-economic-integration.md` (re-derived) + #442 (to be rescoped) | **the build target** |
| Phase 2 ordering/bond economy (design) | `phase2-ordering-economy.md` (annotated: deferred) | design-only |
| Determinism-simulation test suite (design) | `determinism-simulation-testing.md` | design-only |
| Parameter calibration (the "why these numbers") | **separate modeling repo** (`kontor_v1`, `specs/params.typ`) | external; conformance bridge = pre-mainnet gate |

**Keystone:** every Phase-1 contract is *inert* until the reactor's `run_block_lifecycle`
(and, for Phase 2, the finality path) is wired to call it. That wiring is #442 — owned by
the reactor/indexer side, specified by `docs/reactor-economic-integration.md`.

---

## 3. Phase 1 — per-block resource economy

**Goal:** make storage, consensus security, and blockspace economically self-sustaining and
incentive-aligned, settled every Bitcoin block.

| Mechanism | Goal | Algorithm | PR |
|---|---|---|---|
| **Emissions** | Predictable inflation funds the system | Per block mint `ε = total_supply · μ₀ / B` (μ₀ ≈ 5%/yr, B = 52,560 blocks/yr). Split `storage = ε·(1−χ)`, `ordering = ε·χ` (χ ≈ 10%). Minted into **dedicated pool holders** (ORDERING_POOL; STORAGE_POOL from Step 5) — never CORE (the gas escrow `release()` sweeps), never via `issue_to` (a fresh mint). All payouts are transfers out of a pool. In v1 only χ·ε is minted (storage share computed, unminted, until the accumulator lands). | re-derive (was #439) |
| **Storage rewards** | Pay nodes to replicate *valuable* data; resist spam/whale capture | Per file: `rank_f = files_ever + r_offset + 1`; weight `ω_f = log(size)/log(1+rank_f)`; collateral weight `k_f = (ω_f/Ω)·c_stake·ln(1 + (|F|+1)/F_scale)`. Global `Ω` accumulates `ω_f` as files activate; `|F|` tracks active files. `distribute_storage_rewards`: split by `ω_f/Ω`, then equally among a file's active nodes; exact conservation via last-absorbs-remainder. **Per Decision 2 the yield is stake-proportional** (reward and collateral both scale with ω_f, so ROI is content-blind — accepted, stated honestly). **Deferred to Step 5 behind the O(1) accumulator** (`acc += pool/Ω` per block; snapshot at join/leave; lazy claims) — the naive per-block loop is O(files×nodes), the #489 chain-halt shape. | re-derive (was #441) |
| **Storage slashing** | Bond storage commitments; punish proof failure | Per block the reactor collects failed **and expired** challenges → prover is the signer (memberships are signer-keyed) → `slash(signer, λ_slash·k_f)`, saturating. **100 % burned** — `distribute_slash` is deleted from this path (paying co-nodes for a peer's failure was a sabotage incentive, and its escrow paths had two conservation bugs). τ/bounty machinery is reserved for the deferred equivocation path. Zero-stake ⇒ terminal-state unwinding (Decision 4). | re-derive (was #440 + #452) |
| **Node↔stake coupling** | Make slashing *resolvable* (a failed challenge must hit a real bond) | Memberships are **signer-keyed on main** (`(agreement_id, signer_id)`) — identity is structural (§7). Solvency at join is plain `Σ k_f ≤ stake` (λ_stake deleted, Decision 4). | on main + re-derive solvency check (was #452) |
| **Equivocation slashing** | Make double-signing irrational; pay for policing | `slash_equivocation(offender, publisher)`: **100% slash + eject**; `r_evid` (≈ 5%) paid to the evidence publisher's spendable balance **iff publisher ∉ signers** (else fully burned); remaining ≈ 95% burned. | re-derive (was #440) |
| **σ_min floor** | Keep the validator set from collapsing to dust/Sybil | `register_validator` requires `stake ≥ σ_min` (5,000,000 KOR, ~0.5 % of genesis; admin-window class, Decision 3; ~200-participant ceiling accepted explicitly). Genesis set exempt. | re-derive (was #453) |
| **Congestion pricing** | Demand-responsive, deterministic blockspace pricing (EIP-1559-style) | Multiplier `β(t)` by utilization `u`: `u < u_low` → decay `β·λ_decay`; `u_low ≤ u < u_high` → smoothstep ramp (floored by the decay term); `u ≥ u_high` → compound `max(β,1)·(1 + κ·(u − u_high))`. Fee `= φ_base · β`. (u_low ≈ 20%, u_high ≈ 80%, λ_decay ≈ 0.95, κ ≈ 2.0.) | re-derive (was #445) |

**Phase-1 in one line:** mint ε → reward useful storage (`ω_f/Ω`) → punish failed storage
and equivocation (slashing the same stake) → price blockspace (β) → floor the validator
stake — every block, all on deterministic `Decimal`, contract-computes / reactor-moves.

---

## 4. Phase 2 — per-batch ordering/bond economy

**Goal:** the optimistic pre-confirmation is *only worth what's bonded behind it*. Phase 2
bonds the three ways the promise can break: a user double-spends after being ordered; a
staker signs a batch that never confirms; a staker equivocates.

| Mechanism | Goal | Algorithm |
|---|---|---|
| **Ordering fee** `f_ord` | Pay stakers for ordering; price spam | Escrow `f_ord` at batch inclusion. On **confirm**: burn `τ_ord·Σf_ord` (≈ 50%), pay the rest stake-weighted to signers (the per-batch signer-set extension of v1's `distribute_ordering_reward`; the closed #440's version is a mine, not a reuse). On **expire/rollback**: burn 100%. |
| **Expiry bond** `B_exp` | Liveness pressure — only sign batches you believe will confirm | At decide, each signer reserves its stake-share `B_exp·(σ_s/Σ_{signers}σ_{s'})` — shares sum to exactly `B_exp` — against available stake (sign-time pre-check via the conservative quorum-denominator bound; per-batch cap `ε_batch·σ_s`, `ε_batch ≈ 10%` — `phase2-ordering-economy.md` §3.2). Released on confirm/rollback; **burned on expiry** (once, even if later late-confirmed). |
| **User griefing bond** `B_tx` | Make double-spend grief costly | User keeps `≥ B_min` deposited; each ordered tx reserves frozen `B_tx`. Released on Bitcoin-finalization / plain expiry; **entire bond burned** on an attributable Bitcoin-confirmed conflict. |
| **Publisher bond** | Hold batch bundlers accountable | Identical to `B_tx`, keyed by publisher key; the only burn path for *bundled* txs (rolled-back users' `B_tx` is released, not burned). |
| **Equivocation wiring** | Give Phase 1's `slash_equivocation` teeth | The reactor consumes the `AppMsg::Finalized { evidence }` it currently logs and discards, verifies it, and calls `slash_equivocation`. |

**The key Phase-2 algorithm — frozen-at-sign determinism.** Dynamic bonds are computed
**once**, at sign time, from a deterministic fee-pressure signal `r_fee ∈ [0,1]`:

```
B_exp = min(B_exp,max, B_exp,base · (1 + k_exp · r_fee))
B_tx  = min(B_tx,max,  B_tx,base  · (1 + k_tx  · r_fee))
```

…then written into `batch.tx_bonds[i]` and **read, never recomputed**. Larger bonds when
fees are high (when grief is most profitable); frozen so a later parameter change can't alter
an in-flight reservation; every node replays the same number from the canonical batch log.
This is the determinism linchpin of the optimistic economy.

---

## 5. Cross-cutting algorithmic principles

These are shared by both phases and are the parts most worth scrutinizing — they're where
consensus forks hide.

1. **Determinism.** Frozen amounts (Phase 2); `r_fee` derived only from Bitcoin-*confirmed*
   fee state (never optimistic mempool); sorted/canonical iteration everywhere; **no `f64`,
   no `HashMap` iteration order, no wall-clock** in any consensus-affecting path. The SHA256
   checkpoint chain fingerprints all economic state, so cross-node divergence is caught by
   `assert_checkpoints_match`.
2. **Conservation.** Every flow either moves or burns KOR; `distribute_*` use
   last-recipient-absorbs-remainder for exact conservation; total supply only ever decreases
   on burn.
3. **Two settlement clocks, different atomicity.** Per-block settlement runs inside the block
   savepoint (atomic with the block). Per-batch settlement runs *outside* it — each event
   (one confirmed/expired/rolled-back batch) opens its own all-or-nothing savepoint. Group by
   event, not per-tx. This boundary is where partial-settlement bugs live.
4. **Contracts compute, reactor moves.** Contracts return allocations (the `distribute_*`
   pattern); the reactor credits/burns/transfers under the core signer. No user signer ever
   reaches these paths.

---

## 6. Validation strategy

`docs/determinism-simulation-testing.md` proposes proving the above via **deterministic
simulation testing** (FoundationDB `BUGGIFY` / TigerBeetle VOPR / CockroachDB metamorphic
style): a seeded whole-system simulator over the existing `lite_executor` + `MockBitcoin`,
fault injection, continuous economic/consensus invariant checks, and metamorphic relations
(reindex-, crash-restart-, batch-vs-block-end-equivalence). The economic invariants it
asserts are exactly the conservation / no-negative-balance / penalty-applied-once / frozen-
amount-replay properties above. It is sequenced to start on *existing* paths, independent of
the Phase 2 wiring.

---

## 7. Identity architecture & the storage `node_id` question (#452)

**Status:** **DECIDED — option B.** Storage memberships key on the signer; a signer occupies
at most one slot per agreement. The rationale is *legitimacy/optics, not security* (see the
decision note below). Captures the reconciliation of the identities the economic layer touches.

A participant appears to carry many cryptographic identities, but the honest count is smaller:
two of the five are the *same* identity in different forms.

| Identity | Scheme | Role | Verdict |
|---|---|---|---|
| **x-only pubkey** | secp256k1 / BIP-340 | Bitcoin-native identity, on-chain `Holder` | one canonical identity… |
| **signer_id** | `u64` | registry handle for the x-only key (`HolderRef::SignerId`); what contracts key on | …in two representations |
| **consensus key** | Ed25519 | Malachite BFT vote signing | keep separate (below) |
| **BLS key** | BLS12-381 | aggregation (batch attestations, challenge seed) | separate; can share a seed |
| **node_id** | free-form `String` | storage-membership label (#452) | **redundant — remove** |

So it's really **1 canonical identity** (x-only ⇄ signer_id), **2 purpose-specific keys**
(consensus, aggregation) kept separate for good reason, and **1 redundant label** (`node_id`).

### Consensus key: keep it separate from the Bitcoin key

Tempting to make consensus sign with the x-only key (one key for Bitcoin + consensus —
Malachite's `SigningScheme` is pluggable and already ships secp256k1-ECDSA). **Don't:** it
would put the funds-controlling Bitcoin key *hot* on the validator box (every vote signed
there), so a node compromise risks coins. Arc keeps these separate for exactly this reason (a
dedicated remote-signer for the hot ed25519 key). And separation costs nothing in
key-management — derive the consensus (and BLS) keys from the *same* HD seed as the taproot
key (Kontor's keygen already derives ed25519 + x-only from one master): one backup, hot/cold
boundary intact.

### `node_id`: remove it; key storage on the signer

`node_id` is a free-form, **unauthenticated** `String` the caller hands to `join_agreement`
(never checked against `ctx.signer()`), used as the challenge `prover_id`. It's a parallel
identity namespace storage invented, and it's the root of #452.

*Constraint check — it does **not** block the change:* `kontor-crypto` only requires
`prover_id` to be non-empty and `≤ MAX_IDENTIFIER_LEN_BYTES`, hashed as opaque length-prefixed
bytes (never parsed as a key); the file ledger doesn't reference node identity at all. So a
`signer_id`-as-string works, and the PoR proof then binds to the slashable stake by construction.

| Option | Shape | Trade |
|---|---|---|
| **A — #452 (baseline)** | free-form label + `owners: node_id → Holder` side-table | preserves multi-node-per-stake; keeps the parallel namespace + a binding map; one identity can *visibly* fill several slots of the same agreement |
| **B — `node_id == Holder`/signer_id *(DECIDED)*** | drop the param; derive identity from `ctx.signer()`; one membership per signer per agreement | auth & slashability become *structural* (no side-table); proof binds to stake; the one-slot-per-signer property falls out of the map keying (no extra check); **net-negative LOC.** Cost: "N slots = N staked signers" — existing multi-label-per-signer usage must change |
| **C — composite `(signer_id, label)`** *(rejected)* | signer from `ctx.signer()` + label as sub-key | re-admits the exact case B exists to prevent (one signer, many labels, same agreement); no longer on the table |

**Decision (from the protocol designer): B — but as a legitimacy guardrail, not a security
boundary.** Two points settle it:

1. **There's no real *functional* reason to forbid a signer appearing multiple times in one
   agreement** — we forbid it only because an agreement visibly served by one identity *N*
   times is indistinguishable from one genuinely served by *N*, and that looks terrible. B
   gets this for free: a membership map keyed by signer structurally can't hold the same
   signer twice, so the guardrail *is* the data shape.
2. **Proof of replication is provably un-enforceable.** Replication is meant to arise from
   *economic incentives* (pay nodes to store; pay more for more copies), not from a protocol
   primitive. Kontor's challenge layer is proof-of-*retrievability* — `prover_id` only
   personalizes which positions are challenged against the same Merkle root, so one physical
   copy answers every prover. No amount of identity engineering changes that; sealing/PoRep is
   explicitly **off the roadmap**.

So B is the **permanent, correct** answer, not a stopgap — there is no missing proof
primitive to wait for, because the primitive is impossible. **Be careful not to oversell it:**
B blocks only the *same-key-twice* cosmetic case. A single operator running one physical copy
behind *N* distinct signer keys is still undetectable — and that is *expected and accepted*
under the economic model, not a hole B fails to close. **C is rejected** precisely because it
would re-admit the same-identity-many-slots case B is meant to remove.

**Orthogonal:** the solvency check (`stake ≥ Σ k_f`) and slash firing stay **reactor-side**
regardless (the no-native→native-view-call limitation, not an identity issue). B just makes
the reactor's resolution trivial — `prover_id == signer_id`, so it calls
`staking::slash(signer_id, …)` directly.

---

## 8. How to read this / what's not here

- **Goals and algorithms** live here and in the per-mechanism PRs/docs.
- **Calibration — the "why these constants"** (the bond sizes, μ₀, χ, λ_slash, σ_min, the β
  knobs) — is **not in this repo**. It lives in the separate `kontor_v1` modeling package and
  `specs/params.typ`, referenced by #445/#453. To analyze whether the numbers actually deter
  the attacks, that repo is required reading.
- **The reactor wiring is the unbuilt keystone** — specified by the re-derived
  `reactor-economic-integration.md` (v1); issue #442 is being rescoped to it. Until it
  lands, nothing mints/slashes/rewards on-chain, and the Phase-2 per-batch clock has
  nothing to drive it.
- **The public docs-site economics pages** carry the pre-Decision-2 emission story
  ("inflation pays for useful storage") and need the honest-acceptance correction —
  tracked as a separate follow-up.

**References:** #437, #439, #440, #441, #445, #452, #453 (Phase 1 contracts); #442 (reactor
wiring); #443 (`phase2-ordering-economy.md`, `reactor-economic-integration.md`,
`determinism-simulation-testing.md`); the external `kontor_v1` modeling repo.
