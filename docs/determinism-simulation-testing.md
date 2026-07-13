# Deterministic Simulation Testing for Kontor

**Status:** design proposal.
**Thesis:** a reindex-diff is one assertion inside a much larger opportunity. Kontor is a deterministic state machine over Bitcoin — exactly the shape of system that FoundationDB, TigerBeetle, and CockroachDB test with **deterministic simulation + fault injection + invariant checking**, where every bug reduces to a single reproducible seed. We should build that, not a one-off oracle.

---

## 1. Why this, and why Kontor is unusually well-suited

For a metaprotocol, *any* nondeterminism in a consensus-affecting path is a permanent chain fork. Conventional tests sample the happy path; the bugs that kill consensus chains live in the interleavings — a message reordered, a node crashed mid-apply, a Bitcoin reorg landing during reward settlement, a `HashMap` iterated in insertion order in one run and rowid order in the next. You cannot unit-test your way to confidence there.

Kontor is well-positioned because determinism is already the *design goal*, and the scaffolding exists:
- **`lite_executor`** — the whole multi-node Malachite BFT reactor runs in-process.
- **`MockBitcoin`** — Bitcoin is already an injectable abstraction (blocks, confirmations, rollbacks).
- **The checkpoint hash-chain** (`database/sql/checkpoint_trigger.sql`) — a SHA256 state-root over every `contract_state` row; all economic state is fingerprinted for free.
- **`replay_blocks_from`** — state can already be re-derived.
- **The `Deterministic` / `NonDeterministic` `ExecutionError` taxonomy** — the runtime already classifies divergence risk at the source.

What's missing is the *driver* that turns these into a seeded simulator, the *faults*, and the *checkers*.

## 2. The technique stack (and where each comes from)

| Technique | Source | What we take |
|---|---|---|
| **Deterministic whole-system simulation** | FoundationDB (Flow), TigerBeetle (VOPR) | Run the *real* reactor single-threaded; route all I/O, time, network, and randomness through one seeded scheduler so a run is a pure function of its seed. |
| **Fault injection / "Buggify"** | FoundationDB | Seeded, feature-gated hooks that randomly clog/swizzle/drop messages, kill+reboot nodes, corrupt-within-tolerance, partition — forcing adversarial interleavings. |
| **History + invariant checker** | Jepsen, CockroachDB `kvnemesis` | Record the operation/result history and validate it against a model (here: economic conservation + the spec's ordering rules), not just a final snapshot. |
| **Metamorphic relations** | CockroachDB metamorphic testing | Run the *same logical history* through different paths/knobs and assert *identical consensus state*. Reindex-diff is one such relation. |
| **Golden state-roots** | general | Commit a checkpoint for a canonical history as a regression tripwire. |
| **Swarm + seed reproduction + shrinking** | FoundationDB, Hypothesis/proptest, Antithesis | Sweep thousands of seeds with varied fault profiles; every failure prints a seed that reproduces it exactly; shrink the failing schedule to a minimal counterexample. |

## 3. The Kontor instantiation

### 3.1 The determinism contract (what the seed must control)

A run must be a pure function of `(seed, scenario)`. Every nondeterminism source is routed through the seeded scheduler:
- Bitcoin: block arrival timing, contents, and **reorg depth/timing** (via `MockBitcoin`).
- BFT/network: message **delivery order, latency, duplication, loss**; proposer/leader timing.
- Node lifecycle: **crash, restart, late-join** timing.
- Inputs: transaction submission order / mempool contents.
- Randomness: all of it seeded (challenge seeds are already HKDF-deterministic; assert nothing else draws entropy).

Residual sources that must be **zero** in consensus paths — and which the simulator + reindex relation systematically flush out: wall-clock reads, `HashMap`/`Map::keys()` iteration order (the class of bug just fixed in challenge selection), and `f64` (the audit flagged a `reactor/batches.rs` instance). A **determinism-hardening audit** is part of this work, not separate from it.

### 3.2 The simulation driver

A single seeded loop. Each step the scheduler deterministically picks the next event — deliver message *m*, mine a Bitcoin block, crash node *n*, inject a depth-*d* reorg, submit tx *t* — advances exactly that, and records it. No real threads, no real sockets, no real clock. Reuses `lite_executor` + `MockBitcoin`. Runs far faster than real time, so a single core does thousands of simulated block-years.

### 3.3 The fault catalog ("Buggify for Kontor")

Feature-gated, seeded injection points:
- **Message**: delay (clog), reorder (swizzle), drop, duplicate.
- **Node**: crash + restart (forces replay/recovery), late-join (forces sync).
- **Bitcoin**: reorg of depth *d* (rollback cascade), late-confirming tx, RBF replacement.
- **Consensus adversary**: an **equivocating** staker (signs conflicting batches), a **silent** staker (liveness), a staker-set **partition** above/below the 2/3 quorum.
- **Economic-targeted** (the high-value ones): batch **expiry**; a **confirmed conflict at expiry** (cascading rollback); and the nastiest — a **Bitcoin reorg landing mid-settlement**, while rewards are being distributed or bonds released.

### 3.4 The invariant suite (the checker)

Asserted continuously (after each step) and at quiescence:

**Consensus safety**
- All live nodes share one checkpoint at each height.
- A finalized batch order never changes; no batched-UTXO is double-spent.

**Determinism (metamorphic — §3.5)**
- Reindex-equivalence and crash-restart-equivalence hold.

**Economic conservation** (the reason this matters for the bond economy)
- `Δtotal_supply == Σ mints − Σ burns` over any window.
- No negative spendable or staked balance, ever.
- `total_active_stake == Σ active validator stakes`.
- For every bond: `reserved + available == deposited`; a reservation releases/burns exactly the amount it consumed.
- A rolled-back transaction leaves **no** residual state.
- An expiry penalty is applied **exactly once**, even under late-confirmation.

**Ordering (spec conformance)**
- Batch-Confirmed txs execute at `(batch_id, position)`; block-end txs at `(h, i)`; a rollback cascades all positions ≥ the conflict.

**Liveness (weaker, sim-checked)**
- Progress under `< 1/3` faulty stake; graceful degradation to Bitcoin-only finality when consensus stalls.

### 3.5 Metamorphic relations

Same logical history, different path, **identical consensus state**:
1. **Reindex-equivalence** — index a history from genesis twice (fresh DB) → same checkpoint. The base case.
2. **Crash-restart-equivalence** — a run with a crash + `replay_blocks_from` at block *N* vs. one without → same final checkpoint.
3. **Batch-vs-block-end-equivalence** — a non-conflicting tx that gets *batched* vs. the same tx confirmed *without* batching (block-end append) → same final ordering/state (the spec says these converge).
4. **Knob-invariance** — randomize non-consensus knobs (component-cache size, batch interval within bounds, fuel cache) → identical checkpoint. Consensus state must not depend on them. (CockroachDB's "metamorphic constant" idea.)

### 3.6 Golden checkpoints & swarm CI

- **Golden state-roots**: commit the checkpoint of a canonical, fault-free, economically-rich history; CI fails if any change perturbs it (a tripwire that turns "did this refactor change consensus state?" into a red test).
- **Swarm job (nightly)**: thousands of seeds, each with a randomly-chosen fault profile (swarm testing: vary *which* faults are enabled, not just intensities). Bounded block budget per seed; run in release. On failure: print `seed` → one-command reproduction, then **shrink** the event schedule to a minimal counterexample.

## 4. Build path & sequencing

Reuse: `lite_executor`, `MockBitcoin`, the checkpoint chain, `replay_blocks_from`, the error taxonomy. Build: the seeded scheduler/driver, the feature-gated Buggify hooks, the invariant checkers, the metamorphic harness, seed-repro + golden fixtures, the CI swarm job, and the determinism-hardening audit.

**Sequencing — it is a companion to the reactor wiring, not blocked on it:**
1. **Now**: driver + checkpoint/reindex/crash-restart relations + the consensus-safety and ordering invariants, against *existing* paths (challenges, validators, batches, rollback). This alone is high-value — it hardens the current reactor and catches the residual `keys()`/`f64`/time nondeterminism systematically.
2. **With Phase 2 wiring**: the economic-conservation invariants and the economic-targeted faults (bonds, slashing, rewards, reorg-mid-settlement) become live. The frozen-bond-replay rule (reactor spec §6.1) and two-clock atomicity (§5) are precisely what only this suite catches.
3. **Ongoing**: grow the golden fixtures; widen the fault catalog; track simulated-block-years in CI as a coverage metric (FDB's headline number).

## 5. The honest hard part

The leverage is entirely in step 1's *first half*: making the whole system a pure function of a seed. Kontor is closer than most (deterministic-by-design, `MockBitcoin`, the lite cluster), but there will be a tail of residual nondeterminism to hunt down — and finding it *is the point*. Every source removed is a class of consensus fork eliminated, and the payoff compounds: once the simulator is sound, every future economic mechanism (every bond, every settlement path) inherits exhaustive, reproducible, fault-injected coverage for free.

## References

FoundationDB simulation & `BUGGIFY` (the canonical writeup: "Testing Distributed Systems w/ Deterministic Simulation", Will Wilson); TigerBeetle VOPR (Viewstamped Operation Replicator) & the deterministic state-machine model; CockroachDB `kvnemesis` and metamorphic testing; Jepsen (history generation + consistency checkers); Antithesis (autonomous deterministic-hypervisor testing). Kontor scaffolding: `core/indexer/src/reactor/{lite_executor,mock_bitcoin,consensus_state}.rs`, `database/sql/checkpoint_trigger.sql`, `reg_tester.rs:1586` / `reactor_cluster_tests.rs:667` (`assert_checkpoints_match`).
