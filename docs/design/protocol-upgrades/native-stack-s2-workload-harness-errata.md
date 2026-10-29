# Workload harness implementation errata

This note amends the exact-field model in
`native-stack-s2-workload-harness-v1.md`, whose approved SHA-256 is
`4591f9d60881c8875eb5dddb5aa785c306861ce1a01dafaffe4ad2e72430ddb2`.
The original plan remains unchanged so its review identity is preserved.

## Indexed history identity

The manifest's `execution` object additionally requires
`starting_block_height: u64`, greater than zero and no greater than the
snapshot anchor height. The runtime must use this value when constructing
the fixture history. It must not silently substitute a different genesis or
indexed range.

Interlink review message `2e6fe5dfb298b63cd360348daaf61704` requested this
binding when approving development setup at Bitcoin height 93, real indexed
history through 101, and the smoke block at 102. Review message
`dec80417b8bda7b7016c64f125a2cf35` accepted the implemented field and requested
this explicit erratum.

## Receipt interpretation

Each of the three direct smoke operations has `result_index: 0`.
`Runtime::set_context` resets the result counter before each operation;
these particular calls have no guest subcalls, and the internal fee
hold/release receipts are suppressed. This is separate from `op_index`,
which advances through 0, 1, 2. Synthetic validation examples now reflect
that production behavior.

`staking.get-active-set` returns canonical Holder keys in its field named
`x_only_pubkey`. The development runner resolves the funded public key to
its database signer identity before checking this field. It does not
compare the returned key directly to a raw public-key string.

## Current development runner

`reactor::workload_tests::smoke::workload_real_block_smoke` is an explicitly
ignored local-bitcoind test. It uses the existing launcher, compose and
signing helpers, actual mempool validation and mined bytes, followed by two
independent snapshot replays through `Reactor<RuntimeExecutor>::handle_block`.
It checks receipt attribution, successful writes, rollback, useful pruning,
retention of a successor, fee burn and native lifecycle accounting.

The candidate is deliberately distinct from a frozen v1 fixture. Its output
sets `frozen_acceptance: false`. When `KONTOR_WORKLOAD_CANDIDATE_DIR` is set,
it preserves the snapshot, raw block, database projections and receipt
reports in a new directory. An existing directory is rejected. Failed runs
can leave partial diagnostic output, which must not be accepted as a fixture.

The corrected development replay passed at checkout `61abc95f170ad801ea821e8dcd45d69ed589236c`:
one test, two independent restores, 60.55 seconds after a 32.41-second
incremental compile. Its preserved log SHA-256 is
`8609e5ccf310240be49faa8c006a828e2cf00b3b80d372be2631744bdc28a7f6`.
That binary reported the stale embedded revision `18c9e6a87ac8d6f518122d8f513a625c2e0c3927`.
The indexer build script tracked protobuf files but did not invalidate Git
metadata after commits. This run establishes development behavior, not
source-bound qualification. Build metadata invalidation was corrected in
`ae27aa9c7f0aa21e13d70f0ed3d39d356e3580e3`; seven incremental Cargo scenarios
passed, including packed refs and linked worktrees. Its real replay also
passed and reported the correct embedded revision. This tracks commits,
not every uncommitted edit to source files;
qualification must check the compiled revision against the clean source
checkout as well as retaining executable hashes.

The independent numeric diagnostic was added in
`a9efb879bf2b809af8f5600d41c713cca3fbba92`. On a third reset it preserves
decoded operation context and measures each `Runtime::execute` call
separately. Every paid receipt and accumulated user, system and deposit
fuel must exactly match each full-block replay. The integrated test passed
in 64.69 seconds. Both saved replays also passed the existing Python
numeric validator, including the precise failure message and canonical
monetary values. The failed middle operation consumed 9 units of storage
reservation but left the payer floor unchanged at `0.000000014`.
The preserved log SHA-256 is
`6c06e1739fd038d149ce3292c294bbc3664cbe785b6d71c77f3560409e06401f`;
the numeric report SHA-256 is
`b59df3791aae56d939393419269d0655ca0c92a58c9a4e1b0f0be060e69fe7d6`.

Complete typed reports and source/artifact/Bitcoin metadata were added through
`f5a9c4bce2ce0c825dc92ca8793a640ec9031e36`. The integrated run passed in
72.32 seconds. Both restored reports equal the original before report;
both final reports agree. Observation must leave the full database
projection unchanged. Capture requires a clean checkout matching the
embedded revision before and after generation, and preserves the actual
contract bytes, lockfile, SQLite schema, Bitcoin acceptance records and all
101 funding-chain blocks.

The complete candidate manifest passes `load_frozen_documents`, including
all file references, typed reports and numeric checks. Additional inspection
matched the schema projection and contract bytes to the saved database.
Candidate manifest SHA-256:
`859b847fa0b4ce334be22445779c5489552131bf0776bcd56445dc84653b7ae9`.
Run log SHA-256:
`a219010361ce9a1ac5f5389226eb7932d5f74d4f08a092a1917d96fb6ae6f577`.
That revision was a checked development candidate. It cannot stand in for a
newer compiled revision. The strict replay described below uses regenerated
inputs at its own source revision.

## Pinned smoke replay

`71aa0a136aa328771adf843243a6966ebafd6e4a` implements
`reactor::workload_tests::smoke::frozen::workload_frozen_replay`.
It requires `KONTOR_WORKLOAD_MANIFEST` and a separately pinned
`KONTOR_WORKLOAD_MANIFEST_SHA256`. The shared closed-schema validator runs
with Python environment and site hooks disabled. The Rust runner binds the
compiled source, compiler, lockfile, actual input bytes, artifacts, pricing,
engine, schema and operation contexts. A fresh bitcoind accepts the saved
funding chain and measured block. An independent numeric replay and two
fresh full-runtime restores must reproduce the frozen reports exactly.
Both full database projections must agree, and observations must not mutate
persistent state. Input and clean-source identity are checked again at exit.

Candidate generation at this exact revision passed in 72.26 seconds after
a 39.74-second build. The separate frozen replay passed in 51.87 seconds.
Its manifest SHA-256 is
`bb020c06641160129d57c7923ebe3a71b40f39c0eedb88f945a6959022216470`;
the replay log SHA-256 is
`776f668529a92203e50d27f81925ac65e0a7886bac32b4c957e87a64e667f4b9`.
Four actual-binary controls rejected a wrong manifest digest and changed
block, snapshot and artifact bytes. An earlier runner also rejected the
old `f5a9c4bc` fixture specifically for its different source revision.

Generate a candidate only from a clean committed checkout, using the
development test and a new `KONTOR_WORKLOAD_CANDIDATE_DIR`. Then run:

```sh
python3 -E -S -B tools/native-stack/assemble_workload.py path/to/candidate
```

The command refuses to overwrite an existing candidate manifest. Review
and pin its returned digest before running the ignored frozen replay test
with the two manifest environment variables. Generation and replay must
use the same committed source. A mismatch is a failure, not a reason to
automatically regenerate expectations. The assembler's output remains
`frozen_acceptance: false`; actual replay and review are separate gates.
The fixture preserves Bitcoin timestamps, so replay also requires the local
clock to permit those blocks under bitcoind's timestamp rules.

The smoke has one active validator
and no storage agreements; its zero storage-reward assertion does not
qualify populated storage accrual. No timing or six-cell performance claim
follows from this development test.

Even with `consensus_enabled: false`, the existing Malachite startup opens a
WAL. Each development replay therefore uses its own engine directory and
stops and awaits the engine on normal completion. This tests fixture
isolation, not the eventual incompatible-protocol engine handoff.

## Validator population preparation

`0dc6b6987a45c08607e44808ce310b673135311f` adds a deterministic validator
population builder with distinct Bitcoin and consensus keys. The focused
test uses four active validators and schedules two departures and two
replacements through the paid native APIs. It verifies ordered active
identities, consensus keys and weights, retained staking escrow, liquid
balances, collateral floors, execution burns and outstanding token supply.
Burned tokens remain in the burner ledger but are excluded from supply.

Two independent database restores verify unchanged state before the due
height, both transitions at the due height, and idempotent repeated
processing. The original snapshot's runtime remains unchanged. The focused
test passed in 46.87 seconds after a 32.34-second build; its log SHA-256 is
`b4b3e563eff339d04d4a7c09c8f8ce643d74182133a2bd952807c3cab1c7778b`.
An earlier test exposed an incorrect fixture assumption that burned fees
were still outstanding supply. The correction changes test accounting,
not the token contract.

This helper uses synthetic block hashes and direct lifecycle calls. It
prepares validated state for later workload integration; it does not
qualify full Reactor execution, larger validator populations, performance,
or the proposed operational envelope. Parent and independent subagent
reviews and independent Interlink review are complete for this bounded scope.

## Storage population preparation

`1326545afcd87a37dfe08e2c8e15105891ad9d2d` adds populated storage setup
using deterministic host keys and actual `prepare_file` descriptors. It
creates all agreements before joining hosts, then derives admission weights
and collateral from that known state. Funding covers the complete reservation
sum, bond headroom and paid execution. Checks reconcile membership indexes
with point lookups, descriptors, ledger slots, reservations, liquid balances,
floors, staking escrow, execution burns and outstanding supply.

Setup runs the actual registry-root hook before exporting its baseline, so
seeded files do not count as measured-block append work. Independent full
aggregation must match the stored root and reconstructed frontier. Reads of
the pinned storage layout verify the drained append queue, frontier and next
slot counts, active-file ordinal array and total storage weight. Two fresh
restores repeat the root hook and verify that it adds no new root or work.

The focused test uses two files and three hosts. At the exact revision above
it passed in 59.09 seconds after a 35.50-second build. Its log SHA-256 is
`d2f737eff478ba75d877e625683635483552feb19614d53b92111e321e5dda73`.
Parent, independent subagent and independent Interlink source/evidence
reviews are complete for this bounded scope.

This is state preparation, not a full Reactor or performance result. Larger
populations, rewards, challenges and production proof dimensions still need
integration. Regtest initializes eight proof challenges, while production
networks initialize 100; the full workload must preserve the selected
network's semantics rather than treating this regtest fixture as equivalent.


## Populated full-block replay

`452fae0543d34621f1bc40c00e9ca0eca9e48c98` integrates the validator and
storage builders into a bounded full Reactor replay. Actual regtest blocks
89 through 101 establish history. The prepared state has four current
validators, two scheduled exits and two scheduled joins due at 102, plus two
storage agreements with three hosts. Setup uses native APIs before the
measured block. Block 102 contains the actual signed three-operation
transaction used by the earlier smoke test.

Two independent snapshot restores run the same block through the Reactor.
Checks cover complete receipt attribution, gas and persisted fuel, paid-call
rollback, ordering rewards from captured pre-block stakes, validator status
and cached voting-set changes, storage reward liabilities and rounded funding,
and liquid balances, escrow, burns and total supply. Independent integer
arithmetic derives the storage reward amounts. Full database projections must
agree, and observations must leave state unchanged. Any generated challenges
must have valid agreement links and regtest parameters; this does not require
a particular challenge count or verify proofs of retrievability.

At that exact clean revision, both focused tests passed in 53.20 seconds,
including the negative-amount oracle control. The successful log SHA-256 is
`3a172d5960e39724ca14ee1a9f7761b47c456d45cb476ba71be3824662d3d797`.
The first restricted-sandbox attempt could not start bitcoind's HTTP server;
it is not acceptance evidence. The successful run permitted local networking.
Parent, independent subagent and independent Interlink source/evidence
reviews are complete for this bounded scope.

This remains a small development fixture using the existing consensus-disabled
decision helper. It does not establish a frozen populated manifest, production
proof dimensions, consensus handoff, large-population capacity or performance
qualification. The existing filtered transaction index in receipts remains an
explicitly observed limitation, not a corrected transaction-identity policy.


## Explicit population configurations

Source `e66771e7cf2e29f8aad26ae5de72cd3b12b08227` adds a separate ignored
configured replay while preserving the original fixed population test.
`KONTOR_WORKLOAD_POPULATION` must contain exactly `active_validators`,
`replacements`, `agreements` and `members_per_agreement`, all integer counts.
For example, a development configuration is:

```json
{"active_validators":16,"replacements":1,"agreements":4,"members_per_agreement":5}
```

Select `workload_configured_population_replays_transitions_and_rewards`
with `--include-ignored --nocapture` to run it. The configuration is printed
before setup and again only after both replays pass. There is no default for
this separate test. `replacements` counts pairs: one means one due join and
one due exit, two transitions total. The expected post-block active population
remains `active_validators`. This particular reward fixture requires at least
one replacement and one unchanged ordering-reward recipient. Every agreement
uses the same deterministic host set; membership distribution is not varied.

The oracle checks the configured counts before execution and after transitions,
and derives cached voting power from exact stake atoms instead of assuming
100 for every validator. Invalid counts and checked setup arithmetic are
rejected before bitcoind startup. A configuration parser test covers malformed,
duplicate and unknown fields and arithmetic overflow.

The source was validated at documentation-only head
`0c85013682f61987754cfa87c038921174974086`. The configuration rejection test,
negative-amount control and original fixed replay passed, three tests in
53.75 seconds after a 69-second build. Baseline log SHA-256:
`30e37ae4af84cf88dac499041d0735ced904be3677fb3eb17f3a999e849e6fc1`.
The separate 16-validator, one-replacement-pair, four-agreement, five-host
configuration then passed its two-restore replay in 58.86 seconds. Its log
SHA-256 is
`ec64acee676fe7fa1265040d63f4de9b13431bf04a2796269cdd524de8a63302`.
These are test durations, including setup, not block service measurements.

Parent, independent subagent and independent Interlink source and evidence
reviews are complete. No production population, performance threshold or
populated frozen manifest is approved by this configuration API.


## Useful pruning in populated replays

`d48e9e3ebc40df8ac9458da4682a30ee30dfc030` adds a direct pruning witness to
both populated replay configurations. It selects an actual superseded state
version from heights 89 through 95 and saves the newest nondeleted version
at or below 96, including its deposit metadata. After each full block
application, the persisted pruning watermark must be 96, the selected old
version must be absent, and its retained successor must be unchanged.
Requiring a nondeleted successor avoids treating legitimate terminal tombstone
reclamation as a failure. All observations remain within the database
mutation guards.

This check matters because block application can return success even when
best-effort pruning fails. It proves useful removal of a selected historical
version in both independent restores, not exhaustive pruning correctness.

The exact clean revision passed all four selected tests serially in 112.15
seconds after a 57.06-second build: both population replays, invalid population
controls, and the negative-amount control. Log SHA-256:
`4cb8fb545e5b7661f1554cb756f4a9f616bfc78fa01f361eec28c873be938695`.
Parent and independent subagent source/evidence reviews are complete.
Interlink review `d27b59de00dad305b794df00076e92ad` approved this bounded
source and evidence; its subagent-follow-up condition was subsequently
satisfied. No performance or full workload qualification follows from this
result.

The returning Interlink reviewer also closed the prior bounded smoke,
validator, storage and initial populated replay evidence in messages
`4e2a105d372e4b54fcac586a54b085d6`,
`4e0471caf9d1cf3f9c9b84617842cbc4` and
`f7800724a93f12701339911fc2ea7c6d`. These approvals preserve the limitations
recorded above, including regtest proof dimensions and the consensus-disabled
execution helper.
