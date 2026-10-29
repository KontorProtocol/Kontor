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


## Reconciliation with the current S2 candidate

Preparation source `b8bbdfd0c2876ac55b48929a92cad314a9a2b331` ports this harness
onto S2 source `35ee59d0a0cd31dd2626723c9562f1d815eb7766` in the isolated
`native-stack-workload-reconcile` worktree. Donor source is
`7bc47388951865fb86ead66e802a526e7efcdf81`, based on `67a52fed`.
Twenty added files are byte-identical to the donor. The three integration deltas
(test module registration, Bitcoin submission and regtest startup helpers) are
identical; current surrounding source is preserved. The donor's build-script
change was already present and is not duplicated. No production runtime code
changed in this port. Parent, independent subagent and Interlink source reviews
accepted the bounded reconciliation; Interlink receipt
`3202b4225a85e3d2e8fc40427286d999` was acknowledged.

The existing 21 Python tests pass in 0.026 seconds. A locked, offline, two-job Rust
no-run build passes in 1 minute 46 seconds. Its development test binary hashes to
`c6f4df89aac19a03d466d956f302e2ebb9b6ccf6bd40f888d883ddd5f343c57c`.
Seven ordinary workload tests pass in 108.62 seconds, covering snapshot export,
independent restoration, native-state reopening, validator/storage population
setup, invalid configurations and the negative-amount oracle control.
The real-block smoke and populated replay were then explicitly enabled against
local regtest Bitcoin processes; both pass in 125.16 seconds. Their original
accounting expectations are unchanged. These times include fixture setup and
are not operational block-service measurements.

The ignored configured-population and frozen-manifest replay tests are not claimed
as covered by this run. Donor captures are not upgraded to current-source evidence.
Further S2 source reconciliation, an exact frozen operational manifest, reference
profiles and the performance acceptance campaign remain required. The completed
35ee59 boundary capture was preserved in its separate frozen worktree and binary.

Required Clippy initially failed with four imported helper findings and six
findings in unchanged S2 source. Follow-up `8f793dc782c4fed3cb540388775ba784e80c80c7`
replaces three unsigned divisibility expressions with `is_multiple_of(1000)` and
uses a vacant map entry for one host initialization. Both independent reviewers
and the parent verified preserved call/error order and unchanged expectations.
Its no-run build passed in 39.01 seconds; binary SHA-256 is
`6dd38d95d61536fd6be0fa6f229eb501e2805e30dfaa5b6cd89e175bc6bcfd52`.

The populated replay and two oracle/configuration controls passed. The smoke test
then refused the parent's uncommitted documentation draft at its clean-checkout
guard, before execution. That failed run (three passed, one failed, 53.49 seconds)
is preserved. Moving the draft to the ignored evidence directory and restoring
the tracked document resolved the precondition. Only the failed smoke test was
rerun on the same binary and passed in 71.85 seconds. No runtime, fixture or
expected values were changed to address the guard failure.

Clippy was rerun and still exits 101 with exactly six existing S2 findings, all
outside the workload port: a redundant copy clone, items after a test module, a
collapsible conditional, two divisibility expressions and a constant chunking
idiom. The native-stack implementer owns their correction in Stage 1. No lint
was suppressed, and this is not a green-Clippy or merge-ready claim. Commands,
log hashes and terminal results are in the local
`.build-cache/workload-reconcile/validation.json`. Parent and both independent
reviewers accepted this bounded evidence and documentation, including the failed
run and unresolved S2 lints. Interlink receipt
`102b3903e7d6e04a103b331b6dd19e72` was read and acknowledged. Exact dirty-file
history and binary continuity across the retry are recorded execution metadata;
raw logs independently establish the guard failure and subsequent test result.
All parent checks are terminal and the single build slot is released.

## Real batch execution followed by confirmation

Source `d62f8fd1d6045c8d1409946651b51deb21d821e6`, based on `fb12d0b8`, adds
a second delivery mode to the populated workload runner. Two independent restores
execute the same signed reveal through `process_decided_batch` at anchor 101,
then confirm it through the real `handle_block` at 102. The batch must execute,
initially retaining an unconfirmed transaction and three paid receipts. After
confirmation, the transaction row ID, execution anchor, batch height, complete
paid receipts and persisted fuel must remain unchanged. The legacy joined ordinal
changes to zero, while the separate raw Bitcoin confirmation index is two.
A direct count across all receipt heights rejects extra or hidden paid receipts.

The existing independent fee, supply, reward and validator-transition oracle,
useful-pruning assertions, successful effects and failed-write rollback checks
remain active. Complete final database projections must match between restores;
observation calls must not mutate state. The combined anchor and block receipts
are ordered by persisted ID. Empty certificates exercise an already-decided
execution path, not certificate authorization, consensus or finality validation.

Parent and both independent source reviews accepted the exact commit, including
Interlink receipt `c08840931e7eb634f7e82f8f3a332058`. The locked, offline, two-job
no-run build passed in 55.18 seconds. Development binary SHA-256:
`406511f27d9b4ecb7d93f7b34190db96617916134cfdf74b32afac073b82ec91`.
Both explicitly enabled tests, batch-confirmation and the existing fresh populated
block replay, passed in 106.91 seconds. This elapsed time includes setup and is
not a performance qualification measurement.

Clippy still reports exactly the six inherited S2 findings above, with no new
workload finding. No suppression or runtime change was made. The local evidence
record `.build-cache/workload-reconcile/batch-confirmation-validation.json`
preserves commands, terminal results and hashes of all three logs. Parent and both
independent reviewers accepted the bounded evidence and documentation, including
Interlink receipt `49afd2f9f8e484760f5dddd9327896b2`. Commands and terminal exit
codes are parent-recorded metadata consistent with the independently read logs.
Full operational mixes, arrival traces, simulations,
population selection, frozen manifests and performance qualification remain open.

## Simulation rollback before canonical execution

Source `10cbc8cbfbde280a1f7787b9913aef332b549957`, based on `6e54b3de`, adds
two real `Reactor::simulate` calls before the batch-confirmation workload. In each
of two independent snapshot restores, both simulations must restore the complete
logical projection of non-`sqlite_*` tables, storage height, simulation flag and
reactor tip. Each returns three materialized operations, two successful and one
deterministic failure with an error message. The complete returned results must
match between simulations. Their receipt outcomes must then match canonical batch
execution, excluding only discarded receipt IDs, execution height and the joined
confirmation ordinal. Existing fee, supply, reward, transition, pruning and
independent-reset assertions remain active.

The fixture calls do not read height, and both simulation and canonical paid
execution precede block maintenance. This is not general equivalence between
simulating at the next height and executing at an earlier batch anchor. It also
does not establish a cold/warm cache gate: startup can preload components, and
simulation deliberately avoids persisting speculative cache entries. The test
covers completed simulations with an embedded deterministic operation failure,
not infrastructure-error or cancellation cleanup, API admission queues or load.

Parent and both independent source reviews accepted the source, with the final
change limited to an explanatory comment. The no-run build passed in 37.41 seconds;
binary SHA-256 is
`b0cac2d8621404598da3b2076abf9c87003da10fca1209380d9b0ee38b4a559f`.
The explicitly enabled simulation regression passed in 97.85 seconds, including
fixture setup. Clippy reports the same six inherited S2 findings and no new
workload diagnostics. Their fixes exist on the separate native Stage 1 branch;
this workload branch has not yet integrated that source.

Commands, terminal results and three log hashes are recorded in
`.build-cache/workload-reconcile/simulation-validation.json`. Parent and both
independent reviewers accepted the bounded evidence and documentation, including
Interlink receipt `00d7fe03663bf43b86edb75da81f6ab9`. Commands, checkout history
and terminal exit codes are recorded execution metadata consistent with the logs.
This completes no performance or full S2 acceptance gate.


## Mixed paid operations and nested receipt accounting

Sources `0333a40d46229cdd83feb91bce453d98dbe6278c` and
`3028085d1a90730bf61d9983fd20a21ed6c387b2`, based on `70e3ee50`, add one
signed, single-input reveal with 100 operations. Five rounds contain 40 token
transfers, 25 storage operations including 10 post-write failures, 15 proxy
calls, 10 staking calls and 10 hash writes. Each restored execution must produce
100 root receipts and 25 nested receipts with the expected positions, signers,
payers, status, values and gas bounds. Highest result indices select root gas,
so nested work is counted once. The accounting oracle reconciles 0.04 transferred
and 0.01 staked separately from fees, including staking escrow and token supply.
An explicit setup check rejects an existing payer bond. New bonds are inactive
and cannot receive the ordering rewards checked by the existing oracle.

The test verifies counter and blob state, failed-write rollback, independently
calculated SHA-256 values, recipient funds and the payer bond. Existing validator
transitions, storage rewards and challenges, useful pruning, read-only observation
checks and exact logical database equality across two independent restores remain
active. The four guest fixtures are published directly through Runtime with Core
during setup. This does not cover signed publication transactions or cold publish.

Parent and both independent source reviews accepted final `3028085d`, including
Interlink receipt `d70d72c3772fb4fb0167db1c0bf4ff50`. The locked offline two-job
build passed in 52.08 seconds. Binary SHA-256:
`963e7b9d4cd7b61e3ddf20a7feae5f7eedece0cbb8b10fd693dcb4f3210573dd`.
The new mixed test passed in 58.49 seconds. All three existing fresh-block,
batch-confirmation and simulation regressions passed in 204.46 seconds on the
same binary. These durations include fixture setup and are not performance
qualification measurements. Clippy still reports exactly the six inherited S2
findings, with no workload diagnostic; their separate native-branch fixes have
not yet been integrated. No lint was suppressed.

The local `.build-cache/workload-reconcile/mixed-validation.json` records commands,
terminal outcomes, binary identity and hashes of four logs. Parent and both
independent reviewers accepted this bounded evidence and documentation, including
Interlink receipt `aaf392564ad9ed40ef1236989b0219a8`. Commands, historical checkout
checks and terminal exit codes are recorded metadata consistent with the logs.
This is one development recipe, not the full operational workload.
Multiple transactions, multi-input and BLS shapes, pagination, file appends,
near-cap operations, frozen populations, arrival streams, cold-cache and
performance qualification remain required.


## Fifty and five hundred signed transactions

The many-transaction workload distributes the mixed recipe across 50 or 500
real signed reveals, with two executable operations in each single input. It
uses 5 or 50 rounds of the existing mix, giving 100 or 1,000 operations. Setup
spends the mature height-1 coinbase into a funding fanout confirmed at block 101.
Each commit/reveal pair must pass Bitcoin mempool acceptance. The generated
block fixes their order and must contain exactly those pairs after its coinbase.
The confirmed fanout avoids shared unconfirmed-ancestor limits.

Checks cover decoded transaction identities and raw positions, one input and
two operations per reveal, persisted confirmation height and both the filtered
and raw Bitcoin ordinals. Every transaction must have exactly one persisted
usage record, whose user and deposit fuel reconcile with its own root receipts.
The aggregate fee, transferred funds, new bonds, supply, rewards, validator
transitions, storage lifecycle and pruning remain independently checked. Nested
receipt selection now includes transaction identity, since operation indices
repeat. Both independent snapshot restores must produce identical complete
logical projections. Earlier fresh, batch-confirmation, simulation and single-
transaction mixed delivery modes retain their assertions.

The logged shape records actual block bytes, weight and SHA-256. The 50-reveal
fixture contains 101 Bitcoin transactions and the 500-reveal fixture contains
1,001, counting commits and coinbase. These workloads retain four active
validators, two replacements and two agreements with three members each. They
do not qualify the proposed full state populations, maximum Bitcoin capacity,
multi-input/BLS signers, pagination, file appends, near-cap cases, cold
compilation, arrival streams or performance gates.

Final source `1d51c4c662ac89cbb430c9272f674d41ff909c65`, based on
`dfd14159fe5066821ef771b6b6b7386e727efc87`, passed all three source reviews,
including Interlink receipt `fd2722ed8347ccb9e681a34114517d38`. The locked offline
two-job build passed in 40.93 seconds. Binary SHA-256:
`21f43be3f8df446adccafde89d6cff741aa1170dcf8ed8d23db7706683318e40`.
All six delivery tests passed on that binary in 429.57 seconds. Each test runs
two independent restores. The 50-reveal block had 29,401 bytes and weight 64,726;
the 500-reveal block had 291,743 bytes and weight 638,924. These test durations
include setup and are not workload performance measurements.

The earlier two-case run passed in 166.78 seconds before the one-line chunking
lint correction. The initial compilation failure, SQL borrow fix, and the new
chunking lint failure remain recorded. Final Clippy reports exactly the six
inherited S2 errors, with no workload errors. Their native-branch fixes remain
separate pending integration. No lint was suppressed and this is not a green
merge candidate.

The local `.build-cache/workload-reconcile/many-validation.json` records commands,
terminal results, source and binary identities, actual block shapes, and hashes
of all seven logs, including failures. The raw block hashes are specific to each
regtest run, not a frozen qualification input. Full operational populations,
remaining transaction shapes and the final cross-platform qualification remain
required. Parent and both independent reviewers accepted this evidence and documentation,
including Interlink receipt `800ee73f8cafc2cdcf55f0224ca97624`. Historical binary
identity, commands and terminal exit codes are recorded parent observations
consistent with the logs; reviewers did not rerun the shared binary after release.


## Multiple inputs and distinct BLS signers

The signed shape variants reuse the 100-operation mixed workload, its 125
receipts, validator and storage lifecycle checks, pruning, and two independent
snapshot restores. Both have two distinct Bitcoin identities and one fee payer.
The direct variant puts 50 executable operations in each of two inputs. A
Sponsor directive at the end of input zero pays for input one; it emits no
contract receipt. The aggregate variant puts all 100 operations in one input,
alternates two BLS signers, and opts every operation into publisher sponsorship.

The fixture signs every commit and every reveal input, requires actual Bitcoin
mempool acceptance before broadcast, and mines the transactions in a fixed order.
The raw confirmation ordinal is three for the two-commit direct variant and two
for the one-commit aggregate variant. Decoded instructions, signatures, Bitcoin
input keys, stored confirmation metadata and every receipt position are checked.
The test checks each operation's actual signer and payer separately, including
nested receipts. Each signer's transfers and bond follow its own operations.
The secondary balance loses exactly its transfers and stake, with no gas charge;
the primary pays all gas and only its own transfers and stake. Total staking
escrow and supply continue to reconcile independently.

For aggregates, fixture nonces start at 7 and 19 and must finish at 57 and 69.
Deterministic contract errors still consume their signer's nonce. BLS registration
uses Runtime::register_bls_key with valid RegistrationProof values; nonce seeds
use advance_nonce, and Core funds the secondary with 100 tokens. These are
prepared state, not signed registration, issuance or nonce-initialization
transactions. The contract fixtures are also Core-published during setup.

These cases do not establish unsponsored aggregate coverage, the 10,000-operation
aggregate boundary, larger populations, cold compilation, arrival/load behavior
or full cross-platform qualification. Final source `a8ccf3e8eece49a41c8fbffdc46d27de8e83eca4`, based on
`0dd5d8227d1d7e0ac70b61164cf38ee54c431268`, passed all three source reviews,
including Interlink receipt `7de9051deea45f05e3e01cb7006097ed`. The locked offline
two-job build passed (reported 1m00s). Binary SHA-256:
`f6b6e82abc524f219c4453cd0a014ee237c8c759bc9d91765f7138f938c002b1`.
All eight modes passed on this binary in 549.88 seconds, including the six
existing delivery modes. Each case executes twice from independent snapshots.
These durations include setup and are not performance qualification.

The aggregate block contained three Bitcoin transactions, 7,951 bytes and
weight 9,319. The two-input block contained four Bitcoin transactions,
7,897 bytes and weight 9,799. Both carry 100 executable operations; the direct
input instruction counts are 51 and 50 because Sponsor is a directive.
Final Clippy still reports exactly six inherited S2 findings and no workload
finding. Their separate native-branch fixes await integration; this is not a
green merge candidate and no lint has been suppressed.

The ignored `.build-cache/workload-reconcile/shapes-validation.json` records
source/binary identity, terminal results, exact shapes and hashes of three logs.
The raw block hashes identify this regtest run, not frozen qualification inputs.
Parent and both independent reviewers accepted this evidence and documentation,
including Interlink receipt `f45d28841b53f7fc3eebc17141ad37a0`. Historical binary
identity, commands and terminal exit codes are parent-recorded observations
consistent with the logs; reviewers did not rerun the shared binary after release.


## Bounded storage cursor workload

The pagination variant adds a dedicated `workload-storage` contract. It leaves
all existing contract binaries, their provenance, and the shared counter source
byte-identical to `e154e995`. Only this variant publishes the new contract and
seeds 257 entries through Core before taking its state and accounting baseline.
Core publication and seeding are prepared state, not signed setup transactions.

The 100-operation mixed workload replaces five storage-read slots with calls to
the new contract. Forward pages contain entries 0..127, 128..255 and 256; reverse
pages contain 256..129 and 128..1. Every returned key and value is checked against
an independent expected sequence. Fixed-width string keys preserve numeric
ordering under the storage codec. Cursor bounds are exclusive. Additional
observation views check the final reverse entry, exhausted cursors in both
directions and zero-length pages. The guest uses a bounded row iterator, with
128 entries per page at most. These are contract-level cursor pages, not a claim
that SQLite internally fetches rows in batches of 128.

The test retains mixed-operation receipts, rollback, fee and collateral
accounting, validator/storage lifecycle checks, pruning, and two independent
snapshot restores. The final database projection includes all seeded entries.
Resource ownership was traced through the iterator and host row resource;
this case adds no separate lifecycle-counter measurement. It is a bounded
257-row development diagnostic, not the planned 10,000/100,000-key populations,
load testing, or full six-cell qualification.

Final source `6a9857832f73459551ddb6f256992b712835f2e9` passed all three source
reviews, including Interlink `ed8e6480f8652e2619be6d3c64928d52`. The pinned
`tools/kontor build test --runtime podman -j 2` and its `--check` rerun passed.
New compressed artifact SHA-256:
`af367f8fb004d62f15ab83c5c46656394157ac1ce6f814d08c799491484f9a03`.
The first two generation attempts failed because the new crate lacked the WIT
dependency link and because exported tuples are unsupported. The final crate
uses the conventional built-in WIT symlink and a named `entry` record. Both
failed logs are preserved alongside the successful results.

The locked offline two-job node build passed in 54.41 seconds. Binary SHA-256:
`6f45aeaddd10ddc7ba8b6259d1cf0072c79f6985ca85c45603c74fe0311a90f8`.
Pagination, plain mixed operations, multi-input sponsorship and sponsored BLS
all passed in 237.63 seconds on that binary. The fresh-block, batch, simulation,
50-transaction and 500-transaction modes last passed at `a8ccf3e8`; they were not
rerun at this head. This duration includes setup and
is not performance qualification. Clippy reports the same six inherited S2
findings, with no new workload finding. Their native-branch fixes await
integration, so this is not a green merge candidate; no lint was suppressed.

The ignored `.build-cache/workload-reconcile/pagination-validation.json` records
source and artifact identities, commands, terminal outcomes and hashes of seven
logs, including both initial generation failures. Parent and both independent
reviewers accepted this evidence and documentation, including Interlink receipt
`bc6391def8be7719071ee84ca84c4373`. Historical binary identity, commands and
terminal exits are parent-recorded metadata consistent with the logs; reviewers
did not rerun the shared binary after the build slot was released.


## Signed file registration and block registry append

The signed-file variant combines the bounded pagination workload with five
`create-agreement` operations. Each round replaces the second staking call with
one file registration, keeping 100 paid operations. This leaves 100 root receipts
and 20 nested receipts, with total new stake 0.005. Descriptor bytes are prepared
locally using `prepare_file` and deterministic nonces, but the agreements do not
exist in the baseline. Real payer-signed Bitcoin operations create them.

Each receipt's agreement ID and every stored descriptor field are checked.
New agreements occupy the next five ledger indices, remain inactive, and have
no members or active challenge. Weight and collateral are exact cross-checks
of the pinned native `compute_collateral` formula. They are not an independent
pricing oracle. Inactive registrations leave the active count and total weight
unchanged, although their increasing indices change the rank.

The real block lifecycle must produce exactly one successful `record-block-root`
receipt. Checks cover the unchanged active-file cursor, two retained root-history
entries, an empty append queue, frontier count and next ledger index. A full
`aggregate_root_from_files` over the baseline plus new files must match the
persisted incremental frontier and newest root. The earlier root remains intact.
The existing reward, host-obligation, challenge, fee/collateral, pruning and
whole-database replay checks remain enabled. Each mode executes twice from
independent snapshot restores.

Source `fec1d174f280a4568d8e4d1e1b8b98aaf3e7342a`, based on `ee3764fe`, passed
all three source reviews, including Interlink `854ff914906ef80f6e9151cc9a27e68c`.
The final source follow-up only explains the mirrored collateral calculation.
The locked offline two-job build passed in 48.91 seconds. Binary SHA-256:
`f001150cd576460ab2d94a9156a576ab35e3afec6ca3808c9c93b9008579bbae`.
Signed files and the pagination regression both passed in 123.27 seconds.
Plain mixed operations, multi-input sponsorship and BLS last passed at `6a985783`;
fresh-block, batch, simulation, 50-transaction and 500-transaction modes last
passed at `a8ccf3e8`. Those eight other modes were not rerun at this head.
Clippy still reports only the six inherited S2 findings; their native-branch
fixes await integration, and this is not a green merge candidate.

This evidence covers five successful inactive registrations and one block's
ledger append. It does not qualify malformed or duplicate descriptors, joins,
activation, proofs, cleanup backlog, large registries, operational performance,
or the final six-cell campaign. Setup and elapsed test time are not performance
measurements. No contract artifact changed in this addition.
The ignored `.build-cache/workload-reconcile/files-validation.json` records
commands, source/binary identities, terminal outcomes and three raw-log hashes.
Parent and both independent reviewers accepted this evidence and documentation,
including Interlink receipt `3777a2c91aaef3463d9a30cdcde426aa`. Historical binary
identity, commands and terminal exits are parent-recorded metadata consistent
with the logs; reviewers did not rerun the shared binary after slot release.

## Configurable mixed workloads

The configured replay combines population preparation with 50 or 500 signed
Bitcoin transactions, each containing two executable operations. Set
`KONTOR_WORKLOAD_CONFIG` to a JSON object with `population` and `mixed`:

```json
{"population":{"active_validators":4,"replacements":2,"agreements":2,"members_per_agreement":3},"mixed":{"transactions":500,"live_keys":100000,"new_files":100}}
```

Select the ignored test
`workload_configured_mixed_replays_populations_and_accounting`. It rejects
unknown or duplicate fields and invalid population, transaction, key and file
counts before starting bitcoind. The transaction choices describe the existing
fixture shapes, not protocol admission limits. The key bound preserves lexical
ordering of the fixture's eight-digit keys. Input bytes are hashed and the
parsed configuration is printed alongside the actual serialized transaction
shape and operation counts.

Each 20-operation round retains eight transfers, five storage operations
(including two deliberate failures after writes), three proxy calls, two
staking/file calls, and two hashes. File registrations replace the second
staking slot first, then the first slot of enough rounds to reach the requested
count. Descriptor indices follow actual execution order, which matters because
registry rank affects collateral. The initial b539362c implementation duplicated
descriptors in doubled rounds. Independent review caught this; a4f5aaea fixes it
and checks all 112 permitted round/allocation combinations. Runs print paid
staking and file counts separately. A 100-file, 1,000-operation run has zero paid
staking operations, although the block's staking lifecycle still executes.
`proxy_calls` counts root proxy operations; `nested_receipts` also includes
staking children. Pagination is a subset of the storage category.

Pagination seeds the configured number of real contract keys through the
existing bounded seed operation. Large keyspaces use paid page requests in
both directions, spread from the first through the last page. The 257-key,
five-round diagnostic retains its original page order. Boundary views check
empty and zero-limit results separately. Every result page, receipt, transfer,
stake, hash, file descriptor and registry root is checked. Two independent
snapshot restores still exercise real block application, native lifecycle,
accounting, confirmation positions, useful pruning and logical-state equality.

Source through b5e42cc9 has all three reviews. This is a configurable correctness
harness, not the frozen operational manifest or a performance acceptance run.
Full validator/agreement populations, historical-row counts, challenge/cleanup
backlogs, near-cap compute, cold compilation, mixed signer shapes in this new
configured delivery, arrival streams and enforced memory profiles remain to be
integrated and qualified. Existing multi-input/BLS tests are separate modes.

Validation at b5e42cc9 uses the development test binary with SHA-256
`167e7d8cedaad4d1d44fab320d63c28fde00ca044aae4fa273f0c4dc59359752`.
The no-run build passed in 1m00s; all three focused configuration/allocation/page
schedule tests passed in 0.01s. A 50-transaction run with 10,000 keys and six new
files passed in 77.21s. A 500-transaction run with 100,000 keys and 100 new files
passed in 287.46s. Each uses four validators, two replacements, two baseline
agreements and three members per agreement. These durations include fixture
preparation and two replays, so they are not block-service performance samples.
The 50-transaction case recorded 32,532 block bytes and weight 67,857; the
500-transaction case recorded 343,212 bytes and weight 690,393. These include
coinbase and commit transactions. Both were accepted by the local Bitcoin
regtest node.

The first sandboxed 50-transaction attempt failed before workload execution:
bitcoind could not start its HTTP server on eight port attempts. A separate
loopback socket check returned `PermissionError: [Errno 1] Operation not
permitted`. The same binary and input then passed outside that sandbox with
explicit tool approval. Both attempt logs are retained.

Both original pagination and signed-file regression tests also passed at this
head (123.34s combined). Clippy reported exactly the six inherited S2 findings
already assigned to the native branch, with no workload finding. Other delivery
modes were not rerun at this head. The seven logs, including the failed sandbox
attempt, are hashed in `.build-cache/workload-reconcile/configured-validation.json`.

## Saved configured inputs and fresh-process replay

The configured generator can retain its validated inputs by setting
`KONTOR_WORKLOAD_SAVED_DIR` to a new directory outside the checkout or in an
ignored path such as `.build-cache`. It refuses an existing directory. Saving
runs only after both original oracle replays and the unchanged-source-state
check succeed. The saved files are `snapshot.db`, `block.bin`, `chain.json`,
`before.json`, `after.json`, and `manifest.json`. The snapshot includes the
published contract artifacts and existing local metadata. The chain records
all 101 original ancestor blocks, including the confirmed funding fanout.

The manifest binds every input hash, configuration, Bitcoin version, source,
Cargo.lock hash, compiler/profile/features and producing executable hash.
The reader requires the same source/build and executable. This intentionally
rejects cross-build or S1/S2 comparisons; it does not remove provenance or
receipt-epoch rows to make a comparison pass. The reader compares every row
and column returned by the existing projection of all non-SQLite-system
tables. It does not require byte-identical post-execution SQLite files.

All files refuse overwrites. Metadata and block files use temporary staging;
the snapshot is copied directly with hash verification and removal on error.
The manifest is published last. A failed generation leaves its partial directory
for diagnosis. This provides manifest-last visibility and content integrity,
not power-loss durability: the containing directory is not explicitly fsynced.
Output placement is documented rather than rejecting all paths inside the
checkout, because ignored directories are supported. Dirty source is rejected.
Both nonblocking review dispositions were accepted explicitly.

Run the ignored `workload_saved_configured_replay` test with
`KONTOR_WORKLOAD_SAVED_MANIFEST` and
`KONTOR_WORKLOAD_SAVED_MANIFEST_SHA256`. It refuses extra or missing files,
changed hashes, paths escaping the fixture directory, and a different binary
or build identity. It verifies the stored snapshot before opening a private
copy. A fresh bitcoind imports the original chain and block without mining;
its version, hashes and returned raw block bytes must match. Two independent
snapshot copies then undergo real Reactor block application and pruning.
Their complete logical projections must match before startup, after startup,
and after execution. The original snapshot is hashed again afterward.

At source 9b92fc9243e7d1352b0de5e53a6c731fea0cd6f6, the no-run build passed
in 49.71s. Executable SHA-256:
`0b0a84c4891ef3756410e7987a871c516ed82ba83e9fb657e11aa349a43243e2`.
A 50-transaction, 10,000-key, six-file fixture passed generation and its two
oracle replays in 104.28s. Manifest SHA-256:
`85ceefd2535e76c116871f9162ec795328c86c16a11f24d8c7a93824f96b912e`.
A separate process imported that fixture and passed two more replays in
49.11s. Its measured apply intervals were 12,007,473,680ns and 11,848,193,671ns.
They are explicitly diagnostic-only measurements on the development build,
not operational service-gate or performance acceptance samples.

This fixture still uses four validators, two replacements, two active
agreements and three members per agreement. Full W_op populations and
workloads, operational arrivals, enforced memory profiles, cross-build
comparisons and final qualification remain outstanding.

Twelve actual-binary negative controls rejected an incorrect manifest digest,
missing/extra files, changes to each of the five input files, a changed binary
identity, a changed source identity, a symlink escaping the fixture directory,
and generation into an existing output directory. Each required a nonzero
exit and its expected error; the original manifest remained unchanged.

Clippy initially found one new redundant `Ok(...?)` wrapper in directory
entry parsing. Commit 498270c6 removes that wrapper without changing the
returned Result. Its Clippy run reports only the same six inherited S2 errors.
Runtime and saved-input evidence above belongs specifically to 9b92fc92,
before this lint-only correction; it was not relabeled as a new build. The
final S2 source will require fresh qualification. Both Clippy logs, the
control script/results and individual rejection logs are retained.

## Retained application history

Configured workloads accept `mixed.historical_rows` (default zero), up to twelve
versions per live key. When history is nonzero, the existing workload-storage
component is published at height zero. Real Core guest calls then write prefix-shaped key sets after the
history reactor processes heights 89 through 100, followed by the complete live
keyspace at 101. The paid pagination workload reuses this component. History
setup uses unchanged values and Core payments, not signed historical transactions
or changing-value workloads. Its rows have no depositor; it does not demonstrate
paid historical deposit ownership changes.

Checks record exact per-height row counts before and after block application,
compare every historical row's value and deposit metadata with its live version,
verify current-state pointers and visibility throughout the retained window, and
compare every depositor cache entry with a fresh sum of live deposited gas. The
expected retention follows the pruning rule: newest version per key at or below
`102 - max(retain_blocks, FINALITY_WINDOW)`, plus every newer version. This cutoff
is 96 with the fixture settings. Partial prefixes retain the older suffix they
did not overwrite. Pruning superseded rows must preserve live footprint, not
charge or refund it. Existing accounting, rollback and full-state replay oracles
remain enabled.

Source `a6289ce84650ca30665fcfa9aa25a8cafc83f398` built in 45.54s. Both focused
configuration/history tests passed. Four actual block-application cases each
passed two independent snapshot restores:

| Live keys | Historical rows | Result and total duration |
| ---: | ---: | --- |
| 64 | 150 | Passed, 62.39s; retained 42 versions at 90 and 22 at 91, plus live versions at 101 |
| 64 | 529 | Passed, 62.31s; retained 64 at 96 and 17 at 97, plus live versions at 101 |
| 10,000 | 100,000 | Passed, 257.16s; removed 70,000 superseded rows and retained 10,000 each at 96, 97, 98 and 101 |
| 257 | zero | Existing pagination regression passed, 60.71s |

Durations include setup, assertions and two replays. They are development
correctness diagnostics, not block service measurements or performance acceptance.
The first three cases contain 50 real signed reveals with 100 mixed operations
and five paid file registrations. Native populations remain four validators,
two replacements, two agreements and three members. The million-row stress case,
full W_op populations/arrivals, memory profiles and final qualification remain open.

Executable SHA-256:
`8652f920400aa647a399c84e38334fca039f251cd6f4644f8809cab523bb6984`.
The large case also saved its six-file input bundle (41,560,737 bytes). Manifest
SHA-256:
`a4584e15d825578158d570f07d1e58bde284c20d3fffc14b8f90ca3a8d9837d9`.
All five input hashes were independently verified. This bundle was not separately
replayed in a new process at this head; the preceding saved-replay implementation
has its separately attributed evidence above.

Five additional synthetic SQLite histories passed the actual production pruning
DELETE statements against independently constructed expected per-key retained
sets. Those checks support the retention oracle, not runtime execution coverage.

Clippy reported exactly the six inherited S2 findings, with no history-workload
finding. No suppression was added. They remain assigned to native-branch
integration. All parent build and runtime processes finished before handing the
shared build slot back to the native implementer.

## Configured batches and saved confirmation replay

Source `e5207e2cbc740269c6e4d3bde81228aaf3487749` adds an optional
`mixed.batch_operations` setting. Zero preserves fresh block execution; 20 or
40 groups the existing signed two-operation reveals into complete decided
batches. The fixture preserves reveal order and advances global consensus
height per batch. These already-decided calls use empty certificates and do
not qualify consensus authorization.

Transactions execute at anchor 101 and confirm in block 102. The checks preserve
the transaction ID, execution height, batch height, execution usage and paid
receipts, allowing only the joined confirmation ordinal to change. Exact raw
Bitcoin positions and receipt counts are checked. Full mixed accounting,
rollback, lifecycle, retained-history and pruning checks remain enabled. Each
configured generation case executes twice from independent snapshot restores.

The saved fixture records the batch size and reconstructs those same reveals
from the original Bitcoin block. A fresh process replays the groups before
confirmation, checks both restored databases against the full expected logical
state, and verifies the saved baseline remains unchanged. This is same-source,
same-binary replay, not cross-build or S1/S2 compatibility qualification.

The build passed in 47.70s and the configuration validation test passed. Actual
runtime cases all passed:

| Case | Shape | Total duration |
| --- | --- | ---: |
| Representative batch fixture | 50 reveals, 100 operations, five 20-operation batches; 64 live keys, 150 history rows, five paid files | 88.78s |
| Fresh-process saved replay | Same representative fixture, two restores | 47.85s |
| Stress batch fixture | 500 reveals, 1,000 operations, twenty-five 40-operation batches; 257 live keys, 529 history rows, 100 paid files | 134.85s |
| Original single-batch regression | Original three-operation fixture | 53.53s |
| Original simulation regression | Repeated rolled-back simulations, then batch execution and confirmation | 97.87s |

Native populations remain four validators, two replacements, two agreements and
three members. These are correctness diagnostics, not full W_op populations,
arrival scheduling, eight-view competition or performance acceptance. Durations
include setup and assertions. The saved replay's `service_ns` covers only block
application through pruning, explicitly excluding the earlier batch execution.

Executable SHA-256:
`ea4fe1fa5cea4efd99336effc92e6e3dc9da7e8b5c4dc60102a41de6426f139f`.
Saved manifest SHA-256:
`5a41ecc29cdd8ce5736ce030debc8627de3af5d047ce60e8e70c6a2ce56f466d`.
All five input hashes were verified; the six-file bundle totals 3,135,547 bytes.

Clippy reported the same six inherited S2 findings, with no configured-workload
finding. No suppression was added. The fixes remain assigned to native-branch
integration. All parent build and runtime processes are terminal.

## Mixed simulation inputs and explicit cache setup

Final source `42a5a39ca6f628898695364d5b8a160c1049c5a8` adds optional
`mixed.simulation_operations` (zero, two or four, default zero). It partitions
the entire mixed operation sequence into signed simulation requests, checks the
commit/reveal pair with Bitcoin's mempool admission before any canonical spend,
and leaves those alternatives unbroadcast. Each request spends the same confirmed
funding alternative. Decoded public keys and instructions, including gas limits,
must match the flattened canonical two-operation reveals exactly.

Each request runs twice from the same baseline before canonical execution. After
every call, the complete logical database must remain unchanged, including usage,
fees and receipts; storage height, simulation flag and reactor tip must be restored.
The checks cover receipt positions, gas bounds, expected statuses, returned
contract-error values and repeatability of the complete result. These checks do
not assert equivalence with cumulative canonical return values, since each
simulation rolls back before the next request. They also do not cover cancellation
or infrastructure errors, or every mutable runtime context field.

Saved fixtures optionally include a hash-bound `simulations.json`. Its presence
must agree with the configuration, and loading validates the exact inventory,
payload checksum and flattened signer/operation sequence before starting Bitcoin.
Fresh-process replay executes the same requests before the canonical batches or
block and compares the complete expected state on two independent restores.

`mixed.warm_simulation_cache` is separately explicit, defaults to false, and is
invalid without simulation requests. When enabled, the harness compiles every
existing baseline contract through production `load_component` outside simulation,
checks every entry is admitted, and verifies the database is unchanged. The run
records all warmed IDs. This also warms the subsequent canonical batches and block.
It does not change production cache guards or cache speculative publication IDs.

An initial source75eb run failed its new error-detail assertion after 121.84s.
The assertion incorrectly treated a returned WIT error (`ContractErr`) as an
execution error. Sourceccfc corrected it to require no separate `error_message`
and the known returned `err(message("deliberate failure after write"))` value.
The initial failed log and result record are retained.

The unprewarmed ccfc diagnostic was intentionally stopped after 539.56s, not
reported as passing. A debugger sample showed Pulley compilation in regalloc2;
source inspection confirmed that simulation deliberately prevents component-cache
writes, so uncached contracts compile repeatedly. Perf was unavailable, and a
full-debug-info debugger attempt crashed before a minimal-symbol attempt succeeded;
target detachment was verified. Observer intervention and incomplete execution
exclude this run from performance qualification. The operational compilation and
reactor-occupancy finding is tracked separately in the execution ledger. A future
cache change must preserve immutable code/protocol/engine identity because contract
row IDs can be reused after simulated publication rollback.

The final warm-cache correctness cases retain four validators, two replacements,
two agreements, three members, 50 canonical reveals, 64 live keys, 150 historical
rows and five paid files. The two-operation simulation case precedes 20-operation
batches and confirmation; the four-operation case precedes fresh block execution.
These remain development correctness diagnostics. Cold-component qualification,
full populations, timed arrivals, eight competing views, enforced memory profiles
and S1/S2 comparisons remain open. Saved `service_ns` covers only block application
through pruning, excluding earlier simulations and batches.

Final-source build passed in 40.46s and the configuration unit passed. All six
runtime cases passed: two-operation generation (122.21s), its saved replay
(81.28s), four-operation generation (117.62s), its saved replay (76.82s), disabled
simulation generation (88.74s), and legacy-format saved replay (47.84s). Each
saved replay used two independent restores. Two-operation fixtures contain 50
simulation requests; four-operation fixtures contain 25. Each restore executes
each request twice. Both enabled cases explicitly warmed all 12 baseline IDs.

The legacy-format check deliberately removed both new optional configuration
fields from the disabled fixture before fresh-process replay. Its original
manifest SHA256 was `243af2cbb76ce37702dbba0f01474e8a7db980e22abfb743c3779dc35d8b47cf`;
the replayed manifest SHA256 is
`c30d033c369ca52cd40a5ca3bc3ac2994c9ac4cc99b0772654aec61318a4ff40`.
The remaining input bytes and six-file inventory were retained. This is a
same-source legacy-shape compatibility test, not a cross-version replay test.

Ten actual-binary negative controls passed: missing and extra files, disabled
configuration with payload, enabled configuration without its digest, payload
checksum mismatch, symlink escape, unsupported width, empty requests, reordered
operation mix, and missing request. All original fixture files were unchanged.
The record `configured-simulations-validation.json` preserves the commands,
source/binary identities, per-run logs and checksums, and both earlier failed or
stopped attempts. These durations are whole-test diagnostics, not API latency.

Clippy exited 101 with exactly the six inherited S2 findings in sequential_tests,
native_stack/sweep, native_stack_resource and invocation. No new finding concerns
the simulation changes. They remain assigned to the native Stage1 integration;
no warning suppression was introduced and this is not a green-merge claim.

## Eight competing pooled views

Source `1edd1dc94f38a5d9a7b8265d22c34ed2e85bbd8d` adds optional
`mixed.view_concurrency`, accepting zero (default) or eight. Generation and saved
replay use the same wrapper around simulation checks, batches, block application
and pruning. Production runtime code is unchanged.

Eight separately spawned closed-loop clients use production `pool::Manager` and
unsigned `Runtime.execute(None, None, ...)` with the production view gas cap.
The fixture overrides pool size to eight instead of available parallelism. Its
Tokio runtime still has two worker threads; no CPU or memory quota is enforced.
The current source does not configure a fuel-async-yield interval. Those settings
are reported explicitly rather than treated as production performance equivalence.

All fallible pool setup, connection checks and cache warming precede the startup
barrier. Warmup performs checked pagination and counter reads through the separate
view-pool cache; database projections must match the baseline before and afterward.
Each worker reads bounded immutable pages and a counter changed by canonical work,
releasing and reacquiring the pooled runtime between calls. Historical pagination
contracts use height zero; fixtures without history use the anchor height.

Every client must complete a page call within the combined writer interval and
more than one page execution must overlap. This measures in-flight calls, not
simultaneous CPU execution or overlap with every subphase. Counter observations
must not decrease, and a final reacquired view after successful writer completion
must equal the committed expected value. These checks establish eventual
freshness, not visibility of every intervening commit. The field
`last_counter_during_work` is the last loop observation and may finish during drain.

Writer errors and unwinding panics set the stop flag; every worker handle is
joined before returning an error. Calls already in progress finish without abort.
Final-value checks apply only after successful writer completion. This cleanup
was inspected statically; no fault-injection evidence is claimed here. Existing
canonical full-projection, accounting and snapshot checks remain in place.

This is a bounded warm correctness diagnostic, not
HTTP scheduling, open-loop load, cold compilation, enforced-resource performance
or full S2 qualification.

The committed build passed in 28.18s and the selected configuration test passed.
An earlier uncommitted compile failed generic pool inference; explicitly typing
`Pool<Manager>` corrected it, and that preliminary build passed in 39.48s.
The initial short `--exact` unit selector ran zero tests and is not counted.

All six actual-binary runtime cases passed: history plus two-operation simulations
and 20-operation batches (173.24s), saved history replay (121.98s), no-history fresh
block (105.28s), saved fresh replay (65.42s), disabled views (88.81s), and legacy
format replay (48.31s). Every case ran two independent restores. Both enabled
fixtures use 50 canonical reveals, 257 live keys and 5 paid files; the history fixture
adds 150 historical rows. Across the eight enabled restore intervals, all eight
clients completed page calls during the writer interval and peak in-flight page
calls was 8. Per-client completions ranged 54–247. Writer intervals were 18.29–52.70s,
including their checks and projection overhead. These are diagnostic durations,
not production throughput or API latency.

The legacy replay deliberately removed only `view_concurrency:0` from the disabled
manifest. Its original SHA256 was
`889eea0656af97c8b3e4a148cba7bfc5ea14235e830550953a684d7937a77341`,
and replay used
`028cd47bbe3a6142447567694c8c0fbf958c34ed1c7549c33fe5465f396050df`.
All five inputs retained their hashes. Disabled and legacy runs emitted no
competing-view trace. This verifies the defaulted field on the same build.

The source review also traced scheduling through pinned deadpool 0.13.1 and
Tokio 1.53.3. Repeated pool semaphore acquisition and spawned guest-task joins
consume Tokio cooperative budget, so this loop does not indefinitely bypass
cooperative yielding merely because local SQLite awaits complete immediately.
No explicit per-iteration yield policy was added. External cancellation of the
whole adapter remains outside its writer-error draining guarantee.

Clippy 69568 exited 101 with the same six inherited S2 findings in sequential_tests,
native_stack/sweep, native_stack_resource and invocation. It reported no new
finding in this adapter. No suppression was introduced; native Stage1 integration
still owns those fixes. Record `competing-views-validation.json` retains exact
commands, source/binary identities, logs and hashes, and the initial compile failure.

## Explicit consumer identity for saved replay

Source `d0970e218820f3f2762849f51cab3d9782b94ee3` preserves strict same-build
replay by default. The optional `KONTOR_WORKLOAD_REPLAY_RUN` path and
`KONTOR_WORKLOAD_REPLAY_RUN_SHA256` must either both be absent or both be supplied.
The explicit run manifest is separately hash-bound and must resolve to a file
outside the immutable fixture directory, including after symlink resolution.

Its versioned schema binds the exact fixture-manifest digest, full expected
consumer source metadata, consumer executable digest and a descriptive run label.
Typed parsing rejects duplicate and unknown fields, including nested source
fields. The reader retains the fixture producer's identity as provenance while
checking the actual consumer binary and clean compiled source against the run
manifest. Both are checked again before successful completion is reported.

The fixture itself is not rewritten. Exact inventory, input hashes, raw transaction
decoding, private snapshot restoration, and full before/startup/after projections
remain mandatory. This change adds no alternative expected output, normalization
or table exclusion. A difference between implementations must still fail the
existing semantic oracle. Final identity output includes the fixture and run-file
hashes, label, and both producer and verified consumer identities.

The committed build passed in 48.17s and the ambiguity unit test passed. Sixteen
actual-binary controls rejected default cross-build replay, either missing option,
wrong run-file hash, wrong fixture binding, wrong consumer binary or source, wrong
schema, duplicate top-level or nested fields, unknown nested fields, direct and
symlink paths inside the fixture, tampered block or simulation inputs, and an extra
fixture file. All original fixture bytes remained unchanged.

All four runtime cases passed. The distinct-source/binary diagnostic
uses the same runtime family. A run label does not establish engine identity or
S1/S2 compatibility. Final paired qualification must still bind reviewed build
attestations, actual engine settings, common contract artifacts and identical
inputs, and retain complete state and accounting comparisons.

The old producer is source `1edd1dc94f38a5d9a7b8265d22c34ed2e85bbd8d`,
binary `c050571741ba6be0e455180e786ff69e674c830f86995bb95887fe06e8c13401`.
The verified consumer is source `d0970e218820f3f2762849f51cab3d9782b94ee3`,
binary `3b68327955b441482b63557784770559e871d5dd2d1511786f8184df921b765f`.
Explicit replay of the unchanged history/simulation/batch fixture passed in
136.04s; explicit replay of the unchanged fresh-block fixture passed in 77.36s.
Each used two restores and eight competing view clients. Complete expected
logical state remained equal without normalization.

A new fixture generated by the consumer passed in 88.97s, and its default
same-build replay passed in 61.36s, both with views and simulations disabled.
The default replay emitted matching producer/consumer identities and a null
explicit-run field. Both explicit runs emitted distinct producer/consumer
identities and the expected fixture/run-manifest hashes. All original fixture
hashes were retained. Durations cover complete diagnostic test processes, not
isolated API service latency or S1/S2 performance ratios.

Clippy exited 101 with exactly the six inherited S2 findings in sequential_tests,
native_stack/sweep, native_stack_resource and invocation. No new finding concerns
this change, and no suppression was introduced. The validation record preserves
commands, source/binary identities, all runtime and control logs and their hashes.
The paired engine, workload and platform acceptance requirements remain open.

### Consecutive sequence funding setup

Plan `14e3ffce` was reviewed by the lead and both independent reviewers and
committed as `b48a7cae`. Source `1d4724c265baca1296ea246b3678cac5967399be` implements the initial funding helper
only. Existing single-block paths are unchanged. The mature coin funds a small
parent and per-block splits; each child is admission-checked with only the parent
in the mempool, then ordered raw transactions are confirmed together at height
101. This avoids the connected-cluster size limit without policy changes.

The exact-source build passed in 30.85 seconds. One real Bitcoin test passed in
0.94 seconds, covering two blocks of 50 outputs, six of 500, and seven of 500:
100, 3,000 and 3,500 distinct confirmed outputs respectively. Each 500-output
child weighed 86,280 weight units. Checks include signatures via Bitcoin
admission, exact accepted block contents, predecessor/height, empty final
mempool and sampled confirmed UTXOs. The full accepted transaction list binds
all returned output values, scripts and identities.

The executable SHA-256 was `a16f60e69bc661b02cdb8cd77c79a0c067903146adcdc0f8cf64a932a1baf8b4`.
Bitcoin Core v31.0 was `4841faf4cd67d99d8d33dca95ab7f78e1580a4f63513a5473a7e26f6f748082b`.
The five raw logs and complete observations are recorded in
`.build-cache/workload-reconcile/sequence-funding-validation.json`. The earlier
uncommitted-source compile (46.78 seconds) and test (0.98 seconds) are retained
separately. Clippy reported exactly the six inherited S2 findings, with none in
the new helper.

This is funding setup evidence. It does not yet spend those outputs in
consecutive workload blocks, establish evolving state/accounting, saved sequence
replay, continuous views, timed arrivals or performance qualification. Failure
injection for RPC/cleanup is not covered. The caller owns and discards isolated
Bitcoin state on failure; the helper does not undo a submitted parent or mined
anchor. No full sequence, W_op or S2 acceptance is claimed.

### Signed consecutive workload inputs (a59d027f)

The test-only input generator now builds distinct, signed commit/reveal transactions for consecutive blocks after the height-101 funding block. It checks every decoded operation and signer, raw transaction position, unique funding/reveal IDs, parent link, actual Bitcoin height/hash and empty mempool. Duplicate funding is rejected before chain mutation. Wrong operation gas and wrong parent hash are rejected by the structural decoder.

At source `a59d027feef366f09a083eca3725cc720b3e1046`, the exact-head no-run build passed in 46.89s (session 18947). The ignored real-Bitcoin test passed in 25.14s (session 81501): two blocks of 50 transactions/100 operations and seven blocks of 500 transactions/1000 operations, heights 102-103 and 102-108 respectively. Bitcoin was v31.0. Clippy session 54974 reported exactly the six inherited S2 errors and no changed-file errors. Logs and checksums are recorded in `.build-cache/workload-reconcile/sequence-inputs-validation.json`.

This is input preparation evidence, not execution qualification. The test does not publish or execute the named contract. The structural decoder alone does not authenticate signatures, supplied heights or funding values; generation gets consensus/admission checks from real Bitcoin. The future saved-sequence reader must import the chain and independently bind expected heights, hashes and funding outputs. Raw blocks are hashed but not yet archived. The six-block signed case was not run here. Lightweight logs rely on executor records and current source/binary hashes for local invocation identity. Evolving Kontor state, cumulative accounting, schema 2 checkpoints, full W_op and six-cell qualification remain pending.

### Cumulative mixed-call and file expectations (503f38fe)

The test-only workload models now advance expected counter, recipient balance and per-signer stake from prior expected effects. They retain every earlier inactive file registration, contiguous ledger indices and cumulative full-ledger roots. New file identities include the sequence ordinal; first-step descriptor bytes remain unchanged. The model keeps the original active file population and collateral growth factor, while registration ranks advance. Each check verifies prior inactive metadata, active identities, empty new memberships, pending-append drain, registry counters, retained roots and persisted frontier root. The bounded sequence has at most seven steps and eight roots, below the native 4,096-root eviction limit.

At exact source `503f38fe20d8185c0fba22e90ca182dc2f7a9273`, build session 45457 passed in 50.47s. The seven-step native registry diagnostic passed in 50.87s (session 69886): two initial active files and 35 new inactive files, 37 total. Every step rejects missing registrations and an undrained append queue, then rechecks the registry after an idle root hook and rejected duplicate registration. The paid mixed-call diagnostic passed in 43.02s (session 15923), with 200 operations across two synthetic transaction heights and 240 paid receipts including nested calls. It checks the carried counter, transfers, intermediate stake return values and deliberate failed-write rollback. Three separate controls zero only the counter, recipient or stake baseline, retaining the current file expectations; each is rejected. The existing real-Bitcoin single-block file/accounting test passed both snapshot restores in 61.86s (session 1887).

Source review found and fixed a test error before the build: a contract-level `err(...)` is an outer successful runtime return with a `ContractErr` receipt, not an outer execution error. The final test requires the exact contract error and validates its receipt and rollback. Clippy session 99099 retained exactly the six inherited S2 findings, with no changed-file errors. Build/runtime logs and hashes are recorded in `.build-cache/workload-reconcile/sequence-state-validation.json`.

These are bounded oracle diagnostics. Initial preparation assumes an all-active registry with one recorded root; a sequence must advance the existing model instead of preparing from later observed state. Populations and memberships remain fixed. The native registry test stays at context height 1, and the paid test uses synthetic block/transaction rows at 102/103. Neither establishes cumulative reactor lifecycle, Bitcoin signature admission, transaction-usage accounting, batch confirmation, history pruning, root eviction or full-projection observation purity. Broader file counts and signer layouts remain integration work. Saved schema 2, complete evolving accounting/challenge checks, full W_op and six-cell S2 qualification are still pending. Lightweight logs use executor records and current source/executable hashes for local invocation identity.

### Evolving consecutive reactor execution (c3ab8d5a)

Source `c3ab8d5a7415b51fdffcc992d1d90555724476ca` connects the accepted funding, signed-input and cumulative mixed/file models to one evolving reactor for two, six or seven consecutive blocks. Each trial restores the populated height-101 snapshot once. Expected fees, burns, supply, validator rewards/transitions, storage reward index and fractional liabilities advance from the previous model. Challenge selection derives the exact expected set, prover, seed and metadata from each block hash and retains earlier challenges. Batch anchors, simulation heights and pruning cutoffs move with the chain. Complete database projections are compared after every canonical batch and completed block across two independent restores.

Review corrected a missing codec-error conversion and excessive checkpoint memory retention. Full checkpoints now use closed-descriptor temporary files in an explicitly selected workspace cache directory, which is btrfs on this host. `/tmp` is tmpfs and is not used for those retained files. Comparisons stream every byte, with no new projection exclusions. The second restore compares each checkpoint with the first restore’s file; duplicate batch files are retained only through the current block’s confirmation checks. Disk use still scales with the first restore's full checkpoint set. Successful test runs removed their checkpoint directories; this is not disk-exhaustion, cancellation or crash-recovery evidence.

The exact-source build passed in 53.01s (82655). Four focused units passed. The separate real-native challenge diagnostic passed in 35.47s (47299), using deliberately selected synthetic hashes to force two nonempty challenge generations, reject omitted state and wrong prover expectations, preserve the first challenge while creating the second, and produce no further challenge when both files are already challenged. Its runtime context remains height 1; it is not a Bitcoin or expiry/cleanup test.

Real signed replay results, all with two initial-snapshot restores:

| Case | Result | Scope |
| --- | --- | --- |
| Two fresh blocks | 74.80s, session 63918 | 50 transactions/100 operations per block; five new files per block |
| Two batched blocks with simulations and views | 268.10s, session 28605 | Five 20-operation batches per block, 50 two-operation simulation requests repeated twice before each block, eight view clients throughout each writer sequence |
| Six fresh blocks | 99.64s, session 29618 | Heights 102–107, no new file registrations, cumulative rewards/accounting and moving history cutoff |
| Seven batched blocks | 126.47s, session 28311 | Heights 102–108, 35 accumulated inactive file registrations, 42 canonical checkpoints per restore |
| Legacy single-block saved generation | 95.62s, session 95875 | Existing schema 1 with batches, files and retained history |
| Fresh-process legacy replay | 62.95s, session 59970 | Two restores, existing identity binding and complete final-state comparison |

All cases use four initial validators, two replacements, two active agreements with three members, 257 live keys and 3,084 configured historical rows. The combined two-block case records all eight view workers progressing in each interval, peak eight page calls and final observed counter 40. View overlap includes canonical work and oracle checks, not specifically database commits. Independent cumulative arithmetic is checked after each block; batch checkpoints add full-state replay equality and batch-specific confirmation/usage checks.

The executable SHA-256 is `6600db2f4255e5f38d3435375ab007d6a782d6d3d65efe073caaea8c33a96646`. The schema-1 fixture manifest is `df5f56795433e4c6a9ca3dcc21ed200740e0feaceaac08da3174e4d496253c71`. Logs, source/binary/PID/command records, input hashes and limitations are in `.build-cache/workload-reconcile/sequence-runner-validation.json`. Clippy session 62574 returned exactly the six inherited S2 findings, with no changed-file findings; none were suppressed. Those findings still require resolution when the native branch is integrated.

This is bounded Linux ARM64 development correctness evidence. The input-generation and most runtime logs rely on wrapper/executor records for source and process identity; the legacy saved fixture additionally retains its existing embedded identity evidence. Multi-block raw inputs and complete checkpoints are not yet preserved as a portable replay artifact. The existing schema-1 format remains supported, while multi-block saved output is explicitly rejected pending schema 2. Full populations, 500-transaction execution, challenge expiry/cleanup, long root-window eviction, real-clock arrivals, resource-capacity and six-cell S1/S2 qualification remain open. No protocol-upgrade phase or full S2 acceptance is implied.


## Saved multi-block replay

Source `bd67889bb210e53f5689db13ae83516512626a6d` adds schema 2 for
multi-block workload archives while retaining schema 1. It binds the initial
SQLite snapshot and full projection, Bitcoin setup chain, raw consecutive
blocks, ordered batch and simulation inputs, and complete before/after
checkpoints for every canonical batch and block. The manifest is written last,
after two initial-snapshot restores pass independent semantic checks and agree
at every checkpoint. Fresh-process replay checks the complete inventory and
hashes, imports the real Bitcoin chain, and repeats all canonical checkpoints
over two fresh restores. It does not add projection exclusions.

The two-block batch/simulation/eight-view fixture has manifest
`f2f48c439db4d9352a26fec3a749a03e1e634aed5c949a176c99916ba4926495`.
Generation passed in 279.66s and fresh-process replay in 223.31s, with 12
canonical checkpoints per restore. Its 20 files remain unchanged. Reordered
batch associations were rejected, and a rehashed altered intermediate projection
passed structural loading but failed the actual full checkpoint comparison.

The six-block fresh fixture has manifest
`239fd239b15960ba31bc59e0d9b56423acaea605e51ac975ccd381cc3ba0797b`.
Generation passed in 141.60s and fresh-process replay in 94.97s. Its 16 files
cover six checkpoints per restore and 300 unique transaction fundings. This
case has no batches, simulations, competing views or new file registrations.
Both bounded fixture records and raw evidence received all three reviews.

Test-only follow-ups through `488e62286dc929cc7d24a29fa51f5f2db24a8279`
add regular-file/symlink and reused-funding controls. Review found that the
original funding mutation recreated a previous transaction ID and would stop
at the wrong rejection gate. The corrected mutation changes the commit lock
time, derives a distinct reveal ID and repairs the surrounding commitments.
The actual test now reaches `sequence reused or unknown initial funding`.
This is a structural preflight negative, not a valid Bitcoin spend or proof of
signature/PoW rejection.

At `488e6228`, exact compilation and three unit checks passed. Clippy still
reports the six inherited S2 findings, with no suppression. The new binary
`40c05829714a33eacc72acaaf3842a296c810d310180b5181a784f9692a80db6`
correctly rejects the earlier fixture by default. An explicitly pinned external
consumer run manifest permits replay without changing the producer archive.
That replay passed in 233.06s, with both restores matching all 12 checkpoints
and all eight view clients progressing during each restore’s writer interval. This demonstrates the
explicit identity seam across test-only revisions, not real S1/S2 compatibility.

The seven-block batched archive has manifest
`de3dc8a7335e2b8a38732bf44304133ae7e061557cbd99ca08454dc7acbca6f1`.
Generation passed in 169.95s and fresh-process replay in 121.69s. Both use two
restores with 42 canonical checkpoints each. The 53-file archive binds 350
distinct funding inputs, 35 batches, seven confirmation blocks and 35 cumulative
file registrations. This case has no simulations or competing views. All three reviewers accepted generation and terminal replay evidence.

The legacy schema-1 fixture from `c3ab8d5a`, manifest
`df5f56795433e4c6a9ca3dcc21ed200740e0feaceaac08da3174e4d496253c71`,
also replayed successfully under the explicitly pinned `488e6228` consumer in
63.26s. Both fresh restores passed their full projections and confirmation
checks; all six original files remain unchanged. This is legacy-reader
compatibility through the same explicit identity seam. The build, negative
controls and replay records are retained under `.build-cache/workload-reconcile`,
including all original fixtures and logs.

These are Linux ARM64 development correctness diagnostics with small fixed
populations. They do not establish real-clock arrival rates, backlog service,
historical replay throughput, resource ceilings or six-cell qualification.
The agreed timed-workload amendment adds those traces separately and includes
normal post-block finality processing, which the bounded handle_block helper
does not exercise. Full S2 and the protocol-upgrade system remain incomplete.


## Timed workload input schedule

Source `4fa903ce5b09dfb326ab04e71012239bab13c5e3` implements the frozen
event schedule and Bitcoin input preparation from the agreed timed-workload
amendment. The schedule preserves 20/40 batches per 600-second interval,
separate simulation request ordinals, fixed anchors, canonical dependencies,
block/batch/simulation tie ordering and explicit finite-horizon exhaustion.
Confirming blocks include prior batches plus 50/500 fresh transactions, giving
250/1,300 transactions in steady state. A six-block fresh backlog precedes the
first new batch. Shared funding preparation uses standard-sized children with
at most 500 outputs; existing sequence wrappers keep their prior input bounds.

Exact-source compilation and two schedule tests passed in a 58.72s wrapper run.
The unit tests cover rates, partitioning, tie order, anchors, dependencies,
strict-before boundary observations, missing/duplicate/reordered events and
exhaustion. The real Bitcoin input test passed in 162.29s wrapper time
(161.62s reported by the test), covering these concrete schedules:

| Input case | Bitcoin blocks | Reveals | Batch events | Simulation metadata |
| --- | ---: | ---: | ---: | ---: |
| Two representative intervals | 2 | 500 | 40 | 120 |
| Six fresh stress blocks, then two stress intervals | 8 | 5,600 | 80 | 1,200 |
| Six stress historical intervals | 6 | 7,800 | 240 | 3,600 |

Every canonical transaction consumes distinct confirmed initial funding. The
test checks ordered commit/reveal linkage, decoded operations and signer, block
parents, batch/confirmation partitioning and exactly-once coverage. Bitcoin
accepted the funding tree and workload blocks. Funding children were individually
admission-checked with their parent, not simultaneously admitted as one large
mempool cluster. Maximum recorded workload weight was 1,580,444 WU; maximum
individual funding transaction weight was 86,280 WU. The existing two-/seven-block
50-/500-transaction input regression passed in 29.30s wrapper time. Clippy
finished in 16.95s with exactly the six inherited S2 findings and no suppression.

This is input admission and ordering evidence for `increment()` and
`fill-blob()` calls, not admission of the eventual full mixed workload. Contracts
are not executed and simulation events are metadata only. No actual wall-clock
arrival, pending-confirmation database model, normal finality processing or
performance gate is established. Raw Bitcoin inputs are not retained as a
portable event archive; independent review combines source assertions with
recorded hashes, weights and complete schedules. Wrapper records, raw logs and
the consolidated `timed-input-validation.json` remain in the workload evidence
cache. The dispatcher must preserve complete event order, including simulations,
and use full-resolution elapsed time for strict-before completion observations.
