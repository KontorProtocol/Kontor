# Conditional index membership: measurements

Measured locally on 2026-09-13. The useful benefit is reduced retained state and
less work when records stop participating in an index. This is not a broad
execution-speed improvement or a substantial simplification of contract logic.

## Compared implementations

The baseline is the `perf/due-validator-scans` working tree based on
`49a815faddf2bf08f61e705158e651bc1638fe34`. It already has full activation and
deactivation height indexes and range scans. Comparing against this baseline
isolates conditional membership from the scan optimization.

The temporary prototype changes nine declarations:

- Staking status and consensus-key indexes exclude inactive accounts;
  activation indexes contain pending joins, and deactivation indexes contain
  pending exits.
- Filestorage's active-challenge projection contains active challenges. Its
  due, prover/status and membership/status indexes contain active, expired,
  failed and invalid challenges: all statuses that retain obligations.
- The membership index by node contains active memberships only. The separate
  per-agreement index still includes departed members for existing queries.

Primary records remain stored. No runtime ABI, write buffering or record-update
API changes are involved. The generic macro prototype evaluates a field pattern
for old and new index entries. It deliberately keeps eager field reads and the
existing setter order, including redundant intermediate work. These initial
measurements used an experimental tuple syntax. The subsequent implementation
uses the `matches!` declaration documented in the
[index API guide](indexed-map-index-system.md#conditional-membership).

## Method

The ignored Rust benchmarks execute compiled native Wasm through the real host
storage implementation. They measure complete calls, including predicate reads,
index maintenance and storage charges. Three single-threaded runs of each
variant were interleaved, with no concurrent compilation or tests during timing.
Times below are medians of each operation's total per run. They are local latency
observations, not network throughput measurements or statistical confidence
intervals. Storage-operation counts were stable across runs.

State measurements distinguish live key/value payload from all stored versions,
including rollback history and tombstones. Bytes exclude SQLite row overhead,
database indexes and filesystem allocation. Host fuel includes storage-deposit
charges, so it should not be interpreted as CPU time or a user fee estimate.

## Challenge lifecycle

Three storers, 32 files, three create/expire/settle cycles: 96 terminal challenges.
The first storer is funded sufficiently to avoid bond-exhaustion cleanup during
this workload. The benchmark verifies that all 96 challenge records remain and
reach `Settled`.

| Measurement | Full indexes | Conditional indexes | Change |
| --- | ---: | ---: | ---: |
| Settlement `Get` calls | 2,467 | 2,022 | −18% |
| Settlement `Set` calls | 1,728 | 768 | −56% |
| Settlement `Delete` calls | 480 | 384 | −20% |
| Settlement elapsed | 692 ms | 595 ms | −14% |
| Full create/expire/settle elapsed | 1,852 ms | 1,794 ms | −3% |
| Filestorage live payload after settlement | 154,652 B | 112,232 B | −27% |
| Filestorage payload including historical versions | 276,448 B | 224,556 B | −19% |

Creation has exactly the same storage-operation counts and was slightly slower
in the prototype runs (849 to 892 ms). Expiry `Set` calls fall from 1,344 to
1,152, but elapsed time barely changes (310 to 307 ms). This is why the complete
lifecycle saving is much smaller than the settlement-only saving.

Successful cryptographic proof verification is not benchmarked here. The
experiment covers penalty settlement and the existing exhausted-bond cleanup
benchmark; it does not establish proof-verification latency improvements.

## Staking against the full-index scan candidate

For 128 validators, activation `Set` calls fall from 1,408 to 768 and deactivation
from 1,408 to 640. Their measured times fall from 318 to 239 ms and 312 to 250 ms.
Registration does not get faster (2,296 to 2,375 ms). Ordering reward operation
counts are unchanged. Both variants already avoid all row reads during idle
join/exit waiting blocks, so conditional membership adds no idle-scan saving.

For 128 storage-only accounts, creating bonds takes 2,944 versus 1,920 `Set`
calls. After one top-up each, staking's live payload falls from 25,931 to 12,179
bytes. These numbers include avoiding maintenance of the two newly proposed
height indexes; they must not be presented as savings entirely against merged
`main`.

## Additional control against merged main

A separate executable embeds the staking Wasm committed at the base SHA, with
the same host and benchmark harness. It is compared with the prototype in three
alternating staking-only runs. This comparison includes both the new range
indexes and conditional membership, so it does not isolate either feature.

For 128 storage-only accounts:

| Measurement | Main staking | Scan + conditional prototype |
| --- | ---: | ---: |
| Bond creation `Get` calls | 1,531 | 1,277 |
| Bond creation `Set` calls | 2,432 | 1,920 |
| Top-up `Set` calls | 1,408 | 1,280 |
| Live staking payload after top-ups | 20,459 B | 12,179 B |

The live-state saving is 40%, versus 53% against the full-index scan candidate.
It is therefore not entirely a saving from undoing the candidate's added indexes.
Median bond-creation time falls from 1,131 to 1,068 ms; top-ups change little,
from 1,051 to 1,034 ms.

For validators, range scans eliminate waiting-block reads, but maintaining the
new height indexes still costs writes. Across the 128-validator lifecycle,
`Set` calls increase from main's 5,508 to 6,532, versus 8,708 with unconditional
height indexes. At the final inactive snapshot, historical payload increases
from main's 77,483 to 92,933 bytes even though live payload decreases from 40,413
to 23,985 bytes. During the active snapshot, live payload is almost identical
(38,803 versus 38,821 bytes). The added scan indexes have a real write/history
cost; conditional membership reduces that cost without eliminating it.
The complete measured validator lifecycle falls from 4,724 to 3,885 ms, largely
because range scans avoid repeatedly reading future transitions during the 22
waiting blocks. That saving must not be attributed to conditional membership
alone.

## Costs and interpretation

Compressed staking Wasm grows by 114 bytes (100,204 to 100,318); filestorage
shrinks by 49 bytes (111,771 to 111,722). Binary size is effectively unchanged in
this experiment.

Reward accrual and claims have identical storage-operation counts. Active
membership removal saves only two `Set` calls. Exhausted-bond cleanup saves some
writes but shows no convincing elapsed-time benefit in these runs. Those are
weak motivations for this feature on their own.

The strongest justification is preventing terminal challenge index entries from
accumulating and avoiding irrelevant validator indexes for storage-only accounts.
The cost is another language feature whose generated create/update/remove paths
must consistently handle predicate transitions. Any production implementation
needs focused macro tests, explicit lifecycle predicates and a stored-index
rebuild/reset decision. This measurement does not settle the public syntax.

## Final implementation: actual user charges

The adopted implementation uses nine conditional declarations and removes the
validator duplicate-key scan/status filter in favor of index `.is_empty()`.
The predicate parser is shared by Rust records and WIT declaration forwarding.
No host ABI or SDK component rebuild is needed. Boolean predicates compile to
direct boolean checks. Compressed binaries versus the full-index candidate are
100,204 → 100,107 bytes for staking and 111,771 → 111,722 for filestorage.
The tag-predicate follow-up also rebuilds NFT and the arithmetic test contract.

`storage_user_costs` measures real token balances, the public `token::floor`
view, and the burn account. For each operation it checks that user balance loss
minus the stake principal equals the increase in burned tokens. Stake remains
100 tokens after bonding and 101 after the top-up. These are fee measurements,
not host-fuel estimates.

Three runs per variant produced identical token amounts. The control embeds
staking from main `49a815faddf2bf08f61e705158e651bc1638fe34`; the final version
includes range scans, conditional membership and the duplicate-key cleanup.
Rates are the test runtime's configured 0.000000001 tokens per gas unit.

| Measurement, total for 128 storage-only accounts | Main | Final | Reduction |
| --- | ---: | ---: | ---: |
| Required storage collateral after bonding | 0.000020376 | 0.000012096 | 40.6% |
| Fees burned when creating bonds | 0.000029544 | 0.000027403 | 7.2% |
| Fees burned when topping up | 0.000028835 | 0.000027043 | 6.2% |

Top-ups leave collateral unchanged in both variants. The single-account case
requires 0.000000171 → 0.000000087 collateral, charges 0.000000229 → 0.000000212
for bonding, and 0.000000225 → 0.000000211 for topping up. Shared index counters
mean single-account percentages differ from the larger population.

Collateral remains in the user's balance but restricts spending; it is not
burned. These changes do not alter file-hosting prices or reduce stake amounts.
The earlier 27% filestorage database saving is not a 27% user-price reduction:
core-written state can be exempt from user storage collateral.

Final validation: 487 runtime/consensus library tests pass (six opt-in skips),
including the new consensus-key cancellation/reuse and collateral rollback
regression. Macro and stdlib library tests pass (6 and 51); compile-fail and
expansion tests pass. The generated-model lifecycle test covers an independent
predicate field, sorted and covering entries, bucket counts, repeated updates,
failed `try_update`, record replacement and removal. Both pinned contract
workspaces build. A subsequent review added optional-enum materialization coverage
and compile-fail coverage for mutable record predicates (direct, enum-wrapped and
optional). Tag-only predicates also support payload-bearing enums: regression
coverage edits nested records while checking membership, counts and projections,
then changes parent variants, moves buckets and removes the record. Restricted
patterns exclude record destructuring and structural constants, preventing
descendant edits from bypassing index maintenance without a blanket restriction
on payload-bearing enums.

## Reproduction

All six A/B benchmark invocations passed (four ignored tests each). The prototype
library run passed 460 tests; 26 consensus tests failed because the executable was
launched from the repository root and could not locate their counter-contract
fixture. Rerunning the entire consensus-cluster group from `core/indexer` passed
all 27 tests, covering those failures. The runtime coverage includes validator
transition boundaries/cancellation/replay and existing storage obligation,
reward, cleanup and rollback tests. This is not exhaustive validation of a new
language feature. Formatting and indexer test-target Clippy also passed for the
retained benchmark harness after restoring the prototype source changes.
All six additional staking-control invocations passed (two ignored tests each).

The retained ignored benchmarks are in
`core/indexer/src/runtime/staking/transition_costs.rs` and
`core/indexer/src/runtime/filestorage/reward_costs.rs`; shared state measurement is
in `core/indexer/src/runtime/costs.rs`.

Compile with `cargo test --manifest-path core/Cargo.toml --release -p indexer
--lib --no-run`, then run the resulting test executable with
`costs --ignored --nocapture --test-threads=1`. Save a separate executable for each
native Wasm variant. Run regular tests from `core/indexer`, as some consensus
fixtures locate test contracts relative to that working directory.

Local snapshots, binary hashes, the conditional-only source patch, saved test
executables and the six raw benchmark logs are archived under
`/tmp/kontor-conditional-study/`. This is temporary local evidence; the results
and benchmark harness are retained in the repository. The initial prototype was
removed after that experiment; the branch now contains the implementation above.
Final fee logs are `/tmp/kontor-conditional-{main,final}-fees*.log`; its native
binary snapshots and test executable are under the study directory's `final/`
and `final-tests` paths. Run `storage_user_costs --ignored --nocapture
--test-threads=1` to repeat the direct charge measurements.


Review-fix verification logs are `/tmp/kontor-pr560-fix-{checks,build,runtime}.log`
and `/tmp/kontor-pr560-fix-fees-{1,2,3}.log`. The optional-enum regression checks
insertion, updates to the predicate and other indexed fields, replacement and
removal. Ordinary presence-only indexes preserve their no-payload-read path.

Tag-predicate follow-up logs are `/tmp/kontor-pr560-tags-tests-verify.log`,
`/tmp/kontor-pr560-tags-{build,runtime,fees}.log`. The rebuilt contracts pass the
full runtime suite and retain identical collateral and fee measurements.
