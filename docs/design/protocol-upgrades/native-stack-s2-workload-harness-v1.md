# S2 workload harness first slice

Status: draft for exact-manifest review, 28 October 2026. This is preparation
within S2, not a new phase or performance approval. The complete workload
proposal remains required. No population choice or timing gate is resolved
by this smoke case.

## Implementation boundary

The lead implements this ordinary test tooling in an isolated worktree.
Daybreak retains the native-stack and callback implementation. Coordinate
the single local Cargo slot before building either branch.

Use a `cfg(test)` module under `core/indexer/src/reactor/`, constructed with
`Reactor<RuntimeExecutor>`. Reuse the real-executor construction pattern in
`aggregate_error_tests.rs`. Do not use `LiteExecutor` or `NoopExecutor`.
Invoke `handle_block` and observe its return, including
`maybe_prune_state`. The existing processed event and log precede pruning
and cannot establish full service completion. Do not change production
flags, deadlines, logging or consensus behavior for this slice.

Generate and validate raw signed transactions with the existing
`reg_tester.rs` compose/signing builders and bitcoind outside the measured
interval. Preserve the actual serialized block, including coinbase and
commit/reveal transactions. Feed transactions through the production parser
and executor. Cached retrieval supports an execution-only claim, not an
end-to-end Bitcoin ingestion or networking claim.

## Manifest contract

Implement a strict JSON schema and validator before timing runs. The first
schema supports only `kind: smoke`; unknown versions, fields and case kinds
are errors. JSON duplicate keys are errors too. Pin the following data:

| Group | Required information |
| --- | --- |
| Identity | Schema version, case identifier, smoke kind, deterministic setup seed |
| Sources | Kontor commit, compiler version/target, lockfile and feature-set digests, engine identity |
| Contracts | Native and user artifact paths, compressed and raw digests, contract addresses |
| Snapshot | Immutable whole-database digest, schema identity, anchor height/hash, canonical checkpoint, reset assertions |
| Input | Raw serialized block path/digest, preceding anchor, expected transaction/input/operation counts and identities |
| Bitcoin validation | Validated block hash, bitcoind version, network and validation/setup record digest |
| Execution | Real executor kind, explicit cache state, pruning configuration and network lifecycle parameters |
| Expected results | Ordered operation outcomes, root receipts, fee/accounting changes, state assertions and post-prune assertions |

The concrete JSON field names, types and first generated instance still
require review. This table is not a frozen executable manifest. No missing
digest, automatically accepted current digest, unspecified expected outcome
or wildcard comparison is allowed in an executable instance.

Use existing repository hashing and comparison conventions. Validate all
inputs before opening a writable copy of the snapshot. Separate immutable
fixture input from generated reports. Negative controls must cover missing
and extra fields, duplicate keys, hash mismatches, unsupported versions and
incorrect counts. Do not teach the validator to ignore a field merely
because the first smoke fixture does not exercise it.

## Snapshot and reset proof

Export a transactionally consistent database using the existing SQLite
facilities. Preserve all state needed for replay, rather than copying only
application rows. The generator must establish that no required WAL content
is omitted. Pin the exported database bytes and assert the expected anchor,
checkpoint, account balances, contract identities and relevant table counts.

Each trial starts from a fresh copy of the same immutable export. Verify the
whole-file digest before opening it, then verify logical reset assertions
after opening it. Run the smoke twice from independent resets and compare
the complete ordered outcome report. Do not restore by manually reversing
selected writes or call a warm in-memory runtime a reset.

## First smoke fixture

Build one small block containing valid paid calls that exercise successful
execution and a deterministic failure after a contract write. Use checked-in
contract artifacts and existing transaction builders. The exact expressions,
amounts, gas budgets and expected values must be derived from those contracts
and frozen in the first manifest before its acceptance run.

Include a nonempty pruning opportunity in the pre-state, prepared through
valid history or checked equivalent storage invariants. Assert that the
expected obsolete versions are removed and retained/current versions remain
after `handle_block` returns. A run with nothing eligible for pruning cannot
prove the chosen completion boundary includes useful maintenance.

Assert exact root receipt count, ordering, status and gas; payer, burner,
supply and collateral accounting; committed successful effects; rollback of
the failed call's writes; checkpoint/height advancement; and the post-prune
state. Fees must agree with the source pricing policy, not only with a
previous run. Reject invalid or expired fixture transactions instead of
counting their rejection as successful work.

This first slice is an untimed correctness smoke. It does not substitute for
the workload mix, validator and storage populations, cold compilation,
full-block diagnostics, batching/deduplication, API arrivals, backlog,
replay, enforced memory profiles or six-cell semantic qualification in the
agreed S2 plans.

## Review and sequence

1. Agree exact schema fields and the concrete smoke fixture with the lead,
   independent subagent and Interlink reviewer.
2. Implement the strict validator, fixture preparation and test-only runner.
3. Test negative controls and the smoke/reset assertions under the sole
   Cargo-slot constraint. Review actual code and evidence from all three
   perspectives.
4. Extend the reviewed generator to the full workload plan, resolve the
   operator population choice and freeze the complete executable manifest
   before any performance acceptance measurements.

Interlink message `c2ab3c0a5c051b99ceb5205402228f30` accepted the harness
location and completion boundary, conditional on exact receipts/state/fees,
post-prune assertions, strict manifest validation and verified snapshot
reset. It did not approve a still-unwritten manifest or performance results.

## Concrete smoke and freeze procedure

Source baseline inspected: `67a52fed58a893ce2c1c05483f86f4fffa02a675`.
Prepare separate published and initialized `error_test` instances A and B.
Use one signed commit/reveal pair with a single direct input containing these
three ordered instructions, each with `gas_limit: 100000`:

1. A: `write-result-payload(1)` succeeds with the WAVE encoding of `é\n`.
2. B: `scan-compound(false)` fails deterministically after writing its marker
   and record. Its paid root receipt is `Other` and its writes roll back.
3. A: `write-result-payload(2)` succeeds with the WAVE encoding of `é\né\n`.

The different successful return values are mandatory: A's two writes are
identical, so final state alone cannot establish that the third operation
ran. At completion A's `storage-state()` is `[1, 0, 0, 1]`; B's is
`[0, 0, 0, 0]`. There must be exactly three paid root receipts for these
instructions, ordered `Ok, Other, Ok`. Include native lifecycle receipts in
the full report separately; do not assert that the block has only three
receipts. Include the actual coinbase and commit in raw transaction counts,
and enumerate the complete Bitcoin transaction list before `filter_map`.

Prepare pruning history through actual preceding blocks with pruning disabled,
then enable pruning with retention six for the smoke. Select and pin a
specific obsolete state version and its retained successor from that history.
Require a zero persisted watermark before the smoke, or restore the actual
persisted watermark exactly as production startup does. At least one pinned
version must become eligible and disappear. The retained version, current
state and checkpoint must remain valid. `handle_block` success alone does
not prove pruning succeeded, because prune failures are logged and swallowed.

The generator may produce candidate measurements during development. It must
not produce a passing acceptance result or overwrite frozen expectations.
Fix semantic expectations above before generation. Derive numeric gas, fuel,
fees, collateral and lifecycle amounts from the candidate run, independently
check them against source arithmetic, and review the resulting complete
fixture before freezing. Check `gas <= 100000`, reservation consumption on the
failed write, and each fee against `execution_fee(gas - reserved_deposit)`.
Reconcile total payer debit, burner credit and emitted supply separately;
block lifecycle emissions mean that total supply delta is not simply burn.
No automatic refreezing after a replay mismatch is permitted.

Export using `VACUUM INTO` after statements and transactions are finished.
Reopen the standalone export independently and compare all reset assertions
before freezing its whole-file hash. Do not copy a live database file while
omitting its WAL, and do not reseed contracts when restoring an export.
Seeded signing does not alone guarantee byte-identical regeneration of mined
blocks. Preserved bytes and hashes, rather than the seed, define replay input.

## Proposed exact v1 data model

All objects reject unknown and missing fields, including nested objects.
Duplicate JSON keys are rejected before decoding. Integers are bounded u64
unless noted otherwise; hashes are lowercase full-width hexadecimal strings.
Monetary quantities use canonical Decimal strings, never floating-point JSON
numbers. Lists preserve order unless the field explicitly requires a sorted
unique set. No executable fixture permits placeholder values.

The manifest has exactly these fields:

| Field | Type and meaning |
| --- | --- |
| `schema_version` | Integer `1` (historical six-block retention) or `2` (explicit predecessor retention) |
| `kind` | String constant `smoke` |
| `case_id` | String constant `paid-success-failure-success-v1` |
| `funding_seed_hex` | 64 bytes, encoded as 128 hex characters; fixture-only key material |
| `source` | Object described below |
| `artifacts` | Sorted unique list of artifact objects, all native contracts plus user A/B code |
| `snapshot` | Snapshot object described below |
| `input` | Input object described below |
| `execution` | Execution object described below |
| `expected_report` | File reference to the frozen typed semantic report |
| `numeric_check` | File reference to the independently checked three-operation diagnostic report |
| `decision` | Explicit test consensus decision described below |

Reusable `FileRef` is exactly `{path: string, sha256: 64-hex}`. Paths are
relative to the fixture directory; no absolute paths, parent traversal,
symlink escape, duplicate artifact IDs or unreferenced replacement files.

- `source`: `kontor_commit` (40-hex), `rustc_verbose` (nonempty string),
  `target` (nonempty string), `profile` (`dev` or `release`),
  `features` (sorted unique strings), `core_lockfile` (FileRef),
  `wasmtime_revision` (40-hex), `engine` (`pulley`),
  `pulley_stack_bytes` (524288), `native_fiber_bytes` (2097152).
- Each artifact: `id` (unique string), `compressed` (FileRef), `raw_sha256`
  (64-hex), `addresses` (sorted unique contract-address strings).
- `snapshot`: `database` (FileRef), `schema_sha256` (64-hex over the frozen
  ordered SQLite schema projection), `anchor_height` (u64), `anchor_hash`
  (64-hex), `checkpoint` (string), `prune_watermark` (u64), `reset_report`
  (FileRef). No attached database or required WAL file may be omitted.
- `input`: `raw_block` (FileRef), `height` (u64), `block_hash` (64-hex),
  `previous_hash` (64-hex), `raw_txids` (ordered 64-hex strings),
  `kontor_txids` (ordered 64-hex strings), `kontor_input_count` (1),
  `operation_count` (3), `payer_x_only_pubkey` (64-hex), `operations`
  (three objects described below), `bitcoin_validation` (object).
- Each operation: `txid` (64-hex), `tx_index` (u32, original Bitcoin index),
  `input_index` (u32), `op_index` (u32), `contract` (address string),
  `expression` (one of the three expressions above), `gas_limit` (100000).
  Cross-check every value against production decoding, not only JSON types.
- `bitcoin_validation`: `network` (`regtest`), `bitcoind_version` (string),
  `accepted_block_hash` (64-hex), `record` (FileRef recording actual RPC
  acceptance and the funding/parent chain). Match hash to `input.block_hash`.
- `execution`: `executor` (`RuntimeExecutor`), `component_cache` (`cold`),
  `network` (`regtest`), `prune_enabled` (true), `retain_blocks` (6),
  `gas_to_fuel_multiplier` (1000), `execution_price` (`0.000000001`),
  `storage_gas_per_byte` (1), `lifecycle_parameters` (FileRef),
  `independent_resets` (2), `timing_claim` (`none`).

Version 2 adds the required `execution.effective_retain_blocks` value `7`.
The configured `retain_blocks` remains `6`, exercising the node's minimum
retention floor. Finality at anchor plus six rolls back to the anchor's
predecessor, so it needs seven retained blocks. Version 1 readers preserve
the historical six-block watermark and do not relabel those archives as
evidence for the corrected runtime. Regenerate current-source captures and
compare both runtime candidates under the same retention policy.

`reset_report` and `expected_report` use the same versioned report shape:
`schema_version`, `height`, `block_hash`, `checkpoint`, `prune_watermark`,
`receipts`, `usage`, `accounts`, `contract_views`, `state_versions` and
`table_counts`. All fields are required, even empty receipt/usage lists. Receipts and usage
cover exactly the report height, not all history. Order receipts by persisted
`id`; order usage transaction records by original transaction index followed
by the single block-maintenance record. Each usage record also contains
`height` (u64) and `tx_index` (nullable u32), so its scope is unambiguous.

- `receipts`: complete ordered `ResultRow` values as defined in
  `indexer-types/src/lib.rs`, with every field required and explicit nulls.
  Preserve native receipts as well as the three identifiable paid roots.
- `usage`: ordered records with `txid` (nullable string), `user_fuel`,
  `system_fuel`, `deposit_fuel` and `kind` (`transaction` or `block`).
  Compare against persisted transaction/block usage and distinguish system
  lifecycle costs from user costs. Do not synthesize per-op fuel from a
  transaction aggregate.
- `accounts`: fixed objects for payer, burner, Core, ordering pool, storage
  pool and total supply, each with canonical `balance` and `floor` strings.
  Total supply has floor zero; payer identity is pinned by the manifest.
- `contract_views`: exactly A and B, each with `address` and `storage_state`
  (four u64 values). Observation happens after the measured boundary and
  must not append receipts or mutate the expected persistent state.
- `state_versions`: ordered fixed projections for the selected pruning rows
  and A/B state: `contract`, `path_hex`, `height`, `value_hex`, `deleted`,
  `depositor` (nullable u64), `deposited_gas` (nullable u64). Freeze both
  removed and retained identities via the before/after reports.
- `table_counts`: sorted unique records `{table, rows}` for every persistent
  user table in the pinned SQLite schema. Report and reject a changed set.

This exact-field proposal still needs review and a real generated instance.
The schema deliberately accepts only this correctness smoke. Extending it to
paired S1/S2 performance requires separating shared input identity from
candidate-specific build attestations and expectations; do not weaken source
identity checks to reuse a single-source smoke manifest across engines.

Review basis: Interlink `4ef81700aa1318d14139989e930f56dd` approves staged
creation, independent numeric checks, freezing and strict acceptance replay.
The independent subagent checked the source boundary, raw decoding, contract
semantics, lifecycle accounting and restored watermark. It found no source
feasibility blocker; its conditions are incorporated above. Neither review
constitutes approval of the still-unimplemented runner or missing fixture.


## Exact-field review corrections

The manifest `decision` is exactly `{consensus_height: u64, certificate_hex:
string, value_kind: "block", block_height: u64, block_hash: 64-hex,
certified_txs: null}`. Use the next consensus height after the snapshot's
persisted history. Bind block identity to the input. The test supplies this
decision directly with an empty certificate, matching existing reactor tests;
this tests execution and decision persistence, not certificate validation or
Malachite consensus. Do not present it as consensus qualification.

`numeric_check` contains `schema_version: 1`, `snapshot_sha256`,
`raw_block_sha256`, `source_commit`, and three ordered `operations` records.
Each record contains `txid`, `tx_index`, `input_index`, `op_index`, `contract`,
`expression`, `status`, `value` (nullable string), `gas`, `user_fuel`,
`system_fuel`, `deposit_fuel`, `reserved_deposit_gas`, `payer_before`,
`payer_after`, `burner_before`, `burner_after`, `floor_before`, `floor_after`
and `execution_fee`. Integer types and canonical Decimal strings follow the
manifest conventions. Include `error_message` (nullable string), preserving
B's actual scalar-scan error, and `storage_state` (four u64 values). All fields
are required and unknown fields are rejected.

Generate this diagnostic on a separate reset of the same pre-state. Preserve
the decoded contexts, signer, payment, database transaction identity and prior
successful effects. Execute each operation through `Runtime::execute`, with
existing `start_usage`/`finish_usage` around it; read diagnostic balances and
views outside that scope. Independently check:

- `deposit_fuel % gas_to_fuel_multiplier == 0` and the derived reservation;
- `gas >= reserved_deposit_gas` and `gas <= gas_limit`;
- payer debit and burner credit both equal the pricing-source fee;
- B has nonzero reservation consumption but no surviving writes or increased
  floor, and A's successful effects remain;
- diagnostic paid receipts agree with full-block paid receipts on semantic
  fields and gas; aggregate usage agrees with actual persisted transaction
  usage, accounting explicitly for any executor work outside individual calls.

The diagnostic is evidence for checking frozen numbers, not an alternative
acceptance path. It does not replace either full `handle_block` replay. A
mismatch between diagnostic context and production execution must be resolved,
not normalized away. The native token `hold` and `release` receipts are intentionally suppressed;
use observed payer debit and burner credit for the independent cross-check.
Do not claim their return values exist in persisted block evidence.

The validator must verify execution constants against the running source and
runtime configuration, not merely matching JSON literals. Fixture seeds are
regtest-only; refuse every other network and document this in the fixture
README. These corrections incorporate the subagent's exact-field review and
Interlink's implementation approval notes for revision `59bdabfb...`.
