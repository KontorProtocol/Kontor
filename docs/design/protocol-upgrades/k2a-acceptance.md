# K2a implementation and acceptance

Status: local implementation validation and all three phase reviews complete;
current-head CI and merge pending.
This phase provides the in-tree selected executor and live logical storage adapter.
It does not complete the protocol-upgrade system or independently isolate Cargo graphs.

The implementation base is merged OWNERSHIP-1
`dfacbefdac22b898c5bad5b2cae5e2513e147afd`, including S2 and synchronous guest WIT.
The current implementation checkpoint is
`c8e2c3a6f382472be0633e8e9829d9a6ddef2d97`.
The [reconciliation ledger](k2a-reconciliation.md) records the agreed changes,
earlier source comparisons, reviews and intermediate validation, including failures.

## Resulting behavior

- The coordinator selects P1 for parsing, recognition, preparation, execution,
  lifecycle, simulation, public views and committee derivation. Selections distinguish
  purpose, network and canonical snapshot. Preparation does not grant execution
  authority, and rollback/replay invalidates stale selections even at the same hash.
- Selected roots retain their gas, pricing, memory, error and native-contract rules.
  Nested calls inherit the root context. Scoped selection restores previous context
  on return or cancellation. System and committee budgets remain independent of a
  local public-view allowance. No numerical gas limit or block budget is introduced.
- P1 interpretation of logical rows, point reads, ranges, ordered writes, deposits,
  identities, contracts, receipts and savepoints lives under `protocol::v1`.
  Node-owned callbacks retain database connections, cursor lifetimes and transactional
  authority. Existing canonical ownership and child-drain mechanisms are preserved.
- Component-cache entries bind artifact identity and selected executor, so reorgs
  that reuse a contract row ID cannot select stale code. Views pin one database
  snapshot and retain its selected implementation through nested calls and pool reuse.
- The initial native set retains all five exact compressed artifacts, publication
  order, IDs, signer IDs, privilege/deposit/receipt policy, build metadata and exact
  Postcard provenance bytes. Fresh nodes do not derive native provenance from the
  current node commit. Read-only database preflight validates supported genesis
  before schema initialization or migration can write to an existing database.
- Interrupted bootstrap resumes a validated publication/receipt prefix. It restores
  the next receipt index and recognizes committed outer validator initialization,
  so retries and completed restarts do not duplicate receipts or issuance. Malformed
  or inconsistent histories are rejected without repair or renumbering.

Bootstrap recovery deliberately corrects pre-freeze restart behavior. It is not
claimed to be a byte-preserving relocation. Other extraction paths retain P1
error classification and formatting, checkpoint order and accounting semantics.

## Local evidence

Raw logs and comparison reports are in `.build-cache/native-retention/` and
`.build-cache/qualified-prerequisite-integration/` in the implementation worktree.
The integration directory preserves validation against the merged prerequisites;
later native-retention changes have their own current-source checks.

| Check | Evidence and scope |
| --- | --- |
| All-target compilation and lint | Indexer and testlib Clippy with warnings denied passed, 21.60 seconds, `clippy-final.log`. |
| Consolidated regression run | 57 passed, 152.36 seconds, `consolidated-regressions.log`: six database genesis, four coordinator selection, 34 retained protocol, six mempool, three selected-runtime and four staking genesis tests. |
| Final ingress/view integration | Nine passed, 67.54 seconds, `final-integration.log`: HTTP error precedence/raw admission, pending recognition/backpressure, witness replacement and rollback invalidation, and held/fresh views after contract row-ID reuse. |
| Fresh genesis comparison | Candidate `ddba0f10` and qualified-base fixture `d066d72f` match every typed logical row across all 22 tables. `fresh-comparison-result.json` records exact revisions, inputs and report hashes. |
| Interrupted bootstrap | Real owned execution interrupted after partial/full publication, admission floor and nonempty validator initialization matches uninterrupted state after two reopens at each stage. Generated-ID counters remain zero. Included in the consolidated run. |
| Malformed existing genesis | Artifact/provenance/identity/prefix/receipt/state inconsistencies reject before schema or logical-state changes. Includes negative, overflowing, duplicate and incorrectly attributed receipt indexes. |
| Existing-state execution comparison | Current source `c8e2c3a6` matches all 11 baseline stages for recognition, simulation, execution, confirmation, rollback and reconfirmation. The test passed in 28.44 seconds; `validation-final.json` records report and log hashes. |
| Bundle controls | 50 Python controls pass with compiler caching disabled. The first run failed on a read-only cache directory, not a control assertion. |
| Qualification manifests | All four manifests validate against current pinned inputs. This validates source bindings, not cross-platform runtime qualification. |

The fresh comparison gives both real node revisions identical explicit artifacts,
provenance, validator configuration and a seeded node-local receipt epoch. No table
is excluded. The baseline fixture changes provenance input only, alongside the common
reporting harness. Different report source fields identify the distinct revisions.
This is fresh uninterrupted genesis evidence, separate from recovery tests.

The old preserved execution seed is used to compare execution semantics, not to
claim its genesis provenance would pass the new startup preflight. Its historical
native definition is not silently whitelisted. Unsupported prelaunch databases need
an explicit retained definition if an actual deployment requires one.
The exact preserved baseline is source
`213acdecdac67b5cf8587910d9dacbb8f7fd9eb1`, archived locally at
`/home/wilfred/Documents/Kontor/.build-cache/ownership-final-parity-20261031/seed`.
Its `inputs.json` binds `seed.db` and `transaction.bin`; `baseline.json` contains
the 11 stages. Earlier worktree-local baseline archives are not substitutes for
this final comparison input.

## Phase review

The lead and both independent reviewers examined base
`dfacbefdac22b898c5bad5b2cae5e2513e147afd` through
`9ef3c9b777367ddd0769b84db14a96e5a2dfffd2`, whose executable source is `c8e2c3a6`.
The implementation/state reviewer and integration/failure reviewer independently
reported no material findings. Both verified the raw evidence and comparison
inputs, rather than relying on each other's conclusions. Lead findings addressed
during validation were the batch snapshot representation and the bootstrap retry
fixture's invalid durable prefix, as recorded in the reconciliation ledger.

Review covered selection and stale preparation, nested immutable context, cache
and snapshot identity, logical storage/cursor ownership, accounting/order/rollback,
production ownership preservation, native input retention, preflight rejection and
bootstrap recovery. Recovery tests reopen committed boundaries; they do not inject
physical storage failures. Fresh genesis uses one explicit configuration. These
limits and future-phase requirements remain visible rather than being counted as
complete upgrade-system acceptance. Local review does not replace CI.

## Remaining phase gates and later phases

PR #615 is integrated from verified merge
`cd74877fa354ec82f664944536e641d39d02a4d5`. Its six-cell qualification and
all current-head checks passed. The integration preserves the reviewed K2a core
source and the separately reviewed CI changes exactly; regeneration changes only
23 SHA-256 fields in the four qualification manifests. All four manifests validate,
19 CI controls pass, and the 228 qualification controls pass after rerunning the
two socket-dependent modules outside the socket-restricted sandbox (seven tests,
including the six initially blocked by socket creation). No runtime correction
was needed, so the existing independent review coverage is retained.

Before this phase merges: pass current-head CI and verify the actual merge.
Runtime-affecting changes still require their applicable cross-platform qualification.

K2b must isolate the actual production semantic closure into independently locked
graphs, with common interfaces free of dependency-owned types. K3 must persist the
complete execution/network/genesis identity and atomic migration substrate. The
initial native-set digest here is not that complete identity. Authorization,
certified history, engine-only handoff, after-H activation, cross-upgrade recovery,
historical catch-up and final node/SDK integration remain required later phases.
P2 dispatch is not proved by the single P1 implementation in this phase.
