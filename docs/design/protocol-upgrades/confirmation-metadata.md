# Bitcoin confirmation positions (ID3-node candidate)

The candidate adds nullable `transactions.confirmed_bitcoin_tx_index` as node
metadata. Its value is the transaction's position in the confirming raw Bitcoin
block, including coinbase and unrelated transactions. `tx_index` retains its
historical filtered-ordinal meaning. Contract addresses keep their original raw
publication position.

Existing rows start with an unknown position. The coordinator populates it after
ordinary block execution and after confirmation of an earlier batch. Confirmation
does not execute the batch again. A node-owned SQL trigger invalidates the new
position when existing executor SQL clears or changes `confirmed_height`. A
surviving batch therefore loses its confirmation position during a reorg and
receives the new position on reconfirmation.

The migration is atomic and idempotent. It does not change legacy transaction
query projections, execution context, receipt contents or checkpoint inputs.
K2 extraction must retain explicit legacy transaction projections and exclude
this column, its maintenance trigger and `idx_transactions_confirmation_height`
from semantic comparison. Whole-database
digests that include every physical column will change when rebased onto ID3;
they must not be confused with retained protocol semantic projections.

## Historical backfill

The candidate maintenance command handles one block at a time. Stop the node
before running this offline maintenance command, then start it normally afterwards.
It is not part of the protocol activation procedure, which restarts only Malachite.
The command's migration/index build and writer lock have no qualified five-second
bound for a live node, so concurrent daemon operation is unsupported:

```sh
kontor backfill-confirmations \
  --database /path/to/node.db \
  --height 123456 \
  --block-file /path/to/raw-block.bin
```

The file is a raw Bitcoin block in consensus binary encoding, not hex text. The
command requires an existing node database and reads at most 4,000,001 bytes to reject
oversized input. It reports the height, block hash, number updated and number
already known as JSON. It opens without SQLite's create flag, checks the base
node schema before DDL, and runs only the confirmation metadata migration. It
does not run general node initialization, change journal mode, materialize other
state indexes or write/load the crypto extension.

Backfill verifies the transaction merkle root, witness commitment, coinbase shape,
size and unique transaction IDs. A block carrying a witness commitment must not
be supplied with all witnesses stripped. Under an immediate database transaction it then
checks the header hash against the stored canonical block at that height. Every
stored confirmation at that height must occur in the supplied block, and every
known position must agree. Only then are unknown positions filled. A mismatch or
write failure leaves all positions unchanged. The writer lock prevents a reorg
from replacing the checked canonical block before the update commits.

This command relies on the node's existing canonical block selection. It does not
independently validate Bitcoin proof of work, transaction scripts or UTXOs. It
does not parse Kontor instructions, invoke contracts or reconstruct execution
using newer protocol rules. Repeating a successful backfill is a no-op. If the
raw block is unavailable, leave the position unknown; do not infer it from the
filtered ordinal or substitute zero.

## API and SDK coordinates

Transaction, block-transaction and result endpoints expose `execution_height`
separately from `confirmed_height`, `confirmed_bitcoin_tx_index` and
`batch_height` (global consensus height). The legacy `height` and `tx_index`
fields retain their old meaning. `tx_index` is deprecated and is not a raw
Bitcoin index. `ContractAddress.tx_index` still identifies a deployment's raw
Bitcoin position, independently of receipt ordinals.

The block-transaction listing and its `height` filter continue to select
execution height, including a batch's anchor. They are not a list of everything
confirmed in that Bitcoin block. Pagination remains ordered by the existing row
ID; changing confirmation does not move a row across an ID cursor. A cursor does
not notify consumers of metadata updates to an already-read row.

Every affected endpoint reads legacy rows and confirmation metadata within one
SQLite read snapshot. Persisted receipts in GET and POST inspect return the same
`ResultInfo` shape as result queries. Simulation retains provisional receipts
without confirmation metadata. System receipts without a transaction have null
confirmation and batch coordinates. Historical positions unavailable to the node
remain null even when confirmation height is known.

SDK execution events now carry `executionHeight`, nullable `confirmedHeight`,
`confirmedBitcoinTxIndex`, and `batchHeight`. The deprecated `height` alias is
execution height; deprecated `txIndex` is a nullable legacy ordinal. A missing
index is never changed to zero. Event outcomes and decoded persisted receipts
retain their read-time coordinates. Direct transaction lookups on older nodes
without the new fields yield unknown confirmation metadata. Event streams require
the new receipt-stream endpoint and fail explicitly on unsupported servers.

When one transaction spans result pages, the latest observed page supplies its
confirmation coordinates for the whole event and all outcomes. Confirmation,
unconfirmation and reconfirmation can therefore change between page reads without
producing contradictory coordinates within one event. Conflicting execution
heights cause the pending transaction to be discarded and retried from the last
completed transaction token, before duplicate operation keys are collapsed.
Generation checks discard unfinished groups when a rollback intervenes. There is
still no atomic snapshot across HTTP requests: an observation can be invalidated
by a subsequent rollback.

Execution events are snapshots. Confirmation does not execute a batch again and
does not produce another execution event. Consumers tracking confirmation must
refresh with `await session.transaction(txid)`, including after a reorg signal.
Invalidate cached confirmation coordinates after a reorg even if the transaction's
execution anchor survives. The lookup returns the current `TransactionInfo` wire
shape (number-valued heights), or null if the transaction is absent. Transport
failures still throw. It does not start background polling. A known confirmation
height with a null raw index means historical position is unavailable, not that
the transaction is unconfirmed.

## Durable receipt resume

`GET /api/receipt-stream` follows node-local receipt history. Its opaque tokens
contain the node's epoch, rollback generation, receipt cursor and filter identity.
They are positions, not credentials, and cannot be moved to another independent
node or a different filter. Existing `/results` pagination remains available for
browsing, but its numeric row IDs can be reused after rollback and are not safe
resume tokens.

Acquire an initial token with `start=origin` or `start=tip`, then pass it as
`from`. A page supplies a token for each receipt and a `next_token` for continuing
the scan. While a transaction group is unfinished, retain its preceding completed
token as `from` and pass scan progress as `page`. Do not acknowledge a high-water
token until all matching transaction groups before it have completed.

Each canonical rollback records its surviving height and maximum receipt ID
atomically with deletion. A stale token receives a recovery response without
receipt rows. Its cursor is the minimum of the completed cursor and the recorded
surviving maxima; its invalidation boundary is the minimum surviving height.
Recovery processes at most 256 successive records per response and continues
through recovery-only responses before reading replacements. The current log is
retained in full. A missing record, foreign epoch, future generation or unsupported
lineage returns an explicit reset requirement. This covers finality replay with
unchanged Bitcoin hashes and receipt maximum, and rollback without replacement.

The SDK exposes `resumeToken` on both `tx` and `reorg` events. Configure
`events: { from: savedToken }` to resume, or `events: { start: "origin" }` to ingest
current canonical history. The default follows the current tip. Numeric-only
resume requires an explicit resynchronization. `ReceiptStreamError.reason` names
terminal failures; the SDK never silently switches nodes or skips to the tip.
Calling `ready()` before `events()` does not consume receipts. Draining pauses
while there are no subscribers. Multiple iterators on one session share its
progress: a later iterator receives subsequent events, without replaying events
already emitted. Use separate sessions for independent resumable consumers.

Consumers must commit each transaction's derived effects and its token in one
database transaction. For a reorg, retract effects strictly above `forkHeight`
and save its recovery token atomically. This supplies resumable observations, not
exactly-once external effects without application-side atomicity. Confirmation
metadata changes do not cause another application of transaction effects.

After restoring a database backup, stop the node and rotate its receipt epoch
before serving clients:

```sh
kontor rotate-receipt-stream --database /path/to/node.db
```

The command changes only receipt-stream metadata, invalidating old tokens. It
does not initialize a node, replay contracts or delete execution state. Existing
clients must explicitly resynchronize. A normal restart preserves the epoch.
A backup predating receipt-stream metadata needs no rotation: normal startup
migration creates a fresh epoch. The offline command reports this case without
changing the backup.
The stream refuses receipt IDs above JavaScript's exact integer limit. Its
unsupported-lineage marker survives canonical rollback; rotation clears it only
when current IDs are supported. Retained executor allocation remains unchanged.

## Acceptance status

The recovery extension passed 10 database/API tests, the same-hash replay wake
regression, 15 confirmation regressions, and real reactor Bitcoin rollback and
restart/finality rollback tests. The backfill executable test and both rotation
executable tests passed, including nonmutating legacy-backup rejection. All 70
unfiltered indexer-types tests regenerated the SDK declarations. Web and native
SDK builds, the full SDK suite, and installed-tarball consumer checks passed.
Final independent review and current-head CI remain required before merge.
The earlier evidence below predates this recovery extension.

The migration, coordinator, backfill and initial API slices have passed their
focused Rust tests and independent source reviews. Database, batch, consensus
state and aggregate-error regressions passed. The inspect slice passed all 15
confirmation-related tests, including a signed raw POST-inspect receipt compared
with the result endpoint across confirmation, reorg and reconfirmation. A separate
test applies a real writer reorg between the request's two reads and verifies
that the read snapshot remains consistent. Synthetic Bitcoin fixtures do not
claim mining or mempool acceptance.

Generated bindings passed the full unfiltered indexer-types library suite (67
tests). Web and React Native package builds, 208 SDK tests and installed-tarball
checks passed. The package checks cover all public subpaths with bundler and
Node16 TypeScript resolution, strict null handling and the React Native export
condition. They do not execute a React Native application. The package also fixes
a pre-existing rc.6 release defect: its public exports referenced missing generated
wire declarations. The rc.7 version is prepared in source and has not been published.

At source revision `b2fecf1bc7f00c0d0a9de00347c5da120f0e077b`, the actual
`kontor backfill-confirmations` executable passed its process-level smoke test:
exact JSON output, repeat-run idempotence, raw position zero, preserved node
metadata, missing database rejection and unchanged unrelated database bytes.
Nonzero positions and canonical-body checks are covered by the module tests,
not this genesis-block smoke test. All 110 reactor tests passed at that revision,
including cluster, rollback, late-joiner and batch regressions. An earlier test
wrapper used the wrong working directory and failed to find contract fixtures;
that failed capture is retained separately and is not counted as passing evidence.

The agreed IDENTITY-5 plan has hash
`d90ad7ee3d8dc9d9ac5bd2e347cdf28dda8cf0a2c22f0fbf5f8c0c09c5da1857`.
It separates this node/SDK PR from dependent ID3-indexer and ID3-explorer PRs in
`UnspendableLabs/Kontor-Explorer-Indexer` and `UnspendableLabs/Kontor-Explorer`.
Those consumers still use legacy packages and require transaction-ID joins,
live-batch ingestion, separate execution/confirmation displays and a real SDK
release. This PR does not update their deployments. ID3 remains incomplete until
the dependent integrations are complete; K7 and final qualification must still
prove confirmation across distinct protocol bundles. K2 must retain the explicit
semantic projection described above. Native build provenance remains a separate
unresolved K2 qualification concern, not a reason to normalize arbitrary state.
