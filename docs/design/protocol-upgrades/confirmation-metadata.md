# Bitcoin confirmation positions (ID3, implementation in progress)

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
retain their read-time coordinates. Older nodes without the new fields yield
unknown confirmation metadata, not a fabricated position.

When one transaction spans result pages, the latest observed page supplies its
confirmation coordinates for the whole event and all outcomes. Confirmation,
unconfirmation and reconfirmation can therefore change between page reads without
producing contradictory coordinates within one event. Conflicting execution
heights cause the pending transaction to be discarded and retried from the last
completed transaction cursor, before duplicate operation keys are collapsed.
This is a consistency check, not an atomic snapshot across HTTP requests; it does
not detect every possible execution reorg at the same height.

Execution events are snapshots. Confirmation does not execute a batch again and
does not produce another execution event. Consumers tracking confirmation must
refresh with `await session.transaction(txid)`, including after a reorg signal.
Invalidate cached confirmation coordinates after a reorg even if the transaction's
execution anchor survives. The lookup returns the current `TransactionInfo` wire
shape (number-valued heights), or null if the transaction is absent. Transport
failures still throw. It does not start background polling. A known confirmation
height with a null raw index means historical position is unavailable, not that
the transaction is unconfirmed.

## Acceptance status

The migration, coordinator, backfill and initial API slices have passed their
focused Rust tests and independent source reviews. Database, batch, consensus
state and aggregate-error regressions passed. The inspect slice passed all 15
confirmation-related tests, including a signed raw POST-inspect receipt compared
with the result endpoint across confirmation, reorg and reconfirmation. A separate
test applies a real writer reorg between the request's two reads and verifies
that the read snapshot remains consistent. Synthetic Bitcoin fixtures do not
claim mining or mempool acceptance.

Generated bindings use the full unfiltered indexer-types library suite. SDK,
final-head integration and full reactor regressions, the actual CLI executable,
Explorer consumers and their package-release paths still require completion.
The checked-in SDK is `@kontor/sdk`; the separately located Explorer repositories
consume older `@kontor/kontor-ts` packages. Updating this source alone does not
update those deployments. This is not a completed-phase or release-readiness claim.
