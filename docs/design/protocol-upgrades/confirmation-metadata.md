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
this column and its maintenance trigger from semantic comparison. Whole-database
digests that include every physical column will change when rebased onto ID3;
they must not be confused with retained protocol semantic projections.

## Historical backfill

The candidate maintenance command handles one block at a time:

```sh
kontor backfill-confirmations \
  --database /path/to/node.db \
  --height 123456 \
  --block-file /path/to/raw-block.bin
```

The file is a raw Bitcoin block in consensus binary encoding, not hex text. The
command requires an existing database and reads at most 4,000,001 bytes to reject
oversized input. It reports the height, block hash, number updated and number
already known as JSON.

Backfill verifies the transaction merkle root, witness commitment, coinbase shape,
size and unique transaction IDs. Under an immediate database transaction it then
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

## Remaining acceptance work

Source reviews cover the initial migration, coordinator writes, rollback and
reconfirmation tests. Rust execution is still pending. The tests use the actual
Reactor and RuntimeExecutor with synthetic raw Bitcoin fixtures; they do not
claim mining or mempool acceptance. Their successful guest receipt and state are
checked before preservation comparisons.

Backfill and command review, current-head Rust tests, existing rollback/reorg/batch
suites, public API and SDK changes, Explorer consumers and package release paths
remain required. This document is not a completed-phase or release-readiness claim.
