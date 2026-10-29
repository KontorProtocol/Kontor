# SDK changes

## 0.3.0-rc.7

This prerelease changes the event TypeScript interface. Transaction events now
require `executionHeight`, `confirmedHeight`, `confirmedBitcoinTxIndex`, and
`batchHeight`. Update custom event producers and mocks to supply these fields.
Deprecated `txIndex` is now `number | null`, because an unknown position cannot
be represented as zero. It remains the legacy filtered ordinal. Use the new raw
Bitcoin position field for confirmation; deployment addresses are unchanged.

Events and persisted receipt coordinates are read-time snapshots. Refresh with
`session.transaction(txid)` to track later confirmation or reorg. The lookup
returns wire metadata with number-valued heights, while event heights are bigint.
It returns null for an absent transaction and throws for transport errors.
Simulation receipts remain provisional and do not gain confirmation coordinates.
For receipts spanning pages, the latest observed page's confirmation metadata
applies to the entire event. Mixed execution heights are retried before emission.
These separate page reads are not an atomic chain snapshot.

The package now includes the generated API declarations and points its
type exports at the actual build output. `npm run test:package` validates an
installed tarball consumer, including strict null handling for confirmations.
TypeScript consumers need `ESNext.Disposable` in their compiler `lib` list for
the generated Wasm resource declarations (alongside their usual ES and DOM libs).
