# SDK changes

## 0.3.0-rc.7

Protocol upgrades add `session.getProtocol()` and contextual simulation helpers
that report the exact protocol and canonical execution context selected for the
simulation. Protocol discovery includes supported transaction formats and host
ABIs. Node diagnostics distinguish configured mode from actual runtime authority,
committee membership and join progress. These are local observations, not proof
of network freshness or permission to sign. Existing simulation responses remain
available; contextual simulation requires the corresponding node endpoint and
does not silently fall back to a separately fetched protocol snapshot.

SDK upgrade helpers prepare and submit Schedule, Postpone and Cancel actions.
The node CLI inspects and signs explicitly selected actions offline. Submission
is not consensus acceptance. A rolled-back
action needs a newly approved valid attempt. See the SDK README and protocol
operator documentation for the current interfaces and timing assumptions.

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
