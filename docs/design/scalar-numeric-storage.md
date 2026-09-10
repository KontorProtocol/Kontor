# Scalar Integer and Decimal storage

Integer and Decimal now store their signed coefficient as one value at the
field's existing path. The shared built-in types implement the existing
`Store`/`Retrieve` interfaces directly, as other scalar types do. Contracts keep
normal numeric fields, maps, options and generated setters; no reward-specific
storage format or runtime policy is introduced.

## Representation and compatibility

All four uses share the existing numeric `KeyElement` codec: map keys, sorted
index keys/covering projections, equality-index buckets, and stored values. The
payload is 33 bytes: an existing positive/negative numeric type tag followed by a
big-endian magnitude (inverted for negatives so byte order matches numeric order).
Decimal uses its raw 18-place coefficient. Storage wraps those bytes in the host's
existing byte-list serialization. There is no second numeric value encoder.

Zero has one canonical representation: a positive tag with zero magnitude.
Writing raw negative zero stores positive zero, and equivalent zeros use the same
index bucket. This canonicalizes persistence; it does not remove the public sign
field or change the arithmetic/conversion APIs. The shared decoder rejects a
negative-zero encoding that the encoder never emits, and storage rejects trailing
bytes as well as malformed or truncated elements.

Map keys and index sort/covering encodings retain their existing canonical format.
Numeric equality-index buckets now use that same encoding instead of converting
numbers to strings. Their on-disk paths therefore change too. WIT shapes, numeric
precision, arithmetic APIs and parent field ordinals are unchanged.

This replaces the old four-limb-plus-sign child layout everywhere these built-in
types are stored. It requires fresh state/replay with the rebuilt contract set;
it is not an in-place migration of existing databases or an adapter for old
contract binaries. Preproduction history is disposable. A production rollout
would need an explicit versioned migration strategy before making this change.
The obsolete IntegerModel/DecimalModel limb-level APIs are removed; numeric
values are opaque scalars accessed through their parent setters or Store/Retrieve.

## Boundaries and cost

A numeric read is one existing `get-list-u8`; a write is one `set-list-u8`.
Previously each used six storage operations for limbs, sign and existence/variant
bookkeeping. A four-number reward account therefore uses four value reads or
writes instead of 24, before parent-container bookkeeping.

The runtime's normal path validation, serialization, fuel, payer deposit tracking,
versioned writes and subtree deletion still apply. Generated indexed setters
continue to reconcile old and new index memberships; scalar storage does not
bypass them. ReadStorage still returns Option for an absent leaf, allowing
existing Map/Option getters to distinguish absence from stored zero.

## Validation

The Wasm contract regression exercises zero, both signs and the full magnitude
range, numeric map values, an optional Integer, indexed records, numeric sort and
covering projections, in-place setters, replacement, deletion, savepoint rollback
and block-height cascade rollback. It inspects the single stored leaf and its
metering/deposit metadata, and checks the footprint cache after rollback.
Codec tests pin canonical zero, shared key/bucket encodings and rejection of
malformed payloads. The Wasm regression also rewrites positive zero with raw
negative zero and verifies stable stored bytes, equality buckets and deletion.
The reward benchmark compares the combined reward and scalar-storage changes.

On 2026-09-10 the full release workspace suite with
`REGTEST=1` passed 771 tests with three ignored, including 482 indexer library and
121 integration tests.
The separate opt-in reward benchmark passed all six scenarios in 22.87 seconds;
its [comparison](storage-reward-costs.md#scalar-numeric-storage-comparison) records
operation counts and timing limits. Both contract sets were rebuilt with the
repository's pinned image.
