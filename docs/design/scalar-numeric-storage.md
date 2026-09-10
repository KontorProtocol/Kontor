# Scalar Integer and Decimal storage

Integer and Decimal now store their signed coefficient as one value at the
field's existing path. The shared built-in types implement the existing
`Store`/`Retrieve` interfaces directly, as other scalar types do. Contracts keep
normal numeric fields, maps, options and generated setters; no reward-specific
storage format or runtime policy is introduced.

## Representation and compatibility

The numeric payload is exactly 33 bytes: one sign byte (0 = plus, 1 = minus),
followed by four little-endian u64 magnitude limbs, least significant first.
Decimal stores its raw 18-place coefficient. Every limb and the sign are
preserved, including signed zero. Invalid payload lengths or sign tags fail
instead of becoming a zero balance. The host wraps this payload with its existing
byte-list serialization.

Map keys and index buckets/sort/covering values retain their existing encodings.
Those ordered encodings intentionally coalesce equivalent zeros. Numeric value
storage is independent of key ordering and does not reinterpret or round amounts.
WIT shapes, arithmetic, numeric APIs and parent field ordinals are unchanged.

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
Codec unit tests also pin signed-zero preservation and rejection of malformed
payloads. The reward benchmark provides an end-to-end comparison on the combined
reward and scalar-storage branches.
