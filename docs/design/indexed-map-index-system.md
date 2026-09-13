# Maps, indexes, and range queries

This is the current API guide. Earlier staged proposals are preserved in Git
history; they are not alternative supported APIs.

## One map and one range operation

`Map<K, V>` stores values under typed primary keys. `#[derive(Storage)]` generates
value models. Adding `#[index(...)]` to a value declares maintained secondary
indexes; it does not require a different map type.

```rust
#[derive(Clone, Storage)]
#[index(holder, by = owner)]
#[index(creator, by = creator, include = (agreement_id))]
struct NftRecord {
    owner: Holder,
    creator: Holder,
    agreement_id: String,
    attributes: Map<String, String>,
}
```

```rust
nfts.keys();
nfts.range(start..end).keys();
nfts.range((Bound::Excluded(last_id), Bound::Unbounded)).keys();
nfts.range(..=last_id).rev().keys();
nfts.holder(holder).range(start..end).keys();
nfts.creator(creator).range(start..end).iter();
```

Plain maps and unsorted indexes range over `K`. Sorted indexes range over their
sort field. Bounds retain that meaning when `.rev()` reverses iteration. Included,
excluded, unbounded, empty, missing-key, and removed-key bounds use the same
implementation. Bounds are database seeks, not filters over discarded entries.

A covering index's `.iter()` returns `(primary_key, projection)`, and `.values()`
returns projections. `.keys()` fetches keys only, even for covering indexes.
Sorted covering queries additionally expose `.with_scores()`. Fetching keys or scores does
not read a covering projection. Multiple included fields form a projection tuple.

Unbounded index queries expose `.len()` and `.is_empty()` using the maintained
bucket count. Bounded queries deliberately have neither: the bucket count is not
the size of a range. To check whether a range has a member, use `.keys().next()`.

The `contract!` WIT declaration syntax uses the same index machinery:

```rust
contract!(name = "storage", indexed = "
    challenge: due by status sort deadline-height include agreement-id;
");
```

One source supplies each index bucket to stdlib. Generated models no longer carry
separate key, sorted, and covering scan implementations. Internal bucket adapters
are not contract query APIs.

## Scalar map entries

Use `.entries()` when both the key and its scalar value are needed:

```rust
ledger.entries(); // (Holder, Decimal)
ledger.range(start..end).entries();
ledger.range(..=last).rev().entries().take(20);
nft.attributes().entries(); // (String, String)
```

The map carries its value type into the range, so callers do not select a decoder.
`ScalarStorage` is implemented for actual single-row values: strings, byte lists,
booleans, supported integers, `Integer`, `Decimal`, and stored `Holder` handles.
Records, enums, options, and compound built-ins do not gain entry scans merely
because they support `KeyElement`. Their maps still support key scans and per-key
models. An index name cannot shadow `entries`.

The shared `storage-rows` host cursor returns raw stored bytes for both scalar
maps and covering indexes. It replaces `index-rows`, whose host decoder assumed
every value was a byte-list projection. Postcard framing is decoded in stdlib;
native numeric types reuse their existing canonical codec decoder. Covering and
numeric payloads borrow the framed buffer rather than allocate a second copy.
The host remains responsible for latest-row visibility, bounds, and metering.
It rejects compound children instead of returning an arbitrary descendant value.

Each consumed row pays for its key and stored value bytes. Key-only queries keep
using the lighter key cursor. Filters run in the contract, so an entry rejected
by a filter still pays for its fetched value. `.take(n)` pulls at most `n` rows;
there is no hidden lookahead or full-map collection. Snapshot keys/entries before
mutating the scanned collection, as with existing lazy index queries.

No storage encoding, index, or table is added. The host ABI changes, so deployed
contracts and the runtime must be rebuilt together under the preproduction replay
model. The checked-in native/test binaries and SDK component accompany the change.

## Encoding and bounds

Primary keys, index keys, and projections use the shared ordered `KeyElement`
codec. Numeric keys retain numeric order; compound keys are nested tuples.
Integer and Decimal each have a canonical scalar representation. Storage values
still have host serialization framing, so index projections and stored leaf bytes
are not interchangeable without decoding that framing.

Paths concatenate complete elements. Generated structural names are interned
numeric segments. Index members are `K`, or `(sort_value, K)` for a sorted index.
The framework stores bucket counts at bucket roots, outside child scans.

`subtree_end(path)` appends `0xff` to a complete encoded path. Every valid child
element tag is below that sentinel. Escaped NUL continuations start with `0xff`,
so a distinct string/byte sibling such as `"a\0"` stays outside `"a"`'s subtree.
A raw byte-prefix successor is incorrect here and is no longer exposed.
Sorted bounds use the same element-boundary rule around the leading sort value.

Reads and subtree deletion share these bounds. State remains in the existing
height-versioned `contract_state` log, with latest-version liveness, tombstones,
checkpoint hashing, and block rollback. Query results are lazy, ordered database
scans; every consumed storage row is metered. Struct keys can own several rows,
so a returned-key limit is not necessarily the same as a storage-row count.

## Contract consumers

Reward cleanup ranges over the existing
`by_agreement_active(agreement_id, true)` index. Its primary key is
`(agreement_id, node_id)`, so node order is already available in a fixed agreement
bucket. The duplicate `reward_members` sorted index is removed. The remaining two
index IDs are unchanged; deployments use fresh replay under the preproduction
upgrade model to remove old index state and deposits.

The four NFT list views take `after: option<string>` and a limit capped at 100.
They return `{ items, next }`, with one lookahead to distinguish a full final page
from a page with more results. `next` is an exclusive NFT-ID cursor, including
when `items` are agreement IDs. The offset signatures are replaced.

Pages read current state. They do not promise a snapshot across calls: inserts
before the cursor and holder transfers can change what later calls return. A
cursor need not identify a currently existing NFT. No cursor table is stored.

Token balance exports and NFT attributes use scalar entry reads. Their existing
result shapes, order, and filtering rules are preserved; these full exports are
not silently truncated or converted into page APIs.

## Response data and persistent data

WIT records and variants can contain lists of supported call-data types, including
user-defined records. `Wavey` handles their recursive call encoding and decoding.
`contract!` generates storage models only for storage-compatible types, following
aliases, options, records, and variant payloads. A list-bearing response record
has no persistent model; `list<u8>` remains supported as a scalar storage value.
An index declaration on a non-storable response record is rejected explicitly.
This adds response shapes, not persistent variable-length list storage.
