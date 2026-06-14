# Ordered key codec — storage path & key encoding (design)

Status: **proposed — spec for confirmation, then implement on `design/index-system`.**
Supersedes the ad-hoc encodings called out in the IndexedMap work
(`docs/design/indexed-map-index-system.md`): `.`-joined text paths, fixed-width
hex `SortKey`, and the `Pair` fixed-width suffix all collapse into the one codec
described here.

## Why

We have **three** independent key encodings today, and every limitation we've hit
is a symptom of that:

- **`DotPathBuf`** — segments joined by `.`, with `.` *forbidden* in a segment
  (a trap). So no key may contain `.` (filenames, decimals, arbitrary ids).
- **`SortKey`** — fixed-width hex, separate width bookkeeping, encode-only (we had
  to add `from_sort_key` to decode for compound keys).
- **`Pair` / compound keys** — `<variable><fixed-width>` suffix, which only works
  for *one* variable-length field; two `String`s are ambiguous, and the
  alternatives (a printable separator, length-prefixing) either aren't
  order-preserving or aren't delimiter-safe.

The deeper issue: a **storage path, a compound key, a sort prefix, and a composite
index bucket are the same thing** — a sequence of order-preserving, typed
elements — but we encode each differently. Worse, true order-preservation with a
`.` (TEXT) delimiter is *impossible* once a segment can contain a byte below `.`
(`0x2E`): e.g. `-` (`0x2D`) reorders `["a","b"]` ("a.b") vs `["a-b"]` ("a-b")
against their logical order. The only correct delimiter is one that sorts below
all content — `0x00` — which means a binary key.

The right long-term solution is a single **order-preserving, typed tuple codec**
over a binary key, the design used by FoundationDB's tuple layer, CockroachDB, and
TiKV for exactly these requirements. We are pre-production, so we adopt it now and
freeze the format afterward.

## Hard constraints (non-negotiable)

1. **Order-preserving** — lexicographic byte order of an encoded key equals its
   logical (element-by-element, typed) order. This is what `ORDER BY path`,
   `keys()` determinism, sorted-index scans, and `up_to`/`range` bounds rely on.
2. **Prefix-scannable** — an ancestor's encoding is a byte-prefix of every
   descendant's; a subtree is a single byte range. (Subtree tombstone, bucket
   scans, `matching_path` all depend on this.)
3. **Self-delimiting / decodable** — given only the bytes, you can find element
   boundaries and recover the typed values (no external schema needed host-side).
4. **Deterministic & canonical** — exactly one encoding per value, identical on
   every node; the encoded path is hashed into checkpoints, so the byte format is
   consensus-critical and frozen once shipped.
5. **Shared by guest and host** — one codec crate used by both contracts
   (`no_std`/wasm) and the indexer (the SQL layer must extract elements / compute
   ranges).
6. **Row semantics unchanged** — only the `path` encoding changes. The
   versioned-log model (`contract_id, height, tx_id, path, value, deleted`),
   per-path latest-version liveness, reorg rollback, and the checkpoint trigger
   are untouched.

## The unifying model

A key is a **tuple of typed elements**. Paths, map keys, index buckets, sort
prefixes, and compound keys are all tuples; concatenation is path extension.

```
path "agreements" / 42 / "status"        → (str "agreements", u64 42, str "status")
sorted index leaf <map>#idx/due/<status>/<deadline>/<pk>
                                          → (str "challenges#idx", str "due",
                                             <ChallengeStatus discriminant>,
                                             u64 deadline, <pk element>)
compound key (agreement_id, node_id)      → nested-tuple( str, u64 )  [one element]
```

`SortKey` is just "encode an int element"; `IndexKey` is just "encode a value's
bucket discriminant as an element"; a compound key is just a nested tuple. One
codec, three concepts retired.

## The codec

Keys are byte strings (`Vec<u8>`), compared **bytewise** (SQLite `BLOB`
comparison = `memcmp`, which is order-preserving for this codec). Each element is
`tag byte + payload`, so the stream is self-describing.

**Element encodings** (tags illustrative; finalized in impl):

| Element | Tag | Payload | Order property |
|---|---|---|---|
| bytes | `0x01` | content with `0x00 → 0x00 0xFF`, then `0x00` terminator | terminator is the min byte ⇒ `"a" < "ab"`; content stays `0x00`-free |
| string (utf8) | `0x02` | same as bytes | same; **any content allowed, incl. `.` `-` space** |
| nested tuple | `0x05` | encoded elements…, then `0x00` terminator | ordered by element sequence (compound keys) |
| false / true | `0x10` / `0x11` | — | false < true |
| none / some | `0x12` / `0x13(inner)` | some carries the inner element | none < some (matches `Presence::Absent < Present`) |
| u8…u64 | `0x20`…`0x23` | big-endian, fixed width | BE bytewise == numeric |
| i8…i64 | `0x30`…`0x33` | sign-bit-flipped big-endian, fixed width | negatives sort first (today's `SortKey` bias) |

- **Fixed-width ints** (per type) keep the encoding trivially canonical — `u64` is
  always 8 bytes; no varint ambiguity. Width is implied by the tag.
- A given path *position* is always the same type in our schema (a struct field /
  map key has one type), so cross-tag ordering never actually arbitrates real
  data; the tag is constant at a position and ordering is by payload.
- **`strinc(prefix)`** (exclusive upper bound for a prefix range): strip trailing
  `0xFF`, increment the last remaining byte. Subtree of `P` = `[encode(P),
  strinc(encode(P)))`.
- **Escaping** guarantees `0x00` appears only as a terminator, so element
  boundaries are unambiguous and a string element can hold any bytes.

### Worked bytes

```
str "ab"          → 02 61 62 00
str "a.b"         → 02 61 2E 62 00          (the '.' is just content now)
u64 42            → 23 00 00 00 00 00 00 00 2A
i64 -1            → 33 7F FF FF FF FF FF FF FF
compound (s,n):
  ("agr", 42u64)  → 05  02 61 67 72 00  23 00 00 00 00 00 00 00 2A  00
path ("m", ("agr",42), "active")
                  → 02 6D 00  05 02 61 67 72 00 23 …2A 00  02 61 63 74 69 76 65 00
```

`get_keys` of prefix `("m",)` returns the distinct **next element** — the whole
`("agr",42)` nested-tuple element — which the contract decodes back to its key
type. Compound key = **one path position** (a nested tuple), so `keys()` stays a
single-level scan and struct-field nesting is unchanged.

## How every feature maps

- **Arbitrary-content keys** — escaping; `DotPathBuf`'s forbid-and-trap is gone.
- **Single / composite index buckets** — one element per bucket field, appended.
- **Sortable index** — the sort prefix is an int element; `SortKey` hex/width
  machinery deleted. `up_to(b)` / `range(lo..=hi)` become byte ranges over the
  encoded bound element (`[bucket+lo, bucket+strinc(hi)]`).
- **Option / enum discriminant** — a tagged element; `IndexKey` and `Presence`
  fold into the codec.
- **Compound primary keys** — a nested-tuple element; **multiple variable-length
  fields now work** (each string is `0x00`-terminated). `#[derive(Key)]` on a
  named struct gives the named-field ergonomics (`Membership { agreement_id,
  node_id }`).
- **Covering** — unchanged (leaf value column).
- **Counts, liveness, reorg, checkpoint** — unchanged (only `path` bytes differ).

## System architecture / touch points

1. **`keycodec` crate (`no_std`)** — the single source: `KeyElement` trait
   (order-preserving `encode(&self, &mut Vec<u8>)` + `decode(&[u8]) -> (Self,
   rest)`), impls for primitives, nested-tuple encode/decode, `strinc`, and a
   `next_element(bytes, offset)` extractor. Pure byte logic, shared by guest +
   host. Fully unit-tested in isolation (round-trip + ordering fuzz).
2. **stdlib** — `DotPathBuf` → `Key` (a `Vec<u8>` builder; `push` takes a typed
   `KeyElement`). Storage traits take `&[u8]` paths. `SortKey`/`IndexKey`/`Pair`
   re-expressed on `keycodec` (or removed). `#[derive(Key)]` for compound/named
   keys.
3. **WIT host interface** — storage host fns take `list<u8>` paths; `get_keys`
   returns `list<list<u8>>` (each = the child's next-element bytes). Regenerate
   bindings both sides.
4. **Indexer / host / DB** — `path TEXT → BLOB`; replace the
   `regexp_capture('[^.]*')` segment logic and `LIKE :p || '.%'` subtree logic
   with a codec-aware SQLite UDF (`next_element`, range bounds via `strinc`) — we
   already register custom UDFs (`regexp_capture`), so this swaps one for a
   smarter one. `ORDER BY path` / `partition_by(path)` work unchanged on BLOB.
5. **Checkpoint hashing** — now over BLOB paths; deterministic. Pre-prod ⇒ clean
   reindex from genesis; no online migration (consistent with the immutable-
   contract, no-migration stance).
6. **Macro codegen** — build paths via typed `push`; index member segments become
   element sequences (no `sort‖pk` string concat); `SortedScan` bounds become
   encoded ranges; `#[derive(Key)]` replaces the `ToString/FromStr` key bound.
7. **Tooling** — a `tuple_debug(path)` UDF / CLI to render BLOB paths
   human-readably (FDB/Cockroach all ship this; binary paths are otherwise opaque
   in DB tooling).

## Contract-facing API (mostly unchanged)

The point of the rewrite is *under* the API. These stay:

```rust
model.listings().where_due(Open).up_to(height)
model.listings().where_eligible(true, Presence::Absent)
model.memberships().get(&Membership { agreement_id, node_id })
```

What changes for a contract author: a key type implements `Key`
(derive) instead of `ToString + FromStr`; `Pair<A,B>` becomes a named
`#[derive(Key)] struct`; nothing else in normal use.

## Resolved decisions

- **Type-tagged elements (not schema-driven).** The host must extract the next
  element for `keys()` without knowing the contract's types; tags make the stream
  self-describing. +1 byte/element is negligible.
- **`path` is `BLOB`.** Bytewise order + all-byte content. TEXT can't be
  order-preserving with arbitrary content, and embedded `0x00` in TEXT is unsafe.
- **A key occupies one path position; compound keys are nested-tuple elements.**
  Keeps `keys()` single-level and struct-field nesting unchanged; minimizes the
  macro delta.
- **Fixed-width-per-type integers.** Canonical by construction; simplest
  deterministic encoding.
- **`Key` replaces `DotPathBuf`.** The `.`-string representation is retired;
  human-readability comes from the debug UDF/decoder.
- **No migration.** Pre-prod reindex; format frozen after. (Native-contract format
  changes ride a coordinated upgrade, same as any other.)

## Open decisions (to settle before/while implementing)

1. **`get_keys` host return shape** — list of next-element byte-slices (decode
   guest-side) vs. the host decoding to a canonical scalar. Leaning byte-slices
   (keeps the codec one-sided-authoritative and supports compound keys uniformly).
2. **`keycodec` placement** — its own workspace crate vs. a module in `stdlib`
   re-exported for the host. Leaning own crate (the host isn't `no_std` and
   shouldn't pull stdlib).
3. **UDF surface** — one `next_element(path, offset)` + `strinc` computed in Rust
   query-builders, vs. a richer set (`tuple_child`, `tuple_is_descendant`). Start
   minimal.
4. **Do we keep `SortKey`/`IndexKey` as thin trait aliases** over `keycodec` for
   readability in generated code, or delete them entirely and emit codec calls
   directly. Leaning delete, emit `keycodec`.

## Build order (phased, all on this branch)

Phases 2–4 are coupled (stdlib + WIT + macro must move together to keep contracts
compiling); land them as one working step, then re-express features.

0. **`keycodec` crate** — encode/decode/`strinc`/`next_element`, unit-tested
   (round-trip + ordering-vs-logical fuzz). No integration yet.
1. **Host/DB** — `path` → `BLOB`, codec UDF, byte-range subtree/`keys()` queries,
   checkpoint hashing over BLOB. A node boots and round-trips set/get/keys.
2. **stdlib + WIT + macro** — `Key` builder, byte-path storage traits + host-fn
   signatures, `KeyElement` impls, codegen building typed paths. Existing
   contracts compile and pass on the new encoding (string/int keys first).
3. **Re-express the shipped index features** on the codec: sortable `due` (int
   element + range scan), composite `eligible`, the framework counts — verify the
   filestorage regtest stays green with `SortKey`/`Pair` hex retired.
4. **Compound / named keys** — `#[derive(Key)]`; migrate `memberships` to a named
   `Membership` key. Covering (index step 3) becomes trivial here if wanted.
5. **Cleanup** — delete the retired encodings (`DotPathBuf` `.`-logic, hex
   `SortKey`, `Pair` suffix), debug tooling, docs.

## Risks

- **Consensus format** — the encoded path is hashed; the codec must be exactly
  canonical and identical guest/host. Mitigation: one shared crate, fixed-width
  ints, ordering-fuzz tests, no varints.
- **Host query rewrite** — the `regexp_capture`/`LIKE` logic is load-bearing
  (subtree delete, `keys()`, `matching_path`); each must be ported to byte ranges
  and re-tested against the existing query tests.
- **Debuggability regression** — opaque BLOB paths; mitigated by the decode
  UDF/CLI, shipped in the same phase as the schema change.
- **Scope** — this is a foundation swap touching stdlib, WIT, the indexer, the DB
  schema, and the macro at once. It is deliberately taken pre-prod, on this
  branch, with the index work rebased on top.
