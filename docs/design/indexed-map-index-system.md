# Storage keys & indexed maps — design

Status: **shipped.** Part I (the ordered key codec) is the foundation; Part II
(the IndexedMap index system) is built on it. The index features (sortable,
composite, compound) were first shipped on interim encodings (hex `SortKey`,
`Pair` fixed-width suffix, `.`-delimited text paths) and have now been
**re-expressed onto the codec with no contract-facing API change** (Phase 3+4,
commit `21223c68`): map/sort/compound keys are native `KeyElement`s, sorted
members are `(sort, pk)` nested tuples, `SortKey`/`Pair` are deleted. Validated:
stdlib 23 + macro snapshots, indexer 315, full regtest 110/110. Covering and
true-partial remain additive on top.

The unifying realization: a **storage path, a map key, an index bucket, a sort
prefix, and a compound key are the same thing — a sequence of order-preserving,
typed elements.** Today we encode each differently (three ad-hoc schemes), and
every limitation we've hit (no `.` in keys, ≤1 variable field in a compound key,
fixed-width bookkeeping, full-table scans on subtree/`keys()`) is a symptom of
that. One codec collapses them.

---

# Part I — The ordered key codec (foundation)

## Hard constraints (non-negotiable)

1. **Contract storage is always the generic, height-versioned `contract_state`
   log.** We never back contract storage with a bespoke/typed SQL table. (A typed
   host table like the file registry is fine *because it is not contract storage* —
   reached via host functions, not the storage interface.)
2. **Order/range-ability lives in the KEY, never a column.** The host ranges over
   `path` only; there is no "deadline column" escape hatch by design. So the key
   encoding itself must be order-preserving.
3. **Order-preserving** — lexicographic byte order of an encoded key equals its
   logical (element-by-element, typed) order. This is what `ORDER BY path`,
   `keys()` determinism, sorted-index scans, and `up_to`/`range` rely on.
4. **Prefix-scannable** — an ancestor's encoding is a byte-prefix of every
   descendant's; a subtree is one byte range (subtree tombstone, bucket scans,
   variant resolution).
5. **Self-delimiting / decodable** — element boundaries and typed values are
   recoverable from the bytes alone, with no external schema (the host extracts
   elements for `keys()` without knowing contract types).
6. **Deterministic & canonical** — exactly one encoding per value, identical on
   every node; the encoded path is hashed into checkpoints, so the format is
   consensus-critical and frozen once shipped.
7. **Shared by guest and host** — one codec implementation (a `stdlib` module)
   used by contracts (`no_std`/wasm) and the indexer (the SQL/query layer), which
   already depends on `stdlib`. One copy ⇒ no guest/host drift on a consensus
   format.
8. **Row semantics unchanged** — only `path` encoding changes. The versioned-log
   model (`contract_id, height, tx_id, path, value, deleted`), per-path
   latest-version liveness (`live_latest`), reorg rollback, the checkpoint trigger,
   and the single `apply_index_diff` maintenance site are untouched.

## The codec

Keys are byte strings (`path` is a `BLOB`, compared bytewise = `memcmp`, which is
order-preserving for this codec). A key is a sequence of typed **elements**, each
`tag byte + payload`, so the stream is self-describing. This is the FoundationDB
tuple layer, adopted so it's a known quantity.

| Element | Tag | Payload | Order property |
|---|---|---|---|
| bytes | `0x01` | content with `0x00 → 0x00 0xFF`, then `0x00` terminator | terminator is the min byte ⇒ `"a" < "ab"`; content stays `0x00`-free |
| string (utf8) | `0x02` | same as bytes | same; **any content allowed, incl. `.` `-` space** |
| nested tuple | `0x05` | encoded elements…, then `0x00` terminator | ordered by element sequence (compound keys; sort‖pk members) |
| integer | `0x0C`…`0x1C` | **minimal-length** big-endian; tag encodes sign+byte-count (`0x14` = zero, `0x15+n` = positive n-byte, `0x14−n` = negative n-byte stored offset so it sorts first) | tag orders by magnitude class, bytes within — fuzz-verified across full i64/u64 |
| false / true | `0x26` / `0x27` | — | false < true |
| none / some | `0x28` / `0x29(inner)` | some carries the inner element | none < some (matches `Presence::Absent < Present`) |

- **Minimal-length ints (not fixed-width).** The byte count lives in the tag, so a
  value uses the fewest big-endian bytes — still canonical and order-preserving,
  but a small `height` costs 1–2 bytes, not 8. A field's declared width (`u8` vs
  `u64`) isn't in the encoding; the guest decodes into its known type, so `5u8` and
  `5u64` encode and order identically. Hence one `integer` family, not per-width
  tags.
- **`strinc(prefix)`** (exclusive upper bound of a prefix range): strip trailing
  `0xFF`, increment the last remaining byte. Subtree of `P` = `[encode(P),
  strinc(encode(P)))`. Computed host-side in Rust.
- **Escaping** keeps `0x00` as a terminator-only byte, so element boundaries are
  unambiguous and a string element can hold any bytes.

### Reserved tag space (decide once, don't repaint)

```
0x00            terminator / escape sentinel (never a tag)
0x01 bytes   0x02 string   0x05 nested tuple
0x06 – 0x0B   RESERVED  — descending-order variants, Integer/Decimal
0x0C – 0x1C   integer (sign+length)
0x1D – 0x1F   RESERVED
0x20 / 0x21   RESERVED  — order-preserving f32 / f64 (IEEE sign-flip)
0x26 false  0x27 true   0x28 none  0x29 some
```

Reserved for three forward needs: **descending** components (encode the value's
byte-complement — an index that sorts a field DESC), **`Integer`/`Decimal` as
numerically-ordered keys** (today they'd key by `Display` — lexicographic, not
numeric — a latent bug the codec can fix), and **interned field-name ints** (see
Performance & space).

### Worked bytes

```
str "ab"          → 02 61 62 00
str "a.b"         → 02 61 2E 62 00          (the '.' is just content now)
u64 42            → 15 2A                   (1-byte minimal, not 8)
i64 -1            → 13 FE
compound (s,n):
  ("agr", 42u64)  → 05  02 61 67 72 00  15 2A  00
path ("m", ("agr",42), "active")
                  → 02 6D 00  05 02 61 67 72 00 15 2A 00  02 61 63 74 69 76 65 00
```

## Performance & space at scale (measured)

Experiments on SQLite 3.51 (planner behavior is core-SQLite, shared with libsql).

- **Range seek vs the current LIKE — a *fix*, not a cost.** The current
  subtree/`keys()` filter `path LIKE :p || '.%'` does **not** use the
  `(contract_id, path, …)` index — `EXPLAIN QUERY PLAN` shows `SCAN` (full scan of
  the contract's rows), even with `case_sensitive_like=ON` (the LIKE→range opt
  needs a *literal* prefix, which a concatenated parameter isn't). The byte-range
  form `path >= :lo AND path < strinc(:lo)` is a `SEARCH … USING INDEX`
  unconditionally. At 400k rows a single subtree lookup went **~26 ms (scan) →
  ~1.4 µs (seek)**, and the scan grows with table size. Moving to range queries
  (which the codec makes natural) removes a latent O(table) cost from the hottest
  path.
- **BLOB is order-correct and `0x00`-safe** — verified bytewise `ORDER BY` matches
  `sorted()` and `0x00`-containing keys round-trip and order correctly. The NUL
  hazard that rules out TEXT does not exist for BLOB (length-prefixed, `memcmp`).
- **Codec is canonical + order-preserving — fuzzed** over 5,000+ ints (all
  sign/length boundaries), strings (empty/prefix/`.`/`-`/space/`0x00`/high-byte),
  **two-variable-string compound keys**, and `(bucket, sort, pk)` members;
  integer encoding is injective.
- **Space: better for index-heavy data.** Minimal-length ints averaged **5 bytes**
  for typical heights vs 9 fixed-width vs **16** for the old hex `SortKey`; index
  leaves shrink. Strings cost ~+1 byte/element (tag+terminator vs one dot) — minor.

**Two scale levers, orthogonal to the codec (don't conflate):**

1. **Version-log compaction** — every write appends a version row, so the log grows
   faster than per-row path overhead; pruning versions below the
   finalized-checkpoint/reorg horizon is the first real space lever and is
   independent of the encoding.
2. **Field-name interning** — repeated struct field-name strings dominate path
   redundancy (SQLite doesn't prefix-compress B-tree keys, and the index stores the
   path again). The codec is *friendly* to fixing this (ordered keys share
   byte-prefixes — what prefix compression / a compressing VFS want), and a field
   name being "just an element" means we can later encode it as a small
   per-contract canonical int (declaration order, stable since contracts are
   immutable). Reserved; not needed now. Compression is a scale optimization, not a
   correctness need — nothing here forecloses it.

## Host architecture

- `path TEXT → BLOB`; `ORDER BY path` / `partition_by(path)` work unchanged
  (bytewise).
- Subtree / bucket / variant queries become **byte-range bounds** (`path >= :lo AND
  path < strinc(:lo)`), a guaranteed index seek.
- **`keys()` and variant resolution do element extraction in host Rust**, not SQL:
  range-scan the (index-seeked) live rows, extract the child element + dedup via the
  shared `keycodec`. No SQL function is needed — `keys()` already materializes the
  range, and the async `libsql::Connection` only exposes `load_extension` (not Rust
  scalar UDFs). *(A future SQL "distinct next element" pushdown is possible but
  unneeded; index buckets are leaf-only so dedup never pulls grandchildren on the
  hot path.)*
- **Extension footprint shrinks.** We load sqlean `crypto` and `regexp`.
  `crypto_sha256` is in the checkpoint trigger (consensus — stays). `regexp` is used
  *only* for contract_state path matching — `keys()` extraction and the
  enum/option `matching_path`/`delete_matching_paths` — all replaced by byte-range +
  Rust extraction. **So the codec lets us drop the `regexp` extension entirely** (5
  platform binaries, one less native dependency to keep deterministic). We add no
  sqlean modules: the rest are redundant (`math` is built in), determinism-hazards
  for consensus (`uuid` random, `time` wall-clock), or have no use case.

---

# Part II — IndexedMap on the codec

## The index model

An index over an `IndexedMap<K, V>` value is four axes plus one orthogonal concern:

| Axis | Meaning | Status |
|---|---|---|
| **bucket** | 1+ fields whose values partition the index; `where_<i>(b…)` scans a bucket | shipped (single + composite) |
| **sort** *(opt)* | a numeric field that orders members *within* a bucket → range scan + early-break | shipped (native codec: `(sort, pk)` tuple member) |
| **project** *(opt, "covering")* | a field stored in the leaf so a scan returns it without a follow-up `get` | pending |
| **predicate** *(opt, "partial")* | omit a row when false (pure index-*size* optimization). The functional "filter" case is a composite bucket over discriminant fields (incl. `Option` none/some); true partial deferred. | composite shipped; true partial deferred |
| *(orthogonal)* **compound key K** | a tuple key; encoded as a nested-tuple element | shipped (native tuple `(A,B)`) |

These compose: a "due" index is bucket=`status`, sort=`deadline_height`; make it
covering with project=`agreement_id`; turn a bucket field into a composite over an
`Option`/enum discriminant to get a filter with no predicate DSL.

## Leaf layout (one shape, in codec elements)

Every index is a sibling subtree; a member is **one element** under its bucket:

```text
unsorted:   (<map>#idx, <index>, <bucket…>, <pk>)              -> () | <projection>
sorted:     (<map>#idx, <index>, <bucket…>, (<sort>, <pk>))    -> () | <projection>
count:      (<map>#idx, <index>, <bucket…>)                    -> <u64>
```

- `<bucket…>` — one element per bucket field (the value's bucketing aspect:
  `Display`/discriminant/`none`·`some`); composite = several, in declared order.
- **member** — for an unsorted index, just the `<pk>` element; for a sorted index,
  a **nested-tuple element `(<sort>, <pk>)`**. Because it's one element ordered by
  `sort` then `pk`, an ordered scan is a single cursor, the count/`by_index` logic
  is unchanged (members are direct children of the bucket), and the pk is recovered
  by decoding — no fixed-width prefix, no hex, no width bookkeeping. This is the old
  "`sort‖pk` one segment" idea expressed as a nested tuple.
- `<pk>` — the primary key element; a compound key is itself a nested tuple
  (multiple sub-elements, **multiple variable-length fields now fine**).
- **leaf value** — `()` for a plain index, the typed `<projection>` for covering
  (invisible to `keys()`/count, which see child elements).
- **count** — at the bucket node; framework-maintained in `apply_index_diff`.

The shipped single-field index is the degenerate case (no sort, `pk`-only member,
void leaf).

## Declaration syntax

### Internal structs — struct-level `#[index(...)]`

```rust
#[derive(Storage, Indexed)]
#[index(active)]                                          // sugar: by = active
#[index(due, by = status, sort = deadline_height)]        // composite + sortable
#[index(active_id, by = active, include = agreement_id)]   // covering (pending)
#[index(eligible, by = (active, active_challenge))]        // filter via composite + Option discriminant
struct Challenge { /* … */ }
```

- Field-level `#[index] f` = sugar for `#[index(f, by = f)]`.
- `by = a` / `by = (a, b)` → bucket elements (order significant); a bucket field
  may be a bool, an enum (discriminant), or an `Option` (`none`/`some`).
- `sort = f` → the sort element (`f` numeric); `include = f` → covering projection.
- *No `where =` predicate DSL* — composite-over-discriminant covers the need.

### WIT records — `contract!`'s `indexed`

WIT records can't take Rust attributes (injected via the fork), so a small grammar
mirrors the above (`by` takes one or more fields up to `sort`):

```
indexed = "
  challenge-data: due by status sort deadline-height;
  challenge-data: status;
  agreement-data: eligible by active active-challenge;
"
```

## Maintenance — one routine

`Indexed::index_entries` yields **index entry descriptors**:

```rust
struct IndexEntry {
    name: &'static str,
    bucket: Vec<…>,          // 1+ bucket elements
    sort: Option<…>,          // sort element, if any
    projection: Option<…>,    // covering leaf value, if any (pending)
}
```

The field model computes `old`/`new` descriptor sets and hands them to one
`apply_index_diff`, which **keys on the leaf path** (not full-descriptor equality):

- path in `new` not `old` → write leaf, **+count**.
- path in `old` not `new` → tombstone leaf, **−count** (gated on `__delete`'s
  result).
- path in both, projection differs → overwrite leaf value in place, no count
  change.

So no new maintenance path per axis. **In-place setters** reconcile every index a
field participates in — bucket OR sort OR (covering) projected — and each
participating field is read once (hoisted) so old/new entries and shared fields
don't re-read storage.

## Query API (generated per index)

- `where_<i>(bucket…) -> impl Iterator<Item = K>` — bucket scan.
- `count_<i>(bucket…) -> u64` — O(1) maintained bucket size.
- **sortable** adds `where_<i>(bucket…).up_to(bound)` / `.range(lo..=hi)`, typed to
  the sort field. On the codec these become a **host byte-range** over the member's
  `sort` prefix (`[bucket, bucket ++ strinc(encode(bound)))`) — an index seek, so
  the host work is **O(result), not O(bucket)**. This *resolves the old
  cost-honesty caveat*: the deferred "bounded range-scan host primitive" is now the
  default, because byte-range bounds are native.
- **covering** (pending) changes the item type to the projection (or `(K, Proj)`):
  the scan reads the leaf value instead of a follow-up `get` — for scan-and-read
  endpoints, not scan-and-mutate.

## Worked example — `expire_challenges`

Declared `#[index(due, by = status, sort = deadline_height)]`:

```rust
fn expire_challenges(ctx, current_height) -> u64 {
    let model = ctx.proc_context().model();
    let due: Vec<String> = model.challenges()
        .where_due(ChallengeStatus::Active)
        .up_to(current_height)          // host byte-range seek; O(due)
        .collect();                     // snapshot before mutating the index
    for id in &due {
        if let Some(c) = model.challenges().get(id) {
            c.set_status(ChallengeStatus::Expired);  // moves status + due buckets
            if let Some(a) = model.agreements().get(&c.agreement_id()) {
                a.set_active_challenge(None);
            }
        }
    }
    due.len() as u64
}
```

Contract/fuel cost is O(expiring); with the codec the host cost is also O(expiring)
(the sort range is pushed into the index seek). Covering doesn't help here (`expire`
mutates each due challenge, so it `get`s regardless); covering pays off for
scan-and-read endpoints.

---

# Part III — Resolved decisions

### No migration — contracts are immutable
`publish` is a plain `INSERT INTO contracts` with a new `contract_id` + fresh
`init()`; there is no upgrade/reinit/set-code path, so a contract's key/index shape
can never change on live state. The only new-code-meets-old-state case is a native
contract replaced by a coordinated network upgrade (hard-fork-class; rebuilds its
subtree). So: no shape-versioning, no online migration. The codec format and an
index's axes are simply fixed for the life of the (immutable) contract; pre-prod we
reindex from genesis once and freeze.

### Codec
- **Type-tagged elements** (self-describing; host extracts without schema).
- **`path` is `BLOB`**, bytewise order, `0x00`-safe (measured).
- **A key is one path position; compound keys are nested-tuple elements** — keeps
  `keys()` single-level and struct-field nesting unchanged.
- **Minimal-length (FDB-style) integers**, not fixed-width — canonical, ordered,
  smaller (fuzzed).
- **`Key` (byte builder) replaces `DotPathBuf`**; human-readability via a debug
  decoder.
- **`get_keys` returns next-element bytes; the guest decodes** (the host can't type
  `K` generically; uniform for compound keys).
- **`keycodec` is a module in `stdlib`** (no_std, alongside `dot_path_buf`, which
  it replaces), not a new crate. The indexer (host) **already depends on `stdlib`**,
  so there's no isolation to gain from a separate crate; a module keeps one copy of
  a consensus-frozen format with zero packaging overhead. (Extractable to its own
  crate later only if a lean consumer that doesn't want `stdlib`'s weight appears —
  it's a self-contained module.)
- **Own the codec; don't take a runtime dependency — but don't invent it.** The
  format is the FoundationDB tuple layer / Google OrderedCode (well-documented,
  proven); we implement that subset ourselves (~150–250 lines, exhaustively
  fuzzed, reusing FDB's published test vectors). For a *consensus-frozen* encoding
  hashed into checkpoints, controlling the exact bytes beats a third-party crate
  whose format could drift across versions — and existing crates
  (`foundationdb-tuple` is std/FDB-client-bound, `ordered-code`/`bytekey2` would
  need no_std + tag-set vetting) don't match our needs anyway (Option `none`/`some`,
  nested-tuple compound keys, a host-side `next_element(bytes, offset)` extractor,
  decode into our typed `K`). None is in our tree today.
- **No SQL UDF** — host-side Rust extraction over an index range-scan; `strinc`
  Rust-side. Drops the `regexp` extension.
- **Delete the hex `SortKey` encoder** — sort fields become ordinary codec int
  elements (order-preserving natively). `IndexKey` is KEPT as the *bucket*-segment
  encoder, but now also yields a **codec element** (`Vec<u8>`), not a string: a
  `KeyElement` field encodes itself (a `u64` bucket is a compact int element, a
  `Vec<u8>` its raw bytes — no hex), while a storage enum / `Option` keys by its
  DISCRIMINANT as a string element. Buckets are equality partitions (order
  irrelevant), so the element only has to be *distinct* per value, not ordered. So
  bucket-by-discriminant vs order-by-value is a codegen choice — which projection of
  the value to encode, and whether as a bucket segment or an ordered sort element.

### "Partial" → composite over discriminant fields, not a predicate DSL
A `where = <expr>` DSL is a non-starter in the WIT `indexed = "…"` string. The
functional filter (e.g. `active ∧ no active_challenge`) is a composite bucket over
discriminant fields — `#[index(eligible, by = (active, active_challenge))]` →
`where_eligible(true, Presence::Absent)` — keeping every value in *some* bucket.
True partial (omit rows; pure size optimization) stays deferred; the clean future
form is a computed key returning `Option` (`None` ⇒ not indexed).

### Covering — reuse the leaf value slot, tier by size
The leaf is an ordinary row with a value slot (`()` today). Covering writes the
projection there: **single scalar** (the high-value case — the sort field, a filter
field, a display id) via the typed setter/`__get`, zero new machinery; **multi-field**
= a packed blob, deferred; **whole value** = denormalization, usually not worth it
(bounded active sets make the per-key `get` fine).

### Sort over enums
Only with an explicit declared ordinal; otherwise `sort = <enum>` is a macro-time
error. Numeric fields are the intended sort targets.

---

# Build order (phased, all on this branch)

Phases 2–4 are coupled (stdlib + WIT + macro move together to keep contracts
compiling); land them as one working step, then re-express features.

0. ✅ **`keycodec` module in `stdlib`** — encode/decode/`strinc`/`next_element`,
   unit-tested (round-trip + ordering-vs-logical fuzz; FDB test vectors). No
   integration.
1. ✅ **Host/DB** — `path` → `BLOB`; byte-range subtree/`keys()`/variant queries;
   Rust-side element extraction; checkpoint hashing over BLOB; drop `regexp`. A node
   boots and round-trips set/get/keys.
2. ✅ **stdlib + WIT + macro** — `KeyPath` builder; byte-path storage traits + host-fn
   signatures; `KeyElement` impls; codegen building typed paths. Existing contracts
   (string/int keys) compile and pass on the new encoding.
3. ✅ **Re-express the shipped index features** on the codec — sortable `due` (sort
   element + member nested tuple + range-seek `up_to`), composite `eligible`,
   compound `memberships`; retired hex `SortKey` and the `Pair` suffix (folded with
   step 4's compound keys: `K: KeyElement`). filestorage regtest green, API unchanged.
4. ✅ **Compound keys** — native tuples `(A,B)` (filestorage `memberships`); built-in
   `Holder` keys via `key_element_via_display!`. *Deferred:* named-field
   `#[derive(Key)]` and single-scalar **covering** projection (additive).
5. ✅ **Cleanup** — retired encodings (`SortKey`/`Pair`/`assert_segment`) deleted,
   debug decoder kept (`keycodec::debug_render`), docs updated.

# Risks

- **Consensus format** — the encoded path is hashed; the codec must be exactly
  canonical and identical guest/host. Mitigation: one shared module, minimal-length
  ints (no varint ambiguity), ordering-fuzz tests.
- **Host query rewrite** — the `regexp`/`LIKE` logic is load-bearing (subtree
  delete, `keys()`, variant resolution); each ports to byte ranges + Rust
  extraction and must pass the existing query tests.
- **Debuggability** — opaque BLOB paths; mitigated by the decode tool shipped with
  the schema change.
- **Scope** — a foundation swap across stdlib, WIT, the indexer, the DB schema, and
  the macro at once. Taken deliberately pre-prod, on this branch, with the index
  work re-expressed on top.
