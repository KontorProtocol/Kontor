# IndexedMap index system — design

Status: **design / proposed**. Extends the shipped single-field `#[index]` (one
bucket per distinct field value) into a coherent system covering **sortable**,
**composite**, **covering**, and **partial** indexes plus **compound primary
keys**, designed so each lands additively without reworking the others.

## Hard constraints (non-negotiable)

1. **Contract storage is always the generic, height-versioned `contract_state`
   log.** We never back a piece of contract storage with a bespoke/typed SQL
   table. (A typed host table like the file registry is fine *because it is not
   contract storage* — reached via host functions, not the storage interface.)
2. **Therefore sortability/range-ability must live in the KEY (the path), not in
   a column.** The host can only generically range over `path` (TEXT). There is
   no "deadline column" escape hatch by design.
3. **One audited maintenance routine.** All index rows (every shape below) are
   maintained by the single `apply_index_diff` site so the tombstone/reorg/count
   semantics live in one place (see the liveness refactor).
4. **Index rows are ordinary `contract_state` rows** — versioned, reorg-safe,
   checkpoint-covered, read through `live_latest`.

## The unifying model

An index over an `IndexedMap<K, V>` value is fully described by four axes plus
one orthogonal concern:

| Axis | Meaning | Today |
|---|---|---|
| **bucket** | 1+ fields whose `IndexKey` values partition the index; `where_<i>(b)` scans a bucket | 1 field |
| **sort** *(opt)* | a field whose **order-preserving** `SortKey` orders members *within* a bucket → range scan + early-break | — |
| **project** *(opt, "covering")* | fields stored in the index leaf so a scan returns data without a follow-up `get` | — |
| **predicate** *(opt, "partial")* | a value is in the index only when it holds; terminal/irrelevant rows fall out | — |
| *(orthogonal)* **primary key K** | may be compound/tuple; encoded into the `<pk>` segment(s) | scalar |

The whole point: these compose. A "due challenges" index is bucket=`status`,
sort=`deadline_height`; make it covering by adding project=`[agreement_id]`; make
it partial with predicate=`active`. None of those choices interfere.

## Storage layout — one leaf shape

Every index, regardless of axes, is a sibling subtree `<map>#idx/<index>/…`:

```text
<map>#idx/<index>/<bucket…>[/<sort>]/<pk>   ->   () | <projection>
<map>#idx/<index>/<bucket…>                 ->   <count: u64>     (per-bucket count, shipped)
```

- `<bucket…>` — one segment per bucket field (`IndexKey`); composite = several
  segments in declared order.
- `<sort>` — present only for sortable indexes: the `SortKey` (order-preserving,
  fixed-width) of the sort field. Inserted **before** `<pk>` so path order ==
  sort order.
- `<pk>` — the primary key (`ToString`); compound keys encode here (§ Compound
  keys).
- **leaf value** — `()` (void) for a plain index, or the packed `<projection>`
  for a covering index.
- **count** — unchanged: lives *at* the deepest bucket node, members are its
  descendants, so it stays invisible to the child-scan.

This single shape is the forward-compatibility lever — each axis is an
independent edit to the leaf path/value:

```text
plain single-field   <map>#idx/status/active/<pk> -> ()                 (today)
composite            <map>#idx/owner_status/42/active/<pk> -> ()
sortable             <map>#idx/due/active/<padDeadline>/<pk> -> ()
covering             <map>#idx/active/true/<pk> -> <proj>
sortable+covering    <map>#idx/due/active/<padDeadline>/<pk> -> <proj>
partial              any of the above, but the leaf exists only while predicate holds
```

The shipped single-field index is exactly the degenerate case (no sort segment,
void leaf, always-present), so it keeps working untouched.

## Sortable key encoding (`SortKey`)

Bucketing and ordering are **different jobs**, so two traits:

- `IndexKey` (shipped) — a deterministic, delimiter-free segment for *bucketing*.
  Order doesn't matter. (`Display`-based for primitives; discriminant for enums.)
- `SortKey` (new) — an **order-preserving, fixed-width** segment for *ordering*:
  lexicographic byte order of the segment == semantic order of the value.

`SortKey` impls:
- `u64` → 16-char big-endian hex (`format!("{:016x}")`). Fixed width ⇒ no
  zero-pad ambiguity; lexicographic == numeric.
- `u32`/`u16`/`u8` → narrower fixed widths.
- `i64` → bias by `1<<63` (flip the sign bit) then big-endian hex, so negatives
  sort before positives.
- Enums via `#[derive(StorageEnum)]` *may* opt into an explicit ordinal if a
  meaningful order exists; otherwise a field isn't sortable.

Rules: sort fields must be `SortKey`; the width is part of the index's on-disk
format (changing it is a migration). This same encoding fixes the standalone
"`u64` keys sort lexicographically" footgun for primary keys too.

## Declaration syntax

### Internal structs — struct-level `#[index(...)]`

```rust
#[derive(Storage, Indexed)]
#[index(active)]                                          // sugar: by = active
#[index(due, by = status, sort = deadline_height)]        // composite + sortable
#[index(active_list, by = active, include = [agreement_id, file_id])] // covering
#[index(eligible, by = active, where = active && active_challenge.is_none())] // partial
struct Challenge { /* … */ }
```

- Field-level `#[index] f` stays as sugar for `#[index(f, by = f)]`.
- `by = a` or `by = (a, b)` → bucket segments (order significant).
- `sort = f` → the `<sort>` segment (f: `SortKey`).
- `include = [..]` → covering projection (stored in the leaf).
- `where = <expr over fields>` → partial; the derive emits the entry only when the
  expression (over `self`'s fields) is true. (Open question: predicate ergonomics
  — see below.)

### WIT records — `contract!`'s `indexed`

WIT records can't take Rust attributes (injected via the fork), so the
`indexed = "…"` arg gains a small grammar that mirrors the above:

```
indexed = "
  challenge-data: due by status sort deadline-height;
  challenge-data: status;                       // (still its own single-field index)
  agreement-data: active;
"
```

`contract!` parses this and injects the equivalent index descriptors onto the
generated record (it already injects `#[index]`/`#[derive(Indexed)]`).

## Maintenance — generalize the descriptor, keep one routine

`Indexed::index_entries` becomes a list of **index entry descriptors**, each:

```rust
struct IndexEntry {
    index: &'static str,            // index name
    bucket: SmallVec<Cow<'static,str>>, // 1+ bucket segments (IndexKey)
    sort: Option<Cow<'static,str>>, // sort segment (SortKey), if any
    projection: Option<Vec<u8>>,    // packed covering value, if any
    // present? — partial indexes simply omit the descriptor
}
```

The single field model still computes `old`/`new` descriptor sets and hands them
to **one** generalized `apply_index_diff`, which builds the leaf path
`<index>/<bucket…>[/<sort>]/<pk>`, writes `()` or the projection, and adjusts the
bucket count exactly as today (gated on `__delete`'s result). Partial = the
descriptor set just doesn't include the entry when the predicate is false (the
diff then removes it on the transition). So **no new maintenance code path per
axis** — they're all variations of "which descriptors, and what's in the leaf."

## Query API (generated per index)

- `where_<i>(bucket…) -> impl Iterator<Item = K>` — unsorted bucket scan (today).
- `count_<i>(bucket…) -> u64` — O(1) bucket size (today).
- **sortable** adds a bounded/ordered scan over the `<sort>` level:
  `where_<i>(bucket…).up_to(bound)` / `.range(lo..=hi)` — yields `(SortVal, K)` in
  order and **stops early** at the bound. Implemented as a two-level `keys()`
  walk (outer = sort segments in path order, early-break; inner = pks), so it
  needs **no new host primitive** (host already returns ordered child segments).
- **covering** changes the item type to the projection (or `(K, Proj)`): the scan
  reads the leaf value instead of doing a follow-up `get`.

These are additive method generations keyed off the index's declared axes.

## Worked example — `expire_challenges` (the motivating case)

Declared: `#[index(due, by = status, sort = deadline_height)]`. Layout:
`challenges#idx/due/<status>/<padDeadline>/<id>`.

```rust
fn expire_challenges(ctx, current_height) -> u64 {
    let model = ctx.proc_context().model();
    // ordered scan of the active bucket, stop at the first not-yet-due
    let due: Vec<String> = model.challenges()
        .where_due(ChallengeStatus::Active)
        .up_to(current_height)          // SortKey bound; early-break
        .map(|(_, id)| id)
        .collect();                     // snapshot before mutating the index
    for id in &due {
        if let Some(c) = model.challenges().get(id) {
            c.set_status(ChallengeStatus::Expired);
            if let Some(a) = model.agreements().get(&c.agreement_id()) {
                a.set_active_challenge(None);
            }
        }
    }
    due.len() as u64
}
```

Cost drops from O(all active challenges) per block to O(expiring + 1). With
`include = [agreement_id]` (covering) the inner `get` for `agreement_id`
disappears too.

## Build order (each step ships independently, no rework)

1. **`SortKey` + sortable single-bucket index** — the `<sort>` segment, the
   two-level ordered/`up_to` scan, the encoding. Unblocks `expire`. (Also ships
   the numeric-key sortability fix.)
2. **Composite bucket** — multiple `<bucket…>` segments + multi-arg `where_`.
3. **Covering** — projection packed into the leaf value + projection-returning
   scans.
4. **Partial** — declaration sugar (`where =`); maintenance already supports it.
5. **Compound primary keys** — generalize `<pk>` encoding (see below).

The leaf layout and the descriptor-based maintenance already accommodate all
five, so later steps are additive edits, not redesigns. That's the
"don't shut ourselves out" guarantee: ship #1 now, the rest slot in.

## Compound primary keys (orthogonal)

`IndexedMap<(String, u64), V>` (e.g. flattening `agreement_nodes` to
`memberships` keyed by `(agreement_id, node_id)`). The `<pk>` part of every leaf
generalizes to an encoded tuple. Requirements:
- **delimiter-safe** — the encoding must not contain `.` (would split the path).
- **deterministic** `ToString`/`FromStr` round-trip.
- ideally **`SortKey`** too, if you want ordered primary scans.
This is independent of the index axes (the `<pk>` slot is the same in every leaf
shape), so it can land last without touching index layout. Likely a length-
prefixed or fixed-width tuple encoding (NOT naive `a:b`, which isn't delimiter-
safe for arbitrary `a`).

## Open questions

- **Partial predicate ergonomics.** `where = <expr over self's fields>` is
  parseable (syn::Expr) but referencing fields and keeping it well-formed is
  fiddly; the fallback is a hand-written `Indexed` impl. Decide: support
  a restricted predicate grammar, or document the hand-impl escape hatch.
- **Projection encoding.** Single packed blob at the leaf (compact, needs
  generated pack/unpack) vs. a sub-tree via the existing `Store` (reuses
  load/store, but more rows and muddier scan). Lean packed-blob; confirm.
- **Sort over enums.** Only if an explicit ordinal is declared; otherwise reject
  `sort = <enum field>` at macro time.
- **Width changes = migration.** A `SortKey` width or bucket-field-set change
  alters the on-disk index format. Since indexes are derived from values, the
  practical migration is "rebuild the index subtree" — needs a story if we ever
  change an index's shape on a live contract.
```
