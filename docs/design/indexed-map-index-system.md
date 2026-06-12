# IndexedMap index system — design

Status: **confirmed** — implementing in build order (step 1 first). Extends the
shipped single-field `#[index]` (one
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
| **project** *(opt, "covering")* | a field (or few) stored in the index leaf so a scan returns it without a follow-up `get` | — |
| **predicate** *(opt, "partial")* | omit a row entirely when false — a pure index-*size* optimization. **Mostly unneeded:** the functional "filter" case is a composite bucket over discriminant fields (incl. `Option` none/some), see Resolved decisions. True partial deferred. | — |
| *(orthogonal)* **primary key K** | may be compound/tuple; encoded into the `<pk>` segment(s) | scalar |

The whole point: these compose. A "due challenges" index is bucket=`status`,
sort=`deadline_height`; make it covering by adding project=`agreement_id`; turn a
bucket field into a composite over a discriminant (`Option`/enum) to get a filter
without a predicate DSL. None of those choices interfere.

## Storage layout — one leaf shape

Every index, regardless of axes, is a sibling subtree `<map>#idx/<index>/…`, and
**the member leaf is always exactly one segment under its bucket**:

```text
<map>#idx/<index>/<bucket…>/<sort‖pk>   ->   () | <projection>
<map>#idx/<index>/<bucket…>             ->   <count: u64>     (per-bucket count, shipped)
```

- `<bucket…>` — one segment per bucket field (`IndexKey`); composite = several
  segments in declared order.
- `<sort‖pk>` — the **member segment**: an optional fixed-width `SortKey` prefix
  concatenated with the primary key. Because the sort prefix is fixed width,
  lexicographic order of this one segment == (sort order, then pk order), and the
  pk is recovered by stripping the known-width prefix. Unsorted index ⇒ no prefix
  ⇒ the segment *is* the pk (today's layout). Keeping sort+pk in **one** segment
  means an ordered scan is a **single** `keys()` cursor (not a nested two-level
  walk), and the count / `by_index` logic is unchanged — members are still direct
  children of the bucket.
- `<pk>` — the primary key (`ToString`); compound keys encode here (§ Compound
  keys).
- **leaf value** — `()` (void) for a plain index, or the `<projection>` for a
  covering index. A value at the leaf is invisible to `keys()`/the count (those
  see child *segments*), so covering is transparent to them.
- **count** — unchanged: lives *at* the bucket node; members are its direct
  children, so it stays invisible to the child-scan.

This single shape is the forward-compatibility lever — each axis is an
independent edit to the member segment or the leaf value:

```text
plain single-field   <map>#idx/status/active/<pk> -> ()                 (today)
composite            <map>#idx/owner_status/42/active/<pk> -> ()
sortable             <map>#idx/due/active/<padDeadline‖pk> -> ()
covering             <map>#idx/active/true/<pk> -> <proj>
sortable+covering    <map>#idx/due/active/<padDeadline‖pk> -> <proj>
```

The shipped single-field index is exactly the degenerate case (no sort prefix,
void leaf), so it keeps working untouched.

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
format, fixed for the life of the (immutable) contract — no migration story
needed (see Resolved decisions). Hex is used (not raw big-endian bytes) so the
segment is path-safe (printable, no `.`); the cost is a fixed 16 chars on every
sorted leaf's path — acceptable. This same encoding fixes the standalone "`u64`
keys sort lexicographically" footgun for primary keys too.

## Declaration syntax

### Internal structs — struct-level `#[index(...)]`

```rust
#[derive(Storage, Indexed)]
#[index(active)]                                          // sugar: by = active
#[index(due, by = status, sort = deadline_height)]        // composite + sortable
#[index(active_id, by = active, include = agreement_id)]   // covering (single scalar)
#[index(eligible, by = (active, active_challenge))]        // "partial" via composite + Option discriminant
struct Challenge { /* … */ }
```

- Field-level `#[index] f` stays as sugar for `#[index(f, by = f)]`.
- `by = a` or `by = (a, b)` → bucket segments (order significant). A bucket field
  may be a bool, an enum (discriminant), or an `Option` (`none`/`some`
  discriminant) — that last one replaces a predicate DSL for the filter case.
- `sort = f` → the `<sort>` segment (`f: SortKey`).
- `include = f` → covering projection stored in the leaf (single scalar for now;
  multi-field later).
- *No `where =` predicate DSL* — see Resolved decisions (composite-over-
  discriminant covers the need; true partial deferred).

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

The field model computes `old`/`new` descriptor sets and hands them to **one**
generalized `apply_index_diff`. The diff **keys on the leaf PATH**
(`<index>/<bucket…>/<sort‖pk>`), with the projection as the leaf *value* — not on
full-descriptor equality — so the three transitions are distinct:
- path in `new` not in `old` → write the leaf, **+count**.
- path in `old` not in `new` → tombstone the leaf, **−count** (gated on
  `__delete`'s result, as today).
- path in both, projection differs → **overwrite the leaf value in place, no count
  change.** (Keying on equality instead would tombstone+rewrite the same path and
  flip the count down-then-up on every projected-field change — wasted ops.)

So **no new maintenance code path per axis** — they're variations of "which
descriptors, and what's in the leaf."

**Covering ⇄ in-place setters.** Today the generated `set_<field>` reconciles the
index only when `<field>` is a *bucket* field (membership moves). A covering index
adds a second trigger: setting a field that a covering index *projects* must also
update that field's slot inside every such leaf. So `set_<field>` reconciles when
the field is **bucketed OR projected** (or sorted — a sort-field change moves the
member segment). Concretely: projecting a field makes every write of it also an
index write — the covering cost, paid on the write path, to save reads on the
scan path. The macro knows each field's index roles, so it emits exactly the
needed reconciles.

## Query API (generated per index)

- `where_<i>(bucket…) -> impl Iterator<Item = K>` — bucket scan (today; ordered by
  the member segment, which for a sorted index means sort order).
- `count_<i>(bucket…) -> u64` — O(1) bucket size (today).
- **sortable** adds a bounded scan: `where_<i>(bucket…).up_to(bound)` /
  `.range(lo..=hi)`. Implemented as a **single** `keys()` cursor over the member
  segments (already returned in path order); the bound is the **encoded** SortKey
  prefix, so early-break is a string comparison on the segment prefix — **no
  SortKey decode**, and it yields plain `K` (strip the fixed-width prefix). Needs
  **no new host primitive**.
- **covering** changes the item type to the projection (or `(K, Proj)`): the scan
  reads each leaf's *value* instead of a follow-up `get` on the primary map —
  useful for **scan-and-read** endpoints, not scan-and-mutate (you need the full
  value to mutate anyway).

These are additive method generations keyed off the index's declared axes.

> **Cost honesty.** `up_to`'s early-break cuts the **contract/fuel** cost to
> O(expiring) — the expensive part. But `keys()` is backed by `live_latest`
> (window-rank + `DISTINCT` + `ORDER BY`), so the **host still materializes the
> whole ordered bucket** per call — O(bucket) DB work. That's still a big win (DB
> sort ≪ wasm execution). Making the *host* sublinear too needs a **bounded
> `keys()`/range-scan host primitive** (push `WHERE segment ≤ bound ORDER BY
> segment LIMIT` into SQL). That primitive ranges over `path` (TEXT), so it's
> **inside** the storage invariant — a legitimate generic follow-on, distinct
> from the forbidden typed-column approach. Add it only if host scan cost ever
> shows up.

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

Contract/fuel cost drops from O(all active challenges) per block to O(expiring + 1)
(the host still scans the bucket — see *Cost honesty*). Covering does **not** help
here: `expire` mutates each due challenge, so it must `get(id)` regardless.
Covering pays off for **scan-and-read** endpoints like `get_active_challenges`,
which return data without mutating — there, projecting the returned fields removes
the per-key `get`.

## Build order (each step ships independently, no rework)

1. **`SortKey` + sortable single-bucket index** — the `sort‖pk` member segment,
   the single-cursor `up_to`/`range` scan, the encoding. Unblocks `expire`. (Also
   ships the numeric-key sortability fix.)
2. **Composite bucket + `Option`/enum discriminant bucketing** — multiple
   `<bucket…>` segments + multi-arg `where_`, and `IndexKey for Option`. Covers
   the filestorage "eligible" filter (replaces a predicate DSL).
3. **Covering (single scalar)** — write the projected field into the leaf's
   existing value slot; projection-returning scans. Multi-field/blob later.
4. **Compound primary keys** — generalize the `<pk>` encoding (see below).
5. *(deferred)* **True partial** — omit rows when a predicate is false; only if a
   real index-size problem appears. Likely via an `Option`-returning computed key.

The leaf layout and the descriptor-based maintenance already accommodate all of
these, so later steps are additive edits, not redesigns — and there's **no
migration machinery** to build, because contracts are immutable (see Resolved
decisions). That's the "don't shut ourselves out" guarantee: ship #1 now, the
rest slot in.

## Compound primary keys (orthogonal)

`IndexedMap<(String, u64), V>` (e.g. flattening `agreement_nodes` to
`memberships` keyed by `(agreement_id, node_id)`). The `<pk>` part of every leaf
generalizes to an encoded tuple. Requirements:
- **delimiter-safe** — the encoding must not contain `.` (would split the path).
- **deterministic** `ToString`/`FromStr` round-trip.
- ideally **`SortKey`** too, if you want ordered primary scans.
This is independent of the index axes (the `<pk>` slot is the same in every leaf
shape), so it can land last without touching index layout. For the common
`(variable, fixed-width)` shape — e.g. `(agreement_id: String, node_id: u64)` —
the clean encoding is a **fixed-width suffix**: `<agreement_id><16hex-node_id>`,
recovered by splitting off the known-width tail. It's unambiguous because the
variable part is already `.`-free and the numeric part is fixed width, and it
sorts by `agreement_id` then `node_id`. (NOT naive `a:b`, which isn't delimiter-
safe for arbitrary `a`.) General N-tuples of variable parts need length-prefixing.

## Resolved decisions (investigated against the codebase)

### No index migration is needed — contracts are immutable

`publish` is a plain `INSERT INTO contracts` that assigns a **new** `contract_id`
every time, then runs a fresh `init()`; there is **no** upgrade / reinit /
set-code path in the runtime. So a generic contract's code — and therefore its
index shape — can never change on live state: a new version is a new contract
with state built from scratch by its own `init`/writes. There is no "reshape an
index on existing state" scenario to migrate.

The only case where new code meets old state is a **native** contract (fixed id,
part of the protocol) being replaced by a **coordinated network upgrade** — a
hard-fork-class event. An index change there rides that upgrade path (and would
rebuild the index subtree as part of it) exactly like any other native-contract
code change; it is out of scope for the index system to auto-migrate. So: **drop
shape-versioning / online-migration from the design entirely.** A `SortKey` width
or bucket-set is simply part of an index's definition, fixed for the life of the
(immutable) contract.

### "Partial" need → composite indexes over discriminant fields, not a predicate DSL

A `where = <Rust expr>` predicate is awkward exactly where we need it: WIT records
declare indexes through the `indexed = "…"` **string** arg, and a Rust
expression-in-a-string is a non-starter. Sidestep it. The partial-like query we
actually want — filestorage eligibility = `active ∧ no active_challenge` — is a
**composite index over two discriminant-valued fields**:
`#[index(eligible, by = (active, active_challenge))]` →
`where_eligible(true, Presence::Absent)`.
This needs only:
1. composite buckets (already in the plan), and
2. a small extension: **index an `Option<T>` field by its `none`/`some`
   discriminant** — an `IndexKey for Option` that keys on the discriminant (just
   like an enum). No predicate expressions, no string DSL; works identically for
   internal structs and WIT records (you only name fields). The discriminant gets
   a generated marker (like `<E>Kind`) so the call reads `where_eligible(true,
   Presence::Absent)` rather than a bare `None::<String>` that needs a type
   annotation.

This keeps every value in *some* bucket (`active/none`, `active/some`, …) rather
than omitting rows. **True partial indexes** (omit a row entirely when a
predicate is false — purely an index-*size* optimization) stay deferred; if ever
needed, the clean form is a **computed key returning `Option`** (`None` ⇒ not in
the index), which also subsumes the "computed/closure index key" backlog item —
but the WIT-record declaration ergonomics (a function in a string) are the real
blocker, so it waits for a concrete need. For now, composite-over-discriminants
covers the functional case with zero DSL.

### Covering: reuse the leaf's value slot; tier by projection size

The index leaf is an ordinary `contract_state` row that **already has a value
slot** (we write `()` today). A covering index writes the projection there:
- **single scalar** (the high-value case — project the one field a scan needs:
  the sort field, a filter field, or a display id) → store via the existing typed
  setter (`__set_str`/`__set_u64`), read via `__get` — **zero new machinery.**
- **multi-field** → a packed blob in the leaf value (generated pack/unpack) —
  defer until needed.
- **whole value** → that's just denormalization (a full duplicate re-synced on
  every write). Usually NOT worth it; the active sets are bounded, so the `get`
  per key is fine. Frame covering as "project what the scan needs," not "copy the
  value."

### Sort over enums

Only if an explicit ordinal is declared on the enum; otherwise `sort = <enum>` is
a macro-time error. Numeric (`SortKey`) fields are the intended sort targets.
```
