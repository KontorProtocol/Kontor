//! Liveness reads over the `contract_state` version log.
//!
//! `contract_state` is an APPEND-ONLY, height-versioned log keyed by
//! `(contract_id, path)`. A write appends a row; a "delete" appends a row with
//! `deleted = true` (a tombstone) — nothing is ever physically removed (that's
//! what makes reorg rollback and the consensus checkpoint possible). So "what is
//! the current state?" is always a DERIVED computation, and getting that
//! derivation subtly wrong is the entire bug surface of this file.
//!
//! THE ONE RULE — current state is, for each path, its LATEST version (by
//! `height`), kept only if that latest version is live. The "live" test is a
//! **post** predicate (`deleted = false` applied AFTER picking the latest), never a
//! pre-rank filter: filtering `deleted = false` first lets a tombstone drop the
//! path's older live row back into view, so a path that point reads and `exists`
//! treat as gone keeps surfacing in `keys()`/`by_index`.
//!
//! That rule has TWO equivalent SQL formulations, and every current-state read of a
//! path set uses one of them — never a hand-rolled ranking query:
//!   - [`live_latest`] — a `ROW_NUMBER` window (per-path rank, post `deleted =
//!     false`). MATERIALIZES its rows, so it's for the point reads and the
//!     subtree-delete pass, which consume a known-small set.
//!   - [`live_paths_scan`] — the same live set as `NOT EXISTS` (no higher-height row
//!     for the path) `AND deleted = 0`. Index-served, so it STREAMS in `path` order
//!     and terminates early — the form behind the `keys`/`by_index` scan and
//!     `exists`. Same result as the window; the split is materialize vs. stream.
//!
//! **Paths are [`stdlib::keycodec`] bytes** (a `BLOB` column), not text. They are
//! order-preserving and *prefix-structured*: an encoded ancestor is an exact
//! byte-prefix of every descendant (the codec's element terminators rule out
//! false prefixes like `"ab"` vs `"abc"`). So a subtree is a single byte range
//! `[P, strinc(P))` — an index seek, not a `LIKE`/`REGEXP` scan — and a child key
//! is recovered with [`next_element`].
//!
//! Two deliberate EXCEPTIONS, each documented at its call site:
//!   - [`matching_path`] — enum/option variant resolution. GLOBAL-newest across
//!     paths (NOT per-path), because it asks "which variant is current?".
//!   - [`delete_matching_paths`] — a HARD delete at the current height (not a
//!     tombstone, not a liveness read); intra-block `Option` variant cleanup.

use futures_util::{Stream, stream};
use libsql::{Connection, Value, de::from_row, params};
use stdlib::{next_element, strinc};

use super::Error;
use super::versioned::LatestMany;
use crate::database::types::ContractStateRow;

/// The subtree byte-range `WHERE` fragment + its `:lo`/`:hi` bound params for
/// `[prefix, strinc(prefix))`. `lo_cmp` is `>=` (include the node) or `>` (children
/// only). A normal path begins with a tag byte (< `0xFF`), so `strinc` yields an
/// exclusive upper bound; but the guest can pass ANY codec bytes — including an
/// empty `list<u8>` (the contract root) or an all-`0xFF` path — for which `strinc`
/// is `None` (no exclusive upper bound: the range runs to the end of the keyspace).
/// In that case the fragment omits `path < :hi` and the caller's `contract_id =`
/// equality bounds the scan — so an empty/degenerate path is a well-defined
/// whole-(sub)tree operation, not a panic. The caller appends `:contract_id` (and
/// any other) params.
fn subtree_range(lo_cmp: &str, prefix: &[u8]) -> (String, Vec<(String, Value)>) {
    let mut params = vec![(":lo".to_string(), Value::Blob(prefix.to_vec()))];
    match strinc(prefix) {
        Some(hi) => {
            params.push((":hi".to_string(), Value::Blob(hi)));
            (format!("path {lo_cmp} :lo AND path < :hi"), params)
        }
        None => (format!("path {lo_cmp} :lo"), params),
    }
}

/// THE window liveness primitive (see the module header): the latest version of
/// each path that passes `filter`, kept only if that version is live. `partition_by`
/// gives the per-path rank; `deleted = false` is a **post** predicate, never a
/// pre-rank filter. Used by the point reads and the subtree-delete materialization,
/// which consume a known-small row set; the streaming SET reads use
/// [`live_paths_scan`] (`NOT EXISTS`) instead. Same live set either way — the split
/// is purely about whether the result is materialized or streamed.
fn live_latest(select: &str, filter: &str) -> String {
    LatestMany::builder()
        .table("contract_state")
        .select(select)
        .partition_by("path")
        .post("deleted = false")
        .filter(filter)
        .build()
        .to_sql()
}

/// The LIVE-PATHS scan **with its bound params**, returned together so the
/// `cs.path < :hi` clause and the `:hi` bind can't drift (the same fragment/params
/// coupling [`subtree_range`] gives the window callers).
///
/// Reformulated from the `live_latest` window to `NOT EXISTS` (newest non-deleted
/// per path = `deleted = 0` AND no higher-height row for the same path). This lets
/// the `(contract_id, path, height DESC)` index serve BOTH the ordered outer scan
/// AND the covering "newer height?" probe, so `ORDER BY path` + `LIMIT` STREAM and
/// terminate early (≈O(limit)) instead of materializing and sorting the whole range
/// like the window does. Deterministic with NO `rowid` tiebreak: `UNIQUE(contract_id,
/// height, path)` makes the max-height row per path unique, so the per-path liveness
/// is unambiguous (and a sibling tombstone can't hide a live sibling — each row
/// checks only its own path). Same live set and path order as the window form, so
/// it's a drop-in for the SET reads (`keys`, `exists`).
///
/// `lo` is the scan-start bind (`:lo`); `lo_cmp` is `>` (children only — `keys`) or
/// `>=` (include the node — `exists`). `subtree` is the prefix whose `strinc` gives
/// the exclusive upper bound (`:hi`, omitted when `strinc` is `None` — an empty or
/// all-`0xFF` prefix runs to the end of the keyspace, bounded only by `contract_id`).
fn live_paths_scan(
    select: &str,
    lo_cmp: &str,
    contract_id: u64,
    lo: Vec<u8>,
    subtree: &[u8],
    order: Option<&str>,
    limit: Option<u64>,
) -> (String, Vec<(String, Value)>) {
    let mut params = vec![
        (":lo".to_string(), Value::Blob(lo)),
        (
            ":contract_id".to_string(),
            Value::Integer(contract_id as i64),
        ),
    ];
    let hi_clause = match strinc(subtree) {
        Some(hi) => {
            params.push((":hi".to_string(), Value::Blob(hi)));
            " AND cs.path < :hi"
        }
        None => "",
    };
    let order = order.map(|o| format!(" ORDER BY {o}")).unwrap_or_default();
    let limit = limit.map(|n| format!(" LIMIT {n}")).unwrap_or_default();
    let sql = format!(
        "SELECT {select} FROM contract_state AS cs \
         WHERE cs.contract_id = :contract_id AND cs.path {lo_cmp} :lo{hi_clause} AND cs.deleted = 0 \
           AND NOT EXISTS ( \
             SELECT 1 FROM contract_state AS n \
             WHERE n.contract_id = cs.contract_id AND n.path = cs.path AND n.height > cs.height \
           ){order}{limit}"
    );
    (sql, params)
}

pub async fn insert_contract_state(conn: &Connection, row: ContractStateRow) -> Result<u64, Error> {
    Ok(conn
        .execute(
            r#"
            INSERT OR REPLACE INTO contract_state (
                contract_id,
                height,
                tx_id,
                size,
                path,
                value,
                deleted
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
            params![
                row.contract_id,
                row.height,
                row.tx_id.map(Value::try_from).transpose()?,
                row.size(),
                row.path,
                row.value,
                row.deleted
            ],
        )
        .await?)
}

pub async fn get_latest_contract_state(
    conn: &Connection,
    contract_id: u64,
    path: &[u8],
) -> Result<Option<ContractStateRow>, Error> {
    let mut rows = conn
        .query(
            &live_latest(
                "contract_id, height, tx_id, path, value, deleted",
                "contract_id = :contract_id AND path = :path",
            ),
            (
                (":contract_id", contract_id),
                (":path", Value::Blob(path.to_vec())),
            ),
        )
        .await?;

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_latest_contract_state_value(
    conn: &Connection,
    fuel: u64,
    contract_id: u64,
    path: &[u8],
) -> Result<Option<Vec<u8>>, Error> {
    let mut rows = conn
        .query(
            &live_latest(
                "CASE WHEN size <= :fuel THEN value ELSE null END AS value",
                "contract_id = :contract_id AND path = :path",
            ),
            (
                (":contract_id", contract_id),
                (":path", Value::Blob(path.to_vec())),
                (":fuel", fuel),
            ),
        )
        .await?;

    let row = rows.next().await?;
    if let Some(row) = row {
        return match row.get::<Option<Vec<u8>>>(0)? {
            Some(v) => Ok(Some(v)),
            None => Err(Error::OutOfFuel),
        };
    }
    Ok(None)
}

/// Remove an entry by tombstoning its WHOLE subtree: the path itself AND every
/// live descendant (`path/field`, nested struct/map rows, …). A struct value
/// persists under child paths, so tombstoning only the exact path would leave
/// live primary rows behind while the caller (`Map`/`IndexedMap` `remove`) has
/// already cleared the index — a half-removed entry. Height-versioned (one
/// `deleted = true` row per live path at the current height), so reorg-safe.
/// Returns true if any live row was tombstoned. The subtree is the byte range
/// `[path, strinc(path))` (the node + every descendant share `path` as a prefix).
pub async fn delete_contract_state(
    conn: &Connection,
    height: u64,
    tx_id: Option<u64>,
    contract_id: u64,
    path: &[u8],
) -> Result<bool, Error> {
    // Every live path at/under `path`, re-inserted as a tombstone below.
    // `live_latest` skips an already-tombstoned path (its latest version isn't
    // live), so it's not re-tombstoned.
    let (range, mut params) = subtree_range(">=", path);
    params.push((
        ":contract_id".to_string(),
        Value::Integer(contract_id as i64),
    ));
    let query = live_latest(
        "contract_id, height, tx_id, path, value, deleted",
        &format!("contract_id = :contract_id AND {range}"),
    );
    let mut result = conn.query(&query, params).await?;

    // Materialise the live rows BEFORE writing tombstones (don't read and write
    // `contract_state` in the same statement).
    let mut live: Vec<ContractStateRow> = Vec::new();
    while let Some(row) = result.next().await? {
        live.push(from_row(&row)?);
    }

    let removed = !live.is_empty();
    for mut row in live {
        row.deleted = true;
        row.height = height;
        row.tx_id = tx_id;
        insert_contract_state(conn, row).await?;
    }
    Ok(removed)
}

pub async fn exists_contract_state(
    conn: &Connection,
    contract_id: u64,
    path: &[u8],
) -> Result<bool, Error> {
    // "Any live path at/under `path`". `NOT EXISTS` + `LIMIT 1` stops at the FIRST
    // live row instead of ranking the whole subtree. Per-path liveness is inherent
    // (each row checks only its own path for a newer version), so a single newest
    // tombstone — e.g. an IndexedMap index `__delete` under `<map>#idx` — can't hide
    // a still-live sibling. `>=` includes the node itself, not just descendants.
    let (query, params) =
        live_paths_scan("1", ">=", contract_id, path.to_vec(), path, None, Some(1));
    let mut rows = conn.query(&query, params).await?;
    Ok(rows.next().await?.is_some())
}

/// Distinct direct-child key elements under `path` whose subtree has a live path
/// — the `keys()` / `by_index` scan. Range-scans the descendants (`path` strictly
/// a prefix), decides per-path liveness, and [`next_element`] recovers each child's
/// first element from the byte after the prefix. Rows arrive in `path` byte order
/// (== logical order, so deterministic across nodes — a consensus requirement,
/// since filestorage selects challenge targets by index position), so equal child
/// elements are adjacent and deduped in one pass. Each yielded item is the child
/// element's codec bytes; the guest decodes it to `K`.
///
/// `after` is a full-path resume cursor (`None` = start of subtree): the scan
/// continues strictly past it. It exists for CROSS-CALL pagination — a view that
/// returns one page hands its last key back as the next call's `after`. WITHIN a
/// call the bound is the lazy iterator itself, not SQL: the `NOT EXISTS`
/// formulation (see [`live_paths_scan`]) is index-served, so `ORDER BY path`
/// streams off the index and each `Rows::next()` steps incrementally — the guest's
/// `take(n)`/early-break (and, for procs, running out of per-row gas) stops the
/// host scan after ~that many rows. The window form would instead materialise and
/// sort the WHOLE range on the first `next()`, doing unbounded host work for a flat
/// fee — a gas/DoS hole — which is exactly why this scan uses `NOT EXISTS`
/// unconditionally and pushes no `LIMIT`. The per-row "newer?" probe `NOT EXISTS`
/// adds is the price of that laziness, and it's charged: each pulled row costs
/// `Fuel::KeysNext`.
pub async fn path_prefix_filter_contract_state(
    conn: &Connection,
    contract_id: u64,
    path: Vec<u8>,
    after: Option<Vec<u8>>,
) -> Result<impl Stream<Item = Result<Vec<u8>, Error>> + Send + 'static, Error> {
    // `path > :lo` excludes the exact node (no child element); the cursor `after`
    // (a full path) resumes strictly past the last page. `< :hi` is the subtree's
    // own `strinc(path)` bound. Ordered by `path` so children are grouped for dedup
    // and the indexed range can stream lazily.
    let lo = after.unwrap_or_else(|| path.clone());
    let (query, params) = live_paths_scan(
        "cs.path",
        ">",
        contract_id,
        lo,
        &path,
        Some("cs.path"),
        None,
    );
    let rows = conn.query(&query, params).await?;

    let prefix_len = path.len();
    let stream = stream::unfold(
        (rows, None::<Vec<u8>>),
        move |(mut rows, mut last)| async move {
            loop {
                match rows.next().await {
                    Ok(Some(row)) => {
                        let full: Vec<u8> = match row.get::<Vec<u8>>(0) {
                            Ok(p) => p,
                            Err(e) => return Some((Err(e.into()), (rows, last))),
                        };
                        // Recover the child's first element from the suffix after
                        // the scanned prefix. Compare on the borrowed slice and
                        // only allocate for a genuinely new child — every
                        // grandchild repeats its parent's child element, so the
                        // dedup case is the common one in a deep subtree.
                        let elem = match next_element(&full[prefix_len..]) {
                            Ok((elem, _)) => elem,
                            Err(e) => return Some((Err(Error::KeyCodec(e)), (rows, last))),
                        };
                        if last.as_deref() == Some(elem) {
                            continue; // dedup consecutive equal children
                        }
                        let child = elem.to_vec();
                        last = Some(child.clone());
                        return Some((Ok(child), (rows, last)));
                    }
                    Ok(None) => return None,
                    Err(e) => return Some((Err(e.into()), (rows, last))),
                }
            }
        },
    );

    Ok(stream)
}

/// EXCEPTION to `live_latest` (see module header): enum/option variant resolution
/// is GLOBAL-newest, not per-path. Returns the INDEX of whichever `candidates`
/// element is current under `base_path`, or `None` if the field is unset/deleted or
/// the newest discriminant isn't among them. Takes the single NEWEST live row under
/// `base_path` (by height, then rowid) — a stale variant lingering live at a lower
/// height (an old `none`, or an old enum case) must be outranked by the newer write,
/// which a per-path pick would surface — and reads its child element (the variant
/// discriminant). `candidates` are the already-encoded discriminant elements (a
/// string element, or an interned dict-ref); the match is pure BYTE equality, so the
/// host never decodes a name — it works for any encoding the guest chooses.
pub async fn matching_path(
    conn: &Connection,
    contract_id: u64,
    base_path: &[u8],
    candidates: &[Vec<u8>],
) -> Result<Option<u32>, Error> {
    // Global-newest (no `partition_by`) live row under `base_path`.
    let (range, mut params) = subtree_range(">=", base_path);
    params.push((
        ":contract_id".to_string(),
        Value::Integer(contract_id as i64),
    ));
    let query = LatestMany::builder()
        .table("contract_state")
        .select("path")
        .filter(&format!("contract_id = :contract_id AND {range}"))
        .post("deleted = false")
        .build()
        .to_sql();
    let mut rows = conn.query(&query, params).await?;
    let Some(row) = rows.next().await? else {
        return Ok(None);
    };
    let full: Vec<u8> = row.get(0)?;
    // The newest live row may be `base_path` ITSELF (a value stored at the path,
    // with no variant segment after it) — that's not a variant, so report no match
    // rather than decoding an empty suffix (which errors). Matches the old REGEXP
    // post-filter, which treated such a row as non-matching.
    let suffix = &full[base_path.len()..];
    if suffix.is_empty() {
        return Ok(None);
    }
    // The discriminant is the first element after `base_path`; match it against the
    // candidate elements by raw bytes (no decode — encoding-agnostic).
    let (elem, _) = next_element(suffix).map_err(Error::KeyCodec)?;
    Ok(candidates
        .iter()
        .position(|c| c.as_slice() == elem)
        .map(|i| i as u32))
}

/// EXCEPTION to the liveness model (see module header): a HARD delete of rows at
/// the CURRENT height under any of `candidates` — not a tombstone, not a
/// latest-version read. Used only for intra-block `Option`/enum variant cleanup
/// (drop a just-written `some`/`none` before writing the other in the same block);
/// it deliberately does NOT touch earlier-height rows. Each `candidate` is an
/// already-encoded discriminant element, so the subtree is `base_path ++ candidate`
/// — a per-candidate current-height range delete.
pub async fn delete_matching_paths(
    conn: &Connection,
    contract_id: u64,
    height: u64,
    base_path: &[u8],
    candidates: &[Vec<u8>],
) -> Result<u64, Error> {
    let mut deleted = 0;
    for candidate in candidates {
        let mut prefix = base_path.to_vec();
        prefix.extend_from_slice(candidate); // base_path ++ candidate element
        let (range, mut params) = subtree_range(">=", &prefix);
        params.push((
            ":contract_id".to_string(),
            Value::Integer(contract_id as i64),
        ));
        params.push((":height".to_string(), Value::Integer(height as i64)));
        deleted += conn
            .execute(
                &format!(
                    "DELETE FROM contract_state \
                     WHERE contract_id = :contract_id AND height = :height AND {range}"
                ),
                params,
            )
            .await?;
    }
    Ok(deleted)
}

pub async fn contract_has_state(conn: &Connection, contract_id: u64) -> Result<bool, Error> {
    let mut rows = conn
        .query(
            "SELECT COUNT(*) FROM contract_state WHERE contract_id = ?",
            params![contract_id],
        )
        .await?;
    Ok(rows
        .next()
        .await?
        .map(|r| r.get::<i64>(0))
        .transpose()?
        .expect("Query must return at least one row")
        > 0)
}
