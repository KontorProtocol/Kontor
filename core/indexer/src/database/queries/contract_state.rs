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
                deleted,
                depositor,
                deposited_amount
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
            params![
                row.contract_id,
                row.height,
                row.tx_id.map(Value::try_from).transpose()?,
                row.size(),
                row.path,
                row.value,
                row.deleted,
                row.depositor.map(Value::try_from).transpose()?,
                row.deposited_amount
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
                "contract_id, height, tx_id, path, value, deleted, depositor, deposited_amount",
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

/// The cross-contract per-depositor LIVENESS predicate (binds `:signer_id`) — the
/// ONE place this clause lives, because the FLOOR depends on it (so it's
/// consensus-critical). A row is the depositor's current collateral iff they set
/// it, it isn't a tombstone, and no newer version of its `(contract_id, path)`
/// exists — an overwrite/delete drops it from their floor. Cross-contract, so it
/// can't reuse the single-contract `live_latest`/`live_paths_scan`; the `depositor`
/// filter is the selective entry point (see `idx_contract_state_depositor`). The
/// floor sum and the footprint endpoint both build on it.
const LIVE_BY_DEPOSITOR_WHERE: &str = r#"
    cs.depositor = :signer_id
      AND cs.deleted = 0
      AND NOT EXISTS (
          SELECT 1 FROM contract_state n
          WHERE n.contract_id = cs.contract_id
            AND n.path = cs.path
            AND n.height > cs.height
      )
"#;

/// Every live row's FROZEN per-row deposit (`deposited_amount`, the token amount
/// recorded at WRITE time) a depositor currently holds, across ALL contracts — the
/// FLOOR is their sum. Frozen-per-row, so a `D` that evolves over time only affects
/// future writes: the floor never needs a historical-`D` lookup (each row carries
/// the deposit it was charged), and a `D` change does NOT re-price existing rows.
/// The caller sums the decimal strings (no SQL decimal SUM).
pub async fn live_deposit_amounts_by_depositor(
    conn: &Connection,
    signer_id: u64,
) -> Result<Vec<String>, Error> {
    let sql =
        format!("SELECT cs.deposited_amount FROM contract_state cs WHERE {LIVE_BY_DEPOSITOR_WHERE}");
    let mut rows = conn
        .query(&sql, libsql::named_params! { ":signer_id": signer_id })
        .await?;
    let mut out = Vec::new();
    while let Some(r) = rows.next().await? {
        out.push(r.get::<String>(0)?);
    }
    Ok(out)
}

// --- depositor_footprint cache (eager Σ deposited_amount per depositor) ---------
// Off-checkpoint, reconstructible. The token's per-debit floor check reads
// `footprint_cache_get` (O(1)) instead of `live_deposit_amounts_by_depositor`.

/// The cached floor total (decimal string) for a depositor, or `None` if they
/// collateralize nothing (absence ⇔ zero).
pub async fn footprint_cache_get(conn: &Connection, depositor: u64) -> Result<Option<String>, Error> {
    let mut rows = conn
        .query(
            "SELECT total_amount FROM depositor_footprint WHERE depositor = ?",
            [depositor],
        )
        .await?;
    Ok(match rows.next().await? {
        Some(r) => Some(r.get::<String>(0)?),
        None => None,
    })
}

/// Upsert a depositor's cached total, or delete the row when `total` is `None`
/// (their floor returned to zero — absence ⇔ zero keeps the table sparse).
pub async fn footprint_cache_set(
    conn: &Connection,
    depositor: u64,
    total: Option<&str>,
) -> Result<(), Error> {
    match total {
        Some(t) => {
            conn.execute(
                "INSERT INTO depositor_footprint (depositor, total_amount) VALUES (?, ?) \
                 ON CONFLICT(depositor) DO UPDATE SET total_amount = excluded.total_amount",
                (depositor, t),
            )
            .await?;
        }
        None => {
            conn.execute(
                "DELETE FROM depositor_footprint WHERE depositor = ?",
                [depositor],
            )
            .await?;
        }
    }
    Ok(())
}

/// Every distinct depositor with at least one live deposited row — the reconstruct
/// set (recompute each one's total from scratch).
pub async fn live_depositors(conn: &Connection) -> Result<Vec<u64>, Error> {
    let mut rows = conn
        .query(
            "SELECT DISTINCT depositor FROM contract_state WHERE depositor IS NOT NULL",
            (),
        )
        .await?;
    let mut out = Vec::new();
    while let Some(r) = rows.next().await? {
        out.push(r.get::<u64>(0)?);
    }
    Ok(out)
}

/// Depositors whose floor a rollback to `target_height` could change: any depositor
/// holding a version of a `(contract_id, path)` that was touched above the target
/// (the rolled-back rows being deleted, plus the ≤target versions they displaced and
/// that now become live again). Bounded by the rolled-back rows — recompute just
/// these from the post-rollback state.
pub async fn depositors_affected_by_reorg(
    conn: &Connection,
    target_height: u64,
) -> Result<Vec<u64>, Error> {
    let mut rows = conn
        .query(
            "SELECT DISTINCT cs.depositor FROM contract_state cs \
             WHERE cs.depositor IS NOT NULL AND EXISTS ( \
                 SELECT 1 FROM contract_state n \
                 WHERE n.contract_id = cs.contract_id AND n.path = cs.path \
                   AND n.height > :target)",
            libsql::named_params! { ":target": target_height },
        )
        .await?;
    let mut out = Vec::new();
    while let Some(r) = rows.next().await? {
        out.push(r.get::<u64>(0)?);
    }
    Ok(out)
}

/// The live floor total for one depositor, recomputed from scratch (used by
/// reconstruct + reorg). Sums the same `LIVE_BY_DEPOSITOR_WHERE` rows as the legacy
/// per-debit path, so the cache is an exact replica of it.
pub async fn live_depositor_amounts(conn: &Connection, depositor: u64) -> Result<Vec<String>, Error> {
    live_deposit_amounts_by_depositor(conn, depositor).await
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

/// A live row's `(path, size)` WITHOUT its value — the read half of a delete, so
/// the host can meter `Fuel::Delete` by row count + freed bytes before writing the
/// tombstones. Omitting the value is what keeps a large delete from materialising
/// gigabytes (and freeing a row needs no per-row deposit bookkeeping under the
/// floor model — it just drops from its setter's footprint sum).
#[derive(Debug, Clone)]
pub struct DepositRow {
    pub path: Vec<u8>,
    pub size: u64,
    /// The setter that collateralizes this row (for the eager footprint cache: a
    /// delete/overwrite subtracts `deposited_amount` from this depositor's total).
    /// `None` for Core/exempt rows, which carry no floor.
    pub depositor: Option<u64>,
    pub deposited_amount: Option<String>,
}

/// One live deposited row attributed to a depositor, for the per-signer footprint
/// aggregation. `deposited_amount` is non-null here (the `depositor IS NOT NULL ⇔
/// deposited_amount IS NOT NULL` CHECK), summed into a `Decimal` by the caller.
pub struct FootprintRow {
    pub contract_id: u64,
    pub contract_name: String,
    pub deposited_amount: String,
    pub footprint_bytes: u64,
}

/// Every LIVE row a depositor currently holds a deposit on, across ALL contracts —
/// the per-signer footprint ENDPOINT's source (with contract name + byte count for
/// display). An overwritten/deleted row has a newer version, so it drops from the
/// depositor's footprint (their floor un-restricts in place — nothing is refunded).
/// Shares [`LIVE_BY_DEPOSITOR_WHERE`] with the floor sum so the liveness predicate
/// lives in exactly one place.
pub async fn find_footprint_by_depositor(
    conn: &Connection,
    signer_id: u64,
) -> Result<Vec<FootprintRow>, Error> {
    let sql = format!(
        "SELECT cs.contract_id, c.name, cs.deposited_amount, length(cs.path) + cs.size AS footprint \
         FROM contract_state cs JOIN contracts c ON c.id = cs.contract_id \
         WHERE {LIVE_BY_DEPOSITOR_WHERE}"
    );
    let mut rows = conn
        .query(&sql, libsql::named_params! { ":signer_id": signer_id })
        .await?;
    let mut out = Vec::new();
    while let Some(r) = rows.next().await? {
        out.push(FootprintRow {
            contract_id: r.get::<u64>(0)?,
            contract_name: r.get::<String>(1)?,
            deposited_amount: r.get::<String>(2)?,
            footprint_bytes: r.get::<u64>(3)?,
        });
    }
    Ok(out)
}

/// The live rows of a subtree (the node + every live descendant) — `(path, size)`
/// only, NOT values. Read-only: the read half of a delete, split out so the
/// caller can meter `Fuel::Delete` by the row count BEFORE committing to the
/// writes. `live_latest` skips an already-tombstoned path. A struct value persists
/// under child paths, so the subtree (`[path, strinc(path))`) is the whole entry.
pub async fn find_live_subtree(
    conn: &Connection,
    contract_id: u64,
    path: &[u8],
) -> Result<Vec<DepositRow>, Error> {
    let (range, mut params) = subtree_range(">=", path);
    params.push((
        ":contract_id".to_string(),
        Value::Integer(contract_id as i64),
    ));
    let query = live_latest(
        "path, size, depositor, deposited_amount",
        &format!("contract_id = :contract_id AND {range}"),
    );
    let mut result = conn.query(&query, params).await?;
    let mut rows = Vec::new();
    while let Some(row) = result.next().await? {
        rows.push(deposit_row_from(&row)?);
    }
    Ok(rows)
}

/// A `DepositRow` from a `(path, size, depositor, deposited_amount)` projection —
/// shared by the two delete read-halves so the footprint cache can subtract a freed
/// row's deposit from its setter.
fn deposit_row_from(row: &libsql::Row) -> Result<DepositRow, Error> {
    Ok(DepositRow {
        path: row.get::<Vec<u8>>(0)?,
        size: row.get::<u64>(1)?,
        depositor: row.get::<Option<u64>>(2)?,
        deposited_amount: row.get::<Option<String>>(3)?,
    })
}

/// Tombstone the given (already-metered) live rows: append a `deleted = true`
/// version at `height` for each path. The tombstone is VALUE-LESS — it stores an
/// empty value, not the old one (nothing reads a tombstone's value; this keeps
/// big deletes from duplicating their values). Returns `(removed, freed_bytes)`
/// = (anything tombstoned, total path + value bytes freed) for the footprint
/// accumulator.
pub async fn tombstone_rows(
    conn: &Connection,
    contract_id: u64,
    height: u64,
    tx_id: Option<u64>,
    rows: &[DepositRow],
) -> Result<(bool, u64), Error> {
    let removed = !rows.is_empty();
    let freed: u64 = rows.iter().map(|r| r.path.len() as u64 + r.size).sum();
    for row in rows {
        insert_contract_state(
            conn,
            ContractStateRow::builder()
                .contract_id(contract_id)
                .maybe_tx_id(tx_id)
                .height(height)
                .path(row.path.clone())
                // value omitted → empty: the value-less tombstone.
                .deleted(true)
                .build(),
        )
        .await?;
    }
    Ok((removed, freed))
}

/// Remove an entry by tombstoning its WHOLE subtree (find + tombstone). The
/// metered host path uses [`find_live_subtree`] + [`tombstone_rows`] directly so
/// it can charge between the read and the writes; this convenience composition is
/// for unmetered/internal callers and tests.
pub async fn delete_contract_state(
    conn: &Connection,
    height: u64,
    tx_id: Option<u64>,
    contract_id: u64,
    path: &[u8],
) -> Result<(bool, u64), Error> {
    let rows = find_live_subtree(conn, contract_id, path).await?;
    tombstone_rows(conn, contract_id, height, tx_id, &rows).await
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
/// `after` is the full path of the last CHILD NODE already returned (`None` = start
/// of subtree); the scan resumes past that child's ENTIRE subtree. It exists for
/// CROSS-CALL pagination — a view returns a page of keys and, to continue, re-encodes
/// its last key as `path ++ last_child` and passes it back as `after`. The skip is
/// `cs.path >= strinc(after)`, NOT `cs.path > after`: a child can own deeper rows
/// (`path/child/field…`), and `path/child` sorts BEFORE them, so `> path/child` would
/// re-scan the child's own rows and re-emit it; `strinc(after)` is the first path past
/// all of `after`'s descendants, landing on the next sibling. WITHIN a call the bound
/// is the lazy iterator itself, not SQL: the `NOT EXISTS`
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
    // Lower bound of the scan. No cursor: `path > :lo` (children only, exclude the
    // node). With a cursor: `strinc(after)` skips `after`'s whole subtree and the
    // scan is `cs.path >= :lo`, so a multi-row child isn't re-read and re-emitted
    // (see the fn doc). `strinc` is `None` only for an all-`0xFF` path, which isn't
    // well-formed codec bytes (rejected upstream by `validate_path`), so the
    // fallback is unreachable. `< :hi` is the subtree's own `strinc(path)` bound;
    // ordered by `path` so children are grouped for dedup and the range streams.
    let (lo, lo_cmp): (Vec<u8>, &str) = match after {
        None => (path.clone(), ">"),
        Some(after) => (strinc(&after).unwrap_or(after), ">="),
    };
    let (query, params) = live_paths_scan(
        "cs.path",
        lo_cmp,
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
/// The current-height (`:height`) WHERE fragment + params for the subtree under
/// `base_path ++ candidate`. Shared by the count (read) and hard-delete (write)
/// halves so they target identical rows.
fn matching_paths_clause(
    contract_id: u64,
    height: u64,
    base_path: &[u8],
    candidate: &[u8],
) -> (String, Vec<(String, Value)>) {
    let mut prefix = base_path.to_vec();
    prefix.extend_from_slice(candidate); // base_path ++ candidate element
    let (range, mut params) = subtree_range(">=", &prefix);
    params.push((
        ":contract_id".to_string(),
        Value::Integer(contract_id as i64),
    ));
    params.push((":height".to_string(), Value::Integer(height as i64)));
    (
        format!("contract_id = :contract_id AND height = :height AND {range}"),
        params,
    )
}

/// Read half of the intra-block variant hard-delete: the rows it WOULD remove, as
/// `DepositRow`s (path + size). Split from the delete so the host can meter
/// `Fuel::Delete` BEFORE the writes, exactly like [`find_live_subtree`]. (Freeing a
/// row needs no per-row bookkeeping under the floor model — it just drops from its
/// setter's footprint sum.)
pub async fn find_matching_paths(
    conn: &Connection,
    contract_id: u64,
    height: u64,
    base_path: &[u8],
    candidates: &[Vec<u8>],
) -> Result<Vec<DepositRow>, Error> {
    let mut rows = Vec::new();
    for candidate in candidates {
        let (where_clause, params) = matching_paths_clause(contract_id, height, base_path, candidate);
        let mut result = conn
            .query(
                &format!(
                    "SELECT path, size, depositor, deposited_amount \
                     FROM contract_state WHERE {where_clause}"
                ),
                params,
            )
            .await?;
        while let Some(row) = result.next().await? {
            rows.push(deposit_row_from(&row)?);
        }
    }
    Ok(rows)
}

/// Write half: hard-delete the current-height rows under each candidate. Returns
/// the rows removed. Caller must have already metered them (via
/// [`find_matching_paths`]) — op execution is single-threaded in one
/// transaction, so the count matches what this removes.
pub async fn hard_delete_matching_paths(
    conn: &Connection,
    contract_id: u64,
    height: u64,
    base_path: &[u8],
    candidates: &[Vec<u8>],
) -> Result<u64, Error> {
    let mut deleted = 0u64;
    for candidate in candidates {
        let (where_clause, params) = matching_paths_clause(contract_id, height, base_path, candidate);
        deleted += conn
            .execute(
                &format!("DELETE FROM contract_state WHERE {where_clause}"),
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

/// Incrementally prune the newly-finalized band `(w_prev, w]` and persist the new
/// watermark `w`. The three statements (supersede DELETE, tombstone DELETE, watermark
/// upsert) must run in ONE transaction so the step is atomic and resumable — the
/// caller provides it (see [`crate::runtime::storage::Storage::prune`], which wraps
/// this in a savepoint). Not wrapped here so transaction management stays with the
/// storage layer that owns the connection's savepoint bookkeeping.
///
/// `w_prev` is the highest height already collapsed to one row per path; `w` is the
/// current finality watermark. The band is a fixed height *range*, but it only
/// *discovers* the paths that wrote in that range (via the `(height, …)` index) —
/// for each such path we then collapse ITS history (which may reach far below the
/// band). Paths untouched in the band keep their existing single snapshot and are
/// never examined, so the cost is O(band), not O(table). Two passes:
///   1. **supersede** — for a band path, drop versions `≤ w` that aren't its newest
///      `≤ w` (its finalized snapshot is kept, everything `> w` is kept).
///   2. **tombstone reclaim** — drop a `deleted = 1` row that entered the band and
///      has NO newer version anywhere: the path is permanently gone, the tombstone
///      masks nothing, and no reorg can resurrect a newer version. The only way
///      deleted data is physically reclaimed.
///
/// PRECISELY what it preserves: each path's **newest version `≤ H` for every
/// `H ≥ w`** — i.e. CURRENT (latest-per-path) state and any reorg-rollback target
/// (which can't fall below `w`, the finality-bounded watermark). It deliberately
/// deletes *intermediate* historical versions `≤ w`, so it does NOT preserve an
/// as-of-height read for `H < w`. That is correct ONLY because this indexer issues
/// no historical as-of-height reads — every read computes latest-per-path with no
/// upper height bound (`live_latest`/`live_paths_scan`/`matching_path`). A future
/// as-of-`H` reader below `w` would get wrong answers; gate any such feature on
/// archive mode (`prune = false`).
///
/// Removes only rows nothing can observe: the checkpoint trigger reads only the NEW
/// row + latest checkpoint (and is `AFTER INSERT`, so these DELETEs don't fire it),
/// so pure-local GC, no consensus effect. Correct from `w_prev = 0` (band `(0, w]`
/// discovers every path = a full prune). Returns rows deleted. See
/// `project_state_pruning`.
pub async fn prune_contract_state(conn: &Connection, w_prev: u64, w: u64) -> Result<u64, Error> {
    // Defensive: never run an empty/backwards band — it would otherwise still upsert
    // and could LOWER the persisted watermark below w_prev. The reactor already guards
    // `w > prune_watermark`; this protects any other caller.
    if w <= w_prev {
        return Ok(0);
    }

    // Supersede: collapse band paths to their newest version ≤ w. Driven from the
    // small DISTINCT band set (height range-seek on idx_contract_state_height), so
    // there is no full table scan.
    let superseded = conn
        .execute(
            r#"
            DELETE FROM contract_state
            WHERE rowid IN (
              SELECT old.rowid
              FROM (SELECT DISTINCT contract_id, path FROM contract_state
                    WHERE height > ?1 AND height <= ?2) AS band
              JOIN contract_state AS old
                ON old.contract_id = band.contract_id AND old.path = band.path
              WHERE old.height <= ?2
                AND EXISTS (SELECT 1 FROM contract_state n
                            WHERE n.contract_id = old.contract_id AND n.path = old.path
                              AND n.height > old.height AND n.height <= ?2)
            )
            "#,
            params![w_prev, w],
        )
        .await?;

    // Tombstone reclaim: a tombstone that entered the band with no newer version
    // anywhere is the path's final state — drop it (also driven by the height range).
    let tombstoned = conn
        .execute(
            r#"
            DELETE FROM contract_state AS t
            WHERE t.deleted = 1 AND t.height > ?1 AND t.height <= ?2
              AND NOT EXISTS (SELECT 1 FROM contract_state n
                              WHERE n.contract_id = t.contract_id AND n.path = t.path
                                AND n.height > t.height)
            "#,
            params![w_prev, w],
        )
        .await?;

    // Persist the advanced watermark in the same transaction as the deletes, so the
    // prune step is atomic and a restart resumes from exactly here.
    conn.execute(
        "INSERT INTO node_meta(key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![super::node_meta::PRUNE_WATERMARK_KEY, w],
    )
    .await?;

    Ok(superseded + tombstoned)
}

#[cfg(test)]
mod prune_tests {
    use super::*;
    use crate::database::connection::new_connection;
    use tempfile::TempDir;

    async fn insert_block(conn: &Connection, height: u64) {
        conn.execute(
            "INSERT OR IGNORE INTO blocks (height, hash, relevant) VALUES (?, ?, 1)",
            params![height, format!("hash{height}")],
        )
        .await
        .unwrap();
    }

    async fn insert_version(conn: &Connection, height: u64, path: &[u8], deleted: bool) {
        insert_block(conn, height).await;
        // Height-stamped value so equivalence tests prove the *correct* surviving
        // version, not just the right path set.
        let value = format!("v{height}").into_bytes();
        conn.execute(
            "INSERT INTO contract_state (contract_id, height, tx_id, size, path, value, deleted) \
             VALUES (1, ?, NULL, ?, ?, ?, ?)",
            params![height, value.len() as i64, path.to_vec(), value, deleted],
        )
        .await
        .unwrap();
    }

    /// The live set: each path's latest version, kept only if not a tombstone —
    /// `(path, value)` pairs in path order. Mirrors the `live_paths_scan` rule and
    /// is the ground truth a pruned node must match an archive node on.
    async fn live_state(conn: &Connection) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut rows = conn
            .query(
                "SELECT path, value FROM contract_state AS cs \
                 WHERE deleted = 0 \
                   AND NOT EXISTS ( \
                     SELECT 1 FROM contract_state AS n \
                     WHERE n.contract_id = cs.contract_id AND n.path = cs.path \
                       AND n.height > cs.height) \
                 ORDER BY path",
                (),
            )
            .await
            .unwrap();
        let mut out = Vec::new();
        while let Some(r) = rows.next().await.unwrap() {
            out.push((r.get::<Vec<u8>>(0).unwrap(), r.get::<Vec<u8>>(1).unwrap()));
        }
        out
    }

    async fn checkpoint_chain(conn: &Connection) -> Vec<(i64, String)> {
        let mut rows = conn
            .query("SELECT height, hash FROM checkpoints ORDER BY height", ())
            .await
            .unwrap();
        let mut out = Vec::new();
        while let Some(r) = rows.next().await.unwrap() {
            out.push((r.get::<i64>(0).unwrap(), r.get::<String>(1).unwrap()));
        }
        out
    }

    async fn row_count(conn: &Connection) -> i64 {
        let mut rows = conn
            .query("SELECT COUNT(*) FROM contract_state", ())
            .await
            .unwrap();
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap()
    }

    // A scripted sequence of (height, path, deleted) block-writes: updates,
    // deletes, and a recreate — enough to exercise supersede + tombstone paths.
    const SCRIPT: &[(u64, &[u8], bool)] = &[
        (1, b"x", false),
        (2, b"y", false),
        (3, b"x", false),
        (4, b"z", false),
        (5, b"y", true),
        (6, b"x", false),
        (7, b"z", false),
        (8, b"w", false),
        (9, b"x", true),
        (10, b"x", false),
    ];

    async fn heights(conn: &Connection, path: &[u8]) -> Vec<u64> {
        let mut rows = conn
            .query(
                "SELECT height FROM contract_state WHERE contract_id = 1 AND path = ? ORDER BY height",
                params![path.to_vec()],
            )
            .await
            .unwrap();
        let mut out = Vec::new();
        while let Some(r) = rows.next().await.unwrap() {
            out.push(r.get::<i64>(0).unwrap() as u64);
        }
        out
    }

    async fn checkpoint_count(conn: &Connection) -> i64 {
        let mut rows = conn
            .query("SELECT COUNT(*) FROM checkpoints", ())
            .await
            .unwrap();
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap()
    }

    #[tokio::test]
    async fn prune_supersede_tombstone_and_above_watermark() {
        let dir = TempDir::new().unwrap();
        let conn = new_connection(dir.path(), "prune.db").await.unwrap();

        // Distinct, ascending heights — the checkpoint trigger is keyed by height
        // and chains in insert order, mirroring real (monotonic) block processing.
        // A: all-live history below watermark → keep only the newest ≤ F.
        insert_version(&conn, 11, b"a", false).await;
        insert_version(&conn, 12, b"a", false).await;
        insert_version(&conn, 13, b"a", false).await;
        // B: spans the watermark → keep newest ≤ F plus everything above F.
        insert_version(&conn, 14, b"b", false).await;
        // C: live then tombstoned, all finalized → path fully reclaimed.
        insert_version(&conn, 15, b"c", false).await;
        insert_version(&conn, 16, b"c", true).await;
        // D: tombstone below F but re-created above F → keep both (reorg could
        // revert the re-creation and the tombstone must remain the latest).
        insert_version(&conn, 17, b"d", true).await;
        // E: single finalized version → untouched.
        insert_version(&conn, 50, b"e", false).await;
        insert_version(&conn, 90, b"b", false).await;
        insert_version(&conn, 150, b"d", false).await;
        insert_version(&conn, 200, b"b", false).await;

        let before_checkpoints = checkpoint_count(&conn).await;

        // Band (0, 100] discovers every path → equivalent to a full prune at 100.
        let deleted = prune_contract_state(&conn, 0, 100).await.unwrap();

        assert_eq!(heights(&conn, b"a").await, vec![13]); // -11, -12
        assert_eq!(heights(&conn, b"b").await, vec![90, 200]); // -14
        assert_eq!(heights(&conn, b"c").await, Vec::<u64>::new()); // -15, -16
        assert_eq!(heights(&conn, b"d").await, vec![17, 150]); // none
        assert_eq!(heights(&conn, b"e").await, vec![50]); // none
        assert_eq!(deleted, 5);

        // DELETEs must not perturb the checkpoint chain (trigger is AFTER INSERT).
        assert_eq!(checkpoint_count(&conn).await, before_checkpoints);
    }

    #[tokio::test]
    async fn pruned_node_matches_archive_live_state_and_checkpoints() {
        let dir = TempDir::new().unwrap();
        let archive = new_connection(dir.path(), "arch.db").await.unwrap();
        let pruned = new_connection(dir.path(), "pruned.db").await.unwrap();
        let retain = 3u64;

        let mut w_prev = 0u64;
        for &(h, p, del) in SCRIPT {
            insert_version(&archive, h, p, del).await;
            insert_version(&pruned, h, p, del).await;
            if let Some(wm) = h.checked_sub(retain)
                && wm > w_prev
            {
                prune_contract_state(&pruned, w_prev, wm).await.unwrap();
                w_prev = wm;
            }
        }

        // The consensus commitment is identical — pruning never touches the
        // checkpoint chain (trigger is AFTER INSERT and reads only NEW + latest).
        assert_eq!(
            checkpoint_chain(&archive).await,
            checkpoint_chain(&pruned).await
        );
        // And the derived live state (value + liveness) is byte-identical.
        assert_eq!(live_state(&archive).await, live_state(&pruned).await);
        // Pruning actually reclaimed rows.
        assert!(row_count(&pruned).await < row_count(&archive).await);
    }

    #[tokio::test]
    async fn rollback_within_retain_window_matches_archive() {
        let dir = TempDir::new().unwrap();
        let archive = new_connection(dir.path(), "arch_r.db").await.unwrap();
        let pruned = new_connection(dir.path(), "pruned_r.db").await.unwrap();
        let retain = 3u64;

        let mut w_prev = 0u64;
        for &(h, p, del) in SCRIPT {
            insert_version(&archive, h, p, del).await;
            insert_version(&pruned, h, p, del).await;
            if let Some(wm) = h.checked_sub(retain)
                && wm > w_prev
            {
                prune_contract_state(&pruned, w_prev, wm).await.unwrap();
                w_prev = wm;
            }
        }

        // Reorg both to a height INSIDE the retain window (tip 10, retain 3 →
        // last watermark 7; 8 > 7 so the pruned node retained everything needed).
        for c in [&archive, &pruned] {
            c.execute("DELETE FROM blocks WHERE height > ?", params![8u64])
                .await
                .unwrap();
        }

        // The pruned node rolls back to the same correct live state as the archive.
        assert_eq!(live_state(&archive).await, live_state(&pruned).await);
    }

    #[tokio::test]
    async fn prune_below_low_watermark_is_noop() {
        let dir = TempDir::new().unwrap();
        let conn = new_connection(dir.path(), "prune_noop.db").await.unwrap();
        insert_version(&conn, 10, b"a", false).await;
        insert_version(&conn, 20, b"a", false).await;
        // Band (0, 5] is below both versions → nothing finalized-and-superseded yet.
        let deleted = prune_contract_state(&conn, 0, 5).await.unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(heights(&conn, b"a").await, vec![10, 20]);
    }

    // ----- Plan regression: the band prune must never full-scan contract_state -----

    async fn explain(conn: &Connection, sql: &str, w_prev: u64, w: u64) -> Vec<String> {
        let mut rows = conn
            .query(&format!("EXPLAIN QUERY PLAN {sql}"), params![w_prev, w])
            .await
            .unwrap();
        let mut out = Vec::new();
        while let Some(r) = rows.next().await.unwrap() {
            // EXPLAIN QUERY PLAN columns: id, parent, notused, detail
            out.push(r.get::<String>(3).unwrap());
        }
        out
    }

    /// The supersede DELETE — kept in lockstep with `prune_band`'s SQL; this test
    /// asserts its plan, so if the production query changes, update this string too.
    const SUPERSEDE_DEL_SQL: &str = r#"DELETE FROM contract_state
          WHERE rowid IN (
            SELECT old.rowid
            FROM (SELECT DISTINCT contract_id, path FROM contract_state
                  WHERE height > ?1 AND height <= ?2) AS band
            JOIN contract_state AS old
              ON old.contract_id = band.contract_id AND old.path = band.path
            WHERE old.height <= ?2
              AND EXISTS (SELECT 1 FROM contract_state n
                          WHERE n.contract_id = old.contract_id AND n.path = old.path
                            AND n.height > old.height AND n.height <= ?2))"#;

    #[tokio::test]
    async fn band_prune_never_full_scans_contract_state() {
        let dir = TempDir::new().unwrap();
        let conn = new_connection(dir.path(), "plan.db").await.unwrap();

        // Steady-state-ish table: 40 paths × 12 updates = 480 rows, so "rows ≤ W" is
        // large but each band is tiny — the case where a full scan would hurt.
        let mut height = 0u64;
        for round in 0..12u64 {
            for p in 0..40u64 {
                height += 1;
                let path = format!("k{p:03}").into_bytes();
                let deleted = round == 11 && p % 7 == 0;
                insert_version(&conn, height, &path, deleted).await;
            }
        }
        let (w_prev, w) = (height - 4, height - 3); // a one-block band near the tip
        // NB: intentionally NO ANALYZE — production DBs won't have stats, so the
        // plan must hold on the planner's default heuristics.

        // Band discovery is a height-index range seek, not a table scan.
        let band_plan = explain(
            &conn,
            "SELECT DISTINCT contract_id, path FROM contract_state WHERE height > ?1 AND height <= ?2",
            w_prev,
            w,
        )
        .await;
        assert!(
            band_plan
                .iter()
                .any(|d| d.contains("idx_contract_state_height")),
            "band lookup should use the height index, got {band_plan:?}"
        );

        // The full supersede DELETE touches contract_state only via indexes.
        let del_plan = explain(&conn, SUPERSEDE_DEL_SQL, w_prev, w).await;
        assert!(
            !del_plan.iter().any(|d| d == "SCAN contract_state"),
            "band prune must not full-scan contract_state, got {del_plan:?}"
        );
    }
}
