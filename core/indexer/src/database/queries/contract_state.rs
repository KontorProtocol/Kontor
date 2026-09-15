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
//!     false`). Materializes its rows; used for single-path reads.
//!   - [`live_paths_scan`] — the same live set as `NOT EXISTS` (no higher-height row
//!     for the path) `AND deleted = 0`. Index-served, so it STREAMS in `path` order
//!     and terminates early — the form behind the `keys`/`by_index` scan and
//!     `exists`. Same result as the window; the split is materialize vs. stream.
//!
//! **Paths are [`stdlib::keycodec`] bytes** (a `BLOB` column), not text. They are
//! order-preserving and *prefix-structured*: an encoded ancestor is an exact
//! byte-prefix of every descendant. Bounds account for escaped NULs so distinct
//! string/byte siblings remain outside the subtree. A subtree is a single byte range
//! `[P, subtree_end(P))` — an index seek, not a `LIKE`/`REGEXP` scan — and a child key
//! is recovered with [`next_element`].
//!
//! Two deliberate EXCEPTIONS, each documented at its call site:
//!   - [`matching_path`] — enum/option variant resolution. GLOBAL-newest across
//!     paths (NOT per-path), because it asks "which variant is current?".
//!   - [`hard_delete_rows`] — a HARD delete at the current height (not a
//!     tombstone, not a liveness read); intra-block `Option` variant cleanup.

use std::mem::take;

use futures_util::{Stream, StreamExt, TryStreamExt, stream};
use libsql::{Connection, Row, Rows, Statement, Value, de::from_row, params};
use stdlib::{next_element, subtree_end};

use super::Error;
use super::versioned::LatestMany;
use crate::database::types::ContractStateRow;

/// Bounds end at an element boundary: an escaped-NUL sibling is outside the
/// subtree even though it shares the encoded node's raw byte prefix.
fn subtree_range(lo_cmp: &str, prefix: &[u8]) -> (String, Vec<(String, Value)>) {
    let params = vec![
        (":lo".to_string(), Value::Blob(prefix.to_vec())),
        (":hi".to_string(), Value::Blob(subtree_end(prefix))),
    ];
    (format!("path {lo_cmp} :lo AND path < :hi"), params)
}

/// THE window liveness primitive (see the module header): the latest version of
/// each path that passes `filter`, kept only if that version is live. `partition_by`
/// gives the per-path rank; `deleted = false` is a **post** predicate, never a
/// pre-rank filter. Used by point reads; the streaming SET reads use
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
/// terminate early instead of materializing and sorting the whole range
/// like the window does. Deterministic with NO `rowid` tiebreak: `UNIQUE(contract_id,
/// height, path)` makes the max-height row per path unique, so the per-path liveness
/// is unambiguous (and a sibling tombstone can't hide a live sibling — each row
/// checks only its own path). Same live set and path order as the window form, so
/// it's a drop-in for the SET reads (`keys`, `exists`).
///
/// `lo` is the scan-start bind (`:lo`); `lo_cmp` is `>` (children only — `keys`) or
/// `>=` (include the node — `exists`). `hi` is the pre-computed EXCLUSIVE upper bound
/// (`:hi`, `cs.path < :hi`); `None` runs to the end of the keyspace, bounded only by
/// `contract_id`. The
/// caller owns the bound math (see [`scan_bounds`]) so the seek/range rules live in
/// one place. `order` selects the row order — `Some("cs.path")` ascending or
/// `Some("cs.path DESC")` descending; the byte range in `[lo, hi)` is the SAME either
/// way (FDB-style: direction flips iteration order, not the bounds).
fn live_paths_scan(
    select: &str,
    lo_cmp: &str,
    contract_id: u64,
    lo: Vec<u8>,
    hi: Option<Vec<u8>>,
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
    let hi_clause = match hi {
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
                deposited_gas
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
                row.deposited_gas.map(Value::try_from).transpose()?
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
                "contract_id, height, tx_id, path, value, deleted, depositor, deposited_gas",
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

/// The FLOOR (in integer GAS) a depositor currently collateralizes: Σ the FROZEN
/// per-row `deposited_gas` of their live rows across ALL contracts. Frozen-per-row,
/// so an evolving `D` only affects future writes (no historical-`D` lookup). One
/// exact SQL `SUM` — the deposit is integer gas. (Token value = this × gas→token,
/// applied at the read site.)
pub async fn live_deposit_gas_sum(conn: &Connection, signer_id: u64) -> Result<u64, Error> {
    let sql = format!(
        "SELECT COALESCE(SUM(cs.deposited_gas), 0) FROM contract_state cs WHERE {LIVE_BY_DEPOSITOR_WHERE}"
    );
    let mut rows = conn
        .query(&sql, libsql::named_params! { ":signer_id": signer_id })
        .await?;
    Ok(match rows.next().await? {
        Some(r) => r.get::<u64>(0)?,
        None => 0,
    })
}

// --- depositor_footprint cache (eager Σ deposited_gas per depositor) -------------
// Off-checkpoint, reconstructible. The token's per-debit floor check reads
// `footprint_cache_get` (O(1)) instead of `live_deposit_gas_sum`.

/// The cached floor total (integer gas) for a depositor, or `None` if they
/// collateralize nothing (absence ⇔ zero).
pub async fn footprint_cache_get(conn: &Connection, depositor: u64) -> Result<Option<u64>, Error> {
    let mut rows = conn
        .query(
            "SELECT total_gas FROM depositor_footprint WHERE depositor = ?",
            [depositor],
        )
        .await?;
    match rows.next().await? {
        // `total_gas` is stored as SQLite INTEGER (i64). A NEGATIVE value can only
        // mean the cache desynced from truth (an accounting bug) — read it as i64 and
        // FAIL LOUD, never `as u64`, which would wrap a `-1` into ~1.8e19 gas and
        // silently FREEZE the depositor's balance on every debit (the opposite, and
        // worse, failure). The invariant is that this never fires.
        Some(r) => {
            let t = r.get::<i64>(0)?;
            if t < 0 {
                return Err(Error::InvalidData(format!(
                    "depositor_footprint corrupt: negative total_gas {t} for depositor {depositor}"
                )));
            }
            Ok(Some(t as u64))
        }
        None => Ok(None),
    }
}

/// Set a depositor's cached total to an ABSOLUTE value (reorg recompute), or delete
/// the row when `total` is `None` (floor returned to zero — absence ⇔ zero keeps the
/// table sparse).
pub async fn footprint_cache_set(
    conn: &Connection,
    depositor: u64,
    total: Option<u64>,
) -> Result<(), Error> {
    match total {
        Some(t) => {
            conn.execute(
                "INSERT INTO depositor_footprint (depositor, total_gas) VALUES (?, ?) \
                 ON CONFLICT(depositor) DO UPDATE SET total_gas = excluded.total_gas",
                (depositor, t as i64),
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

/// Atomically add `delta` gas to a depositor's cached floor — the incremental
/// write-path maintenance. One `total_gas = max(0, total_gas + :delta)` UPSERT, no
/// read-modify-write. `total_gas` is Σ live deposits, so it is non-negative BY
/// DEFINITION; the `max(0, …)` (and `max(0, :delta)` on a first insert) makes that an
/// invariant the column can't violate — a subtract can never leave a NEGATIVE row that
/// the zero-prune below would miss (the row instead clamps to 0 and is pruned). A
/// clamp only ever fires on a maintenance bug, which the cache-invariant test catches
/// as cache-vs-live drift; in correct operation deltas always balance. The zero-prune
/// runs ONLY on a decrease (a positive delta can never reach zero), so the common add
/// path stays a single statement.
pub async fn footprint_cache_add(
    conn: &Connection,
    depositor: u64,
    delta: i64,
) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO depositor_footprint (depositor, total_gas) VALUES (:d, max(0, :delta)) \
         ON CONFLICT(depositor) DO UPDATE SET total_gas = max(0, total_gas + :delta)",
        libsql::named_params! { ":d": depositor, ":delta": delta },
    )
    .await?;
    if delta < 0 {
        conn.execute(
            "DELETE FROM depositor_footprint WHERE depositor = :d AND total_gas = 0",
            libsql::named_params! { ":d": depositor },
        )
        .await?;
    }
    Ok(())
}

/// Rebuild the WHOLE footprint cache from live state in ONE pass: clear it, then a
/// single grouped `SUM(deposited_gas)` over live deposited rows. Used by the
/// (rare) startup reconstruct; far cheaper than a per-depositor query loop.
pub async fn footprint_rebuild_all(conn: &Connection) -> Result<(), Error> {
    conn.execute("DELETE FROM depositor_footprint", ()).await?;
    conn.execute(
        "INSERT INTO depositor_footprint (depositor, total_gas) \
         SELECT cs.depositor, SUM(cs.deposited_gas) FROM contract_state cs \
         WHERE cs.depositor IS NOT NULL AND cs.deleted = 0 \
           AND NOT EXISTS (SELECT 1 FROM contract_state n \
               WHERE n.contract_id = cs.contract_id AND n.path = cs.path AND n.height > cs.height) \
         GROUP BY cs.depositor",
        (),
    )
    .await?;
    Ok(())
}

/// Depositors whose floor a rollback to `target_height` could change. Driven from the
/// ROLLED-BACK BAND — `target < height <= tip`, a CLOSED range so it range-seeks
/// `idx_contract_state_height` (an open `height > target` makes the planner full-scan).
/// `tip` is derived from the DB itself (`MAX(height)`, an O(1) index lookup), NOT from a
/// caller-supplied height: an in-memory tip can lag the DB (e.g. `Storage.height` is 0 at
/// startup, before the first block advances it), and an under-tip would silently drop the
/// rolled-back depositors from the recompute, leaving the cache stale. The band's paths
/// are exactly those touched above the target, and a depositor is affected iff they hold
/// any version of such a path (the rolled-back rows being deleted, plus the ≤target
/// versions they displaced that now become live again). Bounded by the (shallow) reorg.
pub async fn depositors_affected_by_reorg(
    conn: &Connection,
    target_height: u64,
) -> Result<Vec<u64>, Error> {
    // MAX(height) over the covering `idx_contract_state_height`; NULL (empty table) → 0,
    // which makes the band empty and the recompute a no-op.
    let tip = match conn
        .query("SELECT MAX(height) FROM contract_state", ())
        .await?
        .next()
        .await?
    {
        Some(r) => r.get::<Option<u64>>(0)?.unwrap_or(0),
        None => 0,
    };
    let mut rows = conn
        .query(
            "SELECT DISTINCT cs.depositor FROM contract_state cs \
             JOIN (SELECT DISTINCT contract_id, path FROM contract_state \
                   WHERE height > :target AND height <= :tip) band \
               ON cs.contract_id = band.contract_id AND cs.path = band.path \
             WHERE cs.depositor IS NOT NULL",
            libsql::named_params! { ":target": target_height, ":tip": tip },
        )
        .await?;
    let mut out = Vec::new();
    while let Some(r) = rows.next().await? {
        out.push(r.get::<u64>(0)?);
    }
    Ok(out)
}

/// A live row's deposit attribution `(depositor, deposited_gas)`. The schema CHECK
/// ties the two together, so a row either carries a deposit (this) or doesn't (`None`
/// from [`latest_live_deposit`]) — no impossible "one set, one null" state.
pub struct RowDeposit {
    pub depositor: u64,
    pub deposited_gas: u64,
}

/// The deposit on a path's current LIVE row, or `None` if the path has no live row
/// (never set, or its latest version is a tombstone) OR that row carries no deposit
/// (Core/exempt). A lean point read (latest-by-height via `idx_contract_state_lookup`,
/// `LIMIT 1`) — the displaced-row read the footprint cache does before an overwrite,
/// cheaper than the `ROW_NUMBER` window of `get_latest_contract_state`.
pub async fn latest_live_deposit(
    conn: &Connection,
    contract_id: u64,
    path: &[u8],
) -> Result<Option<RowDeposit>, Error> {
    let mut rows = conn
        .query(
            "SELECT depositor, deposited_gas, deleted FROM contract_state \
             WHERE contract_id = :c AND path = :p ORDER BY height DESC LIMIT 1",
            libsql::named_params! { ":c": contract_id, ":p": Value::Blob(path.to_vec()) },
        )
        .await?;
    Ok(match rows.next().await? {
        // live row (not a tombstone) that carries a deposit
        Some(r) if !r.get::<bool>(2)? => {
            match (r.get::<Option<u64>>(0)?, r.get::<Option<u64>>(1)?) {
                (Some(depositor), Some(deposited_gas)) => Some(RowDeposit {
                    depositor,
                    deposited_gas,
                }),
                _ => None,
            }
        }
        _ => None,
    })
}

pub async fn get_latest_contract_state_value(
    conn: &Connection,
    max_value_bytes: u64,
    contract_id: u64,
    path: &[u8],
) -> Result<Option<Vec<u8>>, Error> {
    let mut rows = conn
        .query(
            &live_latest(
                "CASE WHEN size <= :max_value_bytes THEN value ELSE null END AS value",
                "contract_id = :contract_id AND path = :path",
            ),
            (
                (":contract_id", contract_id),
                (":path", Value::Blob(path.to_vec())),
                (":max_value_bytes", max_value_bytes),
            ),
        )
        .await?;

    let row = rows.next().await?;
    if let Some(row) = row {
        return match row.get::<Option<Vec<u8>>>(0)? {
            Some(v) => Ok(Some(v)),
            None => Err(Error::ValueTooLarge),
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
pub struct LiveRow {
    pub path: Vec<u8>,
    pub size: u64,
    /// The setter that collateralizes this row (for the eager footprint cache: a
    /// delete/overwrite subtracts `deposited_gas` from this depositor's total).
    /// `None` for Core/exempt rows, which carry no floor.
    pub depositor: Option<u64>,
    pub deposited_gas: Option<u64>,
}

/// One live deposited row attributed to a depositor, for the per-signer footprint
/// aggregation. `deposited_gas` is non-null here (the `depositor IS NOT NULL ⇔
/// deposited_gas IS NOT NULL` CHECK), summed by the caller and priced to token.
pub struct FootprintRow {
    pub contract_id: u64,
    pub contract_name: String,
    pub deposited_gas: u64,
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
        "SELECT cs.contract_id, c.name, cs.deposited_gas, length(cs.path) + cs.size AS footprint \
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
            deposited_gas: r.get::<u64>(2)?,
            footprint_bytes: r.get::<u64>(3)?,
        });
    }
    Ok(out)
}

/// Execute on the first poll, not construction: libSQL's `query` already steps
/// to the first row. Keeping that inside the stream lets the host charge first.
fn query_rows(
    conn: Connection,
    sql: String,
    params: Vec<(String, Value)>,
) -> impl Stream<Item = Result<Row, Error>> + Send + 'static {
    stream::once(async move { Ok::<_, Error>(conn.query(&sql, params).await?) })
        .map_ok(|rows| {
            stream::try_unfold(rows, |mut rows| async move {
                Ok(rows.next().await?.map(|row| (row, rows)))
            })
        })
        .try_flatten()
}

/// Live metadata in path order, including the subtree root. No values or window
/// materialization: the consumer can stop discovery between individual rows.
pub async fn find_live_subtree(
    conn: &Connection,
    contract_id: u64,
    path: &[u8],
) -> Result<impl Stream<Item = Result<LiveRow, Error>> + Send + 'static, Error> {
    let (query, params) = live_paths_scan(
        "cs.path, cs.size, cs.depositor, cs.deposited_gas",
        ">=",
        contract_id,
        path.to_vec(),
        Some(subtree_end(path)),
        Some("cs.path"),
        None,
    );
    Ok(query_rows(conn.clone(), query, params).map(|row| row.and_then(|row| live_row_from(&row))))
}

/// A `LiveRow` from a `(path, size, depositor, deposited_gas)` projection —
/// shared by the two delete read-halves so the footprint cache can subtract a freed
/// row's deposit from its setter.
fn live_row_from(row: &libsql::Row) -> Result<LiveRow, Error> {
    #[cfg(test)]
    traversal_probe::record();
    Ok(LiveRow {
        path: row.get::<Vec<u8>>(0)?,
        size: row.get::<u64>(1)?,
        depositor: row.get::<Option<u64>>(2)?,
        deposited_gas: row.get::<Option<u64>>(3)?,
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
    rows: &[LiveRow],
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
/// it can charge during discovery, before writes; this convenience composition is
/// for unmetered/internal callers and tests.
pub async fn delete_contract_state(
    conn: &Connection,
    height: u64,
    tx_id: Option<u64>,
    contract_id: u64,
    path: &[u8],
) -> Result<(bool, u64), Error> {
    let rows: Vec<_> = find_live_subtree(conn, contract_id, path)
        .await?
        .try_collect()
        .await?;
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
    let (query, params) = live_paths_scan(
        "1",
        ">=",
        contract_id,
        path.to_vec(),
        Some(subtree_end(path)),
        None,
        Some(1),
    );
    let mut rows = conn.query(&query, params).await?;
    Ok(rows.next().await?.is_some())
}

/// The scan's byte range `(lo_key, lo_cmp, hi_key)` derived from the `path`/`lo`/`hi`
/// child-element bounds — the ONE place the seek/range rules live, shared by the key
/// scan ([`path_prefix_filter_contract_state`]) and the covering value scan
/// ([`StorageRowCursor`]) so the two can't drift. `lo`/`hi` are
/// child-element codec bytes (relative to `path`); the guest computes them from its
/// `RangeBounds` via `sort_lower_bound`/`sort_upper_bound` (an FDB-style half-open
/// `[lo, hi)` byte range, independent of iteration direction).
///
/// Lower bound. `lo = None`: `path > :lo` (children only, exclude the node itself).
/// `lo = Some(x)`: an INCLUSIVE seek to `path ++ x` (`cs.path >= :lo`), so members at
/// or above `x` are pulled without pulling-and-discarding those below (each pulled key
/// is metered).
///
/// Upper bound. `hi = None`: the whole subtree ends at `subtree_end(path)`.
/// `hi = Some(y)`: an EXCLUSIVE `path ++ y` (`cs.path < :hi`).
///
/// An EMPTY `lo`/`hi` element means "no bound on that side", NOT `path` itself: the
/// real guest never sends one (a seek key is always a non-empty tuple element), but the
/// host is an untrusted boundary, and `path ++ "" = path` with `>=` would wrongly
/// include the row AT the bucket prefix (e.g. the framework bucket count), whose empty
/// suffix then traps `next_element`. Normalize it away so the child-only `> path`
/// invariant holds.
fn scan_bounds(
    path: &[u8],
    lo: Option<Vec<u8>>,
    hi: Option<Vec<u8>>,
) -> (Vec<u8>, &'static str, Option<Vec<u8>>) {
    let lo = lo.filter(|f| !f.is_empty());
    let hi = hi.filter(|f| !f.is_empty());
    let (lo_key, lo_cmp) = match lo {
        Some(lo) => {
            let mut key = path.to_vec();
            key.extend_from_slice(&lo);
            (key, ">=")
        }
        None => (path.to_vec(), ">"),
    };
    let hi_key = match hi {
        Some(hi) => {
            let mut key = path.to_vec();
            key.extend_from_slice(&hi);
            Some(key)
        }
        None => Some(subtree_end(path)),
    };
    (lo_key, lo_cmp, hi_key)
}

/// Distinct child keys. Keep the streaming cursor for small records; preparing a
/// new seek for each two-field record costs more than scanning its second field.
/// A poll skips at most 32 duplicates before seeking past the entire child, so
/// large subtrees cannot hide unbounded work behind a single host poll charge.
pub async fn path_prefix_filter_contract_state(
    conn: &Connection,
    contract_id: u64,
    path: Vec<u8>,
    lo: Option<Vec<u8>>,
    hi: Option<Vec<u8>>,
    descending: bool,
) -> Result<impl Stream<Item = Result<Vec<u8>, Error>> + Send + 'static, Error> {
    let (lo_key, lo_cmp, hi_key) = scan_bounds(&path, lo, hi);
    let conn = conn.clone();
    let prefix_len = path.len();
    Ok(stream::try_unfold(
        (
            None::<Rows>,
            None::<Vec<u8>>,
            lo_key,
            lo_cmp,
            hi_key,
            None::<Statement>,
        ),
        move |(mut rows, mut last, mut lo, mut lo_cmp, mut hi, mut statement)| {
            let conn = conn.clone();
            async move {
                let mut skipped = 0;
                loop {
                    let mut cursor = match rows.take() {
                        Some(rows) => rows,
                        None => {
                            let (sql, params) = live_paths_scan(
                                "cs.path",
                                lo_cmp,
                                contract_id,
                                lo.clone(),
                                hi.clone(),
                                Some(if descending {
                                    "cs.path DESC"
                                } else {
                                    "cs.path"
                                }),
                                None,
                            );
                            let prepared = match statement.take() {
                                Some(prepared) => {
                                    prepared.reset();
                                    prepared
                                }
                                None => conn.prepare(&sql).await?,
                            };
                            let rows = prepared.query(params).await?;
                            statement = Some(prepared);
                            rows
                        }
                    };
                    let Some(row) = cursor.next().await? else {
                        return Ok(None);
                    };
                    #[cfg(test)]
                    traversal_probe::record();
                    let full: Vec<u8> = row.get(0)?;
                    let (elem, _) = next_element(&full[prefix_len..]).map_err(Error::KeyCodec)?;
                    if last.as_deref() != Some(elem) {
                        let child = elem.to_vec();
                        last = Some(child.clone());
                        return Ok(Some((
                            child,
                            (Some(cursor), last, lo, lo_cmp, hi, statement),
                        )));
                    }
                    skipped += 1;
                    if skipped == 32 {
                        let child_path = &full[..prefix_len + elem.len()];
                        if descending {
                            hi = Some(child_path.to_vec());
                        } else {
                            lo = subtree_end(child_path);
                            // Only the first forward seek can change the SQL shape.
                            if lo_cmp != ">=" {
                                statement = None;
                            }
                            lo_cmp = ">=";
                        }
                    } else {
                        rows = Some(cursor);
                    }
                }
            }
        },
    ))
}

/// Streams row metadata, fetching each value only after checking the current
/// byte budget. The range cursor stays open while a rowid lookup reads the value.
pub struct StorageRowCursor {
    conn: Connection,
    prefix_len: usize,
    sql: String,
    params: Vec<(String, Value)>,
    rows: Option<Rows>,
    value_query: Option<Statement>,
    finished: bool,
}

impl StorageRowCursor {
    pub fn new(
        conn: &Connection,
        contract_id: u64,
        path: Vec<u8>,
        lo: Option<Vec<u8>>,
        hi: Option<Vec<u8>>,
        descending: bool,
    ) -> Self {
        let (lo, lo_cmp, hi) = scan_bounds(&path, lo, hi);
        let (sql, mut params) = live_paths_scan(
            "length(cs.path) - :prefix_len, cs.size, cs.path, cs.rowid",
            lo_cmp,
            contract_id,
            lo,
            hi,
            Some(if descending {
                "cs.path DESC"
            } else {
                "cs.path"
            }),
            None,
        );
        params.push((":prefix_len".into(), Value::Integer(path.len() as i64)));
        Self {
            conn: conn.clone(),
            prefix_len: path.len(),
            sql,
            params,
            rows: None,
            value_query: None,
            finished: false,
        }
    }

    pub async fn next(&mut self, max_bytes: u64) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
        if self.finished {
            return Ok(None);
        }
        let result = self.read_next(max_bytes).await;
        if !matches!(result, Ok(Some(_))) {
            self.finished = true;
            self.rows = None;
            self.value_query = None;
        }
        result
    }

    async fn read_next(&mut self, max_bytes: u64) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
        let mut rows = match self.rows.take() {
            Some(rows) => rows,
            None => self.conn.query(&self.sql, take(&mut self.params)).await?,
        };
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let key_bytes: u64 = row.get(0)?;
        let size: u64 = row.get(1)?;
        if key_bytes > max_bytes || size > max_bytes - key_bytes {
            return Err(Error::ValueTooLarge);
        }
        let full: Vec<u8> = row.get(2)?;
        let (elem, tail) = next_element(&full[self.prefix_len..]).map_err(Error::KeyCodec)?;
        if !tail.is_empty() {
            return Err(Error::NonScalarRow);
        }
        let rowid: i64 = row.get(3)?;
        // Fetch the exact version selected by the live scan on the same connection.
        // A new path lookup would repeat liveness resolution for every value.
        let mut statement = match self.value_query.take() {
            Some(statement) => statement,
            None => {
                self.conn
                    .prepare("SELECT value FROM contract_state WHERE rowid = ?")
                    .await?
            }
        };
        let value = statement.query_row([rowid]).await?.get::<Vec<u8>>(0)?;
        // Release SQLite's value buffer before the contract pauses this cursor.
        statement.reset();
        self.value_query = Some(statement);
        #[cfg(test)]
        traversal_probe::copied_value(value.len());
        let member = elem.to_vec();
        self.rows = Some(rows);
        Ok(Some((member, value)))
    }
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

/// Union candidate subtrees before discovery. Duplicate or overlapping guest
/// candidates must not charge/free the same row twice, especially its deposit.
fn matching_suffix_ranges(candidates: &[Vec<u8>]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut suffixes: Vec<_> = candidates.iter().map(Vec::as_slice).collect();
    suffixes.sort_unstable();
    let mut merged: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for lo in suffixes {
        let hi = subtree_end(lo);
        if let Some((_, end)) = merged.last_mut()
            && lo <= end.as_slice()
        {
            if hi > *end {
                *end = hi;
            }
            continue;
        }
        merged.push((lo.to_vec(), hi));
    }
    merged
}

/// Current-height variant rows, including tombstones. This deliberately does
/// not use liveness: removing a current tombstone can revive an older deposit.
pub async fn find_matching_paths(
    conn: &Connection,
    contract_id: u64,
    height: u64,
    base_path: &[u8],
    candidates: &[Vec<u8>],
) -> Result<impl Stream<Item = Result<LiveRow, Error>> + Send + 'static, Error> {
    let ranges = matching_suffix_ranges(candidates);
    let base_path = base_path.to_vec();
    let conn = conn.clone();
    Ok(stream::iter(ranges)
        .flat_map(move |(lo, hi)| {
            // Only the active query owns full bounds; candidate count must not
            // multiply retained copies of a potentially large base path.
            let lo = [base_path.as_slice(), lo.as_slice()].concat();
            let hi = [base_path.as_slice(), hi.as_slice()].concat();
            query_rows(
                conn.clone(),
                "SELECT path, size, depositor, deposited_gas FROM contract_state \
             WHERE contract_id = :contract_id AND height = :height \
             AND path >= :lo AND path < :hi ORDER BY path"
                    .to_string(),
                vec![
                    (
                        ":contract_id".to_string(),
                        Value::Integer(contract_id as i64),
                    ),
                    (":height".to_string(), Value::Integer(height as i64)),
                    (":lo".to_string(), Value::Blob(lo)),
                    (":hi".to_string(), Value::Blob(hi)),
                ],
            )
        })
        .map(|row| row.and_then(|row| live_row_from(&row))))
}

/// Delete exactly the already-metered current-height rows. Small SQL batches
/// retain bulk-write efficiency without a second, potentially broader range scan.
pub async fn hard_delete_rows(
    conn: &Connection,
    contract_id: u64,
    height: u64,
    rows: &[LiveRow],
) -> Result<u64, Error> {
    let mut deleted = 0;
    for chunk in rows.chunks(64) {
        let slots = vec!["?"; chunk.len()].join(",");
        let mut params = vec![
            Value::Integer(contract_id as i64),
            Value::Integer(height as i64),
        ];
        params.extend(chunk.iter().map(|row| Value::Blob(row.path.clone())));
        deleted += conn.execute(
            &format!("DELETE FROM contract_state WHERE contract_id = ? AND height = ? AND path IN ({slots})"),
            params,
        ).await?;
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
    // prune step is atomic and a restart resumes from exactly here. (Single node_meta
    // writer — shared with the footprint cache's marker.)
    super::node_meta::set_meta_u64(conn, super::node_meta::PRUNE_WATERMARK_KEY, w).await?;

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

// Count logical rows crossing the query boundary, not SQLite VM work or elapsed
// time. Task-local scope keeps concurrent database tests independent.
#[cfg(test)]
pub(crate) mod traversal_probe {
    use std::cell::Cell;
    use std::future::Future;

    tokio::task_local! {
        static ROWS: Cell<usize>;
        static VALUE_BYTES: Cell<usize>;
    }

    pub(super) fn copied_value(bytes: usize) {
        let _ = VALUE_BYTES.try_with(|count| count.set(count.get() + bytes));
    }

    pub(crate) async fn measure_value_bytes<T>(future: impl Future<Output = T>) -> (T, usize) {
        VALUE_BYTES
            .scope(Cell::new(0), async {
                let result = future.await;
                (result, VALUE_BYTES.with(Cell::get))
            })
            .await
    }

    pub(super) fn record() {
        let _ = ROWS.try_with(|rows| rows.set(rows.get() + 1));
    }

    pub(crate) async fn measure<T>(future: impl Future<Output = T>) -> (T, usize) {
        ROWS.scope(Cell::new(0), async {
            let result = future.await;
            (result, ROWS.with(Cell::get))
        })
        .await
    }
}

#[cfg(test)]
mod matching_range_tests {
    use super::matching_suffix_ranges;
    use stdlib::{KeyElement, subtree_end};

    #[test]
    fn cleanup_plan_retains_only_unique_suffix_ranges() {
        let suffixes: Vec<_> = (0..512u64).map(|n| n.encode()).collect();
        let mut candidates = suffixes.clone();
        candidates.extend(suffixes.iter().cloned());
        let ranges = matching_suffix_ranges(&candidates);
        assert_eq!(ranges.len(), suffixes.len());
        let retained: usize = ranges.iter().map(|(lo, hi)| lo.len() + hi.len()).sum();
        let input: usize = suffixes.iter().map(Vec::len).sum();
        assert_eq!(retained, 2 * input + suffixes.len());
        for ((lo, hi), suffix) in ranges.iter().zip(&suffixes) {
            assert_eq!(lo, suffix);
            assert_eq!(hi, &subtree_end(suffix));
        }
        candidates.extend(vec![Vec::new(); 512]);
        assert_eq!(
            matching_suffix_ranges(&candidates),
            vec![(vec![], vec![0xff])]
        );
    }
}
