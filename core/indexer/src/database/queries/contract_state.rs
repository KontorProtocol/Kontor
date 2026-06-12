//! Liveness reads over the `contract_state` version log.
//!
//! `contract_state` is an APPEND-ONLY, height-versioned log keyed by
//! `(contract_id, path)`. A write appends a row; a "delete" appends a row with
//! `deleted = true` (a tombstone) — nothing is ever physically removed (that's
//! what makes reorg rollback and the consensus checkpoint possible). So "what is
//! the current state?" is always a DERIVED computation, and getting that
//! derivation subtly wrong is the entire bug surface of this file.
//!
//! THE ONE RULE — current state is, for each path, its LATEST version (ranked by
//! `height` then `rowid`), kept only if that latest version is live. Concretely:
//! rank PER PATH, then apply `deleted = false` as a **post** predicate. The
//! recurring footgun is filtering `deleted = false` *before* ranking: after a
//! tombstone that drops the path's older live row back into view, so a path that
//! point reads and `exists` treat as gone keeps surfacing in `keys()`/`by_index`.
//!
//! So every read of a SET of current paths — point read, `exists`, `keys`/
//! `by_index`, subtree delete — funnels through [`live_latest`], which bakes in
//! `partition_by("path")` + post `deleted = false`. Don't hand-roll a ranking
//! query; if a new read needs the current state, build it on `live_latest`.
//!
//! Two deliberate EXCEPTIONS, each documented at its call site:
//!   - [`matching_path`] — enum/option variant resolution. GLOBAL-newest across
//!     paths (NOT per-path), because it asks "which variant is current?".
//!   - [`delete_matching_paths`] — a HARD delete at the current height (not a
//!     tombstone, not a liveness read); intra-block `Option` variant cleanup.

use futures_util::{Stream, stream};
use libsql::{Connection, Value, de::from_row, params};

use super::Error;
use super::versioned::LatestMany;
use crate::database::types::ContractStateRow;

const DELETE_MATCHING_PATHS_QUERY: &str = include_str!("../sql/delete_matching_paths.sql");

/// THE liveness primitive (see the module header): the latest version of each
/// path that passes `filter`, kept only if that version is live. `partition_by`
/// gives the per-path rank; `deleted = false` is a **post** predicate, never a
/// pre-rank filter. Every current-state read of a path set goes through here, so
/// the tombstone semantics are decided in exactly one place. `order` is for the
/// callers that consume rows positionally and need a deterministic order.
fn live_latest(select: &str, filter: &str, order: Option<&str>) -> String {
    let builder = LatestMany::builder()
        .table("contract_state")
        .select(select)
        .partition_by("path")
        .post("deleted = false")
        .filter(filter);
    match order {
        Some(order) => builder.order_by(order).build().to_sql(),
        None => builder.build().to_sql(),
    }
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
    path: &str,
) -> Result<Option<ContractStateRow>, Error> {
    let mut rows = conn
        .query(
            &live_latest(
                "contract_id, height, tx_id, path, value, deleted",
                "contract_id = :contract_id AND path = :path",
                None,
            ),
            ((":contract_id", contract_id), (":path", path)),
        )
        .await?;

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_latest_contract_state_value(
    conn: &Connection,
    fuel: u64,
    contract_id: u64,
    path: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let mut rows = conn
        .query(
            &live_latest(
                "CASE WHEN size <= :fuel THEN value ELSE null END AS value",
                "contract_id = :contract_id AND path = :path",
                None,
            ),
            (
                (":contract_id", contract_id),
                (":path", path),
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
/// live descendant (`path.field`, nested struct/map rows, …). A struct value
/// persists under child paths, so tombstoning only the exact path would leave
/// live primary rows behind while the caller (`Map`/`IndexedMap` `remove`) has
/// already cleared the index — a half-removed entry. Height-versioned (one
/// `deleted = true` row per live path at the current height), so reorg-safe.
/// Returns true if any live row was tombstoned.
pub async fn delete_contract_state(
    conn: &Connection,
    height: u64,
    tx_id: Option<u64>,
    contract_id: u64,
    path: &str,
) -> Result<bool, Error> {
    // Every live path at/under `path` (the entry root + its descendants),
    // re-inserted as a tombstone below. `live_latest` skips an already-tombstoned
    // path (its latest version isn't live), so it's not re-tombstoned.
    let query = live_latest(
        "contract_id, height, tx_id, path, value, deleted",
        "contract_id = :contract_id AND (path = :path OR path LIKE :path || '.%')",
        None,
    );
    let mut result = conn
        .query(&query, ((":contract_id", contract_id), (":path", path)))
        .await?;

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
    path: &str,
) -> Result<bool, Error> {
    // "Any live path at/under `path`". Per-path liveness is load-bearing here: a
    // single newest tombstone (e.g. an IndexedMap index `__delete` under
    // `<map>#idx`) must not hide sibling paths that are still live — which is
    // exactly what `live_latest` (per-path rank + post `deleted = false`) gives.
    let query = live_latest(
        "1",
        "contract_id = :contract_id AND (path LIKE :path || '.%' OR path = :path)",
        None,
    );
    let mut rows = conn
        .query(&query, ((":contract_id", contract_id), (":path", path)))
        .await?;
    Ok(rows.next().await?.is_some())
}

pub async fn path_prefix_filter_contract_state(
    conn: &Connection,
    contract_id: u64,
    path: String,
) -> Result<impl Stream<Item = Result<String, libsql::Error>> + Send + 'static, Error> {
    // Distinct direct-child segments under `path` whose subtree has a live path.
    // `live_latest` decides the per-path liveness (so a tombstoned child doesn't
    // fall back to its older live row); `DISTINCT regexp_capture` collapses a
    // struct value's many field paths to its one child segment. The `'.%'`
    // boundary keeps a sibling that merely string-extends `path` — e.g. an
    // IndexedMap's `<map>#idx` index root vs the `<map>` primary — out of
    // `<map>`'s keys (it has no `path.`-rooted segment → capture would be NULL).
    // Ordering by the segment keeps iteration deterministic across nodes
    // (filestorage selects challenge targets by index positionally, so SQLite's
    // unspecified order would be a consensus hazard).
    let query = live_latest(
        r"DISTINCT regexp_capture(path, '^' || :path || '\.([^.]*)(\.|$)', 1) AS segment",
        "contract_id = :contract_id AND path LIKE :path || '.%'",
        Some("segment"),
    );
    let rows = conn
        .query(
            &query,
            ((":contract_id", contract_id), (":path", path.clone())),
        )
        .await?;
    let stream = stream::unfold(rows, |mut rows| async move {
        match rows.next().await {
            Ok(Some(row)) => match row.get::<String>(0) {
                Ok(segment) => Some((Ok(segment), rows)),
                Err(e) => Some((Err(e), rows)),
            },
            Ok(None) => None,
            Err(e) => Some((Err(e), rows)),
        }
    });

    Ok(stream)
}

pub async fn matching_path(
    conn: &Connection,
    contract_id: u64,
    base_path: &str,
    regexp: &str,
) -> Result<Option<String>, Error> {
    // EXCEPTION to `live_latest` (see module header): variant resolution is
    // GLOBAL-newest, not per-path. Resolve an enum/option to its current variant
    // by taking the single NEWEST live row under `base_path` (by height, then
    // rowid) that matches `regexp`. No `partition_by`: the resolver asks e.g. "is
    // the current value a `none`?", so a stale variant lingering live at a lower
    // height (an old `none`, or an old enum case) must be outranked by the newer
    // write — a per-path pick would surface it. The REGEXP is a `post` predicate
    // so it's applied to the single ranked row, not used to pick among rows.
    let query = LatestMany::builder()
        .table("contract_state")
        .select("path")
        .filter("contract_id = :contract_id AND path LIKE :base_path || '%'")
        .post("deleted = false AND path REGEXP :regexp")
        .build()
        .to_sql();
    let mut rows = conn
        .query(
            &query,
            (
                (":contract_id", contract_id),
                (":base_path", base_path),
                (":regexp", regexp),
            ),
        )
        .await?;
    Ok(rows.next().await?.map(|r| r.get(0)).transpose()?)
}

/// EXCEPTION to the liveness model (see module header): a HARD delete of rows at
/// the CURRENT height matching `path_regexp` — not a tombstone, not a
/// latest-version read. Used only for intra-block `Option` variant cleanup
/// (drop a just-written `some`/`none` before writing the other in the same
/// block); it deliberately does NOT touch earlier-height rows.
pub async fn delete_matching_paths(
    conn: &Connection,
    contract_id: u64,
    height: u64,
    path_regexp: &str,
) -> Result<u64, Error> {
    Ok(conn
        .execute(
            DELETE_MATCHING_PATHS_QUERY,
            (
                (":contract_id", contract_id),
                (":height", height),
                (":path_regexp", path_regexp),
            ),
        )
        .await?)
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
