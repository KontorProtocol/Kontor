use futures_util::{Stream, stream};
use libsql::{Connection, Value, de::from_row, params};

use super::Error;
use super::versioned::LatestMany;
use crate::database::types::ContractStateRow;

const DELETE_MATCHING_PATHS_QUERY: &str = include_str!("../sql/delete_matching_paths.sql");

/// `contract_state` is height-versioned per `(contract_id, path)`. These build
/// the latest-version reads. Note `deleted = false` placement differs by intent:
/// the point reads apply it as a *post* predicate (the current value, or nothing
/// if the latest write deleted it), while the prefix scan filters deleted rows
/// *before* ranking (latest surviving version per captured prefix).
fn latest_state(select: &str, filter: &str) -> String {
    LatestMany::builder()
        .table("contract_state")
        .select(select)
        .filter(filter)
        .post("deleted = false")
        .build()
        .to_sql()
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
            &latest_state(
                "contract_id, height, tx_id, path, value, deleted",
                "contract_id = :contract_id AND path = :path",
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
            &latest_state(
                "CASE WHEN size <= :fuel THEN value ELSE null END AS value",
                "contract_id = :contract_id AND path = :path",
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
    // Latest live version of every path at/under `path` (the entry root + its
    // descendants). Re-inserted as a tombstone below; `partition_by("path")` +
    // post `deleted = false` mirrors `exists`, so an already-tombstoned path is
    // skipped (not re-tombstoned).
    let query = LatestMany::builder()
        .table("contract_state")
        .select("contract_id, height, tx_id, path, value, deleted")
        .partition_by("path")
        .post("deleted = false")
        .filter("contract_id = :contract_id AND (path = :path OR path LIKE :path || '.%')")
        .build()
        .to_sql();
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
    // "Any live path at/under `path`". This must rank PER PATH (unlike the
    // generic point-read `latest_state`): the prefix matches many paths, and a
    // single newest row that happens to be a tombstone — e.g. an IndexedMap
    // index `__delete` under `<map>#idx` — must not hide sibling paths that are
    // still live. (Global ranking + `deleted=false` post would do exactly that.)
    let query = LatestMany::builder()
        .table("contract_state")
        .select("1")
        .partition_by("path")
        .post("deleted = false")
        .filter("contract_id = :contract_id AND (path LIKE :path || '.%' OR path = :path)")
        .build()
        .to_sql();
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
    // Direct child segments under `path` that are STILL LIVE. Liveness must be
    // judged on each path's LATEST version, so rank PER PATH and apply
    // `deleted = false` as a POST predicate (not a pre-rank filter). A pre-rank
    // `deleted = false` would, after a height-versioned tombstone (a `__delete`
    // / `apply_index_diff` removal), fall back to the path's older live row and
    // keep returning a child that point reads + `exists` already treat as gone —
    // e.g. a departed node still surfacing in `by_index("active","true")` while
    // its bucket count has dropped. `DISTINCT` collapses a struct value's many
    // field paths to one child; ordering by the segment keeps `keys()` iteration
    // deterministic across nodes (filestorage selects challenge targets by index
    // positionally, so SQLite's unspecified order would be a consensus hazard).
    let query = LatestMany::builder()
        .table("contract_state")
        .select(r"DISTINCT regexp_capture(path, '^' || :path || '\.([^.]*)(\.|$)', 1) AS segment")
        .partition_by("path")
        .post("deleted = false")
        // Boundary the prefix at the `.` separator (matching the capture regex
        // above): a sibling whose name merely string-extends `path` — e.g. an
        // IndexedMap's `<map>#idx` index root vs the `<map>` primary — must NOT
        // leak into `<map>`'s keys (it has no `path.`-rooted segment, so the
        // capture would yield NULL → "Null value").
        .filter("contract_id = :contract_id AND path LIKE :path || '.%'")
        .order_by("segment")
        .build()
        .to_sql();
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
    // Resolve an enum/option to its current variant by taking the single NEWEST
    // live row under `base_path` (by height, then rowid) that matches `regexp`.
    // Deliberately a GLOBAL pick (no `partition_by`), not a per-path one: the
    // resolver asks e.g. "is the current value a `none`?", so a stale variant
    // lingering live at a lower height (an old `none`, or an old enum case) must
    // be outranked by the newer write. The REGEXP is a `post` predicate so it's
    // applied to the single ranked row, not used to pick among rows.
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
