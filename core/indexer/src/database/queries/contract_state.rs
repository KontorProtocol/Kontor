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

pub async fn delete_contract_state(
    conn: &Connection,
    height: u64,
    tx_id: Option<u64>,
    contract_id: u64,
    path: &str,
) -> Result<bool, Error> {
    Ok(
        match get_latest_contract_state(conn, contract_id, path).await? {
            Some(mut row) => {
                row.deleted = true;
                row.height = height;
                row.tx_id = tx_id;
                insert_contract_state(conn, row).await?;
                true
            }
            None => false,
        },
    )
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
    // Latest surviving segment per captured prefix: partition by the prefix
    // capture, filter `deleted` before ranking (so a deleted newest row falls
    // back to the prior live one). Order by `path` so `keys()` iteration is
    // deterministic across nodes — a contract that consumes this positionally
    // (e.g. filestorage selecting challenge targets by index) would otherwise
    // rely on SQLite's unspecified row order, a latent consensus hazard.
    let query = LatestMany::builder()
        .table("contract_state")
        .select(r"regexp_capture(path, '^' || :path || '\.([^.]*)(\.|$)', 1)")
        .partition_by(r"regexp_capture(path, '^(' || :path || '\.[^.]*)(\.|$)', 1)")
        // Boundary the prefix at the `.` separator (matching the capture regexes
        // above): a sibling whose name merely string-extends `path` — e.g. an
        // IndexedMap's `<map>#idx` index root vs the `<map>` primary — must NOT
        // leak into `<map>`'s keys (it has no `path.`-rooted segment, so the
        // capture would yield NULL → "Null value").
        .filter("contract_id = :contract_id AND path LIKE :path || '.%' AND deleted = false")
        .order_by("path")
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
    // row under `base_path` (by height, then rowid) and returning it only if it
    // is live and matches `regexp`. This is deliberately a GLOBAL pick, not a
    // per-path one: the resolver asks e.g. "is the current value a `none`?", so
    // a stale variant lingering live at a lower height (an old `none`, or an old
    // enum case) must be outranked by the newer write. `rowid` breaks same-height
    // ties (the write following an in-tx `delete_matching` has the higher rowid),
    // keeping the result consistent across nodes.
    let query = r"
        SELECT path FROM (
            SELECT path, deleted,
                   ROW_NUMBER() OVER (ORDER BY height DESC, rowid DESC) AS rank
            FROM contract_state
            WHERE contract_id = :contract_id AND path LIKE :base_path || '%'
        ) WHERE rank = 1 AND deleted = false AND path REGEXP :regexp";
    let mut rows = conn
        .query(
            query,
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
