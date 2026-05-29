use indexer_types::PaginationMeta;
use libsql::{Connection, Value, de::from_row};
use serde::de::DeserializeOwned;

use super::Error;
use crate::database::types::{HasRowId, OrderDirection};

pub fn clamp_limit(limit: Option<u32>) -> u32 {
    limit.map_or(20, |l| l.min(1000))
}

/// Pagination controls extracted from a Query type.
///
/// `cursor` and `offset` are mutually exclusive — if both are set, `cursor`
/// wins and `offset` is ignored (and `next_offset` is suppressed in the
/// response). Callers should treat them as alternative pagination modes.
///
/// All three are unsigned: rowids and offsets are positions in the table
/// (never negative); limit is a per-page count clamped to 1000.
pub struct PageOptions {
    pub order: OrderDirection,
    pub cursor: Option<u64>,
    pub offset: Option<u64>,
    pub limit: Option<u32>,
}

pub async fn get_paginated<T>(
    conn: &Connection,
    var: &str,
    selects: &str,
    from: &str,
    mut where_clauses: Vec<String>,
    mut params: Vec<(String, Value)>,
    page: PageOptions,
) -> Result<(Vec<T>, PaginationMeta), Error>
where
    T: DeserializeOwned + HasRowId,
{
    let PageOptions {
        order,
        cursor,
        offset,
        limit,
    } = page;
    let limit = clamp_limit(limit);
    let id_name = T::id_name();

    if let Some(cursor) = cursor {
        let cmp = if order == OrderDirection::Desc {
            "<"
        } else {
            ">"
        };
        where_clauses.push(format!("{var}.{id_name} {cmp} :cursor"));
        params.push((":cursor".to_string(), Value::try_from(cursor)?));
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    // SQLite COUNT(...) is i64-shaped; the value is the count of distinct
    // rowids and can't actually be negative, but we still read into i64
    // and cast — propagating any libsql decode error via `?` rather than
    // swallowing it.
    let total_count = match conn
        .query(
            &format!("SELECT COUNT(DISTINCT {var}.{id_name}) FROM {from} {where_sql}"),
            params.clone(),
        )
        .await?
        .next()
        .await?
    {
        Some(row) => row.get::<i64>(0)? as u64,
        None => 0,
    };

    let mut offset_clause = "";
    if cursor.is_none()
        && let Some(offset) = offset
    {
        offset_clause = "OFFSET :offset";
        params.push((":offset".to_string(), Value::try_from(offset)?));
    }

    params.push((":limit".to_string(), Value::Integer(i64::from(limit) + 1)));

    let mut rows = conn
        .query(
            &format!(
                r#"
                SELECT {selects}
                FROM {from}
                {where_sql}
                ORDER BY {var}.{id_name} {order}
                LIMIT :limit
                {offset_clause}
                "#,
            ),
            params,
        )
        .await?;

    let mut results: Vec<T> = Vec::new();
    while let Some(row) = rows.next().await? {
        results.push(from_row(&row)?);
    }

    let has_more = results.len() > limit as usize;

    if has_more {
        results.pop();
    }

    let next_cursor = results
        .last()
        .filter(|_| offset.is_none())
        .map(|last_tx| last_tx.id());

    let next_offset = cursor
        .is_none()
        .then(|| offset.unwrap_or(0).saturating_add(results.len() as u64));

    let pagination = PaginationMeta {
        next_cursor,
        next_offset,
        has_more,
        total_count,
    };

    Ok((results, pagination))
}
