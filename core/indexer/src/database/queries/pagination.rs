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
    pub count: bool,
}

pub struct PageSource<'a> {
    pub alias: &'a str,
    pub columns: &'a str,
    pub from: &'a str,
    // One flag governs deduplication of both the page and its count.
    pub distinct: bool,
    // These joins must preserve row cardinality and cannot be used by filters.
    pub select_joins: &'a str,
}

pub async fn get_paginated<T>(
    conn: &Connection,
    source: PageSource<'_>,
    mut where_clauses: Vec<String>,
    mut params: Vec<(String, Value)>,
    page: PageOptions,
) -> Result<(Vec<T>, PaginationMeta), Error>
where
    T: DeserializeOwned + HasRowId,
{
    let PageSource {
        alias: var,
        columns,
        from,
        distinct,
        select_joins,
    } = source;
    let PageOptions {
        order,
        cursor,
        offset,
        limit,
        count,
    } = page;
    let offset = if cursor.is_some() { None } else { offset };
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

    let total_count = if count {
        let expression = if distinct {
            format!("DISTINCT {var}.{id_name}")
        } else {
            "*".to_string()
        };
        let mut rows = conn
            .query(
                &format!("SELECT COUNT({expression}) FROM {from} {where_sql}"),
                params.clone(),
            )
            .await?;
        Some(match rows.next().await? {
            Some(row) => row.get::<u64>(0)?,
            None => 0,
        })
    } else {
        None
    };

    let mut offset_clause = "";
    if let Some(offset) = offset {
        offset_clause = "OFFSET :offset";
        params.push((":offset".to_string(), Value::try_from(offset)?));
    }

    params.push((":limit".to_string(), Value::Integer(i64::from(limit) + 1)));

    let distinct = if distinct { "DISTINCT " } else { "" };
    let mut rows = conn
        .query(
            &format!(
                r#"
                SELECT {distinct}{columns}
                FROM {from} {select_joins}
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
