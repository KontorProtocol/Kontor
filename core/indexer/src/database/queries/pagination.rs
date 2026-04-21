use indexer_types::PaginationMeta;
use libsql::{Connection, Value, de::from_row};
use serde::de::DeserializeOwned;

use super::Error;
use crate::database::types::{HasRowId, OrderDirection};

pub fn filter_cursor(cursor: Option<i64>) -> Option<i64> {
    cursor.filter(|&c| c >= 0)
}

pub fn clamp_limit(limit: Option<i64>) -> i64 {
    limit.map_or(20, |l| l.clamp(0, 1000))
}

pub async fn get_paginated<T>(
    conn: &Connection,
    var: &str,
    selects: &str,
    from: &str,
    mut where_clauses: Vec<String>,
    mut params: Vec<(String, Value)>,
    order: OrderDirection,
    cursor: Option<i64>,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<(Vec<T>, PaginationMeta), Error>
where
    T: DeserializeOwned + HasRowId,
{
    let cursor = filter_cursor(cursor);
    let limit = clamp_limit(limit);

    if let Some(cursor) = cursor {
        where_clauses.push(format!(
            "{}.{} {} :cursor",
            var,
            T::id_name(),
            if order == OrderDirection::Desc {
                "<"
            } else {
                ">"
            }
        ));
        params.push((":cursor".to_string(), Value::Integer(cursor)));
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    let total_count = conn
        .query(
            &format!(
                "SELECT COUNT(DISTINCT {}.{}) FROM {} {}",
                var,
                T::id_name(),
                from,
                where_sql
            ),
            params.clone(),
        )
        .await?
        .next()
        .await?
        .map_or(0, |r| r.get::<i64>(0).unwrap_or(0));

    let mut offset_clause = "";
    if cursor.is_none()
        && let Some(offset) = offset
    {
        offset_clause = "OFFSET :offset";
        params.push((":offset".to_string(), Value::Integer(offset)));
    }

    params.push((":limit".to_string(), Value::Integer(limit + 1)));

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
                selects = selects,
                from = from,
                where_sql = where_sql,
                var = var,
                id_name = T::id_name(),
                order = order,
                offset_clause = offset_clause
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
        .then(|| offset.unwrap_or(0) + results.len() as i64);

    let pagination = PaginationMeta {
        next_cursor,
        next_offset,
        has_more,
        total_count,
    };

    Ok((results, pagination))
}
