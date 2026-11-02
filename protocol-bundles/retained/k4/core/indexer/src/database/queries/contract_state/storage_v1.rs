use std::mem::take;
use std::sync::Arc;

use libsql::{Connection, Error as DriverError, Row, Rows, Statement, Value, params};

#[cfg(test)]
use super::traversal_probe;
use super::{BudgetedStorageValue, Error, LiveProjection, StorageValueReader, live_paths_scan};
use crate::protocol::storage_keys::{KeyCallbacks, KeyRange};
use crate::protocol::storage_point::PointCallbacks;
use crate::protocol::storage_rows::{CursorOwner, RowCallbacks};

struct PointOwner {
    contract_id: u64,
    values: StorageValueReader,
    _rows: Rows,
    row: Row,
}

fn point_owner(value: CursorOwner) -> Result<Box<PointOwner>, String> {
    value
        .downcast()
        .map_err(|_| "StorageV1 received a point read owned by another adapter".to_owned())
}

pub(crate) fn point_callbacks(conn: &Connection) -> PointCallbacks {
    let conn = conn.clone();
    (
        Arc::new(move |contract_id, path| {
            let conn = conn.clone();
            Box::pin(async move {
                let mut rows = conn.query(
                    "SELECT height, size FROM current_contract_state WHERE contract_id = ? AND path = ?",
                    params![contract_id, path],
                ).await.map_err(driver_error)?;
                let Some(row) = rows.next().await.map_err(driver_error)? else {
                    return Ok(None);
                };
                let height = row.get(0).map_err(driver_error)?;
                let owner = PointOwner {
                    contract_id,
                    values: StorageValueReader::new(&conn),
                    _rows: rows,
                    row,
                };
                Ok(Some((Box::new(owner) as CursorOwner, height)))
            })
        }),
        Arc::new(|owner| {
            Box::pin(async move {
                let owner = point_owner(owner)?;
                let size = owner.row.get(1).map_err(driver_error)?;
                Ok((owner as CursorOwner, size))
            })
        }),
        Arc::new(|owner, height, path| {
            Box::pin(async move {
                let mut owner = point_owner(owner)?;
                let value = BudgetedStorageValue {
                    contract_id: owner.contract_id,
                    height,
                    path,
                };
                let bytes = owner
                    .values
                    .read(value)
                    .await
                    .map_err(|error| error.to_string())?;
                // The metadata rows must outlive the selected-version read.
                drop(owner);
                Ok(bytes)
            })
        }),
    )
}

struct KeyOwner {
    conn: Connection,
    contract_id: u64,
    descending: bool,
    range: KeyRange,
    rows: Option<Rows>,
    statement: Option<Statement>,
}

fn key_owner(value: CursorOwner) -> Result<Box<KeyOwner>, String> {
    value
        .downcast()
        .map_err(|_| "StorageV1 received a key cursor owned by another adapter".to_owned())
}

pub(crate) fn key_callbacks(conn: &Connection) -> KeyCallbacks {
    let conn = conn.clone();
    (
        Arc::new(move |contract_id, range, descending| {
            Box::new(KeyOwner {
                conn: conn.clone(),
                contract_id,
                descending,
                range,
                rows: None,
                statement: None,
            })
        }),
        Arc::new(|owner| {
            Box::pin(async move {
                let mut owner = key_owner(owner)?;
                let mut rows = match owner.rows.take() {
                    Some(rows) => rows,
                    None => {
                        let (sql, params) = live_paths_scan(
                            LiveProjection::Keys,
                            if owner.range.1 { ">=" } else { ">" },
                            owner.contract_id,
                            owner.range.0.clone(),
                            owner.range.2.clone(),
                            Some(if owner.descending {
                                "cs.path DESC"
                            } else {
                                "cs.path"
                            }),
                            None,
                        );
                        let prepared = match owner.statement.take() {
                            Some(statement) => {
                                statement.reset();
                                statement
                            }
                            None => owner.conn.prepare(&sql).await.map_err(driver_error)?,
                        };
                        let rows = prepared.query(params).await.map_err(driver_error)?;
                        owner.statement = Some(prepared);
                        rows
                    }
                };
                let Some(row) = rows.next().await.map_err(driver_error)? else {
                    return Ok(None);
                };
                #[cfg(test)]
                traversal_probe::record();
                let full = row.get(0).map_err(driver_error)?;
                owner.rows = Some(rows);
                Ok(Some((owner as CursorOwner, full)))
            })
        }),
        Arc::new(|owner, range| {
            let mut owner = key_owner(owner)?;
            // The first forward skip changes the SQL comparison; later seeks
            // retain and reset the prepared statement, including reverse scans.
            if owner.range.1 != range.1 {
                owner.statement = None;
            }
            owner.rows = None;
            owner.range = range;
            Ok(owner as CursorOwner)
        }),
    )
}

struct RowOwner {
    contract_id: u64,
    values: StorageValueReader,
    sql: String,
    params: Vec<(String, Value)>,
    rows: Option<Rows>,
    row: Option<Row>,
}

fn owner(value: CursorOwner) -> Result<Box<RowOwner>, String> {
    value
        .downcast()
        .map_err(|_| "StorageV1 received a cursor owned by another adapter".to_owned())
}

fn current(owner: &RowOwner) -> Result<&Row, String> {
    owner
        .row
        .as_ref()
        .ok_or_else(|| "StorageV1 cursor has no current row".to_owned())
}

fn driver_error(error: DriverError) -> String {
    Error::from(error).to_string()
}

pub(crate) fn row_callbacks(conn: &Connection) -> RowCallbacks {
    let conn = conn.clone();
    (
        Arc::new(
            move |(contract_id, lo, inclusive, hi, descending, prefix_len)| {
                let (sql, mut params) = live_paths_scan(
                    LiveProjection::Values,
                    if inclusive { ">=" } else { ">" },
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
                params.push((":prefix_len".into(), Value::Integer(prefix_len as i64)));
                Box::new(RowOwner {
                    contract_id,
                    values: StorageValueReader::new(&conn),
                    sql,
                    params,
                    rows: None,
                    row: None,
                })
            },
        ),
        Arc::new(|value| {
            Box::pin(async move {
                let mut owner = owner(value)?;
                if owner.rows.is_none() {
                    let params = take(&mut owner.params);
                    owner.rows = Some(
                        owner
                            .values
                            .conn
                            .query(&owner.sql, params)
                            .await
                            .map_err(driver_error)?,
                    );
                }
                let Some(row) = owner
                    .rows
                    .as_mut()
                    .unwrap()
                    .next()
                    .await
                    .map_err(driver_error)?
                else {
                    return Ok(None);
                };
                let key_bytes = row.get(0).map_err(driver_error)?;
                owner.row = Some(row);
                Ok(Some((owner as CursorOwner, key_bytes)))
            })
        }),
        Arc::new(|value| {
            Box::pin(async move {
                let owner = owner(value)?;
                let size = current(&owner)?.get(1).map_err(driver_error)?;
                Ok((owner as CursorOwner, size))
            })
        }),
        Arc::new(|value| {
            Box::pin(async move {
                let owner = owner(value)?;
                let key = current(&owner)?.get(2).map_err(driver_error)?;
                Ok((owner as CursorOwner, key))
            })
        }),
        Arc::new(|value| {
            Box::pin(async move {
                let owner = owner(value)?;
                let height = current(&owner)?.get(3).map_err(driver_error)?;
                Ok((owner as CursorOwner, height))
            })
        }),
        Arc::new(|value, height, path| {
            Box::pin(async move {
                let mut owner = owner(value)?;
                let value = BudgetedStorageValue {
                    contract_id: owner.contract_id,
                    height,
                    path,
                };
                let bytes = owner
                    .values
                    .read(value)
                    .await
                    .map_err(|error| error.to_string())?;
                owner.row = None;
                Ok((owner as CursorOwner, bytes))
            })
        }),
    )
}
