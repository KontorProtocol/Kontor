use std::mem::take;
use std::sync::Arc;

use libsql::{Connection, Error as DriverError, Rows, Value, params};

#[cfg(test)]
use super::traversal_probe;
use super::{Error, LiveProjection, live_paths_scan};
use crate::protocol::storage_rows::CursorOwner;
use crate::protocol::storage_state::StateCallbacks;

struct SubtreeOwner {
    conn: Connection,
    sql: String,
    params: Vec<(String, Value)>,
    rows: Option<Rows>,
}

fn driver_error(error: DriverError) -> String {
    Error::from(error).to_string()
}

pub(crate) fn state_callbacks(conn: &Connection) -> StateCallbacks {
    let write_conn = conn.clone();
    let scan_conn = conn.clone();
    let exists_conn = conn.clone();
    (
        Arc::new(
            move |(
                (contract_id, height, tx_id),
                size,
                path,
                value,
                deleted,
                depositor,
                deposited_gas,
            )| {
                let conn = write_conn.clone();
                Box::pin(async move {
                    conn.execute(
                        "INSERT OR REPLACE INTO contract_state (contract_id, height, tx_id, size, path, value, deleted, depositor, deposited_gas) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        params![
                            contract_id,
                            height,
                            tx_id.map(Value::try_from).transpose().map_err(driver_error)?,
                            size,
                            path,
                            value,
                            deleted,
                            depositor.map(Value::try_from).transpose().map_err(driver_error)?,
                            deposited_gas.map(Value::try_from).transpose().map_err(driver_error)?
                        ],
                    )
                    .await
                    .map_err(driver_error)
                })
            },
        ),
        Arc::new(move |contract_id, lower, upper| {
            let (sql, params) = live_paths_scan(
                LiveProjection::Deposits,
                ">=",
                contract_id,
                lower,
                Some(upper),
                Some("cs.path"),
                None,
            );
            Box::new(SubtreeOwner {
                conn: scan_conn.clone(),
                sql,
                params,
                rows: None,
            })
        }),
        Arc::new(|owner| {
            Box::pin(async move {
                let mut owner = owner.downcast::<SubtreeOwner>().map_err(|_| {
                    "StorageV1 received a subtree owned by another adapter".to_owned()
                })?;
                if owner.rows.is_none() {
                    let params = take(&mut owner.params);
                    owner.rows = Some(
                        owner
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
                #[cfg(test)]
                traversal_probe::record();
                let metadata = (
                    row.get(0).map_err(driver_error)?,
                    row.get(1).map_err(driver_error)?,
                    row.get(2).map_err(driver_error)?,
                    row.get(3).map_err(driver_error)?,
                );
                Ok(Some((owner as CursorOwner, metadata)))
            })
        }),
        Arc::new(move |contract_id, lower, upper| {
            let conn = exists_conn.clone();
            Box::pin(async move {
                let (sql, params) = live_paths_scan(
                    LiveProjection::Exists,
                    ">=",
                    contract_id,
                    lower,
                    Some(upper),
                    None,
                    Some(1),
                );
                let mut rows = conn.query(&sql, params).await.map_err(driver_error)?;
                Ok(rows.next().await.map_err(driver_error)?.is_some())
            })
        }),
    )
}
