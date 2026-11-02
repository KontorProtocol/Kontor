use std::sync::Arc;

use libsql::Connection;

use super::{
    Error, footprint_cache_add, footprint_cache_set, footprint_rebuild_all, latest_live_deposit,
    live_deposit_gas_sum,
};
use crate::database::queries::{FOOTPRINT_BUILT_KEY, get_meta_u64, set_meta_u64};
use crate::protocol::storage_footprint::FootprintCallbacks;

pub(crate) fn footprint_callbacks(conn: &Connection) -> FootprintCallbacks {
    (
        {
            let conn = conn.clone();
            Arc::new(move |depositor| {
                let conn = conn.clone();
                Box::pin(async move {
                    let result: Result<_, Error> = async {
                        let mut rows = conn
                            .query(
                                "SELECT total_gas FROM depositor_footprint WHERE depositor = ?",
                                [depositor],
                            )
                            .await?;
                        match rows.next().await? {
                            Some(row) => Ok(Some(row.get::<i64>(0)?)),
                            None => Ok(None),
                        }
                    }
                    .await;
                    result.map_err(|error| error.to_string())
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |contract_id, path| {
                let conn = conn.clone();
                Box::pin(async move {
                    let result: Result<_, Error> = async {
                        Ok(latest_live_deposit(&conn, contract_id, &path)
                            .await?
                            .map(|row| (row.depositor, row.deposited_gas)))
                    }
                    .await;
                    result.map_err(|error| error.to_string())
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |depositor, delta| {
                let conn = conn.clone();
                Box::pin(async move {
                    let result: Result<_, Error> =
                        footprint_cache_add(&conn, depositor, delta).await;
                    result.map_err(|error| error.to_string())
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |depositor| {
                let conn = conn.clone();
                Box::pin(async move {
                    let result: Result<_, Error> = live_deposit_gas_sum(&conn, depositor).await;
                    result.map_err(|error| error.to_string())
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |depositor, total| {
                let conn = conn.clone();
                Box::pin(async move {
                    let result: Result<_, Error> =
                        footprint_cache_set(&conn, depositor, total).await;
                    result.map_err(|error| error.to_string())
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move || {
                let conn = conn.clone();
                Box::pin(async move {
                    let result: Result<_, Error> =
                        get_meta_u64(&conn, FOOTPRINT_BUILT_KEY, 0).await;
                    result.map_err(|error| error.to_string())
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move || {
                let conn = conn.clone();
                Box::pin(async move {
                    let result: Result<_, Error> = footprint_rebuild_all(&conn).await;
                    result.map_err(|error| error.to_string())
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move || {
                let conn = conn.clone();
                Box::pin(async move {
                    let result: Result<_, Error> =
                        set_meta_u64(&conn, FOOTPRINT_BUILT_KEY, 1).await;
                    result.map_err(|error| error.to_string())
                })
            })
        },
    )
}
