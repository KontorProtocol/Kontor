use std::sync::Arc;

use libsql::{Connection, Error as DriverError, Value, de::from_row, params};
use serde::Deserialize;

use super::queries::{
    Error, create_contract_signer, get_contract_bytes_by_id, get_contract_provenance_publisher,
};
use crate::protocol::storage_contracts::ContractCallbacks;

#[derive(Deserialize)]
struct StoredAddress {
    name: String,
    height: u64,
    tx_index: u32,
}

fn driver_error(error: DriverError) -> String {
    Error::from(error).to_string()
}

pub(crate) fn contract_callbacks(conn: &Connection) -> ContractCallbacks {
    (
        {
            let conn = conn.clone();
            Arc::new(move |height| {
                let conn = conn.clone();
                Box::pin(async move {
                    create_contract_signer(&conn, height)
                        .await
                        .map_err(|e| e.to_string())
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |(name, height, tx_index, size, bytes, signer_id)| {
                let conn = conn.clone();
                Box::pin(async move {
                    conn.execute(
                        "INSERT INTO contracts (name, height, tx_index, size, bytes, signer_id) VALUES (?, ?, ?, ?, ?, ?)",
                        params![name, height, tx_index, size, bytes, signer_id.map(Value::try_from).transpose().map_err(driver_error)?],
                    ).await.map_err(driver_error)?;
                    Ok(conn.last_insert_rowid() as u64)
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |(name, height, tx_index)| {
                let conn = conn.clone();
                Box::pin(async move {
                    let mut rows = conn.query(
                        "SELECT id FROM contracts WHERE name = :name AND height = :height AND tx_index = :tx_index",
                        ((":name", name), (":height", height), (":tx_index", tx_index)),
                    ).await.map_err(driver_error)?;
                    rows.next()
                        .await
                        .map_err(driver_error)?
                        .map(|row| row.get(0))
                        .transpose()
                        .map_err(driver_error)
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |id| {
                let conn = conn.clone();
                Box::pin(async move {
                    let mut rows = conn
                        .query(
                            "SELECT name, height, tx_index FROM contracts WHERE id = ?",
                            params![id],
                        )
                        .await
                        .map_err(driver_error)?;
                    rows.next()
                        .await
                        .map_err(driver_error)?
                        .map(|row| {
                            let address: StoredAddress =
                                from_row(&row).map_err(|error| Error::from(error).to_string())?;
                            Ok((address.name, address.height, address.tx_index))
                        })
                        .transpose()
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |id| {
                let conn = conn.clone();
                Box::pin(async move {
                    get_contract_bytes_by_id(&conn, id)
                        .await
                        .map_err(|e| e.to_string())
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(
                move |(contract_id, author_signer_id, height, tx_index, provenance)| {
                    let conn = conn.clone();
                    Box::pin(async move {
                        conn.execute(
                        "INSERT INTO contract_provenance (contract_id, author_signer_id, height, tx_index, provenance) VALUES (?, ?, ?, ?, ?)",
                        params![contract_id, author_signer_id, height, tx_index, provenance],
                    ).await.map_err(driver_error)?;
                        Ok(conn.last_insert_rowid() as u64)
                    })
                },
            )
        },
        {
            let conn = conn.clone();
            Arc::new(move |id| {
                let conn = conn.clone();
                Box::pin(async move {
                    get_contract_provenance_publisher(&conn, id)
                        .await
                        .map_err(|e| e.to_string())
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(
                move |(
                    contract_id,
                    size,
                    func,
                    height,
                    tx_id,
                    input_index,
                    op_index,
                    result_index,
                    gas,
                    value,
                    signer_id,
                    payer_signer_id,
                    status,
                )| {
                    let conn = conn.clone();
                    Box::pin(async move {
                        conn.execute(
                        "INSERT INTO contract_results (contract_id, size, func, height, tx_id, input_index, op_index, result_index, gas, value, signer_id, payer_signer_id, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        params![contract_id, size, func, height, tx_id.map(Value::try_from).transpose().map_err(driver_error)?, input_index, op_index, result_index, gas, value, signer_id, payer_signer_id.map(Value::try_from).transpose().map_err(driver_error)?, status],
                    ).await.map_err(driver_error)?;
                        Ok(conn.last_insert_rowid() as u64)
                    })
                },
            )
        },
    )
}
