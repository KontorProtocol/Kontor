use indexer_types::{ContractListRow, PaginationMeta};
use libsql::{Connection, Value, params};

use super::Error;
use super::pagination::{PageOptions, get_paginated};
use crate::database::types::{ContractQuery, ContractRow};
use crate::runtime::ContractAddress;

pub async fn insert_contract(conn: &Connection, row: ContractRow) -> Result<i64, Error> {
    conn.execute(
        r#"
            INSERT INTO contracts (
                name,
                height,
                tx_index,
                size,
                bytes,
                signer_id
            ) VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
            )
            "#,
        params![
            row.name.clone(),
            row.height,
            row.tx_index,
            row.size(),
            row.bytes,
            row.signer_id
        ],
    )
    .await?;

    Ok(conn.last_insert_rowid())
}

pub async fn get_contracts_paginated(
    conn: &Connection,
    query: ContractQuery,
) -> Result<(Vec<ContractListRow>, PaginationMeta), Error> {
    let var = "c";
    let mut where_clauses = vec![];
    let mut params: Vec<(String, Value)> = vec![];
    if let Some(signer_id) = query.signer_id {
        where_clauses.push("c.signer_id = :signer_id".to_string());
        params.push((":signer_id".to_string(), Value::Integer(signer_id)));
    }
    get_paginated(
        conn,
        var,
        "c.id, c.name, c.height, c.tx_index, c.size, c.signer_id",
        &format!("contracts {}", var),
        where_clauses,
        params,
        PageOptions {
            order: query.order,
            cursor: query.cursor,
            offset: query.offset,
            limit: query.limit,
        },
    )
    .await
}

pub async fn get_contract_bytes_by_address(
    conn: &Connection,
    address: &ContractAddress,
) -> Result<Option<Vec<u8>>, Error> {
    let mut rows = conn
        .query(
            r#"
        SELECT bytes FROM contracts
        WHERE name = :name
        AND height = :height
        AND tx_index = :tx_index
        "#,
            (
                (":name", address.name.clone()),
                (":height", address.height),
                (":tx_index", address.tx_index),
            ),
        )
        .await?;
    Ok(rows.next().await?.map(|r| r.get(0)).transpose()?)
}

pub async fn get_contract_address_from_id(
    conn: &Connection,
    id: i64,
) -> Result<Option<ContractAddress>, Error> {
    let mut rows = conn
        .query(
            r#"
        SELECT name, height, tx_index FROM contracts
        WHERE id = ?
        "#,
            params![id],
        )
        .await?;

    let row = rows.next().await?;
    if let Some(row) = row {
        let name = row.get(0)?;
        let height = row.get(1)?;
        let tx_index = row.get(2)?;
        Ok(Some(ContractAddress {
            name,
            height,
            tx_index,
        }))
    } else {
        Ok(None)
    }
}

pub async fn get_contract_id_from_address(
    conn: &Connection,
    address: &ContractAddress,
) -> Result<Option<i64>, Error> {
    let mut rows = conn
        .query(
            r#"
        SELECT id FROM contracts
        WHERE name = :name
        AND height = :height
        AND tx_index = :tx_index
        "#,
            (
                (":name", address.name.clone()),
                (":height", address.height),
                (":tx_index", address.tx_index),
            ),
        )
        .await?;
    Ok(rows.next().await?.map(|r| r.get(0)).transpose()?)
}

pub async fn get_contract_bytes_by_id(
    conn: &Connection,
    id: i64,
) -> Result<Option<Vec<u8>>, Error> {
    let mut rows = conn
        .query("SELECT bytes FROM contracts WHERE id = ?", params![id])
        .await?;
    Ok(rows.next().await?.map(|r| r.get(0)).transpose()?)
}
