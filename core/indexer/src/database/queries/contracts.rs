use indexer_types::{ContractListRow, PaginationMeta};
use libsql::{Connection, Value, de::from_row, params};

use super::Error;
use super::pagination::{PageOptions, get_paginated};
use crate::database::types::{ContractProvenanceRow, ContractQuery, ContractRow};
use crate::runtime::ContractAddress;

/// Append one entry to a contract's build-provenance log (publish seeds the
/// first; `UpdateProvenance` appends). Append-only — never updates in place.
pub async fn insert_contract_provenance(
    conn: &Connection,
    row: ContractProvenanceRow,
) -> Result<u64, Error> {
    conn.execute(
        r#"
            INSERT INTO contract_provenance (
                contract_id,
                height,
                tx_index,
                provenance
            ) VALUES (?, ?, ?, ?)
            "#,
        params![row.contract_id, row.height, row.tx_index, row.provenance],
    )
    .await?;

    Ok(conn.last_insert_rowid() as u64)
}

pub async fn insert_contract(conn: &Connection, row: ContractRow) -> Result<u64, Error> {
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
            row.signer_id.map(Value::try_from).transpose()?,
        ],
    )
    .await?;

    Ok(conn.last_insert_rowid() as u64)
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
        params.push((":signer_id".to_string(), Value::try_from(signer_id)?));
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
    id: u64,
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

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_contract_id_from_address(
    conn: &Connection,
    address: &ContractAddress,
) -> Result<Option<u64>, Error> {
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
    id: u64,
) -> Result<Option<Vec<u8>>, Error> {
    let mut rows = conn
        .query("SELECT bytes FROM contracts WHERE id = ?", params![id])
        .await?;
    Ok(rows.next().await?.map(|r| r.get(0)).transpose()?)
}

/// A contract's full provenance log, oldest first (append order). Each row's
/// `provenance` is a postcard-encoded `indexer_types::BuildProvenance`.
pub async fn get_contract_provenance_log(
    conn: &Connection,
    contract_id: u64,
) -> Result<Vec<ContractProvenanceRow>, Error> {
    let mut rows = conn
        .query(
            r#"
            SELECT id, contract_id, height, tx_index, provenance
            FROM contract_provenance
            WHERE contract_id = ?
            ORDER BY id
            "#,
            params![contract_id],
        )
        .await?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await? {
        out.push(from_row::<ContractProvenanceRow>(&row)?);
    }
    Ok(out)
}
