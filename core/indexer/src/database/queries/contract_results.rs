use indexer_types::PaginationMeta;
use libsql::{Connection, Value, de::from_row, named_params, params};

use super::Error;
use super::contracts::get_contract_id_from_address;
use super::pagination::get_paginated;
use crate::database::types::{
    ContractResultPublicRow, ContractResultRow, OpResultId, OrderDirection, ResultQuery,
};

pub async fn get_results_paginated(
    conn: &Connection,
    query: ResultQuery,
) -> Result<(Vec<ContractResultPublicRow>, PaginationMeta), Error> {
    let mut params: Vec<(String, Value)> = Vec::new();
    let var = "r";
    let selects = r#"
        DISTINCT
        r.id,
        r.height,
        t.tx_index,
        r.input_index,
        r.op_index,
        r.result_index,
        r.func,
        r.gas,
        r.value,
        c.name as contract_name,
        c.height as contract_height,
        c.tx_index as contract_tx_index,
        t.txid,
        r.signer_id
    "#;
    let from = r#"
        contract_results r
        LEFT JOIN transactions t ON r.tx_id = t.id
        JOIN contracts c ON r.contract_id = c.id
    "#;
    let mut where_clauses = vec![];
    if let Some(address) = &query.contract {
        let contract_id = get_contract_id_from_address(conn, address)
            .await?
            .ok_or(Error::ContractNotFound(address.to_string()))?;
        where_clauses.push(format!("r.contract_id = {}", contract_id));
    }

    if let Some(func) = &query.func {
        where_clauses.push(format!("r.func = '{}'", func));
    }

    if let Some(height) = query.height {
        where_clauses.push("r.height = :height".to_string());
        params.push((":height".to_string(), Value::Integer(height)));
    }

    if let Some(height) = query.start_height {
        where_clauses.push(format!(
            "r.height {} :start_height",
            if query.order == OrderDirection::Desc {
                "<="
            } else {
                ">="
            }
        ));
        params.push((":start_height".to_string(), Value::Integer(height)));
    }

    get_paginated(
        conn,
        var,
        selects,
        from,
        where_clauses,
        params,
        query.order,
        query.cursor,
        query.offset,
        query.limit,
    )
    .await
}

pub async fn get_op_result(
    conn: &Connection,
    op_result_id: &OpResultId,
) -> Result<Option<ContractResultPublicRow>, Error> {
    let mut rows = conn
        .query(
            r#"
            SELECT
                r.id,
                r.height,
                t.tx_index,
                r.input_index,
                r.op_index,
                r.result_index,
                r.func,
                r.gas,
                r.value,
                c.name as contract_name,
                c.height as contract_height,
                c.tx_index as contract_tx_index,
                t.txid,
                r.signer_id
            FROM contract_results r
            LEFT JOIN transactions t ON r.tx_id = t.id
            JOIN contracts c ON r.contract_id = c.id
            WHERE t.txid = :txid AND r.input_index = :input_index AND r.op_index = :op_index
            ORDER BY r.result_index DESC
            LIMIT 1
            "#,
            named_params! {
                ":txid": op_result_id.txid.clone(),
                ":input_index": op_result_id.input_index,
                ":op_index": op_result_id.op_index,
            },
        )
        .await?;

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_contract_result(
    conn: &Connection,
    tx_id: Option<i64>,
    input_index: Option<i64>,
    op_index: Option<i64>,
    result_index: i64,
) -> Result<Option<ContractResultRow>, Error> {
    let mut rows = conn
        .query(
            r#"
            SELECT
                id,
                contract_id,
                func,
                height,
                tx_id,
                input_index,
                op_index,
                result_index,
                gas,
                value,
                signer_id
            FROM contract_results
            WHERE tx_id IS :tx_id
              AND input_index IS :input_index
              AND op_index IS :op_index
              AND result_index = :result_index
            "#,
            named_params! {
                ":tx_id": tx_id,
                ":input_index": input_index,
                ":op_index": op_index,
                ":result_index": result_index,
            },
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn insert_contract_result(
    conn: &Connection,
    row: ContractResultRow,
) -> Result<i64, Error> {
    conn.execute(
        r#"
            INSERT INTO contract_results (
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
                signer_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
        params![
            row.contract_id,
            row.size(),
            row.func,
            row.height,
            row.tx_id,
            row.input_index,
            row.op_index,
            row.result_index,
            row.gas,
            row.value,
            row.signer_id
        ],
    )
    .await?;

    Ok(conn.last_insert_rowid())
}
