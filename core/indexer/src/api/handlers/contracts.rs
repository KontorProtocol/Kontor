use axum::{
    Json,
    extract::{Path, Query, State},
};
use indexer_types::{
    ContractListRow, ContractProvenanceResponse, ContractResponse, PaginatedResponse,
    ProvenanceEntry, ViewExpr, ViewResult,
};
use libsql::Connection;

use super::validate_query;
use crate::api::{Env, error::HttpError, result::Result};
use crate::database::queries;
use crate::database::types::ContractQuery;
use crate::runtime::ContractAddress;

pub async fn post_contract(
    Path(address): Path<String>,
    State(env): State<Env>,
    Json(ViewExpr { expr }): Json<ViewExpr>,
) -> Result<ViewResult> {
    let contract_address = address
        .parse::<ContractAddress>()
        .map_err(|_| HttpError::BadRequest("Invalid contract address".to_string()))?;
    let mut runtime = env.runtime_pool.get().await?;
    warn_if_stale_view_snapshot(&env, &runtime.storage.conn, &address, &expr).await;
    let result = runtime.execute(None, None, &contract_address, &expr).await;
    Ok(match result {
        Ok(value) => ViewResult::Ok { value },
        Err(e) => ViewResult::Err {
            message: format!("{:?}", e),
        },
    }
    .into())
}

/// Diagnostic (non-fatal): the `/view` pool serves reads on a *separate* connection
/// from the reactor's writer. If that connection's visible block tip lags the
/// reactor's last-committed tip, the view executes against pre-commit state — e.g. a
/// just-registered signer or just-deposited row is missing, so a `floor`/balance
/// reads a stale `0`. That race is otherwise invisible in the logs; surface it (one
/// O(1) `MAX(height)` read) so it's greppable and alertable in prod and CI. Emitted
/// on `target: "view_snapshot"` for filtering; carries the height delta + the view
/// that raced, which is exactly what the on-node logs were missing during the
/// storage-deposit floor-view flake investigation.
async fn warn_if_stale_view_snapshot(env: &Env, conn: &Connection, address: &str, expr: &str) {
    // The reactor's last-published committed tip, copied out so the `watch` borrow is
    // released before the await. `None` = no block indexed yet → nothing to lag.
    let Some(committed) = env.info_rx.borrow().height else {
        return;
    };
    let visible = match queries::max_block_height(conn).await {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(target: "view_snapshot", error = ?e, "could not read view snapshot tip");
            return;
        }
    };
    // Trim the expr so a large view argument can't bloat the log line.
    let expr_short: String = expr.chars().take(80).collect();
    match visible {
        Some(v) if v < committed => tracing::warn!(
            target: "view_snapshot",
            visible = v,
            committed,
            delta = committed - v,
            contract = %address,
            expr = %expr_short,
            "stale /view snapshot: pool connection lags the committed tip; view may read \
             pre-commit state (missing signer/deposit → stale 0)"
        ),
        _ => tracing::debug!(
            target: "view_snapshot",
            visible = ?visible,
            committed,
            contract = %address,
            "fresh /view snapshot"
        ),
    }
}

pub async fn get_contracts(
    Query(query): Query<ContractQuery>,
    State(env): State<Env>,
) -> Result<PaginatedResponse<ContractListRow>> {
    validate_query(query.cursor, query.offset)?;
    let (results, pagination) =
        queries::get_contracts_paginated(&*env.reader.connection().await?, query).await?;
    Ok(PaginatedResponse {
        results,
        pagination,
    }
    .into())
}

pub async fn get_contract(
    Path(address): Path<String>,
    State(env): State<Env>,
) -> Result<ContractResponse> {
    let contract_address = address
        .parse::<ContractAddress>()
        .map_err(|_| HttpError::BadRequest("Invalid contract address".to_string()))?;
    let runtime = env.runtime_pool.get().await?;
    let contract_id = runtime
        .storage
        .contract_id(&contract_address)
        .await?
        .ok_or(HttpError::NotFound("Contract not found".to_string()))?;

    let wit = runtime.storage.component_wit(contract_id).await?;
    Ok(ContractResponse { wit }.into())
}

pub async fn get_contract_provenance(
    Path(address): Path<String>,
    State(env): State<Env>,
) -> Result<ContractProvenanceResponse> {
    let contract_address = address
        .parse::<ContractAddress>()
        .map_err(|_| HttpError::BadRequest("Invalid contract address".to_string()))?;
    let conn = env.reader.connection().await?;
    let contract_id = queries::get_contract_id_from_address(&conn, &contract_address)
        .await?
        .ok_or(HttpError::NotFound("Contract not found".to_string()))?;
    let entries = queries::get_contract_provenance_log(&conn, contract_id)
        .await?
        .into_iter()
        .map(|row| {
            let provenance = postcard::from_bytes(&row.provenance)?;
            Ok::<_, anyhow::Error>(ProvenanceEntry {
                height: row.height,
                tx_index: row.tx_index,
                author_signer_id: row.author_signer_id,
                provenance,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(ContractProvenanceResponse { entries }.into())
}
