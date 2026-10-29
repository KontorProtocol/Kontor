use axum::extract::{Query, State};
use bitcoin::hashes::{Hash, sha256};
use indexer_types::{ReceiptStreamResponse, StreamReceipt, StreamResetReason};
use libsql::TransactionBehavior;
use serde::Deserialize;

use crate::api::{Env, confirmation, error::HttpError, result::Result};
use crate::database::queries::{Error as QueryError, get_results_paginated};
use crate::database::receipt_stream::{
    MAX_SAFE_RECEIPT_ID, StreamState, recovery_boundary, stream_state,
};
use crate::database::types::{OrderDirection, ResultQuery};
use crate::runtime::ContractAddress;

const MAX_PAGE_SIZE: u32 = 200;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamStart {
    Origin,
    Tip,
}

#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    pub start: Option<StreamStart>,
    pub from: Option<String>,
    pub page: Option<String>,
    pub contract: Option<String>,
    pub func: Option<String>,
    pub signer_id: Option<u64>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResumeToken {
    epoch: String,
    generation: u64,
    cursor: u64,
    filter: String,
}

impl ResumeToken {
    fn parse(value: &str) -> std::result::Result<Self, HttpError> {
        if value.len() > 192 {
            return Err(bad_request("Invalid receipt resume token"));
        }
        let parts: Vec<_> = value.split(':').collect();
        if parts.len() != 5 || parts[0] != "v1" || !is_digest(parts[1]) || !is_digest(parts[4]) {
            return Err(bad_request("Invalid receipt resume token"));
        }
        let number = |part: &str, max: u64| {
            let parsed = part.parse::<u64>().ok();
            parsed
                .filter(|n| *n <= max && n.to_string() == part)
                .ok_or_else(|| bad_request("Invalid receipt resume token"))
        };
        Ok(Self {
            epoch: parts[1].into(),
            generation: number(parts[2], i64::MAX as u64)?,
            cursor: number(parts[3], MAX_SAFE_RECEIPT_ID)?,
            filter: parts[4].into(),
        })
    }

    fn encode(&self) -> String {
        format!(
            "v1:{}:{}:{}:{}",
            self.epoch, self.generation, self.cursor, self.filter
        )
    }

    fn at(state: &StreamState, filter: &str, cursor: u64) -> Self {
        Self {
            epoch: state.epoch.clone(),
            generation: state.generation,
            cursor,
            filter: filter.into(),
        }
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn bad_request(message: &str) -> HttpError {
    HttpError::BadRequest(message.into())
}

fn reset(reason: StreamResetReason) -> ReceiptStreamResponse {
    ReceiptStreamResponse::ResetRequired { reason }
}

pub async fn get_receipt_stream(
    Query(query): Query<StreamQuery>,
    State(env): State<Env>,
) -> Result<ReceiptStreamResponse> {
    if query.start.is_some() == query.from.is_some()
        || (query.start.is_some() && query.page.is_some())
    {
        return Err(bad_request("Specify start or from; page requires from").into());
    }
    let limit = query.limit.unwrap_or(MAX_PAGE_SIZE);
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(bad_request("Receipt page limit must be between 1 and 200").into());
    }
    let contract = query
        .contract
        .as_deref()
        .map(str::parse::<ContractAddress>)
        .transpose()
        .map_err(|_| bad_request("Invalid receipt contract filter"))?;
    if query.func.is_some() && contract.is_none() {
        return Err(bad_request("func requires contract").into());
    }
    if query.signer_id.is_some_and(|id| id > MAX_SAFE_RECEIPT_ID) {
        return Err(bad_request("Signer filter exceeds the supported integer range").into());
    }
    let filter_bytes = serde_json::to_vec(&(
        contract.as_ref().map(ToString::to_string),
        &query.func,
        query.signer_id,
    ))?;
    let filter = sha256::Hash::hash(&filter_bytes).to_string();
    let completed = query.from.as_deref().map(ResumeToken::parse).transpose()?;
    let page = query.page.as_deref().map(ResumeToken::parse).transpose()?;
    if let Some(completed) = &completed {
        if completed.filter != filter {
            return Err(bad_request("Receipt resume token belongs to another filter").into());
        }
        if let Some(page) = &page
            && (page.epoch != completed.epoch
                || page.generation != completed.generation
                || page.filter != completed.filter
                || page.cursor < completed.cursor)
        {
            return Err(bad_request("Page token does not follow the completed token").into());
        }
    }

    let conn = env.reader.connection().await?;
    let snapshot = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .await?;
    let state = stream_state(&snapshot).await?;
    if state.unsupported || state.max_result_id > MAX_SAFE_RECEIPT_ID {
        return Ok(reset(StreamResetReason::UnsupportedLineage).into());
    }
    if let Some(start) = query.start {
        let cursor = match start {
            StreamStart::Origin => 0,
            StreamStart::Tip => state.max_result_id,
        };
        let response = ReceiptStreamResponse::Start {
            resume_token: ResumeToken::at(&state, &filter, cursor).encode(),
        };
        snapshot.commit().await?;
        return Ok(response.into());
    }
    let completed = completed.expect("validated from or start");
    if completed.epoch != state.epoch {
        return Ok(reset(StreamResetReason::EpochMismatch).into());
    }
    if completed.generation > state.generation {
        return Ok(reset(StreamResetReason::FutureGeneration).into());
    }
    let recovery =
        match recovery_boundary(&snapshot, &state, completed.generation, completed.cursor).await {
            Ok(recovery) => recovery,
            Err(QueryError::InvalidData(_)) => {
                return Ok(reset(StreamResetReason::MissingHistory).into());
            }
            Err(error) => return Err(error.into()),
        };
    if let Some(recovery) = recovery {
        let response = ReceiptStreamResponse::Recovery {
            resume_token: ResumeToken {
                generation: recovery.generation,
                cursor: recovery.cursor,
                ..completed
            }
            .encode(),
            fork_height: recovery.surviving_height,
            more: recovery.generation < state.generation,
        };
        snapshot.commit().await?;
        return Ok(response.into());
    }
    let cursor = page.as_ref().unwrap_or(&completed).cursor;
    if cursor > state.max_result_id {
        return Err(bad_request("Receipt cursor exceeds its generation's current history").into());
    }
    let page_result = get_results_paginated(
        &snapshot,
        ResultQuery {
            cursor: Some(cursor),
            offset: None,
            limit: Some(limit),
            count: false,
            order: OrderDirection::Asc,
            height: None,
            start_height: None,
            contract,
            func: query.func,
            signer_id: query.signer_id,
        },
    )
    .await;
    let (rows, has_more) = match page_result {
        Ok((rows, pagination)) => (rows, pagination.has_more),
        Err(QueryError::ContractNotFound(_)) => (Vec::new(), false),
        Err(error) => return Err(error.into()),
    };
    let rows = confirmation::results(&snapshot, rows.into_iter().map(Into::into).collect()).await?;
    let next_cursor = if has_more {
        rows.last().expect("nonempty page when has_more").row.id
    } else {
        state.max_result_id
    };
    let receipts = rows
        .into_iter()
        .map(|receipt| StreamReceipt {
            resume_token: ResumeToken::at(&state, &filter, receipt.row.id).encode(),
            receipt,
        })
        .collect();
    let response = ReceiptStreamResponse::Page {
        receipts,
        next_token: ResumeToken::at(&state, &filter, next_cursor).encode(),
        has_more,
    };
    snapshot.commit().await?;
    Ok(response.into())
}

#[cfg(test)]
mod tests;
