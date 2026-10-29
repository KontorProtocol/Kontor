use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::ResultInfo;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "bindings.d.ts")]
pub struct StreamReceipt {
    pub receipt: ResultInfo,
    pub resume_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "bindings.d.ts")]
#[serde(rename_all = "snake_case")]
pub enum StreamResetReason {
    EpochMismatch,
    FutureGeneration,
    UnsupportedLineage,
    MissingHistory,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "bindings.d.ts")]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReceiptStreamResponse {
    Start {
        resume_token: String,
    },
    Recovery {
        resume_token: String,
        #[ts(type = "number")]
        fork_height: u64,
        more: bool,
    },
    Page {
        receipts: Vec<StreamReceipt>,
        next_token: String,
        has_more: bool,
    },
    ResetRequired {
        reason: StreamResetReason,
    },
}
