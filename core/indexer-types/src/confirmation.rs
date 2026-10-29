use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{ResultRow, TransactionRow};

/// Public transaction metadata, separate from retained execution row projections.
/// `height` is the legacy alias of `execution_height`. `tx_index` is a deprecated
/// filtered ordinal, never a raw Bitcoin position.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "bindings.d.ts")]
pub struct TransactionInfo {
    #[serde(flatten)]
    pub row: TransactionRow,
    #[ts(type = "number")]
    pub execution_height: u64,
    /// Unknown historical positions and unconfirmed transactions are null.
    pub confirmed_bitcoin_tx_index: Option<u32>,
}

/// A receipt with current confirmation metadata. System receipts without a
/// transaction have null confirmation and batch coordinates.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "bindings.d.ts")]
pub struct ResultInfo {
    #[serde(flatten)]
    pub row: ResultRow,
    #[ts(type = "number")]
    pub execution_height: u64,
    #[ts(type = "number | null")]
    pub confirmed_height: Option<u64>,
    pub confirmed_bitcoin_tx_index: Option<u32>,
    #[ts(type = "number | null")]
    pub batch_height: Option<u64>,
}
