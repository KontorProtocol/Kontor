use std::sync::Arc;

use super::storage_rows::HostFuture;

pub(crate) struct BootstrapReceipt {
    pub(crate) contract_id: i64,
    pub(crate) function: String,
    pub(crate) tx_id: Option<i64>,
    pub(crate) input_index: Option<i64>,
    pub(crate) op_index: Option<i64>,
    pub(crate) result_index: i64,
    pub(crate) signer_id: i64,
    pub(crate) payer_signer_id: Option<i64>,
    pub(crate) status: String,
}

pub(crate) struct BootstrapSnapshot {
    pub(crate) published_count: u64,
    pub(crate) receipts: Vec<BootstrapReceipt>,
    pub(crate) admission_floor: Option<Vec<u8>>,
    pub(crate) validators_initialized: Option<Vec<u8>>,
}

pub(crate) type BootstrapRead =
    Arc<dyn Fn(u64, Vec<u8>, Vec<u8>) -> HostFuture<BootstrapSnapshot> + Send + Sync>;
