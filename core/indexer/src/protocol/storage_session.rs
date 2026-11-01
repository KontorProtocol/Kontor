use std::sync::Arc;

use super::storage_rows::HostFuture;

pub(crate) type TransactionAction = Arc<dyn Fn() -> HostFuture<()> + Send + Sync>;
pub(crate) type SavepointAction = Arc<dyn Fn(u64) -> HostFuture<()> + Send + Sync>;
pub(crate) type SessionCallbacks = (
    TransactionAction,
    SavepointAction,
    TransactionAction,
    SavepointAction,
    TransactionAction,
    SavepointAction,
    TransactionAction,
);
