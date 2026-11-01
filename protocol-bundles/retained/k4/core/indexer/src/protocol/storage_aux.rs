use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

// Preserve outer-to-inner diagnostic causes without exporting a driver error type.
pub(crate) type StorageFailure = Vec<String>;
pub(crate) type StorageFuture<T> = Pin<Box<dyn Future<Output = Result<T, StorageFailure>> + Send>>;
pub(crate) type AffectedDepositors = Arc<dyn Fn(u64) -> StorageFuture<Vec<u64>> + Send + Sync>;
pub(crate) type RollbackHeight = Arc<dyn Fn(u64) -> StorageFuture<u64> + Send + Sync>;
pub(crate) type BlockEntropy = Arc<dyn Fn(u64) -> StorageFuture<Option<Vec<u8>>> + Send + Sync>;
pub(crate) type HistoryCallbacks = (AffectedDepositors, RollbackHeight, BlockEntropy);

pub(crate) type PruneState = Arc<dyn Fn(u64, u64) -> StorageFuture<u64> + Send + Sync>;
pub(crate) type FreelistCount = Arc<dyn Fn() -> StorageFuture<i64> + Send + Sync>;
pub(crate) type VacuumPages = Arc<dyn Fn(i64) -> StorageFuture<()> + Send + Sync>;
pub(crate) type MaintenanceCallbacks = (PruneState, FreelistCount, VacuumPages);
pub(crate) type AuxiliaryCallbacks = (HistoryCallbacks, MaintenanceCallbacks);
