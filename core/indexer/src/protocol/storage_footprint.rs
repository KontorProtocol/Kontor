use std::sync::Arc;

use super::storage_rows::HostFuture;

pub(crate) type ReadFloor = Arc<dyn Fn(u64) -> HostFuture<Option<i64>> + Send + Sync>;
pub(crate) type ReadDeposit =
    Arc<dyn Fn(u64, Vec<u8>) -> HostFuture<Option<(u64, u64)>> + Send + Sync>;
pub(crate) type AddFloor = Arc<dyn Fn(u64, i64) -> HostFuture<()> + Send + Sync>;
pub(crate) type ReadLiveFloor = Arc<dyn Fn(u64) -> HostFuture<u64> + Send + Sync>;
pub(crate) type SetFloor = Arc<dyn Fn(u64, Option<u64>) -> HostFuture<()> + Send + Sync>;
pub(crate) type ReadBuilt = Arc<dyn Fn() -> HostFuture<u64> + Send + Sync>;
pub(crate) type FloorAction = Arc<dyn Fn() -> HostFuture<()> + Send + Sync>;
pub(crate) type FootprintCallbacks = (
    ReadFloor,
    ReadDeposit,
    AddFloor,
    ReadLiveFloor,
    SetFloor,
    ReadBuilt,
    FloorAction,
    FloorAction,
);
