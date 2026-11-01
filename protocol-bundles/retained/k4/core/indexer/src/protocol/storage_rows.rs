use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub(crate) type CursorOwner = Box<dyn Any + Send>;
pub(crate) type HostFuture<T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send>>;
pub(crate) type RowQuery = (u64, Vec<u8>, bool, Option<Vec<u8>>, bool, u64);
pub(crate) type OpenRows = Arc<dyn Fn(RowQuery) -> CursorOwner + Send + Sync>;
pub(crate) type AdvanceRow =
    Arc<dyn Fn(CursorOwner) -> HostFuture<Option<(CursorOwner, u64)>> + Send + Sync>;
pub(crate) type ReadColumn<T> =
    Arc<dyn Fn(CursorOwner) -> HostFuture<(CursorOwner, T)> + Send + Sync>;
pub(crate) type ReadValue =
    Arc<dyn Fn(CursorOwner, u64, Vec<u8>) -> HostFuture<(CursorOwner, Vec<u8>)> + Send + Sync>;
pub(crate) type RowCallbacks = (
    OpenRows,
    AdvanceRow,
    ReadColumn<u64>,
    ReadColumn<Vec<u8>>,
    ReadColumn<u64>,
    ReadValue,
);
