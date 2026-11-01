use std::sync::Arc;

use super::storage_rows::{CursorOwner, HostFuture, ReadColumn};

pub(crate) type OpenPoint =
    Arc<dyn Fn(u64, Vec<u8>) -> HostFuture<Option<(CursorOwner, u64)>> + Send + Sync>;
pub(crate) type ReadPoint =
    Arc<dyn Fn(CursorOwner, u64, Vec<u8>) -> HostFuture<Vec<u8>> + Send + Sync>;
pub(crate) type PointCallbacks = (OpenPoint, ReadColumn<u64>, ReadPoint);
