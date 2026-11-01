use std::sync::Arc;

use super::storage_rows::{CursorOwner, HostFuture};

pub(crate) type WritePosition = (u64, u64, Option<u64>);
pub(crate) type StateWrite = (
    WritePosition,
    u64,
    Vec<u8>,
    Vec<u8>,
    bool,
    Option<u64>,
    Option<u64>,
);
pub(crate) type WriteState = Arc<dyn Fn(StateWrite) -> HostFuture<u64> + Send + Sync>;
pub(crate) type LiveMetadata = (Vec<u8>, u64, Option<u64>, Option<u64>);
pub(crate) type OpenSubtree = Arc<dyn Fn(u64, Vec<u8>, Vec<u8>) -> CursorOwner + Send + Sync>;
pub(crate) type AdvanceSubtree =
    Arc<dyn Fn(CursorOwner) -> HostFuture<Option<(CursorOwner, LiveMetadata)>> + Send + Sync>;
pub(crate) type ExistsState = Arc<dyn Fn(u64, Vec<u8>, Vec<u8>) -> HostFuture<bool> + Send + Sync>;
pub(crate) type StateCallbacks = (WriteState, OpenSubtree, AdvanceSubtree, ExistsState);
