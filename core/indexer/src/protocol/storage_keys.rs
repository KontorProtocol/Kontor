use std::sync::Arc;

use super::storage_rows::{CursorOwner, HostFuture};

pub(crate) type KeyRange = (Vec<u8>, bool, Option<Vec<u8>>);
pub(crate) type OpenKeys = Arc<dyn Fn(u64, KeyRange, bool) -> CursorOwner + Send + Sync>;
pub(crate) type AdvanceKey =
    Arc<dyn Fn(CursorOwner) -> HostFuture<Option<(CursorOwner, Vec<u8>)>> + Send + Sync>;
pub(crate) type SeekKey =
    Arc<dyn Fn(CursorOwner, KeyRange) -> Result<CursorOwner, String> + Send + Sync>;
pub(crate) type KeyCallbacks = (OpenKeys, AdvanceKey, SeekKey);
