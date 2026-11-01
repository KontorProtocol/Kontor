use std::sync::Arc;

use super::session::SharedOwner;
use super::storage_rows::HostFuture;

pub(crate) const INPUT_CHUNK_BYTES: u32 = 64 * 1024;

// Row handles are meaningful only to the node adapter which issued them.
pub(crate) type InputRow = (SharedOwner, u64, u64, Option<u64>, Option<u64>);
pub(crate) type InputPoint =
    Arc<dyn Fn(u64, Vec<u8>) -> HostFuture<Option<InputRow>> + Send + Sync>;
pub(crate) type InputNext =
    Arc<dyn Fn(u64, Option<Vec<u8>>) -> HostFuture<Option<InputRow>> + Send + Sync>;
pub(crate) type InputChunk =
    Arc<dyn Fn(SharedOwner, bool, u64, u32) -> HostFuture<Vec<u8>> + Send + Sync>;
pub(crate) type InputCallbacks = (InputPoint, InputNext, InputChunk);
