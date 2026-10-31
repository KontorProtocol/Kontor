use std::sync::Arc;

use super::storage_aux::StorageFuture;
use super::storage_contracts::Address;

pub(crate) type ResultRecord = (
    (u64, u64, Option<u32>, Option<u32>, Option<u32>, u32),
    (String, u64, String, Option<String>),
    (Address, Option<String>, u64, Option<u64>),
);
pub(crate) type InspectIdentity = Arc<dyn Fn(String) -> StorageFuture<Option<u64>> + Send + Sync>;
pub(crate) type InspectResult =
    Arc<dyn Fn(String, u32, u32) -> StorageFuture<Option<ResultRecord>> + Send + Sync>;
pub(crate) type InspectionCallbacks = (InspectIdentity, InspectResult);
