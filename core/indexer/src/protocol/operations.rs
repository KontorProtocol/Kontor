use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use super::committee::Committee;
use super::execution::SelectionEnvelope;

pub(crate) type SessionOwner = Arc<dyn Any + Send + Sync>;
pub(crate) type OperationFuture<T> = Pin<Box<dyn Future<Output = Result<T, (u8, String)>> + Send>>;
pub(crate) type AddressEnvelope = (String, u64, u32);
// The boolean preserves deterministic classification; the text is P1's Debug
// rendering used by the public view API, rendered before leaving its graph.
pub(crate) type ViewOutcome = Result<String, (bool, String)>;
pub(crate) type ViewCall = Arc<
    dyn Fn(SessionOwner, SelectionEnvelope, AddressEnvelope, String) -> OperationFuture<ViewOutcome>
        + Send
        + Sync,
>;
pub(crate) type CommitteeCall =
    Arc<dyn Fn(SessionOwner, SelectionEnvelope) -> OperationFuture<Committee> + Send + Sync>;
