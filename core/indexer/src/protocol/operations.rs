use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use super::committee::Committee;
use super::execution::SelectionEnvelope;

pub(crate) type SessionOwner = Arc<dyn Any + Send + Sync>;
pub(crate) type OperationFuture<T> = Pin<Box<dyn Future<Output = Result<T, (u8, String)>> + Send>>;
pub(crate) type AddressEnvelope = (String, u64, u32);
// User, system and deposit fuel are distinct persisted accounting categories.
pub(crate) type UsageEnvelope = (u64, u64, u64);
// The opaque transaction is interpreted only by its originating executor.
// Metadata is txid, batchability, then (Bitcoin input index, operation count).
pub(crate) type RecognizedEnvelope = (SessionOwner, [u8; 32], bool, Vec<(u32, u64)>);
pub(crate) type RecognitionCall = Arc<
    dyn Fn(
            SelectionEnvelope,
            Vec<u8>,
        ) -> Result<Result<Option<RecognizedEnvelope>, String>, (u8, String)>
        + Send
        + Sync,
>;
pub(crate) type TransactionOutcome = (UsageEnvelope, Vec<Vec<Option<String>>>);
pub(crate) type TransactionCall = Arc<
    dyn Fn(
            SessionOwner,
            SelectionEnvelope,
            SessionOwner,
            u32,
            u64,
        ) -> OperationFuture<TransactionOutcome>
        + Send
        + Sync,
>;
pub(crate) type LifecycleCall =
    Arc<dyn Fn(SessionOwner, SelectionEnvelope) -> OperationFuture<UsageEnvelope> + Send + Sync>;
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

pub(crate) type InspectCall = Arc<
    dyn Fn(SessionOwner, SelectionEnvelope, SessionOwner, u32) -> OperationFuture<Vec<u8>>
        + Send
        + Sync,
>;
pub(crate) type MaintenanceCall =
    Arc<dyn Fn(SessionOwner, SelectionEnvelope) -> OperationFuture<()> + Send + Sync>;

pub(crate) type BeginUnitCall =
    Arc<dyn Fn(SessionOwner, SelectionEnvelope) -> OperationFuture<()> + Send + Sync>;

pub(crate) type ContractWitCall = Arc<
    dyn Fn(SessionOwner, SelectionEnvelope, AddressEnvelope) -> OperationFuture<Option<String>>
        + Send
        + Sync,
>;
