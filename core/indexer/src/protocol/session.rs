use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use super::execution::SelectionEnvelope;
use super::operations::{
    BeginUnitCall, CommitteeCall, ContractWitCall, InitializeCall, InspectCall, LifecycleCall,
    MaintenanceCall, RecognitionCall, TransactionCall, ViewCall,
};

pub(crate) type SharedOwner = Arc<dyn Any + Send + Sync>;
pub(crate) type Payload = Box<dyn Any + Send>;
pub(crate) type HostError = (u8, String);
pub(crate) type HostFuture<T> = Pin<Box<dyn Future<Output = Result<T, HostError>> + Send>>;
pub(crate) type GuestCompletion = (bool, Payload);
pub(crate) type GuestFuture = Pin<Box<dyn Future<Output = GuestCompletion> + Send>>;
pub(crate) type GuestFactory = Box<dyn FnOnce(SharedOwner) -> GuestFuture + Send>;
pub(crate) type SubmitGuest =
    Arc<dyn Fn(SharedOwner, GuestFactory) -> HostFuture<GuestCompletion> + Send + Sync>;
pub(crate) type BlockingWork = Box<dyn FnOnce() -> Payload + Send>;
pub(crate) type SubmitBlocking =
    Arc<dyn Fn(SharedOwner, BlockingWork) -> HostFuture<Payload> + Send + Sync>;
pub(crate) type CheckCommit = Arc<dyn Fn(SharedOwner) -> Result<(), HostError> + Send + Sync>;
pub(crate) type ReportFailure = Arc<dyn Fn(SharedOwner, u8) -> Result<(), HostError> + Send + Sync>;
pub(crate) type SessionAction = Arc<dyn Fn(SharedOwner) -> HostFuture<()> + Send + Sync>;
pub(crate) type RootSettle = Arc<dyn Fn(SharedOwner, bool) -> HostFuture<()> + Send + Sync>;
pub(crate) type RootReset = Arc<dyn Fn(SharedOwner, bool, bool) -> HostFuture<()> + Send + Sync>;
pub(crate) type SelectionSource = Arc<dyn Fn() -> HostFuture<SelectionEnvelope> + Send + Sync>;
pub(crate) type RootHooks = (SessionAction, SessionAction, RootSettle, RootReset);
pub(crate) type OwnerCapabilities = (
    SharedOwner,
    SubmitGuest,
    SubmitBlocking,
    CheckCommit,
    ReportFailure,
    Option<u64>,
);
pub(crate) type RootFactory =
    Arc<dyn Fn(OwnerCapabilities, bool, SelectionSource) -> RootHooks + Send + Sync>;
pub(crate) type Operations = (
    InitializeCall,
    InspectCall,
    MaintenanceCall,
    RecognitionCall,
    TransactionCall,
    BeginUnitCall,
    LifecycleCall,
    ContractWitCall,
    ViewCall,
    CommitteeCall,
);

// Only structural standard-library types cross the independently built graphs.
// Each graph wraps these values in its own nominal types after receiving them.
pub(crate) type SessionExports = (Operations, SharedOwner, RootFactory, SessionAction);
