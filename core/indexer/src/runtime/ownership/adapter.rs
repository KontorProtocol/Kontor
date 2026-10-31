use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use anyhow::Result;
use libsql::Connection;

use crate::protocol::coordinator::selection::{ExecutionSelection, ExecutorVersion};

use super::{ChildContext, RootKeeper, RootState, TaskCompletion};

pub(crate) type SharedOwner = Arc<dyn Any + Send + Sync>;
pub(crate) type Payload = Box<dyn Any + Send>;
pub(crate) type HostError = (u8, String);

#[derive(Clone, Debug, thiserror::Error)]
#[error("host failure {tag}: {message}")]
pub(crate) struct HostFailure {
    pub(crate) tag: u8,
    pub(crate) message: String,
}

impl From<HostError> for HostFailure {
    fn from((tag, message): HostError) -> Self {
        if tag <= 2 {
            Self { tag, message }
        } else {
            Self {
                tag: 0,
                message: format!("unknown host failure tag {tag}: {message}"),
            }
        }
    }
}
pub(crate) type HostFuture<T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, HostError>> + Send>>;
pub(crate) type GuestCompletion = (bool, Payload);
pub(crate) type GuestFuture = Pin<Box<dyn Future<Output = GuestCompletion> + Send>>;
pub(crate) type GuestFactory = Box<dyn FnOnce(SharedOwner) -> GuestFuture + Send>;
pub(crate) type SubmitGuest =
    Arc<dyn Fn(SharedOwner, GuestFactory) -> HostFuture<GuestCompletion> + Send + Sync>;
pub(crate) type BlockingWork = Box<dyn FnOnce() -> Payload + Send>;
pub(crate) type SubmitBlocking =
    Arc<dyn Fn(SharedOwner, BlockingWork) -> HostFuture<Payload> + Send + Sync>;
pub(crate) type CheckCommit =
    Arc<dyn Fn(SharedOwner) -> std::result::Result<(), HostError> + Send + Sync>;
pub(crate) type ReportFailure =
    Arc<dyn Fn(SharedOwner, u8) -> std::result::Result<(), HostError> + Send + Sync>;

pub(crate) type SessionFuture = Pin<Box<dyn Future<Output = Result<ExecutorSession>> + Send>>;
pub(crate) type SessionFactory = Arc<dyn Fn(Connection) -> SessionFuture + Send + Sync>;
pub(crate) type SessionAction = Arc<dyn Fn(SharedOwner) -> HostFuture<()> + Send + Sync>;
pub(crate) type RootSettle = Arc<dyn Fn(SharedOwner, bool) -> HostFuture<()> + Send + Sync>;
pub(crate) type RootReset = Arc<dyn Fn(SharedOwner, bool, bool) -> HostFuture<()> + Send + Sync>;
pub(crate) type RootHookFactory = Arc<
    dyn Fn(ExecutionSelection, OwnerAdapter) -> std::result::Result<RootHooks, HostError>
        + Send
        + Sync,
>;
pub(crate) type RecycleHook = SessionAction;

#[derive(Clone)]
pub(crate) struct RootHooks {
    pub(crate) prepare: SessionAction,
    pub(crate) inspect_canonical_drain: SessionAction,
    pub(crate) settle: RootSettle,
    pub(crate) reset: RootReset,
}

#[derive(Clone)]
pub(crate) struct ExecutorSession {
    pub(crate) origin: ExecutorVersion,
    pub(crate) owner: SharedOwner,
    pub(crate) make_root: RootHookFactory,
    pub(crate) recycle: RecycleHook,
}

struct OwnerToken {
    keeper: Weak<RootKeeper>,
    context: ChildContext,
}

#[derive(Clone)]
pub(crate) struct OwnerAdapter {
    pub(crate) root: SharedOwner,
    pub(crate) submit_guest: SubmitGuest,
    pub(crate) submit_blocking: SubmitBlocking,
    pub(crate) check_commit: CheckCommit,
    pub(crate) report_failure: ReportFailure,
    pub(crate) fuel_yield_interval: Option<u64>,
}

impl OwnerAdapter {
    pub(super) fn new(keeper: &Arc<RootKeeper>, context: ChildContext) -> Self {
        let fuel_yield_interval = context.fuel_yield_interval();
        let root = token(keeper, context);
        let expected = Arc::downgrade(keeper);
        let guest_keeper = expected.clone();
        let submit_guest: SubmitGuest = Arc::new(move |parent, factory| {
            let guest_keeper = guest_keeper.clone();
            Box::pin(async move {
                let parent = validate(&guest_keeper, parent)?;
                let keeper = guest_keeper
                    .upgrade()
                    .ok_or_else(|| infrastructure("operation root expired"))?;
                parent
                    .run_linked_guest(move |child| {
                        let child_token = token(&keeper, child);
                        Box::pin(async move {
                            let (panicked, payload) = factory(child_token).await;
                            TaskCompletion::Linked(panicked, payload)
                        })
                    })
                    .await
                    .map_err(|error| infrastructure(error.to_string()))
            })
        });

        let blocking_keeper = expected.clone();
        let submit_blocking: SubmitBlocking = Arc::new(move |parent, work| {
            let blocking_keeper = blocking_keeper.clone();
            Box::pin(async move {
                let parent = validate(&blocking_keeper, parent)?;
                parent
                    .run_blocking(work)
                    .await
                    .map_err(|error| infrastructure(error.to_string()))
            })
        });

        let commit_keeper = expected.clone();
        let check_commit: CheckCommit = Arc::new(move |parent| {
            let parent = validate(&commit_keeper, parent)?;
            parent
                .ensure_commit_authorized()
                .map_err(|error| infrastructure(error.to_string()))
        });

        let report_failure: ReportFailure = Arc::new(move |parent, tag| {
            let _ = validate(&expected, parent)?;
            let keeper = expected
                .upgrade()
                .ok_or_else(|| infrastructure("operation root expired"))?;
            if !keeper.quarantine_before_commit() {
                return Err(infrastructure("operation root already committed"));
            }
            match tag {
                0..=2 => Ok(()),
                _ => Err(infrastructure("unknown host failure tag")),
            }
        });

        Self {
            root,
            submit_guest,
            submit_blocking,
            check_commit,
            report_failure,
            fuel_yield_interval,
        }
    }
}

fn token(keeper: &Arc<RootKeeper>, context: ChildContext) -> SharedOwner {
    Arc::new(OwnerToken {
        keeper: Arc::downgrade(keeper),
        context,
    })
}

fn validate(
    expected: &Weak<RootKeeper>,
    owner: SharedOwner,
) -> std::result::Result<ChildContext, HostError> {
    let keeper = expected
        .upgrade()
        .ok_or_else(|| infrastructure("operation root expired"))?;
    let token = owner.downcast::<OwnerToken>().map_err(|_| {
        keeper.quarantine_before_commit();
        misuse("owner capability has the wrong type")
    })?;
    let issued = token.keeper.upgrade();
    if !issued
        .as_ref()
        .is_some_and(|issued| Arc::ptr_eq(issued, &keeper))
        || token.context.task.root != keeper.id
        || !token.context.alive.load(Ordering::SeqCst)
    {
        keeper.quarantine_before_commit();
        return Err(misuse("owner capability is foreign or expired"));
    }
    if RootState::load(&keeper.state) == RootState::Complete {
        return Err(infrastructure("operation root already completed"));
    }
    Ok(token.context.clone())
}

fn infrastructure(message: impl Into<String>) -> HostError {
    (0, message.into())
}

fn misuse(message: impl Into<String>) -> HostError {
    (2, message.into())
}
