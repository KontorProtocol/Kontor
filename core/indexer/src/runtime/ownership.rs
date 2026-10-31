use std::any::Any;
use std::collections::HashMap;
use std::future::{Future, pending};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use deadpool::managed::Object;
use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use metrics::gauge;
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::{AbortHandle, Id, JoinHandle, JoinSet};
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;
use wasmtime::component::ResourceTable;
#[cfg(test)]
use wasmtime::component::Val;

use super::Runtime;
#[cfg(test)]
use super::bundle_session::BundleSession;
use super::call::GuestCompletion;
use super::invocation::InvocationBudget;
#[cfg(test)]
use super::invocation::InvocationStore;
use super::pool::Manager;
use super::pool::{LinkedManager, LinkedSession};
#[cfg(test)]
use super::storage::BlockingGate;
use crate::protocol::coordinator::selection::ExecutionSelection;
use adapter::{OwnerAdapter, Payload, RootHooks, SharedOwner};

pub(crate) mod adapter;

const API_DRAIN_LIMIT: Duration = Duration::from_secs(5);
const NODE_ADMISSION_CAPACITY: usize = 64;
const API_FUEL_YIELD_INTERVAL: u64 = 100_000;

#[cfg(test)]
#[derive(Default)]
pub(crate) struct AsyncGate {
    pub(crate) entered: AtomicBool,
    pub(crate) entries: AtomicUsize,
    release: CancellationToken,
}

#[cfg(test)]
impl AsyncGate {
    pub(crate) async fn wait(&self) {
        self.entered.store(true, Ordering::SeqCst);
        self.entries.fetch_add(1, Ordering::SeqCst);
        self.release.cancelled().await;
    }

    pub(crate) fn release(&self) {
        wake_owner(&self.release);
    }
}

// These private tokens only wake the owner supervisor. Process shutdown remains
// controlled by stopper::Shutdown.
#[allow(clippy::disallowed_methods)]
fn wake_owner(token: &CancellationToken) {
    token.cancel();
}

#[derive(Clone, Copy)]
enum RootKind {
    Api,
    Canonical,
    Simulation,
}

impl RootKind {
    fn fuel_yield_interval(self) -> Option<u64> {
        match self {
            Self::Api => Some(API_FUEL_YIELD_INTERVAL),
            Self::Canonical | Self::Simulation => None,
        }
    }
}

#[derive(Default)]
struct BlockingRegistry {
    next_id: AtomicU64,
    gate: Arc<std::sync::Mutex<BlockingGateState>>,
    panicked: Arc<AtomicBool>,
}

#[derive(Default)]
struct BlockingGateState {
    closed: bool,
    active: HashMap<u64, Arc<BlockingState>>,
}

struct BlockingState {
    done: AtomicBool,
    notify: tokio::sync::Notify,
}

impl BlockingRegistry {
    fn panicked(&self) -> bool {
        self.panicked.load(Ordering::SeqCst)
    }

    async fn wait_all(&self) {
        loop {
            let entries = self
                .gate
                .lock()
                .expect("blocking registry poisoned")
                .active
                .values()
                .cloned()
                .collect::<Vec<_>>();
            if entries.is_empty() {
                return;
            }
            for entry in entries {
                while !entry.done.load(Ordering::SeqCst) {
                    entry.notify.notified().await;
                }
            }
        }
    }

    fn spawn<F, T>(
        &self,
        work: F,
    ) -> Result<oneshot::Receiver<std::result::Result<T, tokio::task::JoinError>>>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let state = Arc::new(BlockingState {
            done: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        });
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        {
            let mut gate = self.gate.lock().expect("blocking registry poisoned");
            ensure!(
                !gate.closed,
                "blocking registration closed after root drain"
            );
            gate.active.insert(id, state.clone());
        }
        let (sender, receiver) = oneshot::channel();
        let task = tokio::task::spawn_blocking(work);
        let gate = self.gate.clone();
        let panicked = self.panicked.clone();
        tokio::spawn(async move {
            let result = task.await;
            // A dropped receiver must not erase the root's panic evidence.
            if result.as_ref().is_err_and(tokio::task::JoinError::is_panic) {
                panicked.store(true, Ordering::SeqCst);
            }
            let _ = sender.send(result);
            gate.lock()
                .expect("blocking registry poisoned")
                .active
                .remove(&id);
            state.done.store(true, Ordering::SeqCst);
            state.notify.notify_one();
        });
        Ok(receiver)
    }

    fn close_registration(&self) {
        self.gate.lock().expect("blocking registry poisoned").closed = true;
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct RootId(u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TaskId {
    root: RootId,
    local: u64,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootState {
    Running = 0,
    Closing = 1,
    Committing = 2,
    Complete = 3,
    Quarantined = 4,
}

impl RootState {
    fn load(state: &AtomicU8) -> Self {
        match state.load(Ordering::SeqCst) {
            0 => Self::Running,
            1 => Self::Closing,
            2 => Self::Committing,
            3 => Self::Complete,
            4 => Self::Quarantined,
            _ => unreachable!("invalid root state"),
        }
    }
}

struct SlotLease(Arc<AtomicBool>);

impl Drop for SlotLease {
    fn drop(&mut self) {
        assert!(
            self.0.swap(false, Ordering::SeqCst),
            "child slot released twice"
        );
    }
}

struct GuestDelivery {
    completion: TaskCompletion,
    slot: SlotLease,
}

enum TaskCompletion {
    Local(GuestCompletion),
    Linked(bool, Box<dyn Any + Send>),
}

impl TaskCompletion {
    fn host_panicked(&self) -> bool {
        match self {
            Self::Local(completion) => completion.host_panicked,
            Self::Linked(panicked, _) => *panicked,
        }
    }
}

type GuestFuture = Pin<Box<dyn Future<Output = TaskCompletion> + Send + 'static>>;

struct Admission {
    id: TaskId,
    parent: TaskId,
    depth: u32,
    future: GuestFuture,
    completion: oneshot::Sender<GuestDelivery>,
    slot: SlotLease,
    child_alive: Arc<AtomicBool>,
}

#[derive(Clone)]
pub(super) struct ChildContext {
    task: TaskId,
    depth: u32,
    kind: RootKind,
    sender: mpsc::Sender<Admission>,
    next_task: Arc<AtomicU64>,
    slot: Arc<AtomicBool>,
    state: Arc<AtomicU8>,
    blocking: Arc<BlockingRegistry>,
    panic_seen: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
}

impl ChildContext {
    fn root(
        root: RootId,
        kind: RootKind,
        sender: mpsc::Sender<Admission>,
        state: Arc<AtomicU8>,
        blocking: Arc<BlockingRegistry>,
        panic_seen: Arc<AtomicBool>,
    ) -> Self {
        Self {
            task: TaskId { root, local: 0 },
            depth: 0,
            kind,
            sender,
            next_task: Arc::new(AtomicU64::new(1)),
            slot: Arc::new(AtomicBool::new(false)),
            state,
            blocking,
            panic_seen,
            alive: Arc::new(AtomicBool::new(true)),
        }
    }

    pub(super) fn fuel_yield_interval(&self) -> Option<u64> {
        self.kind.fuel_yield_interval()
    }

    pub(super) async fn run_guest<F, Fut>(&self, make_future: F) -> Result<GuestCompletion>
    where
        F: FnOnce(ChildContext) -> Fut,
        Fut: Future<Output = GuestCompletion> + Send + 'static,
    {
        match self
            .run_admission(move |child| {
                let future = make_future(child);
                Box::pin(async move { TaskCompletion::Local(future.await) })
            })
            .await?
        {
            TaskCompletion::Local(completion) => Ok(completion),
            TaskCompletion::Linked(..) => Err(anyhow!("local guest received linked completion")),
        }
    }

    async fn run_linked_guest<F>(&self, make_future: F) -> Result<(bool, Box<dyn Any + Send>)>
    where
        F: FnOnce(ChildContext) -> GuestFuture,
    {
        match self.run_admission(make_future).await? {
            TaskCompletion::Linked(panicked, payload) => Ok((panicked, payload)),
            TaskCompletion::Local(..) => Err(anyhow!("linked guest received local completion")),
        }
    }

    async fn run_admission<F>(&self, make_future: F) -> Result<TaskCompletion>
    where
        F: FnOnce(ChildContext) -> GuestFuture,
    {
        if RootState::load(&self.state) != RootState::Running {
            return self.closed_or_infrastructure().await;
        }
        ensure!(
            self.alive.load(Ordering::SeqCst),
            "guest parent capability expired"
        );
        ensure!(
            !self.panic_seen.load(Ordering::SeqCst),
            "host panic already observed in operation root"
        );
        if self
            .slot
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            if RootState::load(&self.state) != RootState::Running {
                return self.closed_or_infrastructure().await;
            }
            return Err(anyhow!("parent already has an outstanding guest child"));
        }
        let slot = SlotLease(self.slot.clone());
        let permit = match self.sender.reserve().await {
            Ok(permit) => permit,
            Err(_) => {
                drop(slot);
                return self.closed_or_infrastructure().await;
            }
        };
        if RootState::load(&self.state) != RootState::Running {
            drop(permit);
            drop(slot);
            return self.closed_or_infrastructure().await;
        }
        let local = self.next_task.fetch_add(1, Ordering::SeqCst);
        let id = TaskId {
            root: self.task.root,
            local,
        };
        let child = Self {
            task: id,
            depth: self.depth + 1,
            kind: self.kind,
            sender: self.sender.clone(),
            next_task: self.next_task.clone(),
            slot: Arc::new(AtomicBool::new(false)),
            state: self.state.clone(),
            blocking: self.blocking.clone(),
            panic_seen: self.panic_seen.clone(),
            alive: Arc::new(AtomicBool::new(true)),
        };
        let child_alive = child.alive.clone();
        let (completion, receiver) = oneshot::channel();
        permit.send(Admission {
            id,
            parent: self.task,
            depth: child.depth,
            future: make_future(child),
            completion,
            slot,
            child_alive,
        });
        match receiver.await {
            Ok(delivery) if RootState::load(&self.state) == RootState::Running => {
                let GuestDelivery { completion, slot } = delivery;
                drop(slot);
                Ok(completion)
            }
            Ok(delivery) => {
                drop(delivery);
                self.closed_or_infrastructure().await
            }
            Err(_) => self.closed_or_infrastructure().await,
        }
    }

    pub(super) async fn run_blocking<F, T>(&self, work: F) -> Result<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        if RootState::load(&self.state) != RootState::Running {
            return self.closed_or_infrastructure().await;
        }
        ensure!(
            !self.panic_seen.load(Ordering::SeqCst),
            "host panic already observed in operation root"
        );
        let receiver = match self.blocking.spawn(work) {
            Ok(receiver) => receiver,
            Err(_) => return self.closed_or_infrastructure().await,
        };
        receiver
            .await
            .context("tracked blocking watcher failed")?
            .context("tracked blocking work failed")
    }

    async fn closed_or_infrastructure<T>(&self) -> Result<T> {
        if RootState::load(&self.state) != RootState::Running {
            if matches!(self.kind, RootKind::Canonical | RootKind::Simulation) {
                return Err(anyhow!("canonical guest child closed; root quarantined"));
            }
            // A closing parent must not resume payment or savepoint settlement.
            pending().await
        }
        Err(anyhow!("guest admission closed without root cancellation"))
    }

    pub(super) fn ensure_commit_authorized(&self) -> Result<()> {
        ensure!(
            matches!(
                RootState::load(&self.state),
                RootState::Running | RootState::Committing
            ) && !self.blocking.panicked()
                && !self.panic_seen.load(Ordering::SeqCst),
            "operation root cannot commit after cancellation or quarantine"
        );
        Ok(())
    }
}

enum RootAuthority {
    Pooled(Object<Manager>),
    Stateful(Runtime),
    LinkedPooled(Object<LinkedManager>),
    LinkedStateful(LinkedSession),
}

impl Deref for RootAuthority {
    type Target = Runtime;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Pooled(object) => object,
            Self::Stateful(runtime) => runtime,
            Self::LinkedPooled(_) | Self::LinkedStateful(_) => {
                unreachable!("linked authority cannot be dereferenced as a runtime")
            }
        }
    }
}

impl DerefMut for RootAuthority {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Pooled(object) => object,
            Self::Stateful(runtime) => runtime,
            Self::LinkedPooled(_) | Self::LinkedStateful(_) => {
                unreachable!("linked authority cannot be dereferenced as a runtime")
            }
        }
    }
}

struct StatefulSessionInner {
    runtime: std::sync::Mutex<Option<Runtime>>,
    available: Notify,
    failed: AtomicBool,
}

#[derive(Clone)]
pub(crate) struct StatefulSession(Arc<StatefulSessionInner>);

#[derive(Clone)]
pub(crate) struct OwnedRuntimeSession {
    service: OwnerService,
    session: StatefulSession,
}

impl OwnedRuntimeSession {
    #[cfg(test)]
    pub(crate) fn new(runtime: Runtime) -> Self {
        Self::with_service(runtime, OwnerService::new())
    }

    pub(crate) fn with_service(runtime: Runtime, service: OwnerService) -> Self {
        let session = service.stateful_session(runtime);
        Self { service, session }
    }

    pub(crate) async fn run<T, F>(&self, commit: bool, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(&'a mut Runtime) -> BoxFuture<'a, Result<T>> + Send + 'static,
    {
        let mut handle = self
            .service
            .start_stateful(&self.session, move |runtime| {
                Box::pin(async move {
                    let value = operation(runtime).await?;
                    Ok(RootOutcome { value, commit })
                })
            })
            .await?;
        handle.result().await
    }
}

struct SessionCheckout {
    session: StatefulSession,
    runtime: Option<Runtime>,
}

impl Drop for SessionCheckout {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            self.session.return_runtime(runtime);
        }
    }
}

impl StatefulSession {
    fn new(runtime: Runtime) -> Self {
        Self(Arc::new(StatefulSessionInner {
            runtime: std::sync::Mutex::new(Some(runtime)),
            available: Notify::new(),
            failed: AtomicBool::new(false),
        }))
    }

    async fn checkout(&self) -> Result<SessionCheckout> {
        loop {
            let available = self.0.available.notified();
            tokio::pin!(available);
            available.as_mut().enable();
            if self.0.failed.load(Ordering::SeqCst) {
                return Err(anyhow!("stateful runtime session is quarantined"));
            }
            if let Some(runtime) = self
                .0
                .runtime
                .lock()
                .expect("stateful runtime lock poisoned")
                .take()
            {
                return Ok(SessionCheckout {
                    session: self.clone(),
                    runtime: Some(runtime),
                });
            }
            available.await;
        }
    }

    fn return_runtime(&self, runtime: Runtime) {
        let previous = self
            .0
            .runtime
            .lock()
            .expect("stateful runtime lock poisoned")
            .replace(runtime);
        assert!(previous.is_none(), "stateful runtime returned twice");
        self.0.available.notify_one();
    }

    fn quarantine(&self) {
        self.0.failed.store(true, Ordering::SeqCst);
        self.0.available.notify_waiters();
    }
}

struct LinkedStatefulSessionInner {
    session: std::sync::Mutex<Option<LinkedSession>>,
    available: Notify,
    failed: AtomicBool,
}

#[derive(Clone)]
pub(crate) struct LinkedStatefulSession(Arc<LinkedStatefulSessionInner>);

struct LinkedSessionCheckout {
    session: LinkedStatefulSession,
    value: Option<LinkedSession>,
}

impl Drop for LinkedSessionCheckout {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            self.session.return_session(value);
        }
    }
}

impl LinkedStatefulSession {
    pub(crate) fn new(session: LinkedSession) -> Self {
        Self(Arc::new(LinkedStatefulSessionInner {
            session: std::sync::Mutex::new(Some(session)),
            available: Notify::new(),
            failed: AtomicBool::new(false),
        }))
    }

    async fn checkout(&self) -> Result<LinkedSessionCheckout> {
        loop {
            let available = self.0.available.notified();
            tokio::pin!(available);
            available.as_mut().enable();
            ensure!(
                !self.0.failed.load(Ordering::SeqCst),
                "linked stateful session is quarantined"
            );
            if let Some(value) = self
                .0
                .session
                .lock()
                .expect("linked session lock poisoned")
                .take()
            {
                return Ok(LinkedSessionCheckout {
                    session: self.clone(),
                    value: Some(value),
                });
            }
            available.await;
        }
    }

    fn return_session(&self, value: LinkedSession) {
        let previous = self
            .0
            .session
            .lock()
            .expect("linked session lock poisoned")
            .replace(value);
        assert!(previous.is_none(), "linked stateful session returned twice");
        self.0.available.notify_one();
    }

    fn quarantine(&self) {
        self.0.failed.store(true, Ordering::SeqCst);
        self.0.available.notify_waiters();
    }
}

struct RootKeeper {
    id: RootId,
    linked_hooks: Mutex<Option<RootHooks>>,
    authority: Mutex<Option<RootAuthority>>,
    state: Arc<AtomicU8>,
    closing_at: Arc<std::sync::Mutex<Option<Instant>>>,
    cancellation: CancellationToken,
    blocking: Arc<BlockingRegistry>,
    caught_host_panic: Arc<AtomicBool>,
    quiescent: AtomicBool,
    _capacity: OwnedSemaphorePermit,
}

impl RootKeeper {
    fn new(id: RootId, authority: Object<Manager>, capacity: OwnedSemaphorePermit) -> Self {
        Self::with_authority(id, RootAuthority::Pooled(authority), capacity)
    }

    fn new_stateful(id: RootId, authority: Runtime, capacity: OwnedSemaphorePermit) -> Self {
        Self::with_authority(id, RootAuthority::Stateful(authority), capacity)
    }

    fn new_linked_pooled(
        id: RootId,
        authority: Object<LinkedManager>,
        capacity: OwnedSemaphorePermit,
    ) -> Self {
        Self::with_authority(id, RootAuthority::LinkedPooled(authority), capacity)
    }

    fn new_linked_stateful(
        id: RootId,
        authority: LinkedSession,
        capacity: OwnedSemaphorePermit,
    ) -> Self {
        Self::with_authority(id, RootAuthority::LinkedStateful(authority), capacity)
    }

    fn with_authority(
        id: RootId,
        authority: RootAuthority,
        capacity: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            id,
            linked_hooks: Mutex::new(None),
            authority: Mutex::new(Some(authority)),
            state: Arc::new(AtomicU8::new(RootState::Running as u8)),
            closing_at: Arc::new(std::sync::Mutex::new(None)),
            cancellation: CancellationToken::new(),
            blocking: Arc::new(BlockingRegistry::default()),
            caught_host_panic: Arc::new(AtomicBool::new(false)),
            quiescent: AtomicBool::new(false),
            _capacity: capacity,
        }
    }

    fn close(&self) {
        let mut closing_at = self.closing_at.lock().expect("root closing clock poisoned");
        if self
            .state
            .compare_exchange(
                RootState::Running as u8,
                RootState::Closing as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            *closing_at = Some(Instant::now());
            wake_owner(&self.cancellation);
        }
    }

    fn quarantine(&self) {
        let mut closing_at = self.closing_at.lock().expect("root closing clock poisoned");
        if closing_at.is_none() {
            *closing_at = Some(Instant::now());
        }
        self.state
            .store(RootState::Quarantined as u8, Ordering::SeqCst);
        wake_owner(&self.cancellation);
    }

    fn quarantine_before_commit(&self) -> bool {
        let mut closing_at = self.closing_at.lock().expect("root closing clock poisoned");
        loop {
            let current = RootState::load(&self.state);
            match current {
                RootState::Running | RootState::Closing => {
                    if self
                        .state
                        .compare_exchange(
                            current as u8,
                            RootState::Quarantined as u8,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok()
                    {
                        if closing_at.is_none() {
                            *closing_at = Some(Instant::now());
                        }
                        wake_owner(&self.cancellation);
                        return true;
                    }
                }
                RootState::Quarantined => return true,
                RootState::Committing | RootState::Complete => return false,
            }
        }
    }

    fn install_linked_hooks(
        &self,
        selection: ExecutionSelection,
        adapter: OwnerAdapter,
    ) -> Result<()> {
        let authority = self
            .authority
            .try_lock()
            .expect("new root authority is uncontended");
        let session = match authority.as_ref().expect("root authority retained") {
            RootAuthority::LinkedPooled(object) => &**object,
            RootAuthority::LinkedStateful(session) => session,
            RootAuthority::Pooled(_) | RootAuthority::Stateful(_) => {
                return Err(anyhow!("linked hooks require a linked session"));
            }
        };
        ensure!(
            session.origin() == selection.version(),
            "executor session does not match selection"
        );
        let hooks = (session.executor.make_root)(selection, adapter)
            .map_err(adapter::HostFailure::from)
            .context("executor root hook construction failed")?;
        *self
            .linked_hooks
            .try_lock()
            .expect("new root hooks are uncontended") = Some(hooks);
        Ok(())
    }

    async fn linked_parts(&self) -> Result<(SharedOwner, RootHooks)> {
        let authority = self.authority.lock().await;
        let owner = match authority.as_ref().expect("root authority retained") {
            RootAuthority::LinkedPooled(object) => object.executor.owner.clone(),
            RootAuthority::LinkedStateful(session) => session.executor.owner.clone(),
            RootAuthority::Pooled(_) | RootAuthority::Stateful(_) => {
                return Err(anyhow!("root has no linked executor"));
            }
        };
        let hooks = self
            .linked_hooks
            .lock()
            .await
            .clone()
            .context("linked root hooks missing")?;
        Ok((owner, hooks))
    }
}

impl Drop for RootKeeper {
    fn drop(&mut self) {
        if RootState::load(&self.state) != RootState::Quarantined {
            return;
        }
        self.linked_hooks.get_mut().take();
        let object = self
            .authority
            .get_mut()
            .take()
            .expect("quarantined root authority retained");
        if self.quiescent.load(Ordering::SeqCst) {
            match object {
                RootAuthority::Pooled(object) => drop(Object::take(object)),
                RootAuthority::Stateful(runtime) => drop(runtime),
                RootAuthority::LinkedPooled(object) => drop(Object::take(object)),
                RootAuthority::LinkedStateful(session) => drop(session),
            }
        } else {
            // The last keeper may disappear after a supervisor failure while
            // detached guest work still has a cloned connection.
            std::mem::forget(object);
            #[cfg(not(test))]
            std::process::abort();
        }
    }
}

struct OwnerRegistry {
    next_root: AtomicU64,
    capacity: Arc<Semaphore>,
    roots: Mutex<HashMap<RootId, Arc<RootKeeper>>>,
    fatal: AtomicBool,
    #[cfg(test)]
    startup_compile_gate: std::sync::Mutex<Option<Arc<BlockingGate>>>,
    #[cfg(test)]
    supervisor_panic_after_root_entered: std::sync::Mutex<Option<Arc<AsyncGate>>>,
    #[cfg(test)]
    canonical_release_gate: std::sync::Mutex<Option<Arc<AsyncGate>>>,
}

impl Default for OwnerRegistry {
    fn default() -> Self {
        Self {
            next_root: AtomicU64::new(0),
            capacity: Arc::new(Semaphore::new(NODE_ADMISSION_CAPACITY)),
            roots: Mutex::new(HashMap::new()),
            fatal: AtomicBool::new(false),
            #[cfg(test)]
            startup_compile_gate: std::sync::Mutex::new(None),
            #[cfg(test)]
            supervisor_panic_after_root_entered: std::sync::Mutex::new(None),
            #[cfg(test)]
            canonical_release_gate: std::sync::Mutex::new(None),
        }
    }
}

type RootStart = Box<dyn FnOnce() -> BoxFuture<'static, ()> + Send>;

#[derive(Clone)]
pub struct OwnerService {
    registry: Arc<OwnerRegistry>,
    admission: mpsc::Sender<RootStart>,
    shutdown: CancellationToken,
    driver: Arc<std::sync::Mutex<Option<JoinHandle<Result<()>>>>>,
}

pub(crate) struct RootOutcome<T> {
    pub value: T,
    pub commit: bool,
}

pub(crate) type LinkedOperation =
    Box<dyn FnOnce(SharedOwner, OwnerAdapter) -> adapter::HostFuture<(Payload, bool)> + Send>;

pub(crate) struct OwnedRootHandle<T> {
    state: Arc<AtomicU8>,
    closing_at: Arc<std::sync::Mutex<Option<Instant>>>,
    cancellation: CancellationToken,
    result: oneshot::Receiver<Result<T>>,
}

pub(crate) struct CanonicalRootLease {
    keeper: Arc<RootKeeper>,
    registry: Arc<OwnerRegistry>,
    finish: Option<oneshot::Sender<()>>,
    drained: oneshot::Receiver<Result<()>>,
    complete: bool,
}

pub(crate) struct LinkedCanonicalRootLease {
    keeper: Arc<RootKeeper>,
    registry: Arc<OwnerRegistry>,
    adapter: OwnerAdapter,
    root_alive: Arc<AtomicBool>,
    finish: Option<oneshot::Sender<()>>,
    drained: oneshot::Receiver<Result<bool>>,
    settlement_signal: Option<oneshot::Sender<(bool, oneshot::Sender<Result<()>>)>>,
    drained_success: bool,
    requires_settlement: bool,
    settled: bool,
    settlement_in_flight: bool,
    complete_signal: Option<oneshot::Sender<()>>,
    released_signal: Option<oneshot::Sender<()>>,
    completed: Option<oneshot::Receiver<Result<()>>>,
    complete: bool,
}

impl LinkedCanonicalRootLease {
    pub(crate) fn adapter(&self) -> OwnerAdapter {
        self.adapter.clone()
    }

    pub(crate) async fn drain(&mut self) -> Result<()> {
        self.finish
            .take()
            .context("canonical root already drained")?
            .send(())
            .map_err(|_| anyhow!("canonical root supervisor disappeared"))?;
        self.requires_settlement = (&mut self.drained)
            .await
            .context("canonical root supervisor disappeared before drain")??;
        self.root_alive.store(false, Ordering::SeqCst);
        self.drained_success = true;
        Ok(())
    }

    pub(crate) async fn settle(&mut self, commit: bool) -> Result<()> {
        ensure!(
            self.drained_success,
            "canonical settlement requires a drained root"
        );
        ensure!(
            self.requires_settlement,
            "canonical root has no transaction to settle"
        );
        ensure!(
            !self.settlement_in_flight,
            "canonical settlement is already running"
        );
        let signal = self
            .settlement_signal
            .take()
            .context("canonical settlement already requested")?;
        let (reply, result) = oneshot::channel();
        self.settlement_in_flight = true;
        signal
            .send((commit, reply))
            .map_err(|_| anyhow!("canonical settlement supervisor disappeared"))?;
        result
            .await
            .context("canonical settlement supervisor disappeared")??;
        self.settlement_in_flight = false;
        self.settled = true;
        Ok(())
    }

    pub(crate) async fn complete(mut self) -> Result<()> {
        ensure!(
            self.drained_success,
            "canonical completion requires a drained root"
        );
        ensure!(
            !self.settlement_in_flight,
            "canonical settlement has not finished"
        );
        ensure!(
            !self.requires_settlement || self.settled,
            "canonical transaction has not been settled"
        );
        ensure!(
            RootState::load(&self.keeper.state) == RootState::Committing,
            "canonical root was not drained"
        );
        self.complete_signal
            .take()
            .context("canonical completion already requested")?
            .send(())
            .map_err(|_| anyhow!("canonical completion supervisor disappeared"))?;
        let completed = self
            .completed
            .take()
            .context("canonical completion receiver missing")?;
        let released = self
            .released_signal
            .take()
            .context("canonical release sender missing")?;
        self.complete = true;
        drop(self);
        let _ = released.send(());
        completed
            .await
            .context("canonical completion supervisor disappeared")?
    }
}

impl Drop for LinkedCanonicalRootLease {
    fn drop(&mut self) {
        if !self.complete {
            self.keeper.quarantine();
            self.registry.fatal.store(true, Ordering::SeqCst);
            self.registry.capacity.close();
        }
    }
}

impl CanonicalRootLease {
    pub(crate) async fn drain(&mut self, runtime: &Runtime) -> Result<()> {
        self.finish
            .take()
            .context("canonical root already drained")?
            .send(())
            .map_err(|_| anyhow!("canonical root supervisor disappeared"))?;
        (&mut self.drained)
            .await
            .context("canonical root supervisor disappeared before drain")??;
        if !runtime.stack.is_empty().await
            || runtime
                .invocation_budget
                .as_ref()
                .is_some_and(|budget| budget.live() != 0)
            || runtime.store_table_owners.as_ref().is_some_and(|owners| {
                owners
                    .lock()
                    .expect("store table tracker poisoned")
                    .iter()
                    .any(|owner| owner.strong_count() != 0)
            })
            || Arc::strong_count(&runtime.table) != 2
        {
            return Err(anyhow!("canonical root retains a guest Store or stack"));
        }
        Ok(())
    }

    pub(crate) async fn complete(mut self, runtime: &mut Runtime) -> Result<()> {
        if RootState::load(&self.keeper.state) != RootState::Committing {
            return Err(anyhow!("canonical root was not drained"));
        }
        runtime.ownership = None;
        runtime.storage.ownership = None;
        runtime.bundle_owner = None;
        runtime.storage.bundle_owner = None;
        runtime.invocation_budget = None;
        runtime.store_table_owners = None;
        *runtime.table.lock().await = ResourceTable::new();
        self.keeper.quiescent.store(true, Ordering::SeqCst);
        self.keeper
            .state
            .store(RootState::Complete as u8, Ordering::SeqCst);
        self.registry.roots.lock().await.remove(&self.keeper.id);
        self.complete = true;
        Ok(())
    }
}

impl Drop for CanonicalRootLease {
    fn drop(&mut self) {
        if !self.complete {
            self.keeper.quarantine();
            self.registry.fatal.store(true, Ordering::SeqCst);
            self.registry.capacity.close();
        }
    }
}

impl<T> OwnedRootHandle<T> {
    pub(crate) async fn result(&mut self) -> Result<T> {
        (&mut self.result)
            .await
            .context("operation owner disappeared before delivering a result")?
    }
}

impl<T> Drop for OwnedRootHandle<T> {
    fn drop(&mut self) {
        let mut closing_at = self.closing_at.lock().expect("root closing clock poisoned");
        if self
            .state
            .compare_exchange(
                RootState::Running as u8,
                RootState::Closing as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            *closing_at = Some(Instant::now());
            wake_owner(&self.cancellation);
        }
    }
}

struct RunningChild {
    parent: TaskId,
    depth: u32,
    abort: AbortHandle,
    completion: oneshot::Sender<GuestDelivery>,
    slot: SlotLease,
    child_alive: Arc<AtomicBool>,
}

#[derive(Clone)]
enum ReturnTo {
    Legacy(StatefulSession),
    Linked(LinkedStatefulSession),
}

impl ReturnTo {
    fn quarantine(&self) {
        match self {
            Self::Legacy(session) => session.quarantine(),
            Self::Linked(session) => session.quarantine(),
        }
    }
}

async fn run_legacy_root<T, F>(
    keeper: Arc<RootKeeper>,
    context: ChildContext,
    operation: F,
) -> Result<RootOutcome<T>>
where
    F: for<'a> FnOnce(&'a mut Runtime) -> BoxFuture<'a, Result<RootOutcome<T>>> + Send + 'static,
{
    ensure!(
        RootState::load(&keeper.state) == RootState::Running,
        "root cancelled before execution"
    );
    let mut authority = keeper.authority.lock().await;
    let runtime: &mut Runtime = authority.as_mut().expect("root authority retained");
    ensure!(
        runtime.bundle_owner.is_none() && runtime.storage.bundle_owner.is_none(),
        "legacy root cannot replace a linked ownership context"
    );
    runtime.invocation_budget = Some(Arc::new(InvocationBudget::default()));
    runtime.store_table_owners = Some(Arc::new(std::sync::Mutex::new(Vec::new())));
    runtime.storage.ownership = Some(context.clone());
    runtime.ownership = Some(context);
    runtime.storage.savepoint().await?;
    operation(runtime).await
}

async fn run_linked_root(
    keeper: Arc<RootKeeper>,
    adapter: OwnerAdapter,
    operation: LinkedOperation,
) -> Result<RootOutcome<Payload>> {
    ensure!(
        RootState::load(&keeper.state) == RootState::Running,
        "root cancelled before execution"
    );
    let (owner, hooks) = keeper.linked_parts().await?;
    (hooks.prepare)(owner.clone())
        .await
        .map_err(adapter::HostFailure::from)
        .context("linked root preparation failed")?;
    let (value, commit) = operation(owner, adapter)
        .await
        .map_err(adapter::HostFailure::from)
        .context("linked executor failed")?;
    Ok(RootOutcome { value, commit })
}

impl OwnerService {
    pub fn new() -> Self {
        let registry = Arc::new(OwnerRegistry::default());
        let (admission, receiver) = mpsc::channel(NODE_ADMISSION_CAPACITY);
        let shutdown = CancellationToken::new();
        let node_registry = registry.clone();
        let node_shutdown = shutdown.clone();
        let driver = tokio::spawn(async move {
            if std::panic::AssertUnwindSafe(run_node(
                receiver,
                node_shutdown,
                node_registry.clone(),
            ))
            .catch_unwind()
            .await
            .is_err()
            {
                node_registry.fatal.store(true, Ordering::SeqCst);
                node_registry.capacity.close();
                return Err(anyhow!("operation-owner node supervisor panicked"));
            }
            Ok(())
        });
        Self {
            registry,
            admission,
            shutdown,
            driver: Arc::new(std::sync::Mutex::new(Some(driver))),
        }
    }

    pub fn take_driver(&self) -> Option<JoinHandle<Result<()>>> {
        self.driver
            .lock()
            .expect("owner driver lock poisoned")
            .take()
    }

    pub fn shutdown(&self) {
        self.registry.capacity.close();
        wake_owner(&self.shutdown);
    }

    pub(crate) async fn reserve_root_capacity(&self) -> Result<OwnedSemaphorePermit> {
        let capacity = self
            .registry
            .capacity
            .clone()
            .acquire_owned()
            .await
            .context("operation-owner root capacity closed")?;
        ensure!(!self.is_fatal(), "operation-owner service is unavailable");
        Ok(capacity)
    }

    #[cfg(test)]
    pub(crate) fn set_startup_compile_gate(&self, gate: Arc<BlockingGate>) {
        *self
            .registry
            .startup_compile_gate
            .lock()
            .expect("startup gate lock poisoned") = Some(gate);
    }

    #[cfg(test)]
    fn set_canonical_release_gate(&self, gate: Arc<AsyncGate>) {
        *self
            .registry
            .canonical_release_gate
            .lock()
            .expect("canonical release gate lock poisoned") = Some(gate);
    }

    #[cfg(test)]
    pub(crate) fn apply_startup_compile_gate(&self, runtime: &mut Runtime) {
        runtime.compile_gate = self
            .registry
            .startup_compile_gate
            .lock()
            .expect("startup gate lock poisoned")
            .clone();
    }

    #[cfg(test)]
    pub(crate) async fn apply_linked_startup_compile_gate(
        &self,
        session: &LinkedSession,
    ) -> Result<()> {
        let owner = session
            .executor
            .owner
            .clone()
            .downcast::<BundleSession>()
            .map_err(|_| anyhow!("in-tree compile gate cannot instrument a foreign executor"))?;
        self.apply_startup_compile_gate(&mut *owner.test_runtime().await);
        Ok(())
    }

    pub async fn active_roots(&self) -> usize {
        self.registry.roots.lock().await.len()
    }

    pub async fn quarantined_roots(&self) -> usize {
        self.registry
            .roots
            .lock()
            .await
            .values()
            .filter(|keeper| RootState::load(&keeper.state) == RootState::Quarantined)
            .count()
    }

    pub fn is_fatal(&self) -> bool {
        self.registry.fatal.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) async fn fail_driver_for_test(&self) -> Result<()> {
        self.admission
            .send(Box::new(|| {
                Box::pin(async {
                    panic!("forced operation-owner driver failure");
                })
            }))
            .await
            .map_err(|_| anyhow!("operation-owner test admission closed"))
    }

    pub(crate) fn stateful_session(&self, runtime: Runtime) -> StatefulSession {
        StatefulSession::new(runtime)
    }

    pub(crate) async fn begin_canonical(
        &self,
        runtime: &mut Runtime,
        simulation: bool,
    ) -> Result<CanonicalRootLease> {
        ensure!(
            runtime.ownership.is_none()
                && runtime.storage.ownership.is_none()
                && runtime.bundle_owner.is_none()
                && runtime.storage.bundle_owner.is_none()
                && runtime.invocation_budget.is_none()
                && runtime.store_table_owners.is_none()
                && Arc::strong_count(&runtime.table) == 1,
            "canonical runtime is still owned by a prior root"
        );
        ensure!(
            runtime.storage.conn.is_autocommit()
                && runtime.storage.savepoint_stack.is_empty().await,
            "canonical root cannot start inside an existing transaction"
        );
        let capacity = self.reserve_root_capacity().await?;
        let permit = self
            .admission
            .reserve()
            .await
            .context("operation-owner node admission closed")?;
        if self.is_fatal() {
            return Err(anyhow!("operation-owner service is unavailable"));
        }
        let id = RootId(self.registry.next_root.fetch_add(1, Ordering::SeqCst));
        let mut roots = self.registry.roots.lock().await;
        let budget = Arc::new(InvocationBudget::default());
        let store_table_owners = Arc::new(std::sync::Mutex::new(Vec::new()));
        runtime.invocation_budget = Some(budget);
        runtime.store_table_owners = Some(store_table_owners);
        let keeper = Arc::new(RootKeeper::new_stateful(id, runtime.clone(), capacity));
        let (sender, receiver) = mpsc::channel(1);
        let kind = if simulation {
            RootKind::Simulation
        } else {
            RootKind::Canonical
        };
        let context = ChildContext::root(
            id,
            kind,
            sender,
            keeper.state.clone(),
            keeper.blocking.clone(),
            keeper.caught_host_panic.clone(),
        );
        runtime.ownership = Some(context.clone());
        runtime.storage.ownership = Some(context);
        roots.insert(id, keeper.clone());
        drop(roots);
        let (finish, finished) = oneshot::channel();
        let (drained_sender, drained) = oneshot::channel();
        let node_keeper = keeper.clone();
        #[cfg(test)]
        let release_gate = self
            .registry
            .canonical_release_gate
            .lock()
            .expect("canonical release gate lock poisoned")
            .clone();
        permit.send(Box::new(move || {
            Box::pin(async move {
                let result = supervise_canonical(node_keeper.clone(), receiver, finished).await;
                #[cfg(test)]
                if let Some(gate) = release_gate {
                    gate.wait().await;
                }
                // Drain authorizes the next root, so release the supervisor's
                // Runtime clone before waking the lease.
                drop(node_keeper);
                let _ = drained_sender.send(result);
            })
        }));
        Ok(CanonicalRootLease {
            keeper,
            registry: self.registry.clone(),
            finish: Some(finish),
            drained,
            complete: false,
        })
    }

    pub(crate) async fn begin_linked_canonical_reserved(
        &self,
        session: &LinkedSession,
        capacity: OwnedSemaphorePermit,
        selection: ExecutionSelection,
        simulation: bool,
    ) -> Result<LinkedCanonicalRootLease> {
        ensure!(
            session.origin() == selection.version(),
            "executor session does not match selection"
        );
        selection.ensure_canonical_root(simulation)?;
        ensure!(
            session.conn.is_autocommit(),
            "canonical root cannot start inside a transaction"
        );
        let permit = self
            .admission
            .reserve()
            .await
            .context("operation-owner node admission closed")?;
        ensure!(!self.is_fatal(), "operation-owner service is unavailable");
        let mut roots = self.registry.roots.lock().await;
        ensure!(
            session
                .canonical_busy
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok(),
            "canonical executor session is still owned by a prior root"
        );
        let id = RootId(self.registry.next_root.fetch_add(1, Ordering::SeqCst));
        let keeper = Arc::new(RootKeeper::new_linked_stateful(
            id,
            session.clone(),
            capacity,
        ));
        roots.insert(id, keeper.clone());
        drop(roots);
        let (sender, receiver) = mpsc::channel(1);
        let kind = if simulation {
            RootKind::Simulation
        } else {
            RootKind::Canonical
        };
        let context = ChildContext::root(
            id,
            kind,
            sender,
            keeper.state.clone(),
            keeper.blocking.clone(),
            keeper.caught_host_panic.clone(),
        );
        let root_alive = context.alive.clone();
        let adapter = OwnerAdapter::new(&keeper, context);
        let hooks_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            keeper.install_linked_hooks(selection, adapter.clone())
        }));
        match hooks_result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                keeper.quarantine();
                self.registry.fatal.store(true, Ordering::SeqCst);
                self.registry.capacity.close();
                return Err(error);
            }
            Err(_) => {
                keeper.quarantine();
                self.registry.fatal.store(true, Ordering::SeqCst);
                self.registry.capacity.close();
                return Err(anyhow!("linked canonical root hook construction panicked"));
            }
        }
        let (finish, finished) = oneshot::channel();
        let (drained_sender, drained) = oneshot::channel();
        let (ready_sender, ready) = oneshot::channel::<Result<()>>();
        let (settlement_signal, mut settlement_request) = oneshot::channel();
        let (complete_signal, complete_request) = oneshot::channel();
        let (released_signal, released) = oneshot::channel();
        let (completed_sender, completed) = oneshot::channel();
        let lease = LinkedCanonicalRootLease {
            keeper: keeper.clone(),
            registry: self.registry.clone(),
            adapter,
            root_alive,
            finish: Some(finish),
            drained,
            settlement_signal: Some(settlement_signal),
            drained_success: false,
            requires_settlement: false,
            settled: false,
            settlement_in_flight: false,
            complete_signal: Some(complete_signal),
            released_signal: Some(released_signal),
            completed: Some(completed),
            complete: false,
        };
        let registry = self.registry.clone();
        let session = session.clone();
        permit.send(Box::new(move || {
            Box::pin(async move {
                let supervised = keeper.clone();
                let task_registry = registry.clone();
                let task_session = session.clone();
                let task = async move {
                    let (owner, hooks) = supervised.linked_parts().await?;
                    if let Err(error) = (hooks.prepare)(owner)
                        .await
                        .map_err(adapter::HostFailure::from)
                    {
                        let _ = ready_sender.send(Err(anyhow!(error.clone())));
                        return Err(anyhow!(error));
                    }
                    if ready_sender.send(Ok(())).is_err() {
                        supervised.quarantine();
                        return Err(anyhow!(
                            "canonical root requester disappeared during preparation"
                        ));
                    }
                    let drain = async {
                        supervise_canonical(supervised.clone(), receiver, finished).await?;
                        let (owner, hooks) = supervised.linked_parts().await?;
                        (hooks.inspect_canonical_drain)(owner)
                            .await
                            .map_err(adapter::HostFailure::from)
                            .context("linked canonical drain inspection failed")
                    }
                    .await;
                    if let Err(error) = drain {
                        let _ = drained_sender.send(Err(anyhow!(error.to_string())));
                        return Err(error);
                    }
                    let must_settle = !task_session.conn.is_autocommit();
                    if drained_sender.send(Ok(must_settle)).is_err() {
                        return Err(anyhow!("canonical root requester disappeared after drain"));
                    }
                    let mut complete_request = complete_request;
                    let mut settled = false;
                    tokio::select! {
                        requested = &mut settlement_request => {
                            if let Ok((commit, reply)) = requested {
                                let (owner, hooks) = supervised.linked_parts().await?;
                                let result = (hooks.settle)(owner, commit)
                                    .await
                                    .map_err(adapter::HostFailure::from);
                                let response = result
                                    .as_ref()
                                    .map(|_| ())
                                    .map_err(|error| anyhow!(error.clone()));
                                let _ = reply.send(response);
                                result.context("linked canonical settlement failed")?;
                                settled = true;
                            }
                            complete_request.await.context("canonical completion was abandoned")?;
                        }
                        requested = &mut complete_request => {
                            requested.context("canonical completion was abandoned")?;
                        }
                    }
                    ensure!(
                        !must_settle || settled,
                        "canonical transaction bypassed settlement"
                    );
                    ensure!(
                        task_session.conn.is_autocommit(),
                        "canonical SQL commit has not completed"
                    );
                    let (owner, hooks) = supervised.linked_parts().await?;
                    (hooks.reset)(owner, true, false)
                        .await
                        .map_err(adapter::HostFailure::from)
                        .context("linked canonical reset failed")?;
                    supervised.quiescent.store(true, Ordering::SeqCst);
                    supervised
                        .state
                        .store(RootState::Complete as u8, Ordering::SeqCst);
                    task_registry.roots.lock().await.remove(&supervised.id);
                    let _ = released.await;
                    Ok::<(), anyhow::Error>(())
                };
                match std::panic::AssertUnwindSafe(task).catch_unwind().await {
                    Ok(Ok(())) => {
                        drop(keeper);
                        let busy = session.canonical_busy.clone();
                        drop(session);
                        busy.store(false, Ordering::SeqCst);
                        let _ = completed_sender.send(Ok(()));
                    }
                    Ok(Err(error)) => {
                        keeper.quarantine();
                        registry.fatal.store(true, Ordering::SeqCst);
                        registry.capacity.close();
                        let _ = completed_sender.send(Err(error));
                    }
                    Err(_) => {
                        keeper.quarantine();
                        registry.fatal.store(true, Ordering::SeqCst);
                        registry.capacity.close();
                        let _ = completed_sender
                            .send(Err(anyhow!("linked canonical supervisor panicked")));
                    }
                }
            })
        }));
        ready
            .await
            .context("linked canonical preparation disappeared")??;
        Ok(lease)
    }

    pub(crate) async fn start_pooled<T, F>(
        &self,
        object: Object<Manager>,
        operation: F,
    ) -> Result<OwnedRootHandle<T>>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(&'a mut Runtime) -> BoxFuture<'a, Result<RootOutcome<T>>>
            + Send
            + 'static,
    {
        let capacity = self.reserve_root_capacity().await?;
        self.start_pooled_reserved(object, capacity, operation)
            .await
    }

    pub(crate) async fn start_pooled_reserved<T, F>(
        &self,
        object: Object<Manager>,
        capacity: OwnedSemaphorePermit,
        operation: F,
    ) -> Result<OwnedRootHandle<T>>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(&'a mut Runtime) -> BoxFuture<'a, Result<RootOutcome<T>>>
            + Send
            + 'static,
    {
        let permit = self
            .admission
            .reserve()
            .await
            .context("operation-owner node admission closed")?;
        if self.is_fatal() {
            return Err(anyhow!("operation-owner service is unavailable"));
        }
        let id = RootId(self.registry.next_root.fetch_add(1, Ordering::SeqCst));
        let keeper = Arc::new(RootKeeper::new(id, object, capacity));
        self.registry.roots.lock().await.insert(id, keeper.clone());
        let (sender, receiver) = mpsc::channel(1);
        let context = ChildContext::root(
            id,
            RootKind::Api,
            sender,
            keeper.state.clone(),
            keeper.blocking.clone(),
            keeper.caught_host_panic.clone(),
        );
        let (result_sender, result) = oneshot::channel();
        let handle = OwnedRootHandle {
            state: keeper.state.clone(),
            closing_at: keeper.closing_at.clone(),
            cancellation: keeper.cancellation.clone(),
            result,
        };
        let registry = self.registry.clone();
        permit.send(Box::new(move || {
            Box::pin(async move {
                let supervisor = supervise(
                    registry.clone(),
                    keeper.clone(),
                    receiver,
                    context,
                    move |keeper, context| Box::pin(run_legacy_root(keeper, context, operation)),
                    result_sender,
                    None,
                );
                if std::panic::AssertUnwindSafe(supervisor)
                    .catch_unwind()
                    .await
                    .is_err()
                {
                    keeper.quarantine();
                    registry.fatal.store(true, Ordering::SeqCst);
                    registry.capacity.close();
                    panic!("operation root supervisor panicked");
                }
            })
        }));
        Ok(handle)
    }

    pub(crate) async fn start_stateful<T, F>(
        &self,
        session: &StatefulSession,
        operation: F,
    ) -> Result<OwnedRootHandle<T>>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(&'a mut Runtime) -> BoxFuture<'a, Result<RootOutcome<T>>>
            + Send
            + 'static,
    {
        let capacity = self.reserve_root_capacity().await?;
        let mut checkout = session.checkout().await?;
        let permit = self
            .admission
            .reserve()
            .await
            .context("operation-owner node admission closed")?;
        if self.is_fatal() {
            return Err(anyhow!("operation-owner service is unavailable"));
        }
        let id = RootId(self.registry.next_root.fetch_add(1, Ordering::SeqCst));
        let keeper = {
            let mut roots = self.registry.roots.lock().await;
            let runtime = checkout
                .runtime
                .take()
                .expect("checked-out runtime retained");
            let keeper = Arc::new(RootKeeper::new_stateful(id, runtime, capacity));
            roots.insert(id, keeper.clone());
            keeper
        };
        let (sender, receiver) = mpsc::channel(1);
        let context = ChildContext::root(
            id,
            RootKind::Api,
            sender,
            keeper.state.clone(),
            keeper.blocking.clone(),
            keeper.caught_host_panic.clone(),
        );
        let (result_sender, result) = oneshot::channel();
        let handle = OwnedRootHandle {
            state: keeper.state.clone(),
            closing_at: keeper.closing_at.clone(),
            cancellation: keeper.cancellation.clone(),
            result,
        };
        let registry = self.registry.clone();
        let return_to = session.clone();
        permit.send(Box::new(move || {
            Box::pin(async move {
                let supervisor = supervise(
                    registry.clone(),
                    keeper.clone(),
                    receiver,
                    context,
                    move |keeper, context| Box::pin(run_legacy_root(keeper, context, operation)),
                    result_sender,
                    Some(ReturnTo::Legacy(return_to.clone())),
                );
                if std::panic::AssertUnwindSafe(supervisor)
                    .catch_unwind()
                    .await
                    .is_err()
                {
                    keeper.quarantine();
                    return_to.quarantine();
                    registry.fatal.store(true, Ordering::SeqCst);
                    registry.capacity.close();
                    panic!("operation root supervisor panicked");
                }
            })
        }));
        Ok(handle)
    }

    pub(crate) async fn start_linked_pooled_reserved(
        &self,
        object: Object<LinkedManager>,
        capacity: OwnedSemaphorePermit,
        selection: ExecutionSelection,
        operation: LinkedOperation,
    ) -> Result<OwnedRootHandle<Payload>> {
        ensure!(
            object.origin() == selection.version(),
            "executor session does not match selection"
        );
        self.start_linked_root(
            move || RootAuthority::LinkedPooled(object),
            capacity,
            selection,
            operation,
            None,
        )
        .await
    }

    pub(crate) async fn start_linked_stateful_reserved(
        &self,
        session: &LinkedStatefulSession,
        capacity: OwnedSemaphorePermit,
        selection: ExecutionSelection,
        operation: LinkedOperation,
    ) -> Result<OwnedRootHandle<Payload>> {
        let mut checkout = session.checkout().await?;
        ensure!(
            checkout
                .value
                .as_ref()
                .is_some_and(|value| value.origin() == selection.version()),
            "executor session does not match selection"
        );
        self.start_linked_root(
            move || {
                RootAuthority::LinkedStateful(
                    checkout.value.take().expect("linked session checked out"),
                )
            },
            capacity,
            selection,
            operation,
            Some(ReturnTo::Linked(session.clone())),
        )
        .await
    }

    async fn start_linked_root<F>(
        &self,
        authority: F,
        capacity: OwnedSemaphorePermit,
        selection: ExecutionSelection,
        operation: LinkedOperation,
        return_to: Option<ReturnTo>,
    ) -> Result<OwnedRootHandle<Payload>>
    where
        F: FnOnce() -> RootAuthority,
    {
        let permit = self
            .admission
            .reserve()
            .await
            .context("operation-owner node admission closed")?;
        ensure!(!self.is_fatal(), "operation-owner service is unavailable");
        let mut roots = self.registry.roots.lock().await;
        let id = RootId(self.registry.next_root.fetch_add(1, Ordering::SeqCst));
        let keeper = Arc::new(RootKeeper::with_authority(id, authority(), capacity));
        roots.insert(id, keeper.clone());
        drop(roots);
        let (sender, receiver) = mpsc::channel(1);
        let context = ChildContext::root(
            id,
            RootKind::Api,
            sender,
            keeper.state.clone(),
            keeper.blocking.clone(),
            keeper.caught_host_panic.clone(),
        );
        let adapter = OwnerAdapter::new(&keeper, context.clone());
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            keeper.install_linked_hooks(selection, adapter.clone())
        })) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                keeper.quarantine();
                if let Some(session) = &return_to {
                    session.quarantine();
                }
                return Err(error);
            }
            Err(_) => {
                keeper.quarantine();
                if let Some(session) = &return_to {
                    session.quarantine();
                }
                return Err(anyhow!("linked root hook construction panicked"));
            }
        }
        let (result_sender, result) = oneshot::channel();
        let handle = OwnedRootHandle {
            state: keeper.state.clone(),
            closing_at: keeper.closing_at.clone(),
            cancellation: keeper.cancellation.clone(),
            result,
        };
        let registry = self.registry.clone();
        permit.send(Box::new(move || {
            Box::pin(async move {
                let supervisor = supervise(
                    registry.clone(),
                    keeper.clone(),
                    receiver,
                    context,
                    move |keeper, _context| Box::pin(run_linked_root(keeper, adapter, operation)),
                    result_sender,
                    return_to.clone(),
                );
                if std::panic::AssertUnwindSafe(supervisor)
                    .catch_unwind()
                    .await
                    .is_err()
                {
                    keeper.quarantine();
                    if let Some(session) = &return_to {
                        session.quarantine();
                    }
                    registry.fatal.store(true, Ordering::SeqCst);
                    registry.capacity.close();
                    panic!("linked operation root supervisor panicked");
                }
            })
        }));
        Ok(handle)
    }
}

async fn run_node(
    mut receiver: mpsc::Receiver<RootStart>,
    shutdown: CancellationToken,
    registry: Arc<OwnerRegistry>,
) {
    let mut supervisors = JoinSet::new();
    let mut gauge_tick = tokio::time::interval(Duration::from_secs(1));
    gauge!("operation_owner_quarantined_roots").set(0.0);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                receiver.close();
                break;
            }
            start = receiver.recv() => {
                match start {
                    Some(start) => {
                        supervisors.spawn(start());
                    }
                    None => break,
                }
            }
            joined = supervisors.join_next(), if !supervisors.is_empty() => {
                if let Some(Err(error)) = joined {
                    panic!("operation supervisor task failed: {error}");
                }
            }
            _ = gauge_tick.tick() => {
                let count = registry
                    .roots
                    .lock()
                    .await
                    .values()
                    .filter(|keeper| RootState::load(&keeper.state) == RootState::Quarantined)
                    .count();
                gauge!("operation_owner_quarantined_roots").set(count as f64);
            }
        }
    }
    while let Some(start) = receiver.recv().await {
        supervisors.spawn(start());
    }
    while let Some(joined) = supervisors.join_next().await {
        if let Err(error) = joined {
            panic!("operation supervisor task failed: {error}");
        }
    }
}

async fn supervise_canonical(
    keeper: Arc<RootKeeper>,
    mut receiver: mpsc::Receiver<Admission>,
    mut finish: oneshot::Receiver<()>,
) -> Result<()> {
    let mut children = JoinSet::<(TaskId, TaskCompletion)>::new();
    let mut active = HashMap::<TaskId, RunningChild>::new();
    let mut by_tokio = HashMap::<Id, TaskId>::new();
    let mut parked_senders = Vec::<oneshot::Sender<GuestDelivery>>::new();
    let mut finished = false;
    let mut receiver_drained = false;
    let mut aborting = None;

    loop {
        let closing = RootState::load(&keeper.state) != RootState::Running;
        if finished || closing {
            receiver.close();
        }
        if closing
            && aborting.is_none()
            && let Some((&id, child)) = active.iter().max_by_key(|(_, child)| child.depth)
        {
            child.abort.abort();
            aborting = Some(id);
        }
        if (finished || closing) && active.is_empty() && receiver_drained {
            break;
        }

        tokio::select! {
            _ = keeper.cancellation.cancelled(), if !closing => {}
            result = &mut finish, if !finished => {
                finished = true;
                if result.is_err() || !active.is_empty() {
                    keeper.quarantine();
                }
            }
            request = receiver.recv(), if !receiver_drained => {
                match request {
                    Some(request)
                        if RootState::load(&keeper.state) == RootState::Running && !finished =>
                    {
                        let valid_parent = request.parent.root == keeper.id
                            && request.id.root == keeper.id
                            && request.id != request.parent
                            && (request.parent.local == 0
                                || active.get(&request.parent).is_some_and(|parent| {
                                    parent.depth + 1 == request.depth
                                }));
                        if !valid_parent {
                            keeper.quarantine();
                            drop(request);
                            continue;
                        }
                        let Admission { id, parent, depth, future, completion, slot, child_alive } = request;
                        let abort = children.spawn(async move { (id, future.await) });
                        by_tokio.insert(abort.id(), id);
                        active.insert(id, RunningChild {
                            parent,
                            depth,
                            abort,
                            completion,
                            slot,
                            child_alive,
                        });
                    }
                    Some(request) => {
                        if !closing {
                            keeper.quarantine();
                        }
                        drop(request);
                    }
                    None => receiver_drained = true,
                }
            }
            joined = children.join_next_with_id(), if !children.is_empty() => {
                if let Some(joined) = joined {
                    let (tokio_id, completion) = match joined {
                        Ok((tokio_id, (id, completion))) => {
                            debug_assert_eq!(by_tokio.get(&tokio_id), Some(&id));
                            (tokio_id, Some(completion))
                        }
                        Err(error) => {
                            if !closing || error.is_panic() {
                                keeper.quarantine();
                            }
                            (error.id(), None)
                        }
                    };
                    let id = by_tokio.remove(&tokio_id).expect("registered child task id");
                    let child = active.remove(&id).expect("registered child completion");
                    child.child_alive.store(false, Ordering::SeqCst);
                    if aborting == Some(id) {
                        aborting = None;
                    }
                    if let Some(completion) = completion {
                        if completion.host_panicked() {
                            keeper.caught_host_panic.store(true, Ordering::SeqCst);
                        }
                        if RootState::load(&keeper.state) == RootState::Running
                            || completion.host_panicked()
                        {
                            if let Err(delivery) = child.completion.send(GuestDelivery {
                                completion,
                                slot: child.slot,
                            }) {
                                drop(delivery);
                                keeper.quarantine();
                            }
                        } else {
                            drop(completion);
                            drop(child.slot);
                            parked_senders.push(child.completion);
                        }
                    } else {
                        drop(child.slot);
                        parked_senders.push(child.completion);
                    }
                }
            }
        }
    }

    keeper.blocking.close_registration();
    keeper.blocking.wait_all().await;
    drop(parked_senders);
    if keeper.blocking.panicked() {
        keeper.quarantine();
    }
    if RootState::load(&keeper.state) == RootState::Running
        && !keeper.caught_host_panic.load(Ordering::SeqCst)
    {
        keeper
            .state
            .store(RootState::Committing as u8, Ordering::SeqCst);
        Ok(())
    } else {
        keeper.quarantine();
        Err(anyhow!("canonical root quarantined"))
    }
}

async fn supervise<T, F>(
    registry: Arc<OwnerRegistry>,
    keeper: Arc<RootKeeper>,
    mut receiver: mpsc::Receiver<Admission>,
    context: ChildContext,
    operation: F,
    response: oneshot::Sender<Result<T>>,
    return_to: Option<ReturnTo>,
) where
    T: Send + 'static,
    F: FnOnce(Arc<RootKeeper>, ChildContext) -> BoxFuture<'static, Result<RootOutcome<T>>>
        + Send
        + 'static,
{
    let root_keeper = keeper.clone();
    let root_alive = context.alive.clone();
    let mut root: JoinHandle<Result<RootOutcome<T>>> =
        tokio::spawn(operation(root_keeper, context));
    #[cfg(test)]
    let injected_gate = registry
        .supervisor_panic_after_root_entered
        .lock()
        .expect("supervisor panic gate lock poisoned")
        .take();
    #[cfg(test)]
    if let Some(gate) = injected_gate {
        while !gate.entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        panic!("injected operation root supervisor panic");
    }
    let mut root_result = None;
    let mut children = JoinSet::<(TaskId, TaskCompletion)>::new();
    let mut active = HashMap::<TaskId, RunningChild>::new();
    let mut by_tokio = HashMap::<Id, TaskId>::new();
    let mut parked_senders = Vec::<oneshot::Sender<GuestDelivery>>::new();
    let mut receiver_drained = false;
    let mut aborting = None;
    let mut root_aborted = false;
    let mut deadline = None;
    let mut timed_out = false;
    let mut response = Some(response);

    loop {
        let closing = matches!(
            RootState::load(&keeper.state),
            RootState::Closing | RootState::Quarantined
        );
        let panic_seen = keeper.caught_host_panic.load(Ordering::SeqCst);
        if closing || root_result.is_some() || panic_seen {
            receiver.close();
            if deadline.is_none() {
                deadline = Some(
                    keeper
                        .closing_at
                        .lock()
                        .expect("root closing clock poisoned")
                        .unwrap_or_else(Instant::now)
                        + API_DRAIN_LIMIT,
                );
            }
        }
        if closing && aborting.is_none() {
            if let Some((&id, child)) = active.iter().max_by_key(|(_, child)| child.depth) {
                child.abort.abort();
                aborting = Some(id);
            } else if !root_aborted && root_result.is_none() {
                root.abort();
                root_aborted = true;
            }
        }
        if root_result.is_some() && active.is_empty() && receiver_drained {
            break;
        }

        tokio::select! {
            _ = keeper.cancellation.cancelled(), if !closing => {}
            request = receiver.recv(), if !receiver_drained => {
                match request {
                    Some(request)
                        if RootState::load(&keeper.state) == RootState::Running
                            && !keeper.caught_host_panic.load(Ordering::SeqCst)
                            && root_result.is_none() =>
                    {
                        let valid_parent = request.parent.root == keeper.id
                            && request.id.root == keeper.id
                            && request.id != request.parent
                            && (request.parent.local == 0
                                || active.get(&request.parent).is_some_and(|parent| {
                                    parent.depth + 1 == request.depth
                                }));
                        if !valid_parent {
                            keeper.quarantine();
                            drop(request);
                            continue;
                        }
                        let Admission { id, parent, depth, future, completion, slot, child_alive } = request;
                        let abort = children.spawn(async move { (id, future.await) });
                        by_tokio.insert(abort.id(), id);
                        active.insert(id, RunningChild {
                            parent,
                            depth,
                            abort,
                            completion,
                            slot,
                            child_alive,
                        });
                    }
                    Some(request) => {
                        if !closing {
                            keeper.quarantine();
                        }
                        drop(request);
                    }
                    None => receiver_drained = true,
                }
            }
            joined = children.join_next_with_id(), if !children.is_empty() => {
                if let Some(joined) = joined {
                    let (tokio_id, completion) = match joined {
                        Ok((tokio_id, (id, completion))) => {
                            debug_assert_eq!(by_tokio.get(&tokio_id), Some(&id));
                            (tokio_id, Some(completion))
                        }
                        Err(error) => {
                            if !closing || error.is_panic() {
                                keeper.quarantine();
                            }
                            (error.id(), None)
                        }
                    };
                    let id = by_tokio.remove(&tokio_id).expect("registered child task id");
                    let child = active.remove(&id).expect("registered child completion");
                    child.child_alive.store(false, Ordering::SeqCst);
                    debug_assert_eq!(child.parent.root, keeper.id);
                    if aborting == Some(id) {
                        aborting = None;
                    }
                    if let Some(completion) = completion {
                        if completion.host_panicked() {
                            keeper.caught_host_panic.store(true, Ordering::SeqCst);
                        }
                        if RootState::load(&keeper.state) == RootState::Running {
                            if let Err(delivery) = child.completion.send(GuestDelivery {
                                completion,
                                slot: child.slot,
                            }) {
                                drop(delivery);
                                keeper.close();
                            }
                        } else {
                            drop(completion);
                            drop(child.slot);
                            parked_senders.push(child.completion);
                        }
                    } else {
                        drop(child.slot);
                        parked_senders.push(child.completion);
                    }
                }
            }
            finished = &mut root, if root_result.is_none() => {
                root_alive.store(false, Ordering::SeqCst);
                if let Err(error) = &finished
                    && error.is_panic()
                {
                    keeper.quarantine();
                }
                root_result = Some(finished);
                if !active.is_empty() {
                    keeper.quarantine();
                }
            }
            _ = sleep_until(deadline.unwrap_or_else(Instant::now)), if deadline.is_some() && !timed_out => {
                timed_out = true;
                keeper.quarantine();
                if let Some(response) = response.take() {
                    let _ = response.send(Err(anyhow!("operation drain exceeded five seconds; root quarantined")));
                }
            }
        }
    }

    keeper.blocking.close_registration();
    if let Some(deadline) = deadline
        && !timed_out
        && tokio::time::timeout_at(deadline, keeper.blocking.wait_all())
            .await
            .is_err()
    {
        timed_out = true;
        keeper.quarantine();
        if let Some(response) = response.take() {
            let _ = response.send(Err(anyhow!(
                "operation drain exceeded five seconds; root quarantined"
            )));
        }
    }
    keeper.blocking.wait_all().await;
    if keeper.blocking.panicked() {
        keeper.quarantine();
    }

    // A closed child receiver remains alive until its parent has joined. Its
    // cancellation must never look like an ordinary guest error to that parent.
    drop(parked_senders);
    let operation_result = match root_result.expect("root joined before restoration") {
        Ok(result) => result,
        Err(error) => Err(anyhow!("root task failed: {error}")),
    };
    let result = restore_with_deadline(
        &keeper,
        operation_result,
        deadline,
        timed_out,
        &mut response,
    )
    .await;
    match result {
        Ok(value)
            if RootState::load(&keeper.state) != RootState::Quarantined
                && !keeper.caught_host_panic.load(Ordering::SeqCst) =>
        {
            keeper
                .state
                .store(RootState::Complete as u8, Ordering::SeqCst);
            let returned = if return_to.is_some() {
                Some(
                    keeper
                        .authority
                        .lock()
                        .await
                        .take()
                        .expect("stateful root authority retained"),
                )
            } else {
                None
            };
            registry.roots.lock().await.remove(&keeper.id);
            match (return_to.as_ref(), returned) {
                (Some(ReturnTo::Legacy(session)), Some(RootAuthority::Stateful(runtime))) => {
                    session.return_runtime(runtime);
                }
                (Some(ReturnTo::Linked(session)), Some(RootAuthority::LinkedStateful(value))) => {
                    session.return_session(value);
                }
                (None, None) => {}
                _ => unreachable!("root authority does not match its return session"),
            }
            if let Some(response) = response.take() {
                let _ = response.send(value);
            }
        }
        Ok(value)
            if RootState::load(&keeper.state) != RootState::Quarantined
                && keeper.caught_host_panic.load(Ordering::SeqCst) =>
        {
            keeper.quarantine();
            if let Some(session) = &return_to {
                session.quarantine();
            }
            if let Some(response) = response.take() {
                let error = value
                    .err()
                    .unwrap_or_else(|| anyhow!("host panic reached operation root"));
                let _ = response.send(Err(error));
            }
        }
        Ok(_) | Err(_) => {
            keeper.quarantine();
            if let Some(session) = &return_to {
                match session {
                    ReturnTo::Legacy(session) => session.quarantine(),
                    ReturnTo::Linked(session) => session.quarantine(),
                }
            }
            if let Some(response) = response.take() {
                let _ = response.send(Err(anyhow!("operation root quarantined")));
            }
        }
    }
    if RootState::load(&keeper.state) == RootState::Quarantined
        && keeper.quiescent.load(Ordering::SeqCst)
    {
        // RootKeeper::Drop detaches a poisoned pool Object only after all task,
        // Store, callback and SQL ownership has been proven quiescent.
        registry.roots.lock().await.remove(&keeper.id);
    }
}

async fn restore_with_deadline<T>(
    keeper: &RootKeeper,
    operation_result: Result<RootOutcome<T>>,
    deadline: Option<Instant>,
    timed_out: bool,
    response: &mut Option<oneshot::Sender<Result<T>>>,
) -> Result<Result<T>> {
    let restoration = restore(keeper, operation_result);
    tokio::pin!(restoration);
    if let Some(deadline) = deadline.filter(|_| !timed_out) {
        tokio::select! {
            biased;
            _ = sleep_until(deadline) => {
                if keeper.quarantine_before_commit()
                    && let Some(response) = response.take()
                {
                    let _ = response.send(Err(anyhow!(
                        "operation restoration exceeded five seconds; root quarantined"
                    )));
                }
            }
            result = &mut restoration => return result,
        }
    }
    restoration.await
}

async fn restore<T>(keeper: &RootKeeper, result: Result<RootOutcome<T>>) -> Result<Result<T>> {
    let mut authority = keeper.authority.lock().await;
    if matches!(
        authority.as_ref(),
        Some(RootAuthority::LinkedPooled(_) | RootAuthority::LinkedStateful(_))
    ) {
        return restore_linked(
            keeper,
            authority.as_mut().expect("root authority retained"),
            result,
        )
        .await;
    }
    let stateful = matches!(authority.as_ref(), Some(RootAuthority::Stateful(_)));
    let runtime: &mut Runtime = authority.as_mut().expect("root authority retained");
    let wants_commit = result.as_ref().is_ok_and(|outcome| outcome.commit);
    let commit_authorized = wants_commit
        && !keeper.caught_host_panic.load(Ordering::SeqCst)
        && !keeper.blocking.panicked()
        && keeper
            .state
            .compare_exchange(
                RootState::Running as u8,
                RootState::Committing as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok();
    if commit_authorized {
        runtime
            .storage
            .commit()
            .await
            .context("root commit failed")?;
    } else if !runtime.storage.conn.is_autocommit() {
        runtime
            .storage
            .rollback_transaction()
            .await
            .context("root rollback failed")?;
        if stateful
            && (result.is_err()
                || matches!(
                    RootState::load(&keeper.state),
                    RootState::Closing | RootState::Quarantined
                ))
        {
            // A cancelled publication can have populated the cache under an id
            // that the full rollback makes available to a different contract.
            runtime.component_cache.clear();
        }
    }
    if !commit_authorized {
        runtime.stack.clear().await;
        runtime.deposit.reset().await;
    }
    runtime.ownership = None;
    runtime.storage.ownership = None;
    runtime.bundle_owner = None;
    runtime.storage.bundle_owner = None;
    let live_store_table = runtime.store_table_owners.as_ref().is_some_and(|owners| {
        owners
            .lock()
            .expect("store table tracker poisoned")
            .iter()
            .any(|owner| owner.strong_count() != 0)
    });
    if !runtime.storage.conn.is_autocommit()
        || !runtime.storage.savepoint_stack.is_empty().await
        || !runtime.stack.is_empty().await
        || runtime
            .invocation_budget
            .as_ref()
            .is_some_and(|budget| budget.live() != 0)
        || live_store_table
        || Arc::strong_count(&runtime.table) != 1
    {
        return Err(anyhow!(
            "root still has live SQL, stack, Store or table ownership"
        ));
    }
    runtime.invocation_budget = None;
    runtime.store_table_owners = None;
    *runtime.table.lock().await = ResourceTable::new();
    keeper.quiescent.store(true, Ordering::SeqCst);
    if RootState::load(&keeper.state) == RootState::Closing {
        return Ok(Err(anyhow!(
            "operation cancelled before commit authorization"
        )));
    }
    Ok(result.map(|outcome| outcome.value))
}

async fn restore_linked<T>(
    keeper: &RootKeeper,
    authority: &mut RootAuthority,
    result: Result<RootOutcome<T>>,
) -> Result<Result<T>> {
    let (session, stateful) = match authority {
        RootAuthority::LinkedPooled(object) => (&mut **object, false),
        RootAuthority::LinkedStateful(session) => (session, true),
        RootAuthority::Pooled(_) | RootAuthority::Stateful(_) => {
            return Err(anyhow!("linked restoration received a legacy authority"));
        }
    };
    let hooks = keeper
        .linked_hooks
        .lock()
        .await
        .clone()
        .context("linked root hooks missing")?;
    let owner = session.executor.owner.clone();
    let wants_commit = result.as_ref().is_ok_and(|outcome| outcome.commit);
    let commit_authorized = wants_commit
        && !keeper.caught_host_panic.load(Ordering::SeqCst)
        && !keeper.blocking.panicked()
        && keeper
            .state
            .compare_exchange(
                RootState::Running as u8,
                RootState::Committing as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok();
    if commit_authorized || !session.conn.is_autocommit() {
        (hooks.settle)(owner.clone(), commit_authorized)
            .await
            .map_err(adapter::HostFailure::from)
            .context("linked root settlement failed")?;
    }
    let clear_cache = stateful
        && (result.is_err()
            || matches!(
                RootState::load(&keeper.state),
                RootState::Closing | RootState::Quarantined
            ));
    (hooks.reset)(owner, false, clear_cache)
        .await
        .map_err(adapter::HostFailure::from)
        .context("linked root reset failed")?;
    ensure!(
        session.conn.is_autocommit(),
        "linked root still has live SQL transaction"
    );
    keeper.quiescent.store(true, Ordering::SeqCst);
    if RootState::load(&keeper.state) == RootState::Closing {
        return Ok(Err(anyhow!(
            "operation cancelled before commit authorization"
        )));
    }
    Ok(result.map(|outcome| outcome.value))
}

#[cfg(test)]
mod tests {
    use super::super::bundle_session::BundleSession;
    use super::super::pool::new_linked;
    use super::adapter::{ExecutorSession, RootHooks, SessionAction, SessionFactory};
    use super::*;
    use crate::consensus::signing::PrivateKey;
    use crate::database::connection::new_connection;
    use crate::protocol::coordinator::linked::link_runtime;
    use crate::protocol::coordinator::selection::{
        ApplicationPosition, ExecutorVersion, select_legacy_p1,
    };
    use crate::protocol::session::GuestFactory;
    use crate::protocol::v1::committee::derive_committee;
    use crate::reg_tester::random_x_only_pubkey;
    use crate::runtime::call::CallOutcome;
    use crate::runtime::fuel::ExecutionUsage;
    use crate::runtime::staking::address as staking_address;
    use crate::runtime::storage::BlockingGate;
    use crate::runtime::wit::{Signer, kontor::built_in::context::HolderRef};
    use crate::runtime::{ComponentSource, GenesisValidator};
    use crate::runtime::{
        ContractAddress, Decimal, ExecutionError, Linkers, Storage, native_provenance,
        to_wave_expr, token,
    };
    use crate::test_utils::{test_runtime, test_runtime_with_genesis};
    use bitcoin::Network;
    use deadpool::managed::Pool;
    use indexer_types::Payment;
    use libsql::Connection;
    use std::future::poll_fn;
    use std::sync::atomic::AtomicUsize;
    use std::task::Poll;
    use tempfile::TempDir;
    use tokio::sync::{Barrier, Notify};
    use tokio::time::timeout;
    use wasmtime::component::{Component, Linker};

    const PURE_LOOP_COMPONENT: &str = r#"
        (component
          (core module $code
            (func (export "run") (param $count i32) (result i32)
              (local $total i32)
              (block $done
                (loop $again
                  local.get $count i32.eqz br_if $done
                  local.get $total i32.const 1 i32.add local.set $total
                  local.get $count i32.const 1 i32.sub local.set $count
                  br $again))
              local.get $total))
          (core instance $code (instantiate $code))
          (func (export "run") (param "count" u32) (result u32)
            (canon lift (core func $code "run"))))
    "#;

    type YieldObservations = Arc<Mutex<Vec<(u32, Val, u64, bool)>>>;
    type DeepAdmission = (
        mpsc::Sender<Admission>,
        Arc<AtomicBool>,
        Arc<InvocationBudget>,
    );

    #[derive(Debug, PartialEq)]
    struct PaidReceiptSnapshot {
        outcome: std::result::Result<String, String>,
        usage: ExecutionUsage,
        receipt: (u64, String, u64, Option<String>),
        payer: Option<Decimal>,
        burner: Option<Decimal>,
    }

    struct ReleaseBlockingGate(Arc<BlockingGate>);

    impl Drop for ReleaseBlockingGate {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    struct ReleaseAsyncGate(Arc<AsyncGate>);

    impl Drop for ReleaseAsyncGate {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    fn rooted_store(runtime: &Runtime, kind: RootKind, fuel: u64) -> Result<InvocationStore> {
        let mut runtime = runtime.clone();
        let (sender, _receiver) = mpsc::channel(1);
        runtime.ownership = Some(ChildContext::root(
            RootId(99),
            kind,
            sender,
            Arc::new(AtomicU8::new(RootState::Running as u8)),
            Arc::new(BlockingRegistry::default()),
            Arc::new(AtomicBool::new(false)),
        ));
        runtime.make_store(fuel)
    }

    async fn run_pure_loop(
        runtime: &Runtime,
        component: &Component,
        kind: RootKind,
        count: u32,
        fuel: u64,
    ) -> Result<(Val, u64, bool)> {
        let (observation, _store) =
            run_pure_loop_in_store(rooted_store(runtime, kind, fuel)?, component, count, None)
                .await?;
        Ok(observation)
    }

    async fn run_pure_loop_in_store(
        mut store: InvocationStore,
        component: &Component,
        count: u32,
        first_yield: Option<&AtomicBool>,
    ) -> Result<((Val, u64, bool), InvocationStore)> {
        let linker = Linker::<Runtime>::new(&store.data().engine);
        let instance = linker.instantiate_async(&mut store, component).await?;
        let run = instance
            .get_func(&mut store, "run")
            .context("pure loop export missing")?;
        let mut results = [Val::U32(0)];
        let args = [Val::U32(count)];
        let yielded = {
            let invocation = run.call_async(&mut store, &args, &mut results);
            tokio::pin!(invocation);
            match poll_fn(|cx| Poll::Ready(invocation.as_mut().poll(cx))).await {
                Poll::Ready(result) => {
                    result?;
                    false
                }
                Poll::Pending => {
                    if let Some(first_yield) = first_yield {
                        first_yield.store(true, Ordering::SeqCst);
                    }
                    timeout(Duration::from_secs(10), invocation.as_mut()).await??;
                    true
                }
            }
        };
        Ok(((results[0].clone(), store.get_fuel()?, yielded), store))
    }

    fn nested_yield_guest(
        mut runtime: Runtime,
        owner: ChildContext,
        component: Arc<Component>,
        depth: u32,
        observations: YieldObservations,
        leaf_count: u32,
        fuel: u64,
        first_yield: Option<Arc<AtomicBool>>,
    ) -> BoxFuture<'static, GuestCompletion> {
        Box::pin(async move {
            runtime.ownership = Some(owner.clone());
            runtime.storage.ownership = Some(owner.clone());
            let (observation, store) = run_pure_loop_in_store(
                runtime.make_store(fuel).expect("nested Store"),
                &component,
                if depth == 2 { leaf_count } else { 200_000 },
                if depth == 2 {
                    first_yield.as_deref()
                } else {
                    None
                },
            )
            .await
            .expect("nested pure guest call");
            observations
                .lock()
                .await
                .push((depth, observation.0, observation.1, observation.2));
            if depth < 2 {
                let child_runtime = runtime.clone();
                let child_component = component.clone();
                let child_observations = observations.clone();
                let child = owner
                    .run_guest(move |next| {
                        nested_yield_guest(
                            child_runtime,
                            next,
                            child_component,
                            depth + 1,
                            child_observations,
                            leaf_count,
                            fuel,
                            first_yield,
                        )
                    })
                    .await
                    .expect("nested child completed");
                assert!(matches!(&child.result, Ok(Ok(()))));
            }
            GuestCompletion {
                result: Ok(Ok(())),
                results: Vec::new(),
                store,
                host_panicked: false,
            }
        })
    }

    fn nested_depth64_guest(
        mut runtime: Runtime,
        owner: ChildContext,
        depth: u32,
        ready: Arc<Mutex<Option<oneshot::Sender<DeepAdmission>>>>,
        gate: Arc<Notify>,
    ) -> BoxFuture<'static, GuestCompletion> {
        Box::pin(async move {
            runtime.ownership = Some(owner.clone());
            runtime.storage.ownership = Some(owner.clone());
            let store = runtime.make_store(1_000_000).expect("nested Store");
            if depth == 63 {
                let budget = store
                    .data()
                    .invocation_budget
                    .as_ref()
                    .expect("root invocation budget")
                    .clone();
                let sender = ready
                    .lock()
                    .await
                    .take()
                    .expect("depth 63 admission sender");
                assert!(
                    sender
                        .send((owner.sender.clone(), owner.slot.clone(), budget))
                        .is_ok(),
                    "admission observer dropped"
                );
                gate.notified().await;
            }
            if depth < 64 {
                let child_runtime = runtime.clone();
                let child_ready = ready.clone();
                let child_gate = gate.clone();
                let child = owner
                    .run_guest(move |next| {
                        nested_depth64_guest(
                            child_runtime,
                            next,
                            depth + 1,
                            child_ready,
                            child_gate,
                        )
                    })
                    .await
                    .expect("nested child completed");
                assert!(matches!(&child.result, Ok(Ok(()))));
            }
            GuestCompletion {
                result: Ok(Ok(())),
                results: Vec::new(),
                store,
                host_panicked: false,
            }
        })
    }

    async fn one_object_pool(dir: &TempDir) -> Result<Pool<Manager>> {
        Ok(Pool::builder(Manager::new(
            dir.path().to_path_buf(),
            "owner.db".into(),
            Network::Regtest,
            100_000,
        )?)
        .max_size(1)
        .build()?)
    }

    async fn paid_receipt_snapshot(
        runtime: &mut Runtime,
        signer: &Signer,
        address: &ContractAddress,
        expr: &str,
    ) -> Result<PaidReceiptSnapshot> {
        let before = runtime.start_usage();
        let outcome = match runtime.execute_api(Some(signer), address, expr).await {
            Ok(value) => Ok(value),
            Err(ExecutionError::Deterministic(error)) => Err(error.to_string()),
            Err(error) => return Err(anyhow!("nondeterministic paid oracle: {error}")),
        };
        let usage = runtime.finish_usage(before)?;
        let mut rows = runtime
            .storage
            .conn
            .query(
                "SELECT contract_id, status, gas, value FROM contract_results ORDER BY id",
                (),
            )
            .await?;
        let row = rows.next().await?.context("paid receipt missing")?;
        let receipt = (
            row.get::<u64>(0)?,
            row.get::<String>(1)?,
            row.get::<u64>(2)?,
            row.get::<Option<String>>(3)?,
        );
        ensure!(rows.next().await?.is_none(), "duplicate paid receipt");
        drop(rows);
        Ok(PaidReceiptSnapshot {
            outcome,
            usage,
            receipt,
            payer: token::api::balance(runtime, HolderRef::from(signer)).await?,
            burner: token::api::balance(runtime, HolderRef::Burner).await?,
        })
    }

    async fn seeded_paid_oracle_with_name()
    -> Result<(Runtime, TempDir, String, Signer, ContractAddress)> {
        let (mut runtime, dir, name) = test_runtime().await?;
        let signer = Signer::Id(
            runtime
                .get_or_create_identity(&random_x_only_pubkey())
                .await?,
        );
        token::api::issue_to(
            &mut runtime,
            &Signer::Core(Box::new(Signer::Nobody)),
            HolderRef::from(&signer),
            Decimal::from("1000000000000"),
        )
        .await??;
        runtime
            .publish(
                &signer,
                Payment {
                    signer_id: signer.signer_id().context("test payer missing")?,
                    gas_limit: runtime.gas_limit_for_non_procs,
                },
                "ownership-paid-oracle",
                include_bytes!("../../../../test-contracts/binaries/error_test.wasm.br"),
                &native_provenance()?,
            )
            .await
            .map_err(anyhow::Error::from)?;
        runtime
            .storage
            .conn
            .execute("DELETE FROM contract_results", ())
            .await?;
        Ok((
            runtime,
            dir,
            name,
            signer,
            ContractAddress {
                name: "ownership-paid-oracle".to_string(),
                height: 0,
                tx_index: 0,
            },
        ))
    }

    async fn seeded_paid_oracle() -> Result<(Runtime, TempDir, Signer, ContractAddress)> {
        let (runtime, dir, _name, signer, address) = seeded_paid_oracle_with_name().await?;
        Ok((runtime, dir, signer, address))
    }

    async fn seeded_nested_paid_oracle()
    -> Result<(Runtime, TempDir, Signer, ContractAddress, ContractAddress)> {
        let (mut runtime, dir, signer, leaf) = seeded_paid_oracle().await?;
        let mut next = leaf.clone();
        for index in 0..2 {
            let name = format!("ownership-proxy-{index}");
            runtime
                .publish(
                    &signer,
                    Payment {
                        signer_id: signer.signer_id().context("test payer missing")?,
                        gas_limit: runtime.gas_limit_for_non_procs,
                    },
                    &name,
                    include_bytes!("../../../../test-contracts/binaries/proxy.wasm.br"),
                    &native_provenance()?,
                )
                .await
                .map_err(anyhow::Error::from)?;
            let address = ContractAddress {
                name,
                height: 0,
                tx_index: 0,
            };
            runtime
                .execute_api(
                    Some(&signer),
                    &address,
                    &format!("set-contract-address({})", to_wave_expr(next)),
                )
                .await
                .map_err(anyhow::Error::from)?;
            next = address;
        }
        runtime
            .storage
            .conn
            .execute("DELETE FROM contract_results", ())
            .await?;
        Ok((runtime, dir, signer, next, leaf))
    }

    async fn receipt_count(runtime: &Runtime) -> Result<i64> {
        let mut rows = runtime
            .storage
            .conn
            .query("SELECT COUNT(*) FROM contract_results", ())
            .await?;
        Ok(rows
            .next()
            .await?
            .context("receipt count missing")?
            .get(0)?)
    }

    async fn checkpoint_hash(conn: &Connection) -> Result<Option<String>> {
        let mut rows = conn
            .query(
                "SELECT hash FROM checkpoints ORDER BY height DESC LIMIT 1",
                (),
            )
            .await?;
        rows.next()
            .await?
            .map(|row| row.get(0))
            .transpose()
            .map_err(Into::into)
    }

    #[tokio::test]
    async fn dropped_view_keeps_pool_object_until_guest_store_is_joined() -> Result<()> {
        let dir = TempDir::new()?;
        let pool = one_object_pool(&dir).await?;
        let object = pool.get().await?;
        let service = OwnerService::new();
        let started = Arc::new(Notify::new());
        let child_started = started.clone();
        let handle = service
            .start_pooled(object, move |runtime| {
                Box::pin(async move {
                    let owner = runtime.ownership.clone().expect("owned runtime context");
                    let store = runtime.make_store(1_000_000)?;
                    owner
                        .run_guest(|child| async move {
                            let mut store = store;
                            store.data_mut().ownership = Some(child);
                            child_started.notify_one();
                            pending().await
                        })
                        .await?;
                    Ok(RootOutcome {
                        value: (),
                        commit: false,
                    })
                })
            })
            .await?;
        timeout(Duration::from_secs(2), started.notified()).await?;
        drop(handle);
        assert_eq!(pool.status().available, 0);
        let object = timeout(Duration::from_secs(2), pool.get()).await??;
        assert!(object.storage.conn.is_autocommit());
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_view_with_live_row_cursor_releases_snapshot_before_pool_reuse() -> Result<()>
    {
        let dir = TempDir::new()?;
        let writer = new_connection(dir.path(), "owner.db").await?;
        writer
            .execute(
                "CREATE TABLE ownership_cursor_probe (k INTEGER PRIMARY KEY)",
                (),
            )
            .await?;
        writer
            .execute("INSERT INTO ownership_cursor_probe (k) VALUES (1)", ())
            .await?;
        let pool = one_object_pool(&dir).await?;
        let object = pool.get().await?;
        let service = OwnerService::new();
        let cursor_open = Arc::new(Notify::new());
        let observed = cursor_open.notified();
        tokio::pin!(observed);
        observed.as_mut().enable();
        let opened = cursor_open.clone();
        let handle = service
            .start_pooled(object, move |runtime| {
                Box::pin(async move {
                    let mut rows = runtime
                        .storage
                        .conn
                        .query("SELECT k FROM ownership_cursor_probe ORDER BY k", ())
                        .await?;
                    ensure!(
                        rows.next()
                            .await?
                            .context("cursor row missing")?
                            .get::<i64>(0)?
                            == 1,
                        "unexpected first cursor row"
                    );
                    opened.notify_one();
                    pending::<()>().await;
                    drop(rows);
                    Ok(RootOutcome {
                        value: (),
                        commit: false,
                    })
                })
            })
            .await?;
        timeout(Duration::from_secs(10), observed).await?;
        writer
            .execute("INSERT INTO ownership_cursor_probe (k) VALUES (2)", ())
            .await?;
        drop(handle);
        let object = timeout(Duration::from_secs(4), pool.get()).await??;
        assert!(object.storage.conn.is_autocommit());
        assert!(object.storage.savepoint_stack.is_empty().await);
        let mut rows = object
            .storage
            .conn
            .query("SELECT COUNT(*) FROM ownership_cursor_probe", ())
            .await?;
        assert_eq!(
            rows.next()
                .await?
                .context("cursor count missing")?
                .get::<i64>(0)?,
            2
        );
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn owned_native_view_matches_direct_guest_result() -> Result<()> {
        let (mut seed, dir, name) = test_runtime().await?;
        let before = seed.start_usage();
        let baseline = token::api::balance(&mut seed, HolderRef::Burner).await?;
        let baseline_usage = seed.finish_usage(before)?;
        drop(seed);
        let pool = Pool::builder(Manager::new(
            dir.path().to_path_buf(),
            name,
            Network::Regtest,
            100_000,
        )?)
        .max_size(1)
        .build()?;
        let object = pool.get().await?;
        let service = OwnerService::new();
        let mut handle = service
            .start_pooled(object, |runtime| {
                Box::pin(async move {
                    let before = runtime.start_usage();
                    let value = token::api::balance(runtime, HolderRef::Burner).await?;
                    let usage = runtime.finish_usage(before)?;
                    Ok(RootOutcome {
                        value: (value, usage),
                        commit: false,
                    })
                })
            })
            .await?;
        assert_eq!(handle.result().await?, (baseline, baseline_usage));
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn owned_paid_call_matches_direct_value_fuel_receipt_and_settlement() -> Result<()> {
        let (mut runtime, _dir, signer, address) = seeded_paid_oracle().await?;
        let contract_id = runtime
            .storage
            .contract_id(&address)
            .await?
            .context("paid oracle contract missing")?;
        let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
        let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
        runtime.storage.savepoint().await?;
        let direct =
            paid_receipt_snapshot(&mut runtime, &signer, &address, "write-result-payload(1)")
                .await?;
        assert_eq!(direct.outcome, Ok("\"é\\n\"".to_string()));
        assert_eq!(direct.receipt.0, contract_id);
        assert_eq!(direct.receipt.1, "Ok");
        assert!(direct.receipt.2 > 0);
        assert!(direct.payer.as_ref() < payer_before.as_ref());
        assert!(direct.burner.as_ref() > burner_before.as_ref());
        runtime.storage.rollback().await?;
        assert!(runtime.storage.conn.is_autocommit());
        let owned = OwnedRuntimeSession::new(runtime);
        let owned_value = owned
            .run(true, move |runtime| {
                Box::pin(async move {
                    paid_receipt_snapshot(runtime, &signer, &address, "write-result-payload(1)")
                        .await
                })
            })
            .await?;
        assert_eq!(owned_value, direct);
        let checkout = owned.session.checkout().await?;
        let recovered = checkout.runtime.as_ref().context("owned runtime missing")?;
        assert!(recovered.storage.conn.is_autocommit());
        let mut rows = recovered
            .storage
            .conn
            .query("SELECT COUNT(*) FROM contract_results", ())
            .await?;
        assert_eq!(
            rows.next()
                .await?
                .context("receipt count missing")?
                .get::<i64>(0)?,
            1
        );
        Ok(())
    }

    fn linked_runtime_session(
        runtime: Runtime,
        canonical: bool,
    ) -> (LinkedSession, Arc<BundleSession>) {
        let conn = runtime.storage.conn.clone();
        let executor = link_runtime(runtime, canonical);
        let retained = executor
            .owner
            .clone()
            .downcast::<BundleSession>()
            .unwrap_or_else(|_| panic!("unexpected bundle session type"));
        (LinkedSession::new(conn, executor), retained)
    }

    #[tokio::test]
    async fn bundle_callbacks_preserve_real_paid_call_and_release_context() -> Result<()> {
        let (mut runtime, _dir, signer, address) = seeded_paid_oracle().await?;
        runtime.storage.savepoint().await?;
        let direct =
            paid_receipt_snapshot(&mut runtime, &signer, &address, "write-result-payload(1)")
                .await?;
        runtime.storage.rollback().await?;
        let selection = select_legacy_p1(
            &runtime.storage.conn,
            runtime.network,
            ApplicationPosition::View,
        )
        .await?;
        let envelope = selection.envelope();
        let (session, retained) = linked_runtime_session(runtime, false);
        let service = OwnerService::new();
        let owned = LinkedStatefulSession::new(session);
        let capacity = service.reserve_root_capacity().await?;
        let operation: LinkedOperation = Box::new(move |opaque, _| {
            Box::pin(async move {
                let session = opaque
                    .downcast::<BundleSession>()
                    .map_err(|_| (2, "unexpected executor session".into()))?;
                let mut runtime = session.runtime.lock().await;
                assert_eq!(
                    runtime.bundle_owner.as_ref().unwrap().fuel_yield_interval(),
                    Some(API_FUEL_YIELD_INTERVAL)
                );
                assert!(runtime.selected_context.is_some());
                drop(
                    runtime
                        .bind_selection(&envelope)
                        .map_err(|error| (0, error.to_string()))?,
                );
                assert!(runtime.selected_context.is_some());
                let mut changed = envelope.clone();
                changed.2.1 += 1;
                assert!(runtime.bind_selection(&changed).is_err());
                runtime.component_cache.clear();
                let value = paid_receipt_snapshot(
                    &mut runtime,
                    &signer,
                    &address,
                    "write-result-payload(1)",
                )
                .await
                .map_err(|error| (0, format!("{error:#}")))?;
                Ok((Box::new(value) as Payload, true))
            })
        });
        let mut handle = service
            .start_linked_stateful_reserved(&owned, capacity, selection, operation)
            .await?;
        let value = handle
            .result()
            .await?
            .downcast::<PaidReceiptSnapshot>()
            .map_err(|_| anyhow!("unexpected receipt payload"))?;
        assert_eq!(*value, direct);
        let checkout = owned.checkout().await?;
        assert!(checkout.value.as_ref().unwrap().conn.is_autocommit());
        let recovered = retained.runtime.lock().await;
        assert!(recovered.bundle_owner.is_none());
        assert!(recovered.storage.bundle_owner.is_none());
        assert!(recovered.selected_context.is_none());
        assert_eq!(receipt_count(&recovered).await?, 1);
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn bundle_canonical_hooks_preserve_paid_settlement_and_rollback() -> Result<()> {
        let (runtime, _dir, signer, address) = seeded_paid_oracle().await?;
        let (session, retained) = linked_runtime_session(runtime, true);
        let service = OwnerService::new();
        for commit in [false, true] {
            let selection = select_legacy_p1(
                &session.conn,
                Network::Regtest,
                ApplicationPosition::Committee,
            )
            .await?;
            let capacity = service.reserve_root_capacity().await?;
            let mut lease = service
                .begin_linked_canonical_reserved(&session, capacity, selection, false)
                .await?;
            {
                let mut runtime = retained.runtime.lock().await;
                assert_eq!(
                    runtime.bundle_owner.as_ref().unwrap().fuel_yield_interval(),
                    None
                );
                runtime.storage.savepoint().await?;
                let result = paid_receipt_snapshot(
                    &mut runtime,
                    &signer,
                    &address,
                    "write-result-payload(1)",
                )
                .await?;
                assert_eq!(result.receipt.1, "Ok");
            }
            lease.drain().await?;
            assert!(!session.conn.is_autocommit());
            assert!(retained.runtime.lock().await.selected_context.is_some());
            lease.settle(commit).await?;
            assert!(retained.runtime.lock().await.selected_context.is_some());
            lease.complete().await?;
            assert!(session.conn.is_autocommit());
            let runtime = retained.runtime.lock().await;
            assert_eq!(receipt_count(&runtime).await?, i64::from(commit));
            assert!(runtime.bundle_owner.is_none());
            assert!(runtime.selected_context.is_none());
            assert!(runtime.storage.savepoint_stack.is_empty().await);
            assert_eq!(service.active_roots().await, 0);
        }
        (session.executor.recycle)(session.executor.owner.clone())
            .await
            .map_err(|error| anyhow!("recycle failed: {error:?}"))?;
        Ok(())
    }

    #[tokio::test]
    async fn bundle_typed_operations_preserve_views_and_committee() -> Result<()> {
        let key = PrivateKey::from([7; 32]).public_key();
        let (mut runtime, _dir, _name) = test_runtime_with_genesis(&[GenesisValidator {
            x_only_pubkey: random_x_only_pubkey(),
            ed25519_pubkey: key.as_bytes().to_vec(),
            stake: Decimal::from("100.9999999"),
        }])
        .await?;
        let address = staking_address();
        let expected_view = runtime
            .execute(None, None, &address, "get-active-set()")
            .await?;
        let error = runtime
            .execute(None, None, &address, "missing-function()")
            .await
            .unwrap_err();
        let expected_error = (
            matches!(&error, ExecutionError::Deterministic(_)),
            format!("{error:?}"),
        );
        let expected_committee = derive_committee(&mut runtime).await?;
        let selection = select_legacy_p1(
            &runtime.storage.conn,
            runtime.network,
            ApplicationPosition::View,
        )
        .await?;
        let envelope = selection.envelope();
        let address = (address.name, address.height, address.tx_index);
        let (linked, retained) = linked_runtime_session(runtime, false);
        let view = retained.view();
        assert!(
            view(
                retained.clone(),
                envelope.clone(),
                address.clone(),
                "get-active-set()".into()
            )
            .await
            .is_err()
        );
        let service = OwnerService::new();
        let owned = LinkedStatefulSession::new(linked.clone());
        let operation: LinkedOperation = Box::new(move |opaque, _| {
            Box::pin(async move {
                assert_eq!(
                    view(
                        opaque.clone(),
                        envelope.clone(),
                        address.clone(),
                        "get-active-set()".into()
                    )
                    .await?,
                    Ok(expected_view)
                );
                assert_eq!(
                    view(
                        opaque.clone(),
                        envelope.clone(),
                        address.clone(),
                        "missing-function()".into()
                    )
                    .await?,
                    Err(expected_error)
                );
                let mut changed = envelope.clone();
                changed.2.1 += 1;
                assert!(
                    view(
                        opaque.clone(),
                        changed,
                        address.clone(),
                        "get-active-set()".into()
                    )
                    .await
                    .is_err()
                );
                let mut wrong_purpose = envelope.clone();
                wrong_purpose.3 = (1, 0, None, 0);
                assert!(
                    view(
                        opaque.clone(),
                        wrong_purpose,
                        address.clone(),
                        "get-active-set()".into()
                    )
                    .await
                    .is_err()
                );
                assert_eq!(
                    view(Arc::new(()), envelope, address, "get-active-set()".into())
                        .await
                        .unwrap_err()
                        .0,
                    2
                );
                Ok((Box::new(()) as Payload, false))
            })
        });
        let capacity = service.reserve_root_capacity().await?;
        let mut handle = service
            .start_linked_stateful_reserved(&owned, capacity, selection, operation)
            .await?;
        handle.result().await?;
        drop(owned.checkout().await?);
        drop(owned);
        assert!(retained.runtime.lock().await.selected_context.is_none());

        // The canonical session uses the same real runtime after the view root
        // has finished cleanup, with canonical settlement hooks instead.
        drop(linked);
        let runtime = Arc::try_unwrap(retained)
            .map_err(|_| anyhow!("view callbacks retained session"))?
            .runtime
            .into_inner();
        let (session, retained) = linked_runtime_session(runtime, true);
        let selection = select_legacy_p1(
            &session.conn,
            Network::Regtest,
            ApplicationPosition::Committee,
        )
        .await?;
        let envelope = selection.envelope();
        let capacity = service.reserve_root_capacity().await?;
        let mut lease = service
            .begin_linked_canonical_reserved(&session, capacity, selection, false)
            .await?;
        retained.runtime.lock().await.storage.savepoint().await?;
        let committee = retained.committee();
        assert_eq!(
            committee(retained.clone(), envelope.clone())
                .await
                .map_err(|error| anyhow!("{error:?}"))?,
            expected_committee
        );
        lease.drain().await?;
        lease.settle(false).await?;
        lease.complete().await?;
        assert!(committee(retained.clone(), envelope).await.is_err());
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn rollback_failure_quarantines_writer_without_durable_receipt_or_checkpoint()
    -> Result<()> {
        let (runtime, dir, name, signer, address) = seeded_paid_oracle_with_name().await?;
        let committed = new_connection(dir.path(), &name).await?;
        let checkpoint_before = checkpoint_hash(&committed).await?;
        let mut rows = committed
            .query("SELECT COUNT(*) FROM contract_results", ())
            .await?;
        assert_eq!(
            rows.next()
                .await?
                .context("receipt count missing")?
                .get::<i64>(0)?,
            0
        );
        drop(rows);
        let service = OwnerService::new();
        let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
        let pending_checkpoint = checkpoint_before.clone();
        let result = owned
            .run(false, move |runtime| {
                Box::pin(async move {
                    runtime
                        .execute_api(Some(&signer), &address, "write-result-payload(1)")
                        .await
                        .map_err(anyhow::Error::from)?;
                    ensure!(
                        receipt_count(runtime).await? == 1,
                        "paid receipt was not staged"
                    );
                    ensure!(
                        checkpoint_hash(&runtime.get_storage_conn()).await? != pending_checkpoint,
                        "state write did not stage a checkpoint"
                    );
                    runtime
                        .storage
                        .fail_rollback_once
                        .store(true, Ordering::SeqCst);
                    Ok(())
                })
            })
            .await;
        assert!(
            result
                .as_ref()
                .is_err_and(|error| error.to_string().contains("quarantined")),
            "rollback failure returned a success: {result:?}"
        );
        assert_eq!(service.quarantined_roots().await, 1);
        assert!(owned.session.checkout().await.is_err());
        let mut rows = committed
            .query("SELECT COUNT(*) FROM contract_results", ())
            .await?;
        assert_eq!(
            rows.next()
                .await?
                .context("receipt count missing")?
                .get::<i64>(0)?,
            0
        );
        drop(rows);
        assert_eq!(checkpoint_hash(&committed).await?, checkpoint_before);
        Ok(())
    }

    async fn injected_outer_commit_error_has_one_durable_result(after_commit: bool) -> Result<()> {
        let (mut runtime, dir, name, signer, address) = seeded_paid_oracle_with_name().await?;
        let committed = new_connection(dir.path(), &name).await?;
        let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
        let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
        let checkpoint_before = checkpoint_hash(&runtime.get_storage_conn()).await?;
        let engine = runtime.engine.clone();
        let linkers = runtime.linkers.clone();
        let cache = runtime.component_cache.clone();
        let service = OwnerService::new();
        let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
        let (staged_sender, staged_receiver) = oneshot::channel();
        let call_signer = signer.clone();
        let result = owned
            .run(true, move |runtime| {
                Box::pin(async move {
                    if after_commit {
                        runtime
                            .storage
                            .fail_outer_commit_after_once
                            .store(true, Ordering::SeqCst);
                    } else {
                        runtime
                            .storage
                            .fail_outer_commit_before_once
                            .store(true, Ordering::SeqCst);
                    }
                    let staged = paid_receipt_snapshot(
                        runtime,
                        &call_signer,
                        &address,
                        "write-result-payload(1)",
                    )
                    .await?;
                    let staged_checkpoint = checkpoint_hash(&runtime.get_storage_conn()).await?;
                    let _ = staged_sender.send((staged, staged_checkpoint));
                    Ok(())
                })
            })
            .await;
        assert!(
            result
                .as_ref()
                .is_err_and(|error| error.to_string().contains("quarantined")),
            "uncertain outer commit returned success: {result:?}"
        );
        let (staged, staged_checkpoint) = staged_receiver.await?;
        assert_eq!(staged.outcome, Ok("\"é\\n\"".to_string()));
        assert!(staged.payer.as_ref() < payer_before.as_ref());
        assert!(staged.burner.as_ref() > burner_before.as_ref());
        assert_ne!(staged_checkpoint, checkpoint_before);
        assert_eq!(service.quarantined_roots().await, 1);
        assert!(owned.session.checkout().await.is_err());
        assert!(
            timeout(
                Duration::from_secs(2),
                owned.run(false, |_runtime| Box::pin(async { Ok(()) }))
            )
            .await?
            .is_err(),
            "poisoned stateful session executed again"
        );

        let mut observer = Runtime::new_with(
            engine,
            linkers,
            cache,
            Storage::builder().conn(committed).build(),
        )
        .await?;
        assert_eq!(receipt_count(&observer).await?, i64::from(after_commit));
        assert_eq!(
            token::api::balance(&mut observer, HolderRef::from(&signer)).await?,
            if after_commit {
                staged.payer
            } else {
                payer_before
            }
        );
        assert_eq!(
            token::api::balance(&mut observer, HolderRef::Burner).await?,
            if after_commit {
                staged.burner
            } else {
                burner_before
            }
        );
        assert_eq!(
            checkpoint_hash(&observer.get_storage_conn()).await?,
            if after_commit {
                staged_checkpoint
            } else {
                checkpoint_before
            }
        );
        if after_commit {
            let mut rows = observer
                .storage
                .conn
                .query(
                    "SELECT contract_id, status, gas, value FROM contract_results ORDER BY id",
                    (),
                )
                .await?;
            let row = rows.next().await?.context("durable paid receipt missing")?;
            assert_eq!(
                (
                    row.get::<u64>(0)?,
                    row.get::<String>(1)?,
                    row.get::<u64>(2)?,
                    row.get::<Option<String>>(3)?,
                ),
                staged.receipt
            );
            assert!(rows.next().await?.is_none(), "duplicate durable receipt");
        }
        Ok(())
    }

    #[tokio::test]
    async fn failure_before_outer_commit_quarantines_without_settlement() -> Result<()> {
        injected_outer_commit_error_has_one_durable_result(false).await
    }

    #[tokio::test]
    async fn error_after_durable_outer_commit_quarantines_without_double_settlement() -> Result<()>
    {
        injected_outer_commit_error_has_one_durable_result(true).await
    }

    #[tokio::test]
    async fn paid_out_of_fuel_matches_with_and_without_api_yielding() -> Result<()> {
        let (mut runtime, _dir, signer, address) = seeded_paid_oracle().await?;
        ensure!(runtime.ownership.is_none(), "direct oracle has an owner");
        let contract_id = runtime
            .storage
            .contract_id(&address)
            .await?
            .context("out-of-fuel oracle contract missing")?;
        let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
        let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
        runtime.storage.savepoint().await?;
        let direct =
            paid_receipt_snapshot(&mut runtime, &signer, &address, "trap-out-of-fuel()").await?;
        assert!(direct.outcome.is_err());
        assert_eq!(direct.receipt.0, contract_id);
        assert_eq!(direct.receipt.1, "OutOfFuel");
        assert!(direct.receipt.2 > 0);
        assert!(direct.receipt.3.is_none());
        assert!(direct.usage.user_fuel >= API_FUEL_YIELD_INTERVAL);
        assert!(direct.payer.as_ref() < payer_before.as_ref());
        assert!(direct.burner.as_ref() > burner_before.as_ref());
        runtime.storage.rollback().await?;
        assert!(runtime.storage.conn.is_autocommit());
        let owned = OwnedRuntimeSession::new(runtime);
        let owned_value = owned
            .run(true, move |runtime| {
                Box::pin(async move {
                    ensure!(
                        runtime
                            .ownership
                            .as_ref()
                            .and_then(ChildContext::fuel_yield_interval)
                            == Some(API_FUEL_YIELD_INTERVAL),
                        "owned paid oracle did not enable API yielding"
                    );
                    paid_receipt_snapshot(runtime, &signer, &address, "trap-out-of-fuel()").await
                })
            })
            .await?;
        assert_eq!(owned_value, direct);
        let checkout = owned.session.checkout().await?;
        let recovered = checkout.runtime.as_ref().context("owned runtime missing")?;
        assert!(recovered.storage.conn.is_autocommit());
        let mut rows = recovered
            .storage
            .conn
            .query("SELECT COUNT(*) FROM contract_results", ())
            .await?;
        assert_eq!(
            rows.next()
                .await?
                .context("out-of-fuel receipt count missing")?
                .get::<i64>(0)?,
            1
        );
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_after_real_payment_hold_rolls_back_without_receipt() -> Result<()> {
        let (mut runtime, _dir, signer, _address) = seeded_paid_oracle().await?;
        let service = OwnerService::new();
        let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
        let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
        let payment = Payment {
            signer_id: signer.signer_id().context("test payer missing")?,
            gas_limit: runtime.gas_limit_for_non_procs,
        };
        let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
        let held = Arc::new(Notify::new());
        let observed = held.notified();
        tokio::pin!(observed);
        observed.as_mut().enable();
        let host_held = held.clone();
        let call_signer = signer.clone();
        let expected_payer = payer_before;
        let handle = service
            .start_stateful(&owned.session, move |runtime| {
                Box::pin(async move {
                    runtime
                        .with_payment(&payment, 1_000_000, async |runtime| {
                            let current =
                                token::api::balance(runtime, HolderRef::from(&call_signer))
                                    .await
                                    .map_err(ExecutionError::NonDeterministic)?;
                            if !matches!(
                                (current.as_ref(), expected_payer.as_ref()),
                                (Some(current), Some(expected)) if current < expected
                            ) {
                                return Err(ExecutionError::NonDeterministic(anyhow!(
                                    "payment hold did not reduce payer balance"
                                )));
                            }
                            host_held.notify_one();
                            pending::<Result<CallOutcome, ExecutionError>>().await
                        })
                        .await
                        .map_err(anyhow::Error::from)?;
                    Ok(RootOutcome {
                        value: (),
                        commit: true,
                    })
                })
            })
            .await?;
        timeout(Duration::from_secs(10), observed).await?;
        drop(handle);
        let mut checkout = timeout(Duration::from_secs(4), owned.session.checkout()).await??;
        let recovered = checkout
            .runtime
            .as_mut()
            .context("restored runtime missing")?;
        assert_eq!(
            token::api::balance(recovered, HolderRef::from(&signer)).await?,
            payer_before
        );
        assert_eq!(
            token::api::balance(recovered, HolderRef::Burner).await?,
            burner_before
        );
        assert_eq!(receipt_count(recovered).await?, 0);
        assert!(recovered.storage.conn.is_autocommit());
        assert!(recovered.storage.savepoint_stack.is_empty().await);
        assert!(recovered.stack.is_empty().await);
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_after_paid_settlement_before_outer_commit_rolls_back_once() -> Result<()> {
        let (mut runtime, _dir, signer, address) = seeded_paid_oracle().await?;
        let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
        let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
        let checkpoint_before = checkpoint_hash(&runtime.get_storage_conn()).await?;
        let service = OwnerService::new();
        let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
        let settled = Arc::new(Notify::new());
        let observed = settled.notified();
        tokio::pin!(observed);
        observed.as_mut().enable();
        let after_settlement = settled.clone();
        let call_signer = signer.clone();
        let handle = service
            .start_stateful(&owned.session, move |runtime| {
                Box::pin(async move {
                    let value = runtime
                        .execute_api(Some(&call_signer), &address, "write-result-payload(1)")
                        .await
                        .map_err(anyhow::Error::from)?;
                    ensure!(value == "\"é\\n\"", "unexpected paid result: {value}");
                    ensure!(
                        receipt_count(runtime).await? == 1,
                        "paid receipt was not staged"
                    );
                    after_settlement.notify_one();
                    pending::<()>().await;
                    Ok(RootOutcome {
                        value: (),
                        commit: true,
                    })
                })
            })
            .await?;
        timeout(Duration::from_secs(10), observed).await?;
        drop(handle);
        let mut checkout = timeout(Duration::from_secs(4), owned.session.checkout()).await??;
        let recovered = checkout
            .runtime
            .as_mut()
            .context("restored runtime missing")?;
        assert_eq!(receipt_count(recovered).await?, 0);
        assert_eq!(
            checkpoint_hash(&recovered.get_storage_conn()).await?,
            checkpoint_before
        );
        assert_eq!(
            token::api::balance(recovered, HolderRef::from(&signer)).await?,
            payer_before
        );
        assert_eq!(
            token::api::balance(recovered, HolderRef::Burner).await?,
            burner_before
        );
        assert!(recovered.storage.conn.is_autocommit());
        assert!(recovered.storage.savepoint_stack.is_empty().await);
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_between_footprint_update_and_state_write_restores_floor() -> Result<()> {
        let (mut runtime, _dir, signer, address) = seeded_paid_oracle().await?;
        let contract_id = runtime
            .storage
            .contract_id(&address)
            .await?
            .context("paid oracle contract missing")?;
        let depositor = signer.signer_id().context("test payer missing")?;
        let floor_before = runtime.storage.footprint().total_gas(depositor).await?;
        let checkpoint_before = checkpoint_hash(&runtime.get_storage_conn()).await?;
        let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
        let service = OwnerService::new();
        let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
        let updated = Arc::new(Notify::new());
        let observed = updated.notified();
        tokio::pin!(observed);
        observed.as_mut().enable();
        let host_updated = updated.clone();
        let handle = service
            .start_stateful(&owned.session, move |runtime| {
                Box::pin(async move {
                    runtime
                        .storage
                        .footprint()
                        .on_set(contract_id, b"cancel-gap", Some(depositor), Some(17))
                        .await?;
                    ensure!(
                        runtime.storage.footprint().total_gas(depositor).await?
                            == floor_before + 17,
                        "footprint update was not staged"
                    );
                    host_updated.notify_one();
                    pending::<()>().await;
                    runtime
                        .storage
                        .set(
                            contract_id,
                            b"cancel-gap",
                            b"value",
                            Some(depositor),
                            Some(17),
                        )
                        .await?;
                    Ok(RootOutcome {
                        value: (),
                        commit: true,
                    })
                })
            })
            .await?;
        timeout(Duration::from_secs(10), observed).await?;
        drop(handle);
        let mut checkout = timeout(Duration::from_secs(4), owned.session.checkout()).await??;
        let runtime = checkout
            .runtime
            .as_mut()
            .context("restored runtime missing")?;
        assert_eq!(
            runtime.storage.footprint().total_gas(depositor).await?,
            floor_before
        );
        assert_eq!(
            checkpoint_hash(&runtime.get_storage_conn()).await?,
            checkpoint_before
        );
        assert_eq!(receipt_count(runtime).await?, 0);
        assert_eq!(
            token::api::balance(runtime, HolderRef::from(&signer)).await?,
            payer_before
        );
        assert!(runtime.storage.conn.is_autocommit());
        assert!(runtime.storage.savepoint_stack.is_empty().await);
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_real_nested_host_write_joins_all_stores_and_rolls_back() -> Result<()> {
        let (mut runtime, _dir, signer, root, leaf) = seeded_nested_paid_oracle().await?;
        let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
        let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
        let observed_guest = Arc::new(Mutex::new(None));
        let guest_observation = observed_guest.clone();
        let entered = Arc::new(Notify::new());
        let host_entered = entered.clone();
        let mut user = runtime.linkers.user.clone();
        user.allow_shadowing(true)
            .instance("kontor:built-in/testing")?
            .func_wrap_async("host-error", move |store, (): ()| {
                let depth = store.data().ownership.as_ref().map(|owner| owner.depth);
                let interval = store
                    .data()
                    .ownership
                    .as_ref()
                    .and_then(ChildContext::fuel_yield_interval);
                let budget = store.data().invocation_budget.clone();
                let guest_observation = guest_observation.clone();
                let host_entered = host_entered.clone();
                Box::new(async move {
                    *guest_observation.lock().await = Some((depth, interval, budget));
                    host_entered.notify_one();
                    pending::<()>().await;
                    Ok((String::new(),))
                })
            })?;
        runtime.linkers = Arc::new(Linkers {
            user,
            native: runtime.linkers.native.clone(),
        });
        let service = OwnerService::new();
        let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
        let observed = entered.notified();
        tokio::pin!(observed);
        observed.as_mut().enable();
        let call_signer = signer.clone();
        let handle = service
            .start_stateful(&owned.session, move |runtime| {
                Box::pin(async move {
                    let value = runtime
                        .execute_api(Some(&call_signer), &root, "chain-probe(false)")
                        .await
                        .map_err(anyhow::Error::from)?;
                    Ok(RootOutcome {
                        value,
                        commit: true,
                    })
                })
            })
            .await?;
        timeout(Duration::from_secs(30), observed).await?;
        let (depth, interval, budget) = observed_guest
            .lock()
            .await
            .take()
            .context("nested guest observation missing")?;
        assert_eq!(depth, Some(3));
        assert_eq!(interval, Some(API_FUEL_YIELD_INTERVAL));
        let budget = budget.context("nested invocation budget missing")?;
        assert_eq!(budget.live(), 3);
        drop(handle);
        let mut checkout = timeout(Duration::from_secs(4), owned.session.checkout()).await??;
        let recovered = checkout
            .runtime
            .as_mut()
            .context("restored runtime missing")?;
        assert_eq!(budget.live(), 0);
        assert_eq!(receipt_count(recovered).await?, 0);
        assert_eq!(
            token::api::balance(recovered, HolderRef::from(&signer)).await?,
            payer_before
        );
        assert_eq!(
            token::api::balance(recovered, HolderRef::Burner).await?,
            burner_before
        );
        assert!(recovered.storage.conn.is_autocommit());
        assert!(recovered.storage.savepoint_stack.is_empty().await);
        assert!(recovered.stack.is_empty().await);
        assert_eq!(recovered.table.lock().await.iter_mut().count(), 0);
        assert_eq!(
            recovered
                .execute_api(None, &leaf, "storage-state()")
                .await?,
            "[0, 0, 0, 0]"
        );
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn caught_paid_host_panic_quarantines_writer_without_durable_receipt() -> Result<()> {
        let (runtime, _dir, signer, address) = seeded_paid_oracle().await?;
        let conn = runtime.get_storage_conn();
        let service = OwnerService::new();
        let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
        let result = owned
            .run(true, move |runtime| {
                Box::pin(async move {
                    runtime
                        .execute_api(Some(&signer), &address, "host-panic()")
                        .await
                        .map_err(anyhow::Error::from)
                })
            })
            .await;
        assert!(
            result
                .as_ref()
                .is_err_and(|error| error.to_string().contains("host panic")),
            "unexpected owned host panic result: {result:?}"
        );
        assert!(
            timeout(Duration::from_secs(2), owned.session.checkout())
                .await?
                .is_err(),
            "caught host panic returned the writer to service"
        );
        assert!(conn.is_autocommit());
        let mut rows = conn
            .query("SELECT COUNT(*) FROM contract_results", ())
            .await?;
        assert_eq!(
            rows.next()
                .await?
                .context("panic receipt count missing")?
                .get::<i64>(0)?,
            0
        );
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn swallowed_paid_host_panic_cannot_commit_writer() -> Result<()> {
        let (runtime, _dir, signer, address) = seeded_paid_oracle().await?;
        let conn = runtime.get_storage_conn();
        let service = OwnerService::new();
        let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
        let result = owned
            .run(true, move |runtime| {
                Box::pin(async move {
                    let error = runtime
                        .execute_api(Some(&signer), &address, "host-panic()")
                        .await
                        .expect_err("host panic must reach the caller");
                    assert!(error.to_string().contains("host panic"));
                    Ok(())
                })
            })
            .await;
        assert!(result.is_err(), "swallowed host panic committed the writer");
        assert!(
            timeout(Duration::from_secs(2), owned.session.checkout())
                .await?
                .is_err(),
            "swallowed host panic returned the writer to service"
        );
        assert!(conn.is_autocommit());
        let mut rows = conn
            .query("SELECT COUNT(*) FROM contract_results", ())
            .await?;
        assert_eq!(
            rows.next()
                .await?
                .context("panic receipt count missing")?
                .get::<i64>(0)?,
            0
        );
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn canonical_lease_drains_native_guest_before_releasing_runtime() -> Result<()> {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let service = OwnerService::new();
        let mut lease = service.begin_canonical(&mut runtime, false).await?;
        let _balance = token::api::balance(&mut runtime, HolderRef::Burner).await?;
        lease.drain(&runtime).await?;
        lease.complete(&mut runtime).await?;
        assert_eq!(service.active_roots().await, 0);
        assert!(runtime.ownership.is_none());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn canonical_drain_waits_for_supervisor_runtime_release() -> Result<()> {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let service = OwnerService::new();
        let gate = Arc::new(AsyncGate::default());
        let _release = ReleaseAsyncGate(gate.clone());
        service.set_canonical_release_gate(gate.clone());
        let mut lease = service.begin_canonical(&mut runtime, false).await?;
        let mut drain = Box::pin(lease.drain(&runtime));
        timeout(Duration::from_secs(2), async {
            while !gate.entered.load(Ordering::SeqCst) {
                assert!(
                    tokio::select! {
                        result = &mut drain => Some(result),
                        () = tokio::task::yield_now() => None,
                    }
                    .is_none(),
                    "drain completed while supervisor retained the runtime"
                );
            }
        })
        .await?;
        assert!(drain.as_mut().now_or_never().is_none());
        gate.release();
        drain.await?;
        lease.complete(&mut runtime).await?;

        let mut next = service.begin_canonical(&mut runtime, false).await?;
        next.drain(&runtime).await?;
        next.complete(&mut runtime).await?;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn canonical_and_simulation_children_keep_no_yield_policy() -> Result<()> {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let service = OwnerService::new();
        let component = Arc::new(Component::new(&runtime.engine, PURE_LOOP_COMPONENT)?);
        for simulation in [false, true] {
            let mut lease = service.begin_canonical(&mut runtime, simulation).await?;
            let owner = runtime.ownership.clone().context("root context missing")?;
            assert_eq!(owner.fuel_yield_interval(), None);
            let (root_observation, root_store) =
                run_pure_loop_in_store(runtime.make_store(20_000_000)?, &component, 200_000, None)
                    .await?;
            let observations = Arc::new(Mutex::new(vec![(
                0,
                root_observation.0,
                root_observation.1,
                root_observation.2,
            )]));
            let child_runtime = runtime.clone();
            let child_component = component.clone();
            let child_observations = observations.clone();
            let child = owner
                .run_guest(move |next| {
                    nested_yield_guest(
                        child_runtime,
                        next,
                        child_component,
                        1,
                        child_observations,
                        200_000,
                        20_000_000,
                        None,
                    )
                })
                .await?;
            ensure!(matches!(&child.result, Ok(Ok(()))), "nested call failed");
            drop(child);
            drop(root_store);
            for (depth, value, remaining, yielded) in observations.lock().await.iter() {
                assert!(!yielded, "depth {depth} yielded in canonical execution");
                assert_eq!(value, &Val::U32(200_000));
                assert!(*remaining < 20_000_000);
            }
            assert_eq!(observations.lock().await.len(), 3);
            lease.drain(&runtime).await?;
            lease.complete(&mut runtime).await?;
            assert!(runtime.ownership.is_none());
            assert_eq!(service.active_roots().await, 0);
        }
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn api_fuel_yield_preserves_pure_pulley_result_fuel_and_gas() -> Result<()> {
        let (runtime, _dir, _name) = test_runtime().await?;
        let component = Component::new(&runtime.engine, PURE_LOOP_COMPONENT)?;
        let fuel = 20_000_000;
        let api = run_pure_loop(&runtime, &component, RootKind::Api, 200_000, fuel).await?;
        let canonical =
            run_pure_loop(&runtime, &component, RootKind::Canonical, 200_000, fuel).await?;
        let simulation =
            run_pure_loop(&runtime, &component, RootKind::Simulation, 200_000, fuel).await?;
        assert!(api.2, "API pure guest did not yield before completion");
        assert!(!canonical.2, "canonical pure guest yielded");
        assert!(!simulation.2, "simulation pure guest yielded");
        assert_eq!(api.0, Val::U32(200_000));
        assert_eq!((&api.0, api.1), (&canonical.0, canonical.1));
        assert_eq!((&canonical.0, canonical.1), (&simulation.0, simulation.1));
        assert_eq!(
            runtime.gas_consumed(fuel, api.1),
            runtime.gas_consumed(fuel, canonical.1)
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nested_api_children_inherit_actual_fuel_yields() -> Result<()> {
        let (runtime, _dir, _name) = test_runtime().await?;
        let service = OwnerService::new();
        let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
        let mut handle = service
            .start_stateful(&owned.session, |runtime| {
                Box::pin(async move {
                    let component = Arc::new(Component::new(&runtime.engine, PURE_LOOP_COMPONENT)?);
                    let owner = runtime.ownership.clone().context("root context missing")?;
                    let (root_observation, root_store) = run_pure_loop_in_store(
                        runtime.make_store(20_000_000)?,
                        &component,
                        200_000,
                        None,
                    )
                    .await?;
                    let observations = Arc::new(Mutex::new(vec![(
                        0,
                        root_observation.0,
                        root_observation.1,
                        root_observation.2,
                    )]));
                    let child_runtime = runtime.clone();
                    let child_component = component.clone();
                    let child_observations = observations.clone();
                    let child = owner
                        .run_guest(move |next| {
                            nested_yield_guest(
                                child_runtime,
                                next,
                                child_component,
                                1,
                                child_observations,
                                200_000,
                                20_000_000,
                                None,
                            )
                        })
                        .await?;
                    ensure!(matches!(&child.result, Ok(Ok(()))), "nested call failed");
                    drop(child);
                    drop(root_store);
                    let values = observations.lock().await.clone();
                    Ok(RootOutcome {
                        value: values,
                        commit: false,
                    })
                })
            })
            .await?;
        let observations = handle.result().await?;
        assert_eq!(observations.len(), 3);
        let expected_fuel = observations[0].2;
        for (index, (depth, value, remaining, yielded)) in observations.into_iter().enumerate() {
            assert_eq!(depth as usize, index);
            assert!(yielded, "depth {depth} API child did not yield");
            assert_eq!(value, Val::U32(200_000));
            assert_eq!(remaining, expected_fuel);
        }
        assert!(expected_fuel < 20_000_000);
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelling_nested_yielding_api_guest_joins_before_runtime_reuse() -> Result<()> {
        let (runtime, _dir, _name) = test_runtime().await?;
        let service = OwnerService::new();
        let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
        let leaf_yielded = Arc::new(AtomicBool::new(false));
        let observed_yield = leaf_yielded.clone();
        let handle = service
            .start_stateful(&owned.session, move |runtime| {
                Box::pin(async move {
                    let component = Arc::new(Component::new(&runtime.engine, PURE_LOOP_COMPONENT)?);
                    let owner = runtime.ownership.clone().context("root context missing")?;
                    let child_runtime = runtime.clone();
                    let observations = Arc::new(Mutex::new(Vec::new()));
                    owner
                        .run_guest(move |next| {
                            nested_yield_guest(
                                child_runtime,
                                next,
                                component,
                                1,
                                observations,
                                100_000_000,
                                2_000_000_000,
                                Some(observed_yield),
                            )
                        })
                        .await?;
                    Ok(RootOutcome {
                        value: (),
                        commit: false,
                    })
                })
            })
            .await?;
        timeout(Duration::from_secs(10), async {
            while !leaf_yielded.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        drop(handle);
        let mut checkout = timeout(Duration::from_secs(4), owned.session.checkout()).await??;
        let recovered = checkout
            .runtime
            .as_mut()
            .context("restored runtime missing")?;
        assert!(recovered.storage.conn.is_autocommit());
        assert!(recovered.storage.savepoint_stack.is_empty().await);
        assert!(recovered.stack.is_empty().await);
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelling_fuel_yielding_guest_joins_before_pool_reuse() -> Result<()> {
        let (seed, dir, name) = test_runtime().await?;
        drop(seed);
        let pool = Pool::builder(Manager::new(
            dir.path().to_path_buf(),
            name,
            Network::Regtest,
            100_000,
        )?)
        .max_size(1)
        .build()?;
        let object: Object<Manager> = pool.get().await?;
        let cached = Component::new(&object.engine, PURE_LOOP_COMPONENT)?;
        object
            .component_cache
            .put_selected(
                ComponentSource::new(u64::MAX, PURE_LOOP_COMPONENT.as_bytes()),
                object.executor_version,
                cached,
                PURE_LOOP_COMPONENT.len(),
            )
            .await?;
        let service = OwnerService::new();
        let entered = Arc::new(AtomicBool::new(false));
        let guest_entered = entered.clone();
        let handle = service
            .start_pooled(object, move |runtime| {
                Box::pin(async move {
                    let component = Component::new(&runtime.engine, PURE_LOOP_COMPONENT)?;
                    let mut store = runtime.make_store(500_000_000)?;
                    let linker = Linker::<Runtime>::new(&runtime.engine);
                    let instance = linker.instantiate_async(&mut store, &component).await?;
                    let run = instance
                        .get_func(&mut store, "run")
                        .context("pure loop export missing")?;
                    let mut results = [Val::U32(0)];
                    guest_entered.store(true, Ordering::SeqCst);
                    run.call_async(&mut store, &[Val::U32(20_000_000)], &mut results)
                        .await?;
                    Ok(RootOutcome {
                        value: (),
                        commit: false,
                    })
                })
            })
            .await?;
        timeout(Duration::from_secs(10), async {
            while !entered.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(pool.status().available, 0);
        drop(handle);
        let object = timeout(Duration::from_secs(2), pool.get()).await??;
        assert!(object.storage.conn.is_autocommit());
        assert!(object.component_cache.get(&u64::MAX).await.is_some());
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn eight_view_roots_measure_normal_and_cancelled_drain() -> Result<()> {
        let (mut seed, dir, name) = test_runtime().await?;
        let baseline = token::api::balance(&mut seed, HolderRef::Burner).await?;
        drop(seed);
        let pool: Pool<Manager> = Pool::builder(Manager::new(
            dir.path().to_path_buf(),
            name,
            Network::Regtest,
            100_000,
        )?)
        .max_size(8)
        .build()?;
        let mut prewarmed = Vec::new();
        for _ in 0..8 {
            prewarmed.push(pool.get().await?);
        }
        for object in &mut prewarmed {
            assert_eq!(
                token::api::balance(object, HolderRef::Burner).await?,
                baseline
            );
        }
        drop(prewarmed);
        let unowned_started = Instant::now();
        let mut unowned = JoinSet::new();
        for _ in 0..8 {
            let mut object = pool.get().await?;
            unowned.spawn(async move { token::api::balance(&mut object, HolderRef::Burner).await });
        }
        while let Some(result) = unowned.join_next().await {
            assert_eq!(result??, baseline);
        }
        let unowned_elapsed = unowned_started.elapsed();
        assert_eq!(pool.status().available, 8);
        let service = OwnerService::new();
        let normal_started = Instant::now();
        let mut normal = Vec::new();
        for _ in 0..8 {
            let object = pool.get().await?;
            normal.push(
                service
                    .start_pooled(object, |runtime| {
                        Box::pin(async move {
                            Ok(RootOutcome {
                                value: token::api::balance(runtime, HolderRef::Burner).await?,
                                commit: false,
                            })
                        })
                    })
                    .await?,
            );
        }
        for mut handle in normal {
            assert_eq!(handle.result().await?, baseline);
        }
        let normal_elapsed = normal_started.elapsed();

        let started = Arc::new(AtomicUsize::new(0));
        let mut cancelled = Vec::new();
        for _ in 0..8 {
            let object = pool.get().await?;
            let guest_started = started.clone();
            cancelled.push(
                service
                    .start_pooled(object, move |runtime| {
                        Box::pin(async move {
                            let component = Component::new(&runtime.engine, PURE_LOOP_COMPONENT)?;
                            let mut store = runtime.make_store(2_000_000_000)?;
                            let linker = Linker::<Runtime>::new(&runtime.engine);
                            let instance = linker.instantiate_async(&mut store, &component).await?;
                            let run = instance
                                .get_func(&mut store, "run")
                                .context("pure loop export missing")?;
                            let mut results = [Val::U32(0)];
                            guest_started.fetch_add(1, Ordering::SeqCst);
                            run.call_async(&mut store, &[Val::U32(100_000_000)], &mut results)
                                .await?;
                            Ok(RootOutcome {
                                value: (),
                                commit: false,
                            })
                        })
                    })
                    .await?,
            );
        }
        timeout(Duration::from_secs(10), async {
            while started.load(Ordering::SeqCst) != 8 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(pool.status().available, 0);
        let cancelled_started = Instant::now();
        drop(cancelled);
        timeout(Duration::from_secs(5), async {
            while service.active_roots().await != 0 || pool.status().available != 8 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let cancelled_elapsed = cancelled_started.elapsed();
        println!(
            "eight view roots: unowned_ms={}, owned_ms={}, cancel_drain_ms={}",
            unowned_elapsed.as_millis(),
            normal_elapsed.as_millis(),
            cancelled_elapsed.as_millis()
        );
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_publication_rolls_back_outer_root_transaction() -> Result<()> {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let signer = Signer::Id(
            runtime
                .get_or_create_identity(&random_x_only_pubkey())
                .await?,
        );
        token::api::issue_to(
            &mut runtime,
            &Signer::Core(Box::new(Signer::Nobody)),
            HolderRef::from(&signer),
            Decimal::from("1000000000000"),
        )
        .await??;
        let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
        let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
        let payment = Payment {
            signer_id: signer.signer_id().context("test payer identity missing")?,
            gas_limit: runtime.gas_limit_for_non_procs,
        };
        let service = OwnerService::new();
        let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
        let published = Arc::new(Notify::new());
        let published_id = Arc::new(AtomicU64::new(0));
        let observed = published.notified();
        tokio::pin!(observed);
        observed.as_mut().enable();
        let after_publish = published.clone();
        let recorded_id = published_id.clone();
        let published_signer = signer.clone();
        let handle = service
            .start_stateful(&owned.session, move |runtime| {
                Box::pin(async move {
                    runtime
                        .publish(
                            &published_signer,
                            payment,
                            "ownership-publish-cancel",
                            include_bytes!(
                                "../../../../test-contracts/binaries/error_test.wasm.br"
                            ),
                            &native_provenance()?,
                        )
                        .await
                        .map_err(anyhow::Error::from)?;
                    let address = ContractAddress {
                        name: "ownership-publish-cancel".to_string(),
                        height: 0,
                        tx_index: 0,
                    };
                    let contract_id = runtime
                        .storage
                        .contract_id(&address)
                        .await?
                        .context("published contract row missing before cancellation")?;
                    assert!(runtime.component_cache.get(&contract_id).await.is_some());
                    recorded_id.store(contract_id, Ordering::SeqCst);
                    after_publish.notify_one();
                    pending::<()>().await;
                    Ok(RootOutcome {
                        value: (),
                        commit: true,
                    })
                })
            })
            .await?;
        timeout(Duration::from_secs(10), observed).await?;
        drop(handle);
        let mut checkout = timeout(Duration::from_secs(2), owned.session.checkout()).await??;
        let recovered = checkout
            .runtime
            .as_mut()
            .context("restored runtime missing")?;
        let address = ContractAddress {
            name: "ownership-publish-cancel".to_string(),
            height: 0,
            tx_index: 0,
        };
        assert!(recovered.storage.contract_id(&address).await?.is_none());
        let mut receipts = recovered
            .storage
            .conn
            .query(
                "SELECT COUNT(*) FROM contract_results WHERE contract_id = ?",
                [published_id.load(Ordering::SeqCst)],
            )
            .await?;
        assert_eq!(
            receipts
                .next()
                .await?
                .context("publication receipt count missing")?
                .get::<i64>(0)?,
            0
        );
        assert!(
            recovered
                .component_cache
                .get(&published_id.load(Ordering::SeqCst))
                .await
                .is_none()
        );
        assert!(recovered.storage.conn.is_autocommit());
        assert_eq!(
            token::api::balance(recovered, HolderRef::from(&signer)).await?,
            payer_before
        );
        assert_eq!(
            token::api::balance(recovered, HolderRef::Burner).await?,
            burner_before
        );
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_cold_publication_waits_for_decode_and_compile_workers() -> Result<()> {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let signer = Signer::Id(
            runtime
                .get_or_create_identity(&random_x_only_pubkey())
                .await?,
        );
        token::api::issue_to(
            &mut runtime,
            &Signer::Core(Box::new(Signer::Nobody)),
            HolderRef::from(&signer),
            Decimal::from("1000000000000"),
        )
        .await??;
        let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
        let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
        let receipts_before = receipt_count(&runtime).await?;
        let checkpoint_before = checkpoint_hash(&runtime.get_storage_conn()).await?;
        let gas_limit = runtime.gas_limit_for_non_procs;
        let service = OwnerService::new();
        let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
        for decode in [true, false] {
            let gate = Arc::new(BlockingGate::default());
            let _release = ReleaseBlockingGate(gate.clone());
            let name = if decode {
                "ownership-cold-decode-cancel"
            } else {
                "ownership-cold-compile-cancel"
            };
            let address = ContractAddress {
                name: name.to_string(),
                height: 0,
                tx_index: 0,
            };
            {
                let mut checkout = owned.session.checkout().await?;
                let runtime = checkout.runtime.as_mut().context("writer missing")?;
                runtime.storage.decode_gate = decode.then(|| gate.clone());
                runtime.compile_gate = (!decode).then(|| gate.clone());
            }
            let payment = Payment {
                signer_id: signer.signer_id().context("test payer missing")?,
                gas_limit,
            };
            let call_signer = signer.clone();
            let handle = service
                .start_stateful(&owned.session, move |runtime| {
                    Box::pin(async move {
                        runtime
                            .publish(
                                &call_signer,
                                payment,
                                name,
                                include_bytes!(
                                    "../../../../test-contracts/binaries/error_test.wasm.br"
                                ),
                                &native_provenance()?,
                            )
                            .await
                            .map_err(anyhow::Error::from)?;
                        Ok(RootOutcome {
                            value: (),
                            commit: true,
                        })
                    })
                })
                .await?;
            timeout(Duration::from_secs(30), async {
                while !gate.entered.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            drop(handle);
            let retained = timeout(Duration::from_millis(100), owned.session.checkout())
                .await
                .is_err();
            gate.release();
            let mut checkout = timeout(Duration::from_secs(5), owned.session.checkout()).await??;
            assert!(
                retained,
                "cold worker released the writer before it finished"
            );
            let runtime = checkout.runtime.as_mut().context("writer missing")?;
            assert!(runtime.storage.contract_id(&address).await?.is_none());
            assert_eq!(receipt_count(runtime).await?, receipts_before);
            assert_eq!(
                checkpoint_hash(&runtime.get_storage_conn()).await?,
                checkpoint_before
            );
            assert_eq!(
                token::api::balance(runtime, HolderRef::from(&signer)).await?,
                payer_before
            );
            assert_eq!(
                token::api::balance(runtime, HolderRef::Burner).await?,
                burner_before
            );
            assert!(runtime.storage.conn.is_autocommit());
            assert!(runtime.storage.savepoint_stack.is_empty().await);
            runtime.storage.decode_gate = None;
            runtime.compile_gate = None;
            assert_eq!(service.active_roots().await, 0);
        }
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_while_publication_guest_init_is_pending_rolls_back_everything() -> Result<()>
    {
        let (mut runtime, _dir, signer, _address) = seeded_paid_oracle().await?;
        let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
        let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
        let checkpoint_before = checkpoint_hash(&runtime.get_storage_conn()).await?;
        let receipts_before = receipt_count(&runtime).await?;
        let mut rows = runtime
            .storage
            .conn
            .query("SELECT COALESCE(MAX(id), 0) + 1 FROM contracts", ())
            .await?;
        let next_contract_id: u64 = rows
            .next()
            .await?
            .context("next contract id missing")?
            .get(0)?;
        drop(rows);
        let gate = Arc::new(AsyncGate::default());
        runtime.init_host_gate = Some((next_contract_id, gate.clone()));
        let payment = Payment {
            signer_id: signer.signer_id().context("test payer missing")?,
            gas_limit: runtime.gas_limit_for_non_procs,
        };
        let service = OwnerService::new();
        let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
        let call_signer = signer.clone();
        let handle = service
            .start_stateful(&owned.session, move |runtime| {
                Box::pin(async move {
                    runtime
                        .publish(
                            &call_signer,
                            payment,
                            "ownership-init-cancel",
                            include_bytes!(
                                "../../../../test-contracts/binaries/error_test.wasm.br"
                            ),
                            &native_provenance()?,
                        )
                        .await
                        .map_err(anyhow::Error::from)?;
                    Ok(RootOutcome {
                        value: (),
                        commit: true,
                    })
                })
            })
            .await?;
        let entered = timeout(Duration::from_secs(30), async {
            while !gate.entered.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await;
        if entered.is_err() {
            gate.release();
            drop(handle);
            return Err(anyhow!(
                "publication init did not enter its storage host call"
            ));
        }
        drop(handle);
        let checkout = timeout(Duration::from_secs(5), owned.session.checkout()).await;
        gate.release();
        let mut checkout = checkout??;
        let runtime = checkout
            .runtime
            .as_mut()
            .context("restored writer missing")?;
        let address = ContractAddress {
            name: "ownership-init-cancel".to_string(),
            height: 0,
            tx_index: 0,
        };
        assert!(runtime.storage.contract_id(&address).await?.is_none());
        assert_eq!(receipt_count(runtime).await?, receipts_before);
        assert_eq!(
            checkpoint_hash(&runtime.get_storage_conn()).await?,
            checkpoint_before
        );
        assert_eq!(
            token::api::balance(runtime, HolderRef::from(&signer)).await?,
            payer_before
        );
        assert_eq!(
            token::api::balance(runtime, HolderRef::Burner).await?,
            burner_before
        );
        assert!(runtime.storage.conn.is_autocommit());
        assert!(runtime.storage.savepoint_stack.is_empty().await);
        assert!(runtime.stack.is_empty().await);
        assert_eq!(runtime.table.lock().await.iter_mut().count(), 0);
        assert!(runtime.invocation_budget.is_none());
        runtime.init_host_gate = None;
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_and_commit_authorization_have_one_durable_outcome() -> Result<()> {
        let (runtime, _dir, _name) = test_runtime().await?;
        runtime
            .storage
            .conn
            .execute(
                "CREATE TABLE ownership_commit_race (id INTEGER PRIMARY KEY)",
                (),
            )
            .await?;
        let mut runtime = runtime;

        for id in 1..=10i64 {
            let capacity = Arc::new(Semaphore::new(1)).acquire_owned().await?;
            let keeper = Arc::new(RootKeeper::new_stateful(
                RootId(id as u64),
                runtime,
                capacity,
            ));
            {
                let mut authority = keeper.authority.lock().await;
                let runtime = authority.as_mut().expect("root authority retained");
                runtime.storage.savepoint().await?;
                runtime
                    .storage
                    .conn
                    .execute("INSERT INTO ownership_commit_race (id) VALUES (?)", [id])
                    .await?;
            }
            let committed = if id == 1 {
                keeper.close();
                restore(
                    &keeper,
                    Ok(RootOutcome {
                        value: (),
                        commit: true,
                    }),
                )
                .await?
                .is_ok()
            } else if id == 2 {
                let committed = restore(
                    &keeper,
                    Ok(RootOutcome {
                        value: (),
                        commit: true,
                    }),
                )
                .await?
                .is_ok();
                keeper.close();
                committed
            } else {
                let barrier = Arc::new(Barrier::new(3));
                let cancellation_keeper = keeper.clone();
                let cancellation_barrier = barrier.clone();
                let cancellation = tokio::spawn(async move {
                    cancellation_barrier.wait().await;
                    cancellation_keeper.close();
                });
                let commit_keeper = keeper.clone();
                let commit_barrier = barrier.clone();
                let commit = tokio::spawn(async move {
                    commit_barrier.wait().await;
                    restore(
                        &commit_keeper,
                        Ok(RootOutcome {
                            value: (),
                            commit: true,
                        }),
                    )
                    .await
                });
                barrier.wait().await;
                cancellation.await?;
                commit.await??.is_ok()
            };
            if id == 1 {
                assert!(!committed, "cancellation won before authorization");
            } else if id == 2 {
                assert!(committed, "commit was authorized before cancellation");
            }
            let count = {
                let authority = keeper.authority.lock().await;
                let runtime = authority.as_ref().expect("root authority retained");
                let mut rows = runtime
                    .storage
                    .conn
                    .query(
                        "SELECT COUNT(*) FROM ownership_commit_race WHERE id = ?",
                        [id],
                    )
                    .await?;
                rows.next()
                    .await?
                    .context("commit count missing")?
                    .get::<i64>(0)?
            };
            assert_eq!(count, i64::from(committed));
            assert_eq!(
                RootState::load(&keeper.state),
                if committed {
                    RootState::Committing
                } else {
                    RootState::Closing
                }
            );
            runtime = match keeper
                .authority
                .lock()
                .await
                .take()
                .context("root authority missing after race")?
            {
                RootAuthority::Stateful(runtime) => runtime,
                RootAuthority::Pooled(_)
                | RootAuthority::LinkedPooled(_)
                | RootAuthority::LinkedStateful(_) => {
                    unreachable!("race uses a stateful writer")
                }
            };
        }
        Ok(())
    }

    #[tokio::test]
    async fn canonical_child_panic_cannot_commit_or_leave_reactor_waiting() -> Result<()> {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let service = OwnerService::new();
        let mut lease = service.begin_canonical(&mut runtime, false).await?;
        runtime.storage.savepoint().await?;
        let owner = runtime
            .ownership
            .clone()
            .expect("canonical context installed");
        let result = timeout(
            Duration::from_secs(2),
            owner.run_guest(|_| async { panic!("forced canonical child failure") }),
        )
        .await?;
        assert!(result.is_err());
        assert!(runtime.storage.commit().await.is_err());
        assert!(lease.drain(&runtime).await.is_err());
        drop(lease);
        assert!(service.is_fatal());
        Ok(())
    }

    #[tokio::test]
    async fn abandoned_canonical_guest_cannot_commit() -> Result<()> {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let service = OwnerService::new();
        let mut lease = service.begin_canonical(&mut runtime, false).await?;
        runtime.storage.savepoint().await?;
        let mut store = runtime.make_store(1_000_000)?;
        let owner = runtime
            .ownership
            .clone()
            .expect("canonical context installed");
        let started = Arc::new(Notify::new());
        let observed = started.notified();
        tokio::pin!(observed);
        observed.as_mut().enable();
        let child_started = started.clone();
        let request = tokio::spawn(async move {
            owner
                .run_guest(|child| async move {
                    store.data_mut().ownership = Some(child);
                    child_started.notify_one();
                    pending().await
                })
                .await
        });
        timeout(Duration::from_secs(2), observed).await?;
        request.abort();
        let _ = request.await;
        assert!(
            timeout(Duration::from_secs(2), lease.drain(&runtime))
                .await?
                .is_err()
        );
        assert!(runtime.storage.commit().await.is_err());
        drop(lease);
        assert!(service.is_fatal());
        Ok(())
    }

    #[tokio::test]
    async fn stateful_session_retains_runtime_across_owned_calls() -> Result<()> {
        let (runtime, _dir, _name) = test_runtime().await?;
        let session = OwnedRuntimeSession::new(runtime);
        session
            .run(false, |runtime| {
                Box::pin(async move {
                    runtime.node_label = "owned-session".to_string();
                    Ok(())
                })
            })
            .await?;
        let label = session
            .run(false, |runtime| {
                Box::pin(async move { Ok(runtime.node_label.clone()) })
            })
            .await?;
        assert_eq!(label, "owned-session");
        Ok(())
    }

    #[tokio::test]
    async fn dropped_stateful_call_releases_runtime_only_after_child_join() -> Result<()> {
        let (runtime, _dir, _name) = test_runtime().await?;
        let session = OwnedRuntimeSession::new(runtime);
        let started = Arc::new(Notify::new());
        let child_started = started.clone();
        let interrupted = session.clone();
        let request = tokio::spawn(async move {
            interrupted
                .run(false, move |runtime| {
                    Box::pin(async move {
                        let owner = runtime.ownership.clone().expect("owned runtime context");
                        let store = runtime.make_store(1_000_000)?;
                        owner
                            .run_guest(|child| async move {
                                let mut store = store;
                                store.data_mut().ownership = Some(child);
                                child_started.notify_one();
                                pending().await
                            })
                            .await?;
                        Ok(())
                    })
                })
                .await
        });
        timeout(Duration::from_secs(2), started.notified()).await?;
        request.abort();
        let _ = request.await;
        let _label = timeout(
            Duration::from_secs(2),
            session.run(false, |runtime| {
                Box::pin(async move { Ok(runtime.node_label.clone()) })
            }),
        )
        .await??;
        Ok(())
    }

    #[tokio::test]
    async fn undelivered_store_retains_parent_slot() -> Result<()> {
        let dir = TempDir::new()?;
        let pool = one_object_pool(&dir).await?;
        let object = pool.get().await?;
        let store = object.make_store(1_000_000)?;
        let budget = store.data().invocation_budget.as_ref().unwrap().clone();
        let slot = Arc::new(AtomicBool::new(true));
        let (sender, receiver) = oneshot::channel();
        sender
            .send(GuestDelivery {
                completion: TaskCompletion::Local(GuestCompletion {
                    result: Ok(Ok(())),
                    results: Vec::new(),
                    store,
                    host_panicked: false,
                }),
                slot: SlotLease(slot.clone()),
            })
            .map_err(|_| anyhow!("delivery receiver closed"))?;
        assert!(slot.load(Ordering::SeqCst));
        assert_eq!(budget.live(), 1);
        drop(receiver);
        assert!(!slot.load(Ordering::SeqCst));
        assert_eq!(budget.live(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn reserved_permit_is_released_when_parent_is_aborted() -> Result<()> {
        let (sender, mut receiver) = mpsc::channel(1);
        let state = Arc::new(AtomicU8::new(RootState::Running as u8));
        let owner = ChildContext::root(
            RootId(1),
            RootKind::Api,
            sender.clone(),
            state.clone(),
            Arc::new(BlockingRegistry::default()),
            Arc::new(AtomicBool::new(false)),
        );
        let slot = owner.slot.clone();
        let permit = sender.reserve().await?;
        let parent =
            tokio::spawn(async move { owner.run_guest(|_| async move { pending().await }).await });
        timeout(Duration::from_secs(2), async {
            while !slot.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        state.store(RootState::Closing as u8, Ordering::SeqCst);
        receiver.close();
        parent.abort();
        let _ = parent.await;
        drop(permit);
        assert!(receiver.recv().await.is_none());
        assert!(!slot.load(Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn depth64_parent_with_preclose_permit_drains_before_pool_reuse() -> Result<()> {
        let dir = TempDir::new()?;
        let pool = one_object_pool(&dir).await?;
        let object = pool.get().await?;
        let service = OwnerService::new();
        let (ready_tx, ready_rx) = oneshot::channel();
        let gate = Arc::new(Notify::new());
        let root_gate = gate.clone();
        let handle = service
            .start_pooled(object, move |runtime| {
                Box::pin(async move {
                    let store = runtime.make_store(1_000_000)?;
                    let owner = runtime.ownership.clone().context("root context missing")?;
                    let child_runtime = runtime.clone();
                    let ready = Arc::new(Mutex::new(Some(ready_tx)));
                    let child = owner
                        .run_guest(move |next| {
                            nested_depth64_guest(child_runtime, next, 1, ready, root_gate)
                        })
                        .await?;
                    ensure!(matches!(&child.result, Ok(Ok(()))), "nested call failed");
                    drop(child);
                    drop(store);
                    Ok(RootOutcome {
                        value: (),
                        commit: false,
                    })
                })
            })
            .await?;
        let (sender, slot, budget) = timeout(Duration::from_secs(20), ready_rx).await??;
        assert_eq!(budget.live(), 64);
        let permit = timeout(Duration::from_secs(2), sender.reserve()).await??;
        gate.notify_one();
        timeout(Duration::from_secs(2), async {
            while !slot.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        drop(handle);
        drop(permit);
        let object = timeout(Duration::from_secs(5), pool.get()).await??;
        assert_eq!(budget.live(), 0);
        assert!(object.storage.conn.is_autocommit());
        assert!(object.storage.savepoint_stack.is_empty().await);
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn panic_discards_pool_object_after_quiescence() -> Result<()> {
        let dir = TempDir::new()?;
        let pool = one_object_pool(&dir).await?;
        let object = pool.get().await?;
        let poisoned_id = Object::id(&object);
        let service = OwnerService::new();
        let mut handle = service
            .start_pooled(object, |_runtime| {
                Box::pin(async move {
                    panic!("injected root panic");
                    #[allow(unreachable_code)]
                    Ok(RootOutcome {
                        value: (),
                        commit: false,
                    })
                })
            })
            .await?;
        assert!(handle.result().await.is_err());
        timeout(Duration::from_secs(2), async {
            while service.active_roots().await != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let fresh = timeout(Duration::from_secs(2), pool.get()).await??;
        assert_ne!(Object::id(&fresh), poisoned_id);
        Ok(())
    }

    #[tokio::test]
    async fn supervisor_panic_fences_live_pool_authority_and_fails_driver() -> Result<()> {
        let dir = TempDir::new()?;
        let pool = one_object_pool(&dir).await?;
        let object = pool.get().await?;
        let service = OwnerService::new();
        let gate = Arc::new(AsyncGate::default());
        let _release = ReleaseAsyncGate(gate.clone());
        *service
            .registry
            .supervisor_panic_after_root_entered
            .lock()
            .expect("supervisor panic gate lock poisoned") = Some(gate.clone());
        let operation_gate = gate.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let operation_finished = finished.clone();
        let mut handle = service
            .start_pooled(object, move |runtime| {
                Box::pin(async move {
                    assert!(!runtime.storage.conn.is_autocommit());
                    operation_gate.wait().await;
                    operation_finished.store(true, Ordering::SeqCst);
                    Ok(RootOutcome {
                        value: (),
                        commit: false,
                    })
                })
            })
            .await?;
        let driver = service.take_driver().context("owner driver missing")?;
        let reported = timeout(Duration::from_secs(2), driver).await??;
        assert!(
            reported
                .as_ref()
                .is_err_and(|error| error.to_string().contains("node supervisor panicked")),
            "supervisor panic did not fail the driver: {reported:?}"
        );
        assert!(
            timeout(Duration::from_secs(2), handle.result())
                .await?
                .is_err()
        );
        assert!(gate.entered.load(Ordering::SeqCst));
        assert!(service.is_fatal());
        assert_eq!(service.quarantined_roots().await, 1);
        assert_eq!(pool.status().available, 0);
        assert!(
            timeout(Duration::from_millis(100), pool.get())
                .await
                .is_err()
        );
        assert!(service.admission.reserve().await.is_err());
        gate.release();
        timeout(Duration::from_secs(2), async {
            while !finished.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(pool.status().available, 0);
        Ok(())
    }

    #[tokio::test]
    async fn dropped_blocking_receiver_does_not_release_work_early() -> Result<()> {
        let registry = BlockingRegistry::default();
        let (release, blocked) = std::sync::mpsc::channel();
        let receiver = registry.spawn(move || blocked.recv())?;
        drop(receiver);
        assert!(
            timeout(Duration::from_millis(30), registry.wait_all())
                .await
                .is_err()
        );
        release.send(())?;
        timeout(Duration::from_secs(2), registry.wait_all()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn blocking_drain_closes_registration_before_empty_snapshot() -> Result<()> {
        let registry = BlockingRegistry::default();
        let (release, blocked) = std::sync::mpsc::channel();
        let receiver = registry.spawn(move || blocked.recv())?;
        registry.close_registration();
        assert!(registry.spawn(|| 1u8).is_err());
        assert!(
            timeout(Duration::from_millis(30), registry.wait_all())
                .await
                .is_err()
        );
        release.send(())?;
        timeout(Duration::from_secs(2), registry.wait_all()).await?;
        receiver.await???;
        assert!(registry.spawn(|| 2u8).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn root_capacity_retains_quarantined_authority() -> Result<()> {
        let service = OwnerService::new();
        let (runtime, _dir, _name) = test_runtime().await?;
        let mut other_permits = Vec::new();
        for _ in 0..NODE_ADMISSION_CAPACITY - 1 {
            other_permits.push(service.reserve_root_capacity().await?);
        }
        let capacity = service.reserve_root_capacity().await?;
        let keeper = Arc::new(RootKeeper::new_stateful(RootId(99), runtime, capacity));
        service
            .registry
            .roots
            .lock()
            .await
            .insert(keeper.id, keeper.clone());
        keeper.quarantine();
        assert!(
            timeout(Duration::from_millis(30), service.reserve_root_capacity())
                .await
                .is_err()
        );
        keeper.quiescent.store(true, Ordering::SeqCst);
        service.registry.roots.lock().await.remove(&keeper.id);
        drop(keeper);
        let released = timeout(Duration::from_secs(2), service.reserve_root_capacity()).await??;
        drop(released);
        drop(other_permits);
        Ok(())
    }

    #[tokio::test]
    async fn reported_bundle_failure_quarantines_even_if_guest_catches_error() -> Result<()> {
        let service = OwnerService::new();
        let (runtime, _dir, _name) = test_runtime().await?;
        let keeper = Arc::new(RootKeeper::new_stateful(
            RootId(100),
            runtime,
            service.reserve_root_capacity().await?,
        ));
        let (sender, _receiver) = mpsc::channel(1);
        let context = ChildContext::root(
            keeper.id,
            RootKind::Api,
            sender,
            keeper.state.clone(),
            keeper.blocking.clone(),
            keeper.caught_host_panic.clone(),
        );
        let adapter = OwnerAdapter::new(&keeper, context);
        assert!((adapter.check_commit)(adapter.root.clone()).is_ok());
        assert!((adapter.report_failure)(adapter.root.clone(), 2).is_ok());
        assert_eq!(RootState::load(&keeper.state), RootState::Quarantined);
        assert!((adapter.check_commit)(adapter.root.clone()).is_err());
        assert_eq!((adapter.check_commit)(Arc::new(7u8)).unwrap_err().0, 2);
        assert!((adapter.check_commit)(adapter.root.clone()).is_err());
        keeper.quiescent.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[tokio::test]
    async fn expired_tokens_only_allow_root_commit_check_during_settlement() -> Result<()> {
        let service = OwnerService::new();
        let (runtime, _dir, _name) = test_runtime().await?;
        let keeper = Arc::new(RootKeeper::new_stateful(
            RootId(102),
            runtime,
            service.reserve_root_capacity().await?,
        ));
        let (sender, _receiver) = mpsc::channel(1);
        let context = ChildContext::root(
            keeper.id,
            RootKind::Api,
            sender,
            keeper.state.clone(),
            keeper.blocking.clone(),
            keeper.caught_host_panic.clone(),
        );
        let adapter = OwnerAdapter::new(&keeper, context.clone());
        context.alive.store(false, Ordering::SeqCst);
        keeper
            .state
            .store(RootState::Committing as u8, Ordering::SeqCst);
        let guest: GuestFactory =
            Box::new(|_| Box::pin(async { (false, Box::new(1u8) as Payload) }));
        let guest_error = (adapter.submit_guest)(adapter.root.clone(), guest)
            .await
            .unwrap_err();
        assert_eq!(guest_error.0, 2);
        let blocking_error =
            (adapter.submit_blocking)(adapter.root.clone(), Box::new(|| Box::new(2u8) as Payload))
                .await
                .unwrap_err();
        assert_eq!(blocking_error.0, 2);
        assert!((adapter.check_commit)(adapter.root.clone()).is_ok());
        let expired_child = ChildContext {
            task: TaskId {
                root: keeper.id,
                local: 1,
            },
            depth: 1,
            alive: Arc::new(AtomicBool::new(false)),
            ..context
        };
        let child_adapter = OwnerAdapter::new(&keeper, expired_child);
        assert_eq!(
            (child_adapter.check_commit)(child_adapter.root.clone())
                .unwrap_err()
                .0,
            2
        );
        keeper.quiescent.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[tokio::test]
    async fn exported_host_panic_cannot_authorize_sql_commit() -> Result<()> {
        let (runtime, _dir, _name) = test_runtime().await?;
        let conn = runtime.storage.conn.clone();
        conn.execute(
            "CREATE TABLE host_panic_commit (id INTEGER PRIMARY KEY)",
            (),
        )
        .await?;
        let keeper = Arc::new(RootKeeper::new_stateful(
            RootId(101),
            runtime,
            Arc::new(Semaphore::new(1)).acquire_owned().await?,
        ));
        {
            let mut authority = keeper.authority.lock().await;
            let runtime: &mut Runtime = authority.as_mut().expect("root authority retained");
            runtime.storage.savepoint().await?;
            runtime
                .storage
                .conn
                .execute("INSERT INTO host_panic_commit (id) VALUES (1)", ())
                .await?;
        }
        keeper.caught_host_panic.store(true, Ordering::SeqCst);
        restore(
            &keeper,
            Ok(RootOutcome {
                value: (),
                commit: true,
            }),
        )
        .await??;
        let mut rows = conn
            .query("SELECT COUNT(*) FROM host_panic_commit", ())
            .await?;
        let count: i64 = rows.next().await?.context("count row missing")?.get(0)?;
        assert_eq!(count, 0);
        keeper.quarantine();
        Ok(())
    }

    #[tokio::test]
    async fn linked_guest_runs_under_node_owner_and_returns_opaque_payload() -> Result<()> {
        let (runtime, dir, name) = test_runtime().await?;
        let selection = select_legacy_p1(
            &runtime.storage.conn,
            Network::Regtest,
            ApplicationPosition::View,
        )
        .await?;
        let factory: SessionFactory = Arc::new(|_| {
            Box::pin(async {
                let action: SessionAction = Arc::new(|_| Box::pin(async { Ok(()) }));
                let make_root = Arc::new(|_selection, _adapter| {
                    let action: SessionAction = Arc::new(|_| Box::pin(async { Ok(()) }));
                    Ok(RootHooks {
                        prepare: action.clone(),
                        inspect_canonical_drain: action,
                        settle: Arc::new(|_, _| Box::pin(async { Ok(()) })),
                        reset: Arc::new(|_, _, _| Box::pin(async { Ok(()) })),
                    })
                });
                Ok(ExecutorSession {
                    origin: ExecutorVersion::LegacyP1,
                    operations: Default::default(),
                    owner: Arc::new(()),
                    make_root,
                    recycle: action,
                })
            })
        });
        let pool = new_linked(dir.path().to_path_buf(), name, factory, 1)?;
        let service = OwnerService::new();
        let capacity = service.reserve_root_capacity().await?;
        let object = pool.get().await?;
        let operation: LinkedOperation = Box::new(|_, adapter| {
            Box::pin(async move {
                let guest: GuestFactory =
                    Box::new(|_child| Box::pin(async { (false, Box::new(7u8) as Payload) }));
                let (panicked, payload) =
                    (adapter.submit_guest)(adapter.root.clone(), guest).await?;
                if panicked {
                    return Err((1, "guest unexpectedly panicked".into()));
                }
                let value = *payload
                    .downcast::<u8>()
                    .map_err(|_| (2, "opaque guest payload type mismatch".into()))?;
                let blocking = (adapter.submit_blocking)(
                    adapter.root.clone(),
                    Box::new(|| Box::new(9u8) as Payload),
                )
                .await?;
                let blocking_value = *blocking
                    .downcast::<u8>()
                    .map_err(|_| (2, "opaque blocking payload type mismatch".into()))?;
                if blocking_value != 9 {
                    return Err((0, "blocking work returned the wrong value".into()));
                }
                Ok((Box::new(value) as Payload, true))
            })
        });
        let mut handle = service
            .start_linked_pooled_reserved(object, capacity, selection, operation)
            .await?;
        let value = handle.result().await?;
        assert_eq!(
            *value
                .downcast::<u8>()
                .map_err(|_| anyhow!("root payload type mismatch"))?,
            7
        );
        assert_eq!(service.quarantined_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn linked_stateful_commit_uses_root_token_after_operation_returns() -> Result<()> {
        let (runtime, _dir, _name) = test_runtime().await?;
        let conn = runtime.storage.conn.clone();
        conn.execute(
            "CREATE TABLE linked_stateful_commit (id INTEGER PRIMARY KEY)",
            (),
        )
        .await?;
        let selection =
            select_legacy_p1(&conn, Network::Regtest, ApplicationPosition::View).await?;
        let hook_conn = conn.clone();
        let make_root = Arc::new(move |_selection, adapter: OwnerAdapter| {
            let prepare_conn = hook_conn.clone();
            let prepare: SessionAction = Arc::new(move |_| {
                let conn = prepare_conn.clone();
                Box::pin(async move {
                    conn.execute("BEGIN", ())
                        .await
                        .map(|_| ())
                        .map_err(|error| (0, error.to_string()))
                })
            });
            let settle_conn = hook_conn.clone();
            let check_commit = adapter.check_commit.clone();
            let root_token = adapter.root.clone();
            Ok(RootHooks {
                prepare,
                inspect_canonical_drain: Arc::new(|_| Box::pin(async { Ok(()) })),
                settle: Arc::new(move |_, commit| {
                    let conn = settle_conn.clone();
                    let check_commit = check_commit.clone();
                    let root_token = root_token.clone();
                    Box::pin(async move {
                        if commit {
                            check_commit(root_token)?;
                        }
                        conn.execute(if commit { "COMMIT" } else { "ROLLBACK" }, ())
                            .await
                            .map(|_| ())
                            .map_err(|error| (0, error.to_string()))
                    })
                }),
                reset: Arc::new(|_, _, _| Box::pin(async { Ok(()) })),
            })
        });
        let executor = ExecutorSession {
            origin: ExecutorVersion::LegacyP1,
            operations: Default::default(),
            owner: Arc::new(()),
            make_root,
            recycle: Arc::new(|_| Box::pin(async { Ok(()) })),
        };
        let session = LinkedStatefulSession::new(LinkedSession::new(conn.clone(), executor));
        let service = OwnerService::new();
        let operation_conn = conn.clone();
        let operation: LinkedOperation = Box::new(move |_, _| {
            Box::pin(async move {
                operation_conn
                    .execute("INSERT INTO linked_stateful_commit (id) VALUES (1)", ())
                    .await
                    .map_err(|error| (0, error.to_string()))?;
                Ok((Box::new(7u8) as Payload, true))
            })
        });
        let mut handle = service
            .start_linked_stateful_reserved(
                &session,
                service.reserve_root_capacity().await?,
                selection,
                operation,
            )
            .await?;
        let value = handle.result().await?;
        assert_eq!(*value.downcast::<u8>().expect("root payload type"), 7);
        let mut rows = conn
            .query("SELECT COUNT(*) FROM linked_stateful_commit", ())
            .await?;
        assert_eq!(
            rows.next()
                .await?
                .context("commit count missing")?
                .get::<i64>(0)?,
            1
        );
        assert_eq!(service.quarantined_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn linked_canonical_cleanup_outlives_completion_caller() -> Result<()> {
        let (runtime, _dir, _name) = test_runtime().await?;
        let selection = select_legacy_p1(
            &runtime.storage.conn,
            Network::Regtest,
            ApplicationPosition::Committee,
        )
        .await?;
        let gate = Arc::new(AsyncGate::default());
        let make_root_gate = gate.clone();
        let executor = ExecutorSession {
            origin: ExecutorVersion::LegacyP1,
            operations: Default::default(),
            owner: Arc::new(()),
            make_root: Arc::new(move |_, _| {
                let action: SessionAction = Arc::new(|_| Box::pin(async { Ok(()) }));
                let reset_gate = make_root_gate.clone();
                Ok(RootHooks {
                    prepare: action.clone(),
                    inspect_canonical_drain: action,
                    settle: Arc::new(|_, _| Box::pin(async { Ok(()) })),
                    reset: Arc::new(move |_, _, _| {
                        let gate = reset_gate.clone();
                        Box::pin(async move {
                            gate.wait().await;
                            Ok(())
                        })
                    }),
                })
            }),
            recycle: Arc::new(|_| Box::pin(async { Ok(()) })),
        };
        let session = LinkedSession::new(runtime.storage.conn.clone(), executor);
        let service = OwnerService::new();
        let mut lease = service
            .begin_linked_canonical_reserved(
                &session,
                service.reserve_root_capacity().await?,
                selection,
                false,
            )
            .await?;
        assert!((lease.adapter().check_commit)(lease.adapter().root.clone()).is_ok());
        lease.drain().await?;
        let complete = tokio::spawn(lease.complete());
        timeout(Duration::from_secs(2), async {
            while !gate.entered.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        complete.abort();
        let _ = complete.await;
        assert!(session.canonical_busy.load(Ordering::SeqCst));
        assert_eq!(service.active_roots().await, 1);
        gate.release();
        timeout(Duration::from_secs(2), async {
            while session.canonical_busy.load(Ordering::SeqCst) || service.active_roots().await != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(service.quarantined_roots().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn linked_canonical_settlement_selects_rollback_or_commit_once() -> Result<()> {
        let (runtime, _dir, _name) = test_runtime().await?;
        let conn = runtime.storage.conn.clone();
        conn.execute(
            "CREATE TABLE linked_canonical_settlement (id INTEGER PRIMARY KEY)",
            (),
        )
        .await?;
        let selection =
            select_legacy_p1(&conn, Network::Regtest, ApplicationPosition::Committee).await?;
        let root_conn = conn.clone();
        let settlements = Arc::new(AtomicUsize::new(0));
        let root_settlements = settlements.clone();
        let executor = ExecutorSession {
            origin: ExecutorVersion::LegacyP1,
            operations: Default::default(),
            owner: Arc::new(()),
            make_root: Arc::new(move |_, _| {
                let prepare_conn = root_conn.clone();
                let settle_conn = root_conn.clone();
                let count = root_settlements.clone();
                Ok(RootHooks {
                    prepare: Arc::new(move |_| {
                        let conn = prepare_conn.clone();
                        Box::pin(async move {
                            conn.execute("BEGIN", ())
                                .await
                                .map_err(|error| (0, error.to_string()))?;
                            Ok(())
                        })
                    }),
                    inspect_canonical_drain: Arc::new(|_| Box::pin(async { Ok(()) })),
                    settle: Arc::new(move |_, commit| {
                        let conn = settle_conn.clone();
                        let count = count.clone();
                        Box::pin(async move {
                            conn.execute(if commit { "COMMIT" } else { "ROLLBACK" }, ())
                                .await
                                .map_err(|error| (0, error.to_string()))?;
                            count.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        })
                    }),
                    reset: Arc::new(|_, _, _| Box::pin(async { Ok(()) })),
                })
            }),
            recycle: Arc::new(|_| Box::pin(async { Ok(()) })),
        };
        let session = LinkedSession::new(conn.clone(), executor);
        let service = OwnerService::new();
        for (id, commit) in [(1i64, false), (2i64, true)] {
            let mut lease = service
                .begin_linked_canonical_reserved(
                    &session,
                    service.reserve_root_capacity().await?,
                    selection.clone(),
                    false,
                )
                .await?;
            conn.execute(
                "INSERT INTO linked_canonical_settlement (id) VALUES (?)",
                [id],
            )
            .await?;
            lease.drain().await?;
            lease.settle(commit).await?;
            assert!(lease.settle(commit).await.is_err());
            lease.complete().await?;
        }
        let mut rows = conn
            .query("SELECT id FROM linked_canonical_settlement", ())
            .await?;
        assert_eq!(
            rows.next()
                .await?
                .context("committed row missing")?
                .get::<i64>(0)?,
            2
        );
        assert!(rows.next().await?.is_none());
        assert_eq!(settlements.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[tokio::test]
    async fn linked_canonical_admission_rejects_wrong_selection_purpose() -> Result<()> {
        let (runtime, _dir, _name) = test_runtime().await?;
        let conn = runtime.storage.conn.clone();
        let action: SessionAction = Arc::new(|_| Box::pin(async { Ok(()) }));
        let executor = ExecutorSession {
            origin: ExecutorVersion::LegacyP1,
            operations: Default::default(),
            owner: Arc::new(()),
            make_root: Arc::new(move |_, _| {
                let action: SessionAction = Arc::new(|_| Box::pin(async { Ok(()) }));
                Ok(RootHooks {
                    prepare: action.clone(),
                    inspect_canonical_drain: action,
                    settle: Arc::new(|_, _| Box::pin(async { Ok(()) })),
                    reset: Arc::new(|_, _, _| Box::pin(async { Ok(()) })),
                })
            }),
            recycle: action,
        };
        let session = LinkedSession::new(conn.clone(), executor);
        let service = OwnerService::new();
        let view = select_legacy_p1(&conn, Network::Regtest, ApplicationPosition::View).await?;
        let preparation = select_legacy_p1(
            &conn,
            Network::Regtest,
            ApplicationPosition::Preparation {
                anchor_height: 0,
                anchor_hash: None,
            },
        )
        .await?;
        let committee =
            select_legacy_p1(&conn, Network::Regtest, ApplicationPosition::Committee).await?;
        let simulation = select_legacy_p1(
            &conn,
            Network::Regtest,
            ApplicationPosition::Simulation { height: 0 },
        )
        .await?;
        for (selection, simulated) in [
            (view.clone(), false),
            (view, true),
            (preparation, false),
            (committee, true),
            (simulation.clone(), false),
        ] {
            assert!(
                service
                    .begin_linked_canonical_reserved(
                        &session,
                        service.reserve_root_capacity().await?,
                        selection,
                        simulated,
                    )
                    .await
                    .is_err()
            );
            assert!(!session.canonical_busy.load(Ordering::SeqCst));
            assert_eq!(service.active_roots().await, 0);
        }
        let mut lease = service
            .begin_linked_canonical_reserved(
                &session,
                service.reserve_root_capacity().await?,
                simulation,
                true,
            )
            .await?;
        lease.drain().await?;
        lease.complete().await?;
        assert_eq!(service.active_roots().await, 0);
        Ok(())
    }

    async fn blocking_worker_panic_fences_pooled_authority(abandon_receiver: bool) -> Result<()> {
        let dir = TempDir::new()?;
        let pool = one_object_pool(&dir).await?;
        let object = pool.get().await?;
        let poisoned_id = Object::id(&object);
        let service = OwnerService::new();
        let mut handle = service
            .start_pooled(object, move |runtime| {
                Box::pin(async move {
                    let owner = runtime.ownership.clone().context("root owner missing")?;
                    if abandon_receiver {
                        drop(
                            owner
                                .blocking
                                .spawn(|| -> () { panic!("injected abandoned blocking panic") }),
                        );
                    } else {
                        let result: Result<()> = owner
                            .run_blocking(|| -> () { panic!("injected attached blocking panic") })
                            .await;
                        ensure!(result.is_err(), "blocking panic returned success");
                        ensure!(
                            runtime.storage.commit().await.is_err(),
                            "blocking panic allowed a root commit"
                        );
                    }
                    Ok(RootOutcome {
                        value: (),
                        commit: true,
                    })
                })
            })
            .await?;
        ensure!(
            timeout(Duration::from_secs(5), handle.result())
                .await?
                .is_err(),
            "blocking panic returned an owned success"
        );
        timeout(Duration::from_secs(5), async {
            while service.active_roots().await != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let fresh = timeout(Duration::from_secs(5), pool.get()).await??;
        assert_ne!(Object::id(&fresh), poisoned_id);
        Ok(())
    }

    #[tokio::test]
    async fn attached_blocking_panic_discards_pooled_authority() -> Result<()> {
        blocking_worker_panic_fences_pooled_authority(false).await
    }

    #[tokio::test]
    async fn abandoned_blocking_panic_discards_pooled_authority() -> Result<()> {
        blocking_worker_panic_fences_pooled_authority(true).await
    }

    #[tokio::test]
    async fn ordinary_blocking_error_keeps_pooled_authority_reusable() -> Result<()> {
        let dir = TempDir::new()?;
        let pool = one_object_pool(&dir).await?;
        let object = pool.get().await?;
        let original_id = Object::id(&object);
        let service = OwnerService::new();
        let mut handle = service
            .start_pooled(object, move |runtime| {
                Box::pin(async move {
                    let owner = runtime.ownership.clone().context("root owner missing")?;
                    let content = owner
                        .run_blocking(|| Err::<(), _>(anyhow!("ordinary content error")))
                        .await?;
                    ensure!(content.is_err(), "ordinary blocking error was lost");
                    Ok(RootOutcome {
                        value: (),
                        commit: false,
                    })
                })
            })
            .await?;
        handle.result().await?;
        assert_eq!(service.active_roots().await, 0);
        let reused = timeout(Duration::from_secs(5), pool.get()).await??;
        assert_eq!(Object::id(&reused), original_id);
        Ok(())
    }

    #[tokio::test]
    async fn canonical_blocking_panic_prevents_drain_and_commit() -> Result<()> {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let service = OwnerService::new();
        let mut lease = service.begin_canonical(&mut runtime, false).await?;
        let owner = runtime
            .ownership
            .clone()
            .context("canonical owner missing")?;
        let result: Result<()> = owner
            .run_blocking(|| -> () { panic!("injected canonical blocking panic") })
            .await;
        assert!(result.is_err());
        assert!(lease.drain(&runtime).await.is_err());
        assert!(runtime.storage.commit().await.is_err());
        drop(lease);
        assert!(service.is_fatal());
        Ok(())
    }

    #[tokio::test]
    async fn drain_timeout_retains_capacity_until_blocking_work_finishes() -> Result<()> {
        let dir = TempDir::new()?;
        let pool = one_object_pool(&dir).await?;
        let object = pool.get().await?;
        let poisoned_id = Object::id(&object);
        let service = OwnerService::new();
        let started = Arc::new(Notify::new());
        let work_started = started.clone();
        let (release, blocked) = std::sync::mpsc::channel();
        let handle = service
            .start_pooled(object, move |runtime| {
                Box::pin(async move {
                    let owner = runtime.ownership.clone().expect("owned runtime context");
                    owner
                        .run_blocking(move || {
                            work_started.notify_one();
                            blocked.recv()
                        })
                        .await??;
                    Ok(RootOutcome {
                        value: (),
                        commit: false,
                    })
                })
            })
            .await?;
        timeout(Duration::from_secs(2), started.notified()).await?;
        drop(handle);
        timeout(Duration::from_secs(7), async {
            while service
                .registry
                .roots
                .lock()
                .await
                .values()
                .next()
                .is_some_and(|keeper| RootState::load(&keeper.state) != RootState::Quarantined)
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(pool.status().available, 0);
        assert_eq!(service.active_roots().await, 1);
        assert_eq!(service.quarantined_roots().await, 1);
        release.send(())?;
        timeout(Duration::from_secs(2), async {
            while service.active_roots().await != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(service.quarantined_roots().await, 0);
        let fresh = timeout(Duration::from_secs(2), pool.get()).await??;
        assert_ne!(Object::id(&fresh), poisoned_id);
        Ok(())
    }

    #[tokio::test]
    async fn restoration_deadline_responds_while_authority_is_locked() -> Result<()> {
        let dir = TempDir::new()?;
        let pool = one_object_pool(&dir).await?;
        let object = pool.get().await?;
        let capacity = Arc::new(Semaphore::new(1)).acquire_owned().await?;
        let keeper = Arc::new(RootKeeper::new(RootId(9), object, capacity));
        let mut authority = keeper.authority.lock().await;
        authority
            .as_mut()
            .expect("root authority retained")
            .storage
            .savepoint()
            .await?;
        keeper.close();
        let (sender, receiver) = oneshot::channel();
        let restoring = keeper.clone();
        let task = tokio::spawn(async move {
            let mut response = Some(sender);
            restore_with_deadline(
                &restoring,
                Err::<RootOutcome<()>, _>(anyhow!("cancelled operation")),
                Some(Instant::now() + Duration::from_millis(30)),
                false,
                &mut response,
            )
            .await
        });
        assert!(timeout(Duration::from_secs(2), receiver).await??.is_err());
        assert_eq!(RootState::load(&keeper.state), RootState::Quarantined);
        assert_eq!(pool.status().available, 0);
        drop(authority);
        let restored = timeout(Duration::from_secs(2), task).await??;
        assert!(restored?.is_err());
        assert!(
            keeper
                .authority
                .lock()
                .await
                .as_ref()
                .expect("root authority retained")
                .storage
                .conn
                .is_autocommit()
        );
        Ok(())
    }
}
