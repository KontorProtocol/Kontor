use std::collections::HashMap;
use std::future::{Future, pending};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use deadpool::managed::Object;
use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use metrics::gauge;
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio::task::{AbortHandle, Id, JoinHandle, JoinSet};
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;
use wasmtime::component::{ResourceTable, Val};

use super::Runtime;
use super::invocation::{InvocationBudget, InvocationStore};
use super::pool::Manager;

const API_DRAIN_LIMIT: Duration = Duration::from_secs(5);
const NODE_ADMISSION_CAPACITY: usize = 64;
const API_FUEL_YIELD_INTERVAL: u64 = 100_000;

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
    active: Arc<std::sync::Mutex<HashMap<u64, Arc<BlockingState>>>>,
}

struct BlockingState {
    done: AtomicBool,
    notify: tokio::sync::Notify,
}

impl BlockingRegistry {
    async fn wait_all(&self) {
        loop {
            let entries = self
                .active
                .lock()
                .expect("blocking registry poisoned")
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
    ) -> oneshot::Receiver<std::result::Result<T, tokio::task::JoinError>>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let state = Arc::new(BlockingState {
            done: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        });
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.active
            .lock()
            .expect("blocking registry poisoned")
            .insert(id, state.clone());
        let (sender, receiver) = oneshot::channel();
        let task = tokio::task::spawn_blocking(work);
        let active = self.active.clone();
        tokio::spawn(async move {
            let _ = sender.send(task.await);
            active
                .lock()
                .expect("blocking registry poisoned")
                .remove(&id);
            state.done.store(true, Ordering::SeqCst);
            state.notify.notify_one();
        });
        receiver
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

pub(super) struct GuestCompletion {
    pub result: std::result::Result<std::result::Result<(), wasmtime::Error>, String>,
    pub results: Vec<Val>,
    pub store: InvocationStore,
    pub host_panicked: bool,
}

struct GuestDelivery {
    completion: GuestCompletion,
    slot: SlotLease,
}

type GuestFuture = Pin<Box<dyn Future<Output = GuestCompletion> + Send + 'static>>;

struct Admission {
    id: TaskId,
    parent: TaskId,
    depth: u32,
    future: GuestFuture,
    completion: oneshot::Sender<GuestDelivery>,
    slot: SlotLease,
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
}

impl ChildContext {
    fn root(
        root: RootId,
        kind: RootKind,
        sender: mpsc::Sender<Admission>,
        state: Arc<AtomicU8>,
        blocking: Arc<BlockingRegistry>,
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
        };
        let (completion, receiver) = oneshot::channel();
        permit.send(Admission {
            id,
            parent: self.task,
            depth: child.depth,
            future: Box::pin(make_future(child)),
            completion,
            slot,
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
        let receiver = self.blocking.spawn(work);
        receiver
            .await
            .context("tracked blocking watcher failed")?
            .context("tracked blocking work failed")
    }

    async fn closed_or_infrastructure(&self) -> Result<GuestCompletion> {
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
            ),
            "operation root cannot commit after cancellation or quarantine"
        );
        Ok(())
    }
}

enum RootAuthority {
    Pooled(Object<Manager>),
    Stateful(Runtime),
}

impl Deref for RootAuthority {
    type Target = Runtime;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Pooled(object) => object,
            Self::Stateful(runtime) => runtime,
        }
    }
}

impl DerefMut for RootAuthority {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Pooled(object) => object,
            Self::Stateful(runtime) => runtime,
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

struct RootKeeper {
    id: RootId,
    authority: Mutex<Option<RootAuthority>>,
    state: Arc<AtomicU8>,
    closing_at: Arc<std::sync::Mutex<Option<Instant>>>,
    cancellation: CancellationToken,
    blocking: Arc<BlockingRegistry>,
    caught_host_panic: AtomicBool,
    quiescent: AtomicBool,
}

impl RootKeeper {
    fn new(id: RootId, authority: Object<Manager>) -> Self {
        Self::with_authority(id, RootAuthority::Pooled(authority))
    }

    fn new_stateful(id: RootId, authority: Runtime) -> Self {
        Self::with_authority(id, RootAuthority::Stateful(authority))
    }

    fn with_authority(id: RootId, authority: RootAuthority) -> Self {
        Self {
            id,
            authority: Mutex::new(Some(authority)),
            state: Arc::new(AtomicU8::new(RootState::Running as u8)),
            closing_at: Arc::new(std::sync::Mutex::new(None)),
            cancellation: CancellationToken::new(),
            blocking: Arc::new(BlockingRegistry::default()),
            caught_host_panic: AtomicBool::new(false),
            quiescent: AtomicBool::new(false),
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
}

impl Drop for RootKeeper {
    fn drop(&mut self) {
        if RootState::load(&self.state) != RootState::Quarantined {
            return;
        }
        let object = self
            .authority
            .get_mut()
            .take()
            .expect("quarantined root authority retained");
        if self.quiescent.load(Ordering::SeqCst) {
            match object {
                RootAuthority::Pooled(object) => drop(Object::take(object)),
                RootAuthority::Stateful(runtime) => drop(runtime),
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

#[derive(Default)]
struct OwnerRegistry {
    next_root: AtomicU64,
    roots: Mutex<HashMap<RootId, Arc<RootKeeper>>>,
    fatal: AtomicBool,
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
        wake_owner(&self.shutdown);
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
        let keeper = Arc::new(RootKeeper::new_stateful(id, runtime.clone()));
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
        );
        runtime.ownership = Some(context.clone());
        runtime.storage.ownership = Some(context);
        roots.insert(id, keeper.clone());
        drop(roots);
        let (finish, finished) = oneshot::channel();
        let (drained_sender, drained) = oneshot::channel();
        let node_keeper = keeper.clone();
        permit.send(Box::new(move || {
            Box::pin(async move {
                supervise_canonical(node_keeper, receiver, finished, drained_sender).await;
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
        let permit = self
            .admission
            .reserve()
            .await
            .context("operation-owner node admission closed")?;
        if self.is_fatal() {
            return Err(anyhow!("operation-owner service is unavailable"));
        }
        let id = RootId(self.registry.next_root.fetch_add(1, Ordering::SeqCst));
        let keeper = Arc::new(RootKeeper::new(id, object));
        self.registry.roots.lock().await.insert(id, keeper.clone());
        let (sender, receiver) = mpsc::channel(1);
        let context = ChildContext::root(
            id,
            RootKind::Api,
            sender,
            keeper.state.clone(),
            keeper.blocking.clone(),
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
                    operation,
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
            let keeper = Arc::new(RootKeeper::new_stateful(id, runtime));
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
                    operation,
                    result_sender,
                    Some(return_to.clone()),
                );
                if std::panic::AssertUnwindSafe(supervisor)
                    .catch_unwind()
                    .await
                    .is_err()
                {
                    keeper.quarantine();
                    return_to.quarantine();
                    registry.fatal.store(true, Ordering::SeqCst);
                    panic!("operation root supervisor panicked");
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
    drained: oneshot::Sender<Result<()>>,
) {
    let mut children = JoinSet::<(TaskId, GuestCompletion)>::new();
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
                        let Admission { id, parent, depth, future, completion, slot } = request;
                        let abort = children.spawn(async move { (id, future.await) });
                        by_tokio.insert(abort.id(), id);
                        active.insert(id, RunningChild {
                            parent,
                            depth,
                            abort,
                            completion,
                            slot,
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
                    if aborting == Some(id) {
                        aborting = None;
                    }
                    if let Some(completion) = completion {
                        if completion.host_panicked {
                            keeper.caught_host_panic.store(true, Ordering::SeqCst);
                            keeper.quarantine();
                        }
                        if RootState::load(&keeper.state) == RootState::Running
                            || completion.host_panicked
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

    keeper.blocking.wait_all().await;
    drop(parked_senders);
    if RootState::load(&keeper.state) == RootState::Running
        && !keeper.caught_host_panic.load(Ordering::SeqCst)
    {
        keeper
            .state
            .store(RootState::Committing as u8, Ordering::SeqCst);
        let _ = drained.send(Ok(()));
    } else {
        keeper.quarantine();
        let _ = drained.send(Err(anyhow!("canonical root quarantined")));
    }
}

async fn supervise<T, F>(
    registry: Arc<OwnerRegistry>,
    keeper: Arc<RootKeeper>,
    mut receiver: mpsc::Receiver<Admission>,
    context: ChildContext,
    operation: F,
    response: oneshot::Sender<Result<T>>,
    return_to: Option<StatefulSession>,
) where
    T: Send + 'static,
    F: for<'a> FnOnce(&'a mut Runtime) -> BoxFuture<'a, Result<RootOutcome<T>>> + Send + 'static,
{
    let root_keeper = keeper.clone();
    let mut root: JoinHandle<Result<RootOutcome<T>>> = tokio::spawn(async move {
        if RootState::load(&root_keeper.state) != RootState::Running {
            return Err(anyhow!("root cancelled before execution"));
        }
        let mut authority = root_keeper.authority.lock().await;
        let runtime: &mut Runtime = authority.as_mut().expect("root authority retained");
        runtime.invocation_budget = Some(Arc::new(InvocationBudget::default()));
        runtime.store_table_owners = Some(Arc::new(std::sync::Mutex::new(Vec::new())));
        runtime.storage.ownership = Some(context.clone());
        runtime.ownership = Some(context);
        runtime.storage.savepoint().await?;
        operation(runtime).await
    });
    let mut root_result = None;
    let mut children = JoinSet::<(TaskId, GuestCompletion)>::new();
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
        if closing || root_result.is_some() {
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
                        let Admission { id, parent, depth, future, completion, slot } = request;
                        let abort = children.spawn(async move { (id, future.await) });
                        by_tokio.insert(abort.id(), id);
                        active.insert(id, RunningChild {
                            parent,
                            depth,
                            abort,
                            completion,
                            slot,
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
                    debug_assert_eq!(child.parent.root, keeper.id);
                    if aborting == Some(id) {
                        aborting = None;
                    }
                    if let Some(completion) = completion {
                        if completion.host_panicked {
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
                (Some(session), Some(RootAuthority::Stateful(runtime))) => {
                    session.return_runtime(runtime);
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
                let _ = response.send(value);
            }
        }
        Ok(_) | Err(_) => {
            keeper.quarantine();
            if let Some(session) = &return_to {
                session.quarantine();
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
    let stateful = matches!(authority.as_ref(), Some(RootAuthority::Stateful(_)));
    let runtime: &mut Runtime = authority.as_mut().expect("root authority retained");
    let wants_commit = result.as_ref().is_ok_and(|outcome| outcome.commit);
    let commit_authorized = wants_commit
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reg_tester::random_x_only_pubkey;
    use crate::runtime::fuel::ExecutionUsage;
    use crate::runtime::wit::{Signer, kontor::built_in::context::HolderRef};
    use crate::runtime::{ContractAddress, Decimal, ExecutionError, native_provenance, token};
    use crate::test_utils::test_runtime;
    use bitcoin::Network;
    use deadpool::managed::Pool;
    use indexer_types::Payment;
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

    #[derive(Debug, PartialEq)]
    struct PaidReceiptSnapshot {
        outcome: std::result::Result<String, String>,
        usage: ExecutionUsage,
        receipt: (u64, String, u64, Option<String>),
        payer: Option<Decimal>,
        burner: Option<Decimal>,
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

    async fn seeded_paid_oracle() -> Result<(Runtime, TempDir, Signer, ContractAddress)> {
        let (mut runtime, dir, _name) = test_runtime().await?;
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
            signer,
            ContractAddress {
                name: "ownership-paid-oracle".to_string(),
                height: 0,
                tx_index: 0,
            },
        ))
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
            .put_admitted(u64::MAX, cached, PURE_LOOP_COMPONENT.len())
            .await;
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
        let pool = Pool::builder(Manager::new(
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
        drop(prewarmed);
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
            "eight owned view roots: normal_ms={}, cancel_drain_ms={}",
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
            let keeper = Arc::new(RootKeeper::new_stateful(RootId(id as u64), runtime));
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
                RootAuthority::Pooled(_) => unreachable!("race uses a stateful writer"),
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
                completion: GuestCompletion {
                    result: Ok(Ok(())),
                    results: Vec::new(),
                    store,
                    host_panicked: false,
                },
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
    async fn dropped_blocking_receiver_does_not_release_work_early() -> Result<()> {
        let registry = BlockingRegistry::default();
        let (release, blocked) = std::sync::mpsc::channel();
        let receiver = registry.spawn(move || blocked.recv());
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
        let keeper = Arc::new(RootKeeper::new(RootId(9), object));
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
