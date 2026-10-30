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
    use crate::runtime::{token, wit::kontor::built_in::context::HolderRef};
    use crate::test_utils::test_runtime;
    use bitcoin::Network;
    use deadpool::managed::Pool;
    use tempfile::TempDir;
    use tokio::sync::Notify;
    use tokio::time::timeout;

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
        let baseline = token::api::balance(&mut seed, HolderRef::Burner).await?;
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
                    let value = token::api::balance(runtime, HolderRef::Burner).await?;
                    Ok(RootOutcome {
                        value,
                        commit: false,
                    })
                })
            })
            .await?;
        assert_eq!(handle.result().await?, baseline);
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
    async fn panic_quarantines_and_retains_pool_capacity() -> Result<()> {
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
        assert_eq!(service.active_roots().await, 1);
        assert!(
            timeout(Duration::from_millis(30), pool.get())
                .await
                .is_err()
        );
        drop(service);
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
    async fn drain_timeout_keeps_the_pool_object_quarantined() -> Result<()> {
        let dir = TempDir::new()?;
        let pool = one_object_pool(&dir).await?;
        let object = pool.get().await?;
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
        release.send(())?;
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
