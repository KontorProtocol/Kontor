use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
#[cfg(not(kontor_node))]
use std::ops::{Deref, DerefMut};
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
#[cfg(not(kontor_node))]
use deadpool::managed::Object;
use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use metrics::gauge;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::{AbortHandle, Id, JoinHandle, JoinSet};
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;
#[cfg(test)]
use wasmtime::component::Val;

use self::read_snapshot::AdmittedRead;
#[cfg(not(kontor_node))]
use super::Runtime;
#[cfg(test)]
use super::bundle_session::BundleSession;
#[cfg(not(kontor_node))]
use super::call::GuestCompletion;
#[cfg(not(kontor_node))]
use super::invocation::InvocationBudget;
#[cfg(test)]
use super::invocation::InvocationStore;
use super::pool::LinkedSession;
#[cfg(not(kontor_node))]
use super::pool::Manager;
#[cfg(test)]
use super::storage::BlockingGate;
use crate::database::migration_input::MigrationInput;
use crate::protocol::coordinator::selection::ExecutionSelection;
use adapter::{OwnerAdapter, Payload, RootHooks, SharedOwner};

pub(crate) mod adapter;
mod admission;
mod blocking;
mod leases;
pub(crate) mod read_snapshot;
mod sessions;
mod settlement;

pub(super) use admission::ChildContext;
use blocking::BlockingRegistry;
#[cfg(not(kontor_node))]
pub(crate) use leases::CanonicalRootLease;
pub(crate) use leases::{LinkedCanonicalRootLease, OwnedRootHandle};
pub(crate) use sessions::LinkedStatefulSession;
#[cfg(not(kontor_node))]
pub(crate) use sessions::{OwnedRuntimeSession, StatefulSession};
#[cfg(test)]
use settlement::restore;
use settlement::restore_with_deadline;
#[cfg(test)]
mod migration_tests;

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
    #[cfg(not(kontor_node))]
    Local(GuestCompletion),
    Linked(bool, Box<dyn Any + Send>),
}

impl TaskCompletion {
    fn host_panicked(&self) -> bool {
        match self {
            #[cfg(not(kontor_node))]
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

enum RootAuthority {
    #[cfg(not(kontor_node))]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Exercised by in-tree ownership compatibility tests"
        )
    )]
    Pooled(Object<Manager>),
    #[cfg(not(kontor_node))]
    Stateful(Runtime),
    LinkedPooled(AdmittedRead),
    LinkedStateful(LinkedSession),
}

#[cfg(not(kontor_node))]
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

#[cfg(not(kontor_node))]
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

struct RootKeeper {
    id: RootId,
    migration_input: Option<Arc<MigrationInput>>,
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
    #[cfg(not(kontor_node))]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Exercised by in-tree ownership compatibility tests"
        )
    )]
    fn new(id: RootId, authority: Object<Manager>, capacity: OwnedSemaphorePermit) -> Self {
        Self::with_authority(id, RootAuthority::Pooled(authority), capacity)
    }

    #[cfg(not(kontor_node))]
    fn new_stateful(id: RootId, authority: Runtime, capacity: OwnedSemaphorePermit) -> Self {
        Self::with_authority(id, RootAuthority::Stateful(authority), capacity)
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
            migration_input: None,
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
            RootAuthority::LinkedPooled(object) => object.session(),
            RootAuthority::LinkedStateful(session) => session,
            #[cfg(not(kontor_node))]
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
            RootAuthority::LinkedPooled(object) => object.session().executor.owner.clone(),
            RootAuthority::LinkedStateful(session) => session.executor.owner.clone(),
            #[cfg(not(kontor_node))]
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
                #[cfg(not(kontor_node))]
                RootAuthority::Pooled(object) => drop(Object::take(object)),
                #[cfg(not(kontor_node))]
                RootAuthority::Stateful(runtime) => drop(runtime),
                RootAuthority::LinkedPooled(object) => object.discard(),
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
pub(crate) type ReadStartPermit = mpsc::OwnedPermit<RootStart>;

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
    #[cfg(not(kontor_node))]
    Legacy(StatefulSession),
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Exercised by in-tree ownership compatibility tests"
        )
    )]
    Linked(LinkedStatefulSession),
}

impl ReturnTo {
    fn quarantine(&self) {
        match self {
            #[cfg(not(kontor_node))]
            Self::Legacy(session) => session.quarantine(),
            Self::Linked(session) => session.quarantine(),
        }
    }
}

#[cfg(not(kontor_node))]
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

    #[cfg(not(kontor_node))]
    pub(crate) fn stateful_session(&self, runtime: Runtime) -> StatefulSession {
        StatefulSession::new(runtime)
    }

    #[cfg(not(kontor_node))]
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
        self.begin_linked_canonical_with_input(session, capacity, selection, simulation, None)
            .await
    }

    pub(crate) async fn begin_linked_migration_reserved(
        &self,
        session: &LinkedSession,
        capacity: OwnedSemaphorePermit,
        selection: ExecutionSelection,
        input: Arc<MigrationInput>,
    ) -> Result<LinkedCanonicalRootLease> {
        self.begin_linked_canonical_with_input(session, capacity, selection, false, Some(input))
            .await
    }

    async fn begin_linked_canonical_with_input(
        &self,
        session: &LinkedSession,
        capacity: OwnedSemaphorePermit,
        selection: ExecutionSelection,
        simulation: bool,
        input: Option<Arc<MigrationInput>>,
    ) -> Result<LinkedCanonicalRootLease> {
        ensure!(
            selection.is_migration() == input.is_some(),
            "migration root requires its dedicated input"
        );
        ensure!(
            session.origin() == selection.version(),
            "executor session does not match selection"
        );
        selection.ensure_canonical_root(simulation)?;
        ensure!(
            session.conn.is_autocommit(),
            "canonical root cannot start inside a transaction"
        );
        if let Some(input) = &input {
            input.verify_writer(&session.conn).await?;
        }
        let permit = self
            .admission
            .reserve()
            .await
            .context("operation-owner node admission closed")?;
        ensure!(!self.is_fatal(), "operation-owner service is unavailable");
        let mut roots = self.registry.roots.lock().await;
        if let Some(input) = &input {
            input.claim()?;
        }
        ensure!(
            session
                .canonical_busy
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok(),
            "canonical executor session is still owned by a prior root"
        );
        let id = RootId(self.registry.next_root.fetch_add(1, Ordering::SeqCst));
        let mut keeper = RootKeeper::new_linked_stateful(id, session.clone(), capacity);
        keeper.migration_input = input;
        let keeper = Arc::new(keeper);
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
                    if let Some(input) = &supervised.migration_input {
                        input
                            .close()
                            .await
                            .context("migration input cleanup failed")?;
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

    #[cfg(not(kontor_node))]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Exercised by in-tree ownership compatibility tests"
        )
    )]
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

    #[cfg(not(kontor_node))]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Exercised by in-tree ownership compatibility tests"
        )
    )]
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

    #[cfg(not(kontor_node))]
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

    pub(crate) async fn reserve_read_start(&self) -> Result<ReadStartPermit> {
        self.admission
            .clone()
            .reserve_owned()
            .await
            .context("operation-owner node admission closed")
    }

    pub(crate) async fn start_linked_pooled_reserved(
        &self,
        object: AdmittedRead,
        capacity: OwnedSemaphorePermit,
        permit: ReadStartPermit,
        selection: ExecutionSelection,
        operation: LinkedOperation,
    ) -> Result<OwnedRootHandle<Payload>> {
        ensure!(
            object.session().origin() == selection.version(),
            "executor session does not match selection"
        );
        self.start_linked_root(
            move || RootAuthority::LinkedPooled(object),
            capacity,
            selection,
            operation,
            None,
            Some(permit),
        )
        .await
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Exercised by in-tree ownership compatibility tests"
        )
    )]
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
            None,
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
        reserved: Option<ReadStartPermit>,
    ) -> Result<OwnedRootHandle<Payload>>
    where
        F: FnOnce() -> RootAuthority,
    {
        let permit = match reserved {
            Some(permit) => permit,
            None => self.reserve_read_start().await?,
        };
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
        let installation = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            keeper.install_linked_hooks(selection, adapter.clone())
        })) {
            Ok(result) => result,
            Err(_) => Err(anyhow!("linked root hook construction panicked")),
        };
        if let Err(error) = installation {
            let mut authority = keeper.authority.lock().await;
            if let Some(RootAuthority::LinkedPooled(read)) = authority.as_mut() {
                match AssertUnwindSafe(read.rollback()).catch_unwind().await {
                    Ok(Ok(())) => {}
                    failure => {
                        keeper.quarantine();
                        let cleanup = match failure {
                            Ok(Err(error)) => error,
                            _ => anyhow!("read admission cleanup panicked"),
                        };
                        return Err(
                            cleanup.context(format!("{error:#}; read admission cleanup failed"))
                        );
                    }
                }
                keeper.quiescent.store(true, Ordering::SeqCst);
                drop(authority);
                self.registry.roots.lock().await.remove(&id);
            } else {
                keeper.quarantine();
                if let Some(session) = &return_to {
                    session.quarantine();
                }
            }
            return Err(error);
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
                #[cfg(not(kontor_node))]
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
                    #[cfg(not(kontor_node))]
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

#[cfg(test)]
mod tests;
