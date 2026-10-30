use std::collections::HashMap;
use std::future::{Future, pending};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use deadpool::managed::Object;
use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use tokio::sync::{Mutex, mpsc, oneshot};
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
            state.done.store(true, Ordering::SeqCst);
            state.notify.notify_one();
            active
                .lock()
                .expect("blocking registry poisoned")
                .remove(&id);
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
                pending().await
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
            // A closing parent must not resume payment or savepoint settlement.
            pending().await
        }
        Err(anyhow!("guest admission closed without root cancellation"))
    }
}

struct RootKeeper {
    id: RootId,
    authority: Mutex<Object<Manager>>,
    state: Arc<AtomicU8>,
    closing_at: Arc<std::sync::Mutex<Option<Instant>>>,
    cancellation: CancellationToken,
    blocking: Arc<BlockingRegistry>,
    caught_host_panic: AtomicBool,
}

impl RootKeeper {
    fn new(id: RootId, authority: Object<Manager>) -> Self {
        Self {
            id,
            authority: Mutex::new(authority),
            state: Arc::new(AtomicU8::new(RootState::Running as u8)),
            closing_at: Arc::new(std::sync::Mutex::new(None)),
            cancellation: CancellationToken::new(),
            blocking: Arc::new(BlockingRegistry::default()),
            caught_host_panic: AtomicBool::new(false),
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
            self.cancellation.cancel();
        }
    }

    fn quarantine(&self) {
        let mut closing_at = self.closing_at.lock().expect("root closing clock poisoned");
        if closing_at.is_none() {
            *closing_at = Some(Instant::now());
        }
        self.state
            .store(RootState::Quarantined as u8, Ordering::SeqCst);
        self.cancellation.cancel();
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
pub(crate) struct OwnerService {
    registry: Arc<OwnerRegistry>,
    admission: mpsc::Sender<RootStart>,
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
            self.cancellation.cancel();
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
    pub(crate) fn new() -> Self {
        let registry = Arc::new(OwnerRegistry::default());
        let (admission, receiver) = mpsc::channel(NODE_ADMISSION_CAPACITY);
        let node_registry = registry.clone();
        tokio::spawn(async move {
            if std::panic::AssertUnwindSafe(run_node(receiver))
                .catch_unwind()
                .await
                .is_err()
            {
                node_registry.fatal.store(true, Ordering::SeqCst);
                #[cfg(not(test))]
                std::process::abort();
            }
        });
        Self {
            registry,
            admission,
        }
    }

    pub(crate) async fn active_roots(&self) -> usize {
        self.registry.roots.lock().await.len()
    }

    pub(crate) fn is_fatal(&self) -> bool {
        self.registry.fatal.load(Ordering::SeqCst)
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
                );
                if std::panic::AssertUnwindSafe(supervisor)
                    .catch_unwind()
                    .await
                    .is_err()
                {
                    keeper.quarantine();
                    registry.fatal.store(true, Ordering::SeqCst);
                    #[cfg(not(test))]
                    std::process::abort();
                }
            })
        }));
        Ok(handle)
    }
}

async fn run_node(mut receiver: mpsc::Receiver<RootStart>) {
    let mut supervisors = JoinSet::new();
    loop {
        tokio::select! {
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
        }
    }
    while let Some(joined) = supervisors.join_next().await {
        if let Err(error) = joined {
            panic!("operation supervisor task failed: {error}");
        }
    }
}

async fn supervise<T, F>(
    registry: Arc<OwnerRegistry>,
    keeper: Arc<RootKeeper>,
    mut receiver: mpsc::Receiver<Admission>,
    context: ChildContext,
    operation: F,
    response: oneshot::Sender<Result<T>>,
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
        let runtime: &mut Runtime = &mut authority;
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
                if let Err(error) = &finished {
                    if error.is_panic() {
                        keeper.quarantine();
                    }
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

    if let Some(deadline) = deadline {
        if !timed_out
            && tokio::time::timeout_at(deadline, keeper.blocking.wait_all())
                .await
                .is_err()
        {
            keeper.quarantine();
            if let Some(response) = response.take() {
                let _ = response.send(Err(anyhow!(
                    "operation drain exceeded five seconds; root quarantined"
                )));
            }
        }
    }
    keeper.blocking.wait_all().await;

    // A closed child receiver remains alive until its parent has joined. Its
    // cancellation must never look like an ordinary guest error to that parent.
    drop(parked_senders);
    let result = match root_result.expect("root joined before restoration") {
        Ok(result) => restore(&keeper, result).await,
        Err(error) => restore(&keeper, Err(anyhow!("root task failed: {error}"))).await,
    };
    match result {
        Ok(value)
            if RootState::load(&keeper.state) != RootState::Quarantined
                && !keeper.caught_host_panic.load(Ordering::SeqCst) =>
        {
            keeper
                .state
                .store(RootState::Complete as u8, Ordering::SeqCst);
            registry.roots.lock().await.remove(&keeper.id);
            if let Some(response) = response.take() {
                let _ = response.send(value);
            }
        }
        Ok(value)
            if RootState::load(&keeper.state) != RootState::Quarantined
                && keeper.caught_host_panic.load(Ordering::SeqCst) =>
        {
            keeper.quarantine();
            if let Some(response) = response.take() {
                let _ = response.send(value);
            }
        }
        Ok(_) | Err(_) => {
            keeper.quarantine();
            if let Some(response) = response.take() {
                let _ = response.send(Err(anyhow!("operation root quarantined")));
            }
        }
    }
}

async fn restore<T>(keeper: &RootKeeper, result: Result<RootOutcome<T>>) -> Result<Result<T>> {
    let mut authority = keeper.authority.lock().await;
    let runtime: &mut Runtime = &mut authority;
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
}
