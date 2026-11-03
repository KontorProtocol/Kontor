use std::any::Any;
#[cfg(not(kontor_node))]
use std::future::Future;
use std::future::pending;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow, ensure};
use tokio::sync::{mpsc, oneshot};

#[cfg(not(kontor_node))]
use super::GuestCompletion;
use super::{
    Admission, BlockingRegistry, GuestDelivery, GuestFuture, RootId, RootKind, RootState,
    SlotLease, TaskCompletion, TaskId,
};

#[derive(Clone)]
pub(in crate::runtime) struct ChildContext {
    pub(super) task: TaskId,
    pub(super) depth: u32,
    pub(super) kind: RootKind,
    pub(super) sender: mpsc::Sender<Admission>,
    pub(super) next_task: Arc<AtomicU64>,
    pub(super) slot: Arc<AtomicBool>,
    pub(super) state: Arc<AtomicU8>,
    pub(super) blocking: Arc<BlockingRegistry>,
    pub(super) panic_seen: Arc<AtomicBool>,
    pub(super) alive: Arc<AtomicBool>,
}

impl ChildContext {
    pub(super) fn root(
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

    pub(in crate::runtime) fn fuel_yield_interval(&self) -> Option<u64> {
        self.kind.fuel_yield_interval()
    }

    #[cfg(not(kontor_node))]
    pub(in crate::runtime) async fn run_guest<F, Fut>(
        &self,
        make_future: F,
    ) -> Result<GuestCompletion>
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

    pub(super) async fn run_linked_guest<F>(
        &self,
        make_future: F,
    ) -> Result<(bool, Box<dyn Any + Send>)>
    where
        F: FnOnce(ChildContext) -> GuestFuture,
    {
        match self.run_admission(make_future).await? {
            TaskCompletion::Linked(panicked, payload) => Ok((panicked, payload)),
            #[cfg(not(kontor_node))]
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

    pub(in crate::runtime) async fn run_blocking<F, T>(&self, work: F) -> Result<T>
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

    pub(in crate::runtime) fn ensure_commit_authorized(&self) -> Result<()> {
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
