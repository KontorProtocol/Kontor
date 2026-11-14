use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use anyhow::{Context, Result, anyhow, ensure};
use tokio::sync::oneshot;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
#[cfg(not(kontor_node))]
use wasmtime::component::ResourceTable;

#[cfg(not(kontor_node))]
use super::Runtime;
use super::{OwnerAdapter, OwnerRegistry, RootKeeper, RootState, wake_owner};

pub(crate) struct OwnedRootHandle<T> {
    pub(super) state: Arc<AtomicU8>,
    pub(super) closing_at: Arc<std::sync::Mutex<Option<Instant>>>,
    pub(super) cancellation: CancellationToken,
    pub(super) result: oneshot::Receiver<Result<T>>,
}

#[cfg(not(kontor_node))]
pub(crate) struct CanonicalRootLease {
    pub(super) keeper: Arc<RootKeeper>,
    pub(super) registry: Arc<OwnerRegistry>,
    pub(super) finish: Option<oneshot::Sender<()>>,
    pub(super) drained: oneshot::Receiver<Result<()>>,
    pub(super) complete: bool,
}

pub(crate) struct LinkedCanonicalRootLease {
    release: CanonicalRelease,
    root_alive: Arc<AtomicBool>,
    finish: oneshot::Sender<()>,
    drained: oneshot::Receiver<Result<bool>>,
    settlement: SettlementSignal,
}

type SettlementSignal = oneshot::Sender<(bool, oneshot::Sender<Result<()>>)>;

pub(super) struct CanonicalRequests {
    pub(super) finished: oneshot::Receiver<()>,
    pub(super) drained: oneshot::Sender<Result<bool>>,
    pub(super) settlement: oneshot::Receiver<(bool, oneshot::Sender<Result<()>>)>,
    pub(super) complete: oneshot::Receiver<()>,
    pub(super) released: oneshot::Receiver<()>,
    pub(super) completed: oneshot::Sender<Result<()>>,
}

pub(crate) enum DrainedCanonicalRoot {
    NeedsSettlement(CanonicalSettlement),
    NoTransaction(CanonicalCompletion),
}

pub(crate) struct CanonicalSettlement {
    release: CanonicalRelease,
    settlement: SettlementSignal,
}

pub(crate) struct CanonicalCompletion {
    release: CanonicalRelease,
}

struct CanonicalRelease {
    guard: CanonicalGuard,
    complete: oneshot::Sender<()>,
    released: oneshot::Sender<()>,
    completed: oneshot::Receiver<Result<()>>,
}

struct CanonicalGuard {
    keeper: Arc<RootKeeper>,
    registry: Arc<OwnerRegistry>,
    _adapter: OwnerAdapter,
    armed: bool,
}

impl Drop for CanonicalGuard {
    fn drop(&mut self) {
        if self.armed {
            self.keeper.quarantine();
            self.registry.fatal.store(true, Ordering::SeqCst);
            self.registry.capacity.close();
        }
    }
}

impl LinkedCanonicalRootLease {
    pub(super) fn new(
        keeper: Arc<RootKeeper>,
        registry: Arc<OwnerRegistry>,
        adapter: OwnerAdapter,
        root_alive: Arc<AtomicBool>,
    ) -> (Self, CanonicalRequests) {
        let (finish, finished) = oneshot::channel();
        let (drained_sender, drained) = oneshot::channel();
        let (settlement, settlement_request) = oneshot::channel();
        let (complete, complete_request) = oneshot::channel();
        let (released, released_request) = oneshot::channel();
        let (completed_sender, completed) = oneshot::channel();
        (
            Self {
                release: CanonicalRelease {
                    guard: CanonicalGuard {
                        keeper,
                        registry,
                        _adapter: adapter,
                        armed: true,
                    },
                    complete,
                    released,
                    completed,
                },
                root_alive,
                finish,
                drained,
                settlement,
            },
            CanonicalRequests {
                finished,
                drained: drained_sender,
                settlement: settlement_request,
                complete: complete_request,
                released: released_request,
                completed: completed_sender,
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn adapter(&self) -> OwnerAdapter {
        self.release.guard._adapter.clone()
    }

    pub(crate) async fn drain(self) -> Result<DrainedCanonicalRoot> {
        let Self {
            release,
            root_alive,
            finish,
            drained,
            settlement,
        } = self;
        finish
            .send(())
            .map_err(|_| anyhow!("canonical root supervisor disappeared"))?;
        let must_settle = drained
            .await
            .context("canonical root supervisor disappeared before drain")??;
        root_alive.store(false, Ordering::SeqCst);
        if must_settle {
            Ok(DrainedCanonicalRoot::NeedsSettlement(CanonicalSettlement {
                release,
                settlement,
            }))
        } else {
            drop(settlement);
            Ok(DrainedCanonicalRoot::NoTransaction(CanonicalCompletion {
                release,
            }))
        }
    }
}

impl DrainedCanonicalRoot {
    pub(crate) fn require_settlement(self) -> Result<CanonicalSettlement> {
        match self {
            Self::NeedsSettlement(root) => Ok(root),
            Self::NoTransaction(_) => Err(anyhow!("canonical root has no transaction to settle")),
        }
    }
}

impl CanonicalSettlement {
    pub(crate) async fn settle(self, commit: bool) -> Result<CanonicalCompletion> {
        let Self {
            release,
            settlement,
        } = self;
        let (reply, result) = oneshot::channel();
        settlement
            .send((commit, reply))
            .map_err(|_| anyhow!("canonical settlement supervisor disappeared"))?;
        result
            .await
            .context("canonical settlement supervisor disappeared")??;
        Ok(CanonicalCompletion { release })
    }
}

impl CanonicalCompletion {
    pub(crate) async fn complete(self) -> Result<()> {
        let CanonicalRelease {
            mut guard,
            complete,
            released,
            completed,
        } = self.release;
        ensure!(
            RootState::load(&guard.keeper.state) == RootState::Committing,
            "canonical root was not drained"
        );
        complete
            .send(())
            .map_err(|_| anyhow!("canonical completion supervisor disappeared"))?;
        // No await may split disarming the caller from releasing its authority.
        // Reset belongs to the supervisor even if the completion waiter disappears.
        guard.armed = false;
        drop(guard);
        let _ = released.send(());
        completed
            .await
            .context("canonical completion supervisor disappeared")?
    }
}

#[cfg(not(kontor_node))]
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

#[cfg(not(kontor_node))]
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

#[cfg(test)]
mod tests;
