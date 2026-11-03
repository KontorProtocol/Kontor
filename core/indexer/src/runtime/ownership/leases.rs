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
    pub(super) keeper: Arc<RootKeeper>,
    pub(super) registry: Arc<OwnerRegistry>,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "Retained for ownership inspection in unit tests")
    )]
    pub(super) adapter: OwnerAdapter,
    pub(super) root_alive: Arc<AtomicBool>,
    pub(super) finish: Option<oneshot::Sender<()>>,
    pub(super) drained: oneshot::Receiver<Result<bool>>,
    pub(super) settlement_signal: Option<oneshot::Sender<(bool, oneshot::Sender<Result<()>>)>>,
    pub(super) drained_success: bool,
    pub(super) requires_settlement: bool,
    pub(super) settled: bool,
    pub(super) settlement_in_flight: bool,
    pub(super) complete_signal: Option<oneshot::Sender<()>>,
    pub(super) released_signal: Option<oneshot::Sender<()>>,
    pub(super) completed: Option<oneshot::Receiver<Result<()>>>,
    pub(super) complete: bool,
}

impl LinkedCanonicalRootLease {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Exercised by in-tree ownership compatibility tests"
        )
    )]
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
