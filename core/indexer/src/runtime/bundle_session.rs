use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{Error, Result, ensure};
use tokio::sync::Mutex;
use wasmtime::component::ResourceTable;

use super::Runtime;
use super::bundle_ownership::{
    BundleOwner, HostError, HostFailure, RootHooks, RootReset, RootSettle, SessionAction,
    SharedOwner,
};
use super::invocation::InvocationBudget;
use crate::protocol::execution::SelectionEnvelope;

pub(super) struct BundleSession {
    pub(super) runtime: Mutex<Runtime>,
}

impl BundleSession {
    pub(super) fn new(runtime: Runtime) -> Arc<Self> {
        Arc::new(Self {
            runtime: Mutex::new(runtime),
        })
    }

    pub(super) fn root_hooks(
        self: &Arc<Self>,
        capability: BundleOwner,
        canonical: bool,
        selection: SelectionEnvelope,
    ) -> RootHooks {
        let committed = Arc::new(AtomicBool::new(false));
        let expected = self.clone();
        let prepare_owner = capability.clone();
        let prepare: SessionAction = Arc::new(move |opaque| {
            let session = expected.clone();
            let owner = prepare_owner.clone();
            let selection = selection.clone();
            Box::pin(async move {
                session.verify_owner(opaque, &owner)?;
                let mut runtime = session.runtime.lock().await;
                runtime.ensure_bundle_idle().await.map_err(infrastructure)?;
                runtime
                    .install_root_selection(&selection)
                    .map_err(infrastructure)?;
                runtime.invocation_budget = Some(Arc::new(InvocationBudget::default()));
                runtime.store_table_owners = Some(Arc::new(StdMutex::new(Vec::new())));
                runtime.storage.bundle_owner = Some(owner.clone());
                runtime.bundle_owner = Some(owner);
                if !canonical {
                    runtime.storage.savepoint().await.map_err(infrastructure)?;
                }
                Ok(())
            })
        });
        let expected = self.clone();
        let inspect_owner = capability.clone();
        let inspect: SessionAction = Arc::new(move |opaque| {
            let session = expected.clone();
            let owner = inspect_owner.clone();
            Box::pin(async move {
                session.verify_owner(opaque, &owner)?;
                let runtime = session.runtime.lock().await;
                runtime
                    .ensure_bundle_drained()
                    .await
                    .map_err(infrastructure)
            })
        });
        let expected = self.clone();
        let settle_owner = capability.clone();
        let settled_commit = committed.clone();
        let settle: RootSettle = Arc::new(move |opaque, commit| {
            let session = expected.clone();
            let owner = settle_owner.clone();
            let committed = settled_commit.clone();
            Box::pin(async move {
                session.verify_owner(opaque, &owner)?;
                let runtime = session.runtime.lock().await;
                if commit {
                    runtime.storage.commit().await.map_err(infrastructure)?;
                    committed.store(true, Ordering::SeqCst);
                } else {
                    runtime
                        .storage
                        .rollback_transaction()
                        .await
                        .map_err(infrastructure)?;
                }
                Ok(())
            })
        });
        let expected = self.clone();
        let reset: RootReset = Arc::new(move |opaque, canonical_reset, clear_cache| {
            let session = expected.clone();
            let owner = capability.clone();
            let committed = committed.clone();
            Box::pin(async move {
                session.verify_owner(opaque, &owner)?;
                if canonical_reset != canonical {
                    owner.report_failure(2)?;
                    return Err((2, "executor root cleanup kind mismatch".into()));
                }
                let mut runtime = session.runtime.lock().await;
                if !canonical && !committed.load(Ordering::SeqCst) {
                    runtime.stack.clear().await;
                    runtime.deposit.reset().await;
                }
                if clear_cache {
                    runtime.component_cache.clear();
                }
                runtime
                    .ensure_bundle_drained()
                    .await
                    .map_err(infrastructure)?;
                if !runtime.storage.savepoint_stack.is_empty().await {
                    return Err((0, "executor root retains a savepoint".into()));
                }
                runtime.bundle_owner = None;
                runtime.storage.bundle_owner = None;
                runtime.invocation_budget = None;
                runtime.store_table_owners = None;
                runtime.selected_context = None;
                *runtime.table.lock().await = ResourceTable::new();
                Ok(())
            })
        });
        (prepare, inspect, settle, reset)
    }

    pub(super) fn recycle(self: &Arc<Self>) -> SessionAction {
        let expected = self.clone();
        Arc::new(move |opaque| {
            let session = expected.clone();
            Box::pin(async move {
                let supplied = opaque
                    .downcast::<Self>()
                    .map_err(|_| (2, "executor session has the wrong type".into()))?;
                if !Arc::ptr_eq(&supplied, &session) {
                    return Err((2, "executor session has the wrong identity".into()));
                }
                let runtime = session.runtime.lock().await;
                runtime.ensure_bundle_idle().await.map_err(infrastructure)?;
                *runtime.table.lock().await = ResourceTable::new();
                Ok(())
            })
        })
    }

    fn verify_owner(
        self: &Arc<Self>,
        opaque: SharedOwner,
        capability: &BundleOwner,
    ) -> Result<(), HostError> {
        let supplied = opaque.downcast::<Self>();
        if supplied
            .as_ref()
            .is_ok_and(|supplied| Arc::ptr_eq(supplied, self))
        {
            return Ok(());
        }
        capability.report_failure(2)?;
        Err((2, "executor session has the wrong identity".into()))
    }
}

impl Runtime {
    async fn ensure_bundle_drained(&self) -> Result<()> {
        let live_table = self.store_table_owners.as_ref().is_some_and(|owners| {
            owners
                .lock()
                .expect("store table tracker poisoned")
                .iter()
                .any(|owner| owner.strong_count() != 0)
        });
        // The node retains this session, not a cloned Runtime. Only the session
        // may retain the root table after every invocation has been joined.
        ensure!(
            self.stack.is_empty().await
                && self
                    .invocation_budget
                    .as_ref()
                    .is_none_or(|budget| budget.live() == 0)
                && !live_table
                && Arc::strong_count(&self.table) == 1,
            "executor root retains a guest Store, stack or table"
        );
        Ok(())
    }

    async fn ensure_bundle_idle(&self) -> Result<()> {
        ensure!(
            self.ownership.is_none()
                && self.storage.ownership.is_none()
                && self.bundle_owner.is_none()
                && self.storage.bundle_owner.is_none()
                && self.invocation_budget.is_none()
                && self.store_table_owners.is_none()
                && self.selected_context.is_none(),
            "executor session is still owned by a prior root"
        );
        ensure!(
            self.storage.savepoint_stack.is_empty().await,
            "executor session retains a savepoint"
        );
        self.ensure_bundle_drained().await
    }
}

pub(super) fn infrastructure(error: Error) -> HostError {
    let tag = error
        .downcast_ref::<HostFailure>()
        .map_or(0, |error| error.tag);
    (tag, format!("{error:#}"))
}
