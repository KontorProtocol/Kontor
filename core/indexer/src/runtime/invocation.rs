use std::fmt::{self, Display, Formatter};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex as StdMutex;
#[cfg(test)]
use std::sync::Weak;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(test)]
use tokio::sync::Mutex;
#[cfg(test)]
use wasmtime::component::ResourceTable;
use wasmtime::{AsContext, AsContextMut, Store, StoreContext, StoreContextMut};

#[cfg(test)]
use serde_json::{Value as JsonValue, json};

use super::Runtime;
#[cfg(test)]
use super::{ContractAddress, token};

pub(super) const MAX_LIVE_INVOCATIONS: u32 = 64;

#[derive(Default)]
pub(super) struct InvocationBudget {
    live: AtomicU32,
    #[cfg(test)]
    peak: AtomicU32,
    #[cfg(test)]
    teardown_recorder: Option<Arc<ResourceTeardownRecorder>>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResourceProbeRole {
    NestedChain,
    TargetNativeAuxiliary,
    PreObservation,
    PostObservation,
    RollbackObservation,
    Unassigned,
}

#[cfg(test)]
impl ResourceProbeRole {
    fn name(self) -> &'static str {
        match self {
            Self::NestedChain => "nested_chain",
            Self::TargetNativeAuxiliary => "target_native_auxiliary",
            Self::PreObservation => "pre_observation",
            Self::PostObservation => "post_observation",
            Self::RollbackObservation => "rollback_observation",
            Self::Unassigned => "unassigned",
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) enum ResourceProbePhase {
    Target(Arc<Vec<ContractAddress>>),
    PreObservation,
    PostObservation(ContractAddress),
    RollbackObservation(ContractAddress),
}

#[cfg(test)]
impl ResourceProbePhase {
    pub(crate) fn classify(&self, address: &ContractAddress) -> ResourceProbeRole {
        let token = token::address();
        match self {
            Self::Target(chain) if chain.contains(address) => ResourceProbeRole::NestedChain,
            // with_payment invokes token hold/release around paid guest calls.
            Self::Target(_) if address == &token => ResourceProbeRole::TargetNativeAuxiliary,
            Self::PreObservation if address == &token => ResourceProbeRole::PreObservation,
            Self::PostObservation(root) if address == &token || address == root => {
                ResourceProbeRole::PostObservation
            }
            Self::RollbackObservation(root) if address == &token || address == root => {
                ResourceProbeRole::RollbackObservation
            }
            _ => panic!("unreviewed resource probe contract address: {address}"),
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct ResourceTeardownRecorder {
    next_id: AtomicU64,
    events: StdMutex<Vec<JsonValue>>,
    retain_next_table: AtomicBool,
    retained_table: StdMutex<Option<Arc<Mutex<ResourceTable>>>>,
}

#[cfg(test)]
impl ResourceTeardownRecorder {
    fn record(
        &self,
        id: Option<u64>,
        role: ResourceProbeRole,
        kind: &str,
        table_alive: Option<bool>,
    ) {
        self.events
            .lock()
            .expect("teardown recorder poisoned")
            .push(json!({
                "id": id,
                "role": role.name(),
                "kind": kind,
                "table_alive": table_alive,
            }));
    }

    fn reserve(self: &Arc<Self>, role: ResourceProbeRole) -> LeaseTeardownToken {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.record(Some(id), role, "reserved", None);
        LeaseTeardownToken {
            id,
            role,
            recorder: self.clone(),
            live: Arc::new(AtomicBool::new(true)),
        }
    }

    pub(crate) fn record_rejection(&self, role: ResourceProbeRole, kind: &str) {
        assert_ne!(
            role,
            ResourceProbeRole::Unassigned,
            "unassigned resource probe role"
        );
        self.record(None, role, kind, None);
    }

    pub(crate) fn events(&self) -> Vec<JsonValue> {
        self.events
            .lock()
            .expect("teardown recorder poisoned")
            .clone()
    }

    fn store_created(&self, token: &LeaseTeardownToken, table: &Arc<Mutex<ResourceTable>>) {
        if self.retain_next_table.swap(false, Ordering::SeqCst) {
            *self.retained_table.lock().expect("retained table poisoned") = Some(table.clone());
        }
        self.record(Some(token.id), token.role, "store_created", None);
    }

    #[cfg(test)]
    fn retain_one_table_for_negative_control(&self) {
        self.retain_next_table.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
#[derive(Clone)]
struct LeaseTeardownToken {
    id: u64,
    role: ResourceProbeRole,
    recorder: Arc<ResourceTeardownRecorder>,
    live: Arc<AtomicBool>,
}

#[cfg(test)]
struct LifecycleProbe {
    token: LeaseTeardownToken,
    table: Weak<Mutex<ResourceTable>>,
}

#[cfg(test)]
impl Drop for LifecycleProbe {
    fn drop(&mut self) {
        self.token.recorder.record(
            Some(self.token.id),
            self.token.role,
            "table_destroyed",
            Some(self.table.upgrade().is_some()),
        );
        assert!(
            self.token.live.load(Ordering::SeqCst),
            "lease released before Store teardown"
        );
    }
}

impl InvocationBudget {
    #[cfg(test)]
    pub(crate) fn with_teardown_recorder(recorder: Arc<ResourceTeardownRecorder>) -> Self {
        Self {
            teardown_recorder: Some(recorder),
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub(crate) fn record_rejection(&self, role: ResourceProbeRole, kind: &str) {
        if let Some(recorder) = &self.teardown_recorder {
            recorder.record_rejection(role, kind);
        }
    }

    pub(super) fn live(&self) -> u32 {
        self.live.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(super) fn peak(&self) -> u32 {
        self.peak.load(Ordering::SeqCst)
    }

    pub(super) fn reserve(
        self: &Arc<Self>,
    ) -> Result<InvocationLease, InvocationCapacityExhausted> {
        let mut live = self.live();
        loop {
            if live >= MAX_LIVE_INVOCATIONS {
                return Err(InvocationCapacityExhausted);
            }
            match self.live.compare_exchange_weak(
                live,
                live + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    #[cfg(test)]
                    self.peak.fetch_max(live + 1, Ordering::SeqCst);
                    return Ok(InvocationLease {
                        budget: self.clone(),
                        #[cfg(test)]
                        teardown_token: None,
                    });
                }
                Err(actual) => live = actual,
            }
        }
    }

    #[cfg(test)]
    pub(super) fn reserve_for_role(
        self: &Arc<Self>,
        role: ResourceProbeRole,
    ) -> Result<InvocationLease, InvocationCapacityExhausted> {
        let mut lease = match self.reserve() {
            Ok(lease) => lease,
            Err(error) => {
                self.record_rejection(role, "reserve_rejected");
                return Err(error);
            }
        };
        if let Some(recorder) = &self.teardown_recorder {
            assert_ne!(
                role,
                ResourceProbeRole::Unassigned,
                "unassigned resource probe role"
            );
            lease.teardown_token = Some(recorder.reserve(role));
        }
        Ok(lease)
    }
}

pub(super) struct InvocationLease {
    budget: Arc<InvocationBudget>,
    #[cfg(test)]
    teardown_token: Option<LeaseTeardownToken>,
}

impl Drop for InvocationLease {
    fn drop(&mut self) {
        self.budget
            .live
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |live| {
                live.checked_sub(1)
            })
            .expect("invocation lease count underflow");
        #[cfg(test)]
        if let Some(token) = &self.teardown_token {
            assert!(
                token.live.swap(false, Ordering::SeqCst),
                "duplicate lease release"
            );
            token
                .recorder
                .record(Some(token.id), token.role, "lease_released", None);
        }
    }
}

#[derive(Debug)]
pub(super) struct InvocationLimitReached;

impl Display for InvocationLimitReached {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "live invocation limit of {MAX_LIVE_INVOCATIONS} reached")
    }
}

impl std::error::Error for InvocationLimitReached {}

#[derive(Debug)]
pub(super) struct InvocationCapacityExhausted;

impl Display for InvocationCapacityExhausted {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "physical invocation capacity of {MAX_LIVE_INVOCATIONS} exhausted"
        )
    }
}

impl std::error::Error for InvocationCapacityExhausted {}

pub(crate) struct InvocationStore {
    store: Store<Runtime>,
    #[cfg(test)]
    _lifecycle_probe: Option<LifecycleProbe>,
    // Store must finish deallocating before its lease releases capacity.
    #[cfg(test)]
    teardown_probe: Option<TeardownProbe>,
    _lease: InvocationLease,
}

#[cfg(test)]
struct TeardownProbe {
    budget: Arc<InvocationBudget>,
    table: Weak<Mutex<ResourceTable>>,
    observed: Arc<AtomicBool>,
}

#[cfg(test)]
impl Drop for TeardownProbe {
    fn drop(&mut self) {
        assert!(
            self.table.upgrade().is_none(),
            "Store data must be gone first"
        );
        assert_eq!(self.budget.live(), 1, "lease must survive Store teardown");
        self.observed.store(true, Ordering::SeqCst);
    }
}

impl InvocationStore {
    pub(super) fn new(store: Store<Runtime>, lease: InvocationLease) -> Self {
        #[cfg(test)]
        let lifecycle_probe = lease.teardown_token.as_ref().map(|token| {
            token.recorder.store_created(token, &store.data().table);
            LifecycleProbe {
                token: token.clone(),
                table: Arc::downgrade(&store.data().table),
            }
        });
        Self {
            store,
            #[cfg(test)]
            _lifecycle_probe: lifecycle_probe,
            #[cfg(test)]
            teardown_probe: None,
            _lease: lease,
        }
    }

    #[cfg(test)]
    pub(super) fn record_initialization_failure(&self) {
        if let Some(probe) = &self._lifecycle_probe {
            probe.token.recorder.record(
                Some(probe.token.id),
                probe.token.role,
                "store_initialization_failed",
                None,
            );
        }
    }

    #[cfg(test)]
    fn install_teardown_probe(&mut self, observed: Arc<AtomicBool>) {
        self.teardown_probe = Some(TeardownProbe {
            budget: self._lease.budget.clone(),
            table: Arc::downgrade(&self.store.data().table),
            observed,
        });
    }
}

impl Deref for InvocationStore {
    type Target = Store<Runtime>;

    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

impl DerefMut for InvocationStore {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.store
    }
}

impl AsContext for InvocationStore {
    type Data = Runtime;

    fn as_context(&self) -> StoreContext<'_, Self::Data> {
        self.store.as_context()
    }
}

impl AsContextMut for InvocationStore {
    fn as_context_mut(&mut self) -> StoreContextMut<'_, Self::Data> {
        self.store.as_context_mut()
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use anyhow::Result;

    use crate::test_utils::test_runtime;

    use super::{InvocationBudget, InvocationLease, ResourceProbePhase, ResourceTeardownRecorder};
    use crate::runtime::ContractAddress;
    use crate::runtime::token;

    #[test]
    fn lease_underflow_panics_without_wrapping_the_count() {
        let budget = Arc::new(InvocationBudget::default());
        let lease = InvocationLease {
            budget: budget.clone(),
            teardown_token: None,
        };
        assert!(catch_unwind(AssertUnwindSafe(|| drop(lease))).is_err());
        assert_eq!(budget.live(), 0);
    }

    #[tokio::test]
    async fn owner_keeps_the_lease_until_store_teardown_finishes() -> Result<()> {
        let (runtime, _dir, _name) = test_runtime().await?;
        let mut store = runtime.make_store(1_000_000)?;
        let budget = store.data().invocation_budget.as_ref().unwrap().clone();
        let observed = Arc::new(AtomicBool::new(false));
        store.install_teardown_probe(observed.clone());
        assert_eq!(budget.live(), 1);
        drop(store);
        assert!(observed.load(Ordering::SeqCst));
        assert_eq!(budget.live(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn retained_table_negative_control_reports_one_live_table() -> Result<()> {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let recorder = Arc::new(ResourceTeardownRecorder::default());
        recorder.retain_one_table_for_negative_control();
        let budget = Arc::new(InvocationBudget::with_teardown_recorder(recorder.clone()));
        runtime.invocation_budget = Some(budget.clone());
        runtime.resource_probe_phase = Some(ResourceProbePhase::PreObservation);
        let store = runtime.make_store_for_call(1_000_000, &token::address())?;
        drop(store);
        let events = recorder.events();
        assert_eq!(budget.live(), 0);
        assert_eq!(events.len(), 4);
        assert_eq!(events[2]["kind"], "table_destroyed");
        assert_eq!(events[2]["table_alive"], true);
        assert_eq!(events[3]["kind"], "lease_released");
        Ok(())
    }

    #[test]
    fn target_phase_rejects_unreviewed_contract_address() {
        let chain_address = ContractAddress {
            name: "deep-errors".into(),
            height: 1,
            tx_index: 0,
        };
        let unknown = ContractAddress {
            name: "unknown".into(),
            height: 1,
            tx_index: 0,
        };
        let phase = ResourceProbePhase::Target(Arc::new(vec![chain_address.clone()]));
        assert_eq!(phase.classify(&chain_address).name(), "nested_chain");
        assert_eq!(
            phase.classify(&token::address()).name(),
            "target_native_auxiliary"
        );
        assert!(catch_unwind(AssertUnwindSafe(|| phase.classify(&unknown))).is_err());
    }
}
