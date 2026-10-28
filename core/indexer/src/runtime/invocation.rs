use std::fmt::{self, Display, Formatter};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Weak;
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(test)]
use tokio::sync::Mutex;
#[cfg(test)]
use wasmtime::component::ResourceTable;
use wasmtime::{AsContext, AsContextMut, Store, StoreContext, StoreContextMut};

use super::Runtime;

pub(super) const MAX_LIVE_INVOCATIONS: u32 = 64;

#[derive(Default)]
pub(super) struct InvocationBudget {
    live: AtomicU32,
}

impl InvocationBudget {
    pub(super) fn live(&self) -> u32 {
        self.live.load(Ordering::SeqCst)
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
                    return Ok(InvocationLease {
                        budget: self.clone(),
                    });
                }
                Err(actual) => live = actual,
            }
        }
    }
}

pub(super) struct InvocationLease {
    budget: Arc<InvocationBudget>,
}

impl Drop for InvocationLease {
    fn drop(&mut self) {
        self.budget
            .live
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |live| {
                live.checked_sub(1)
            })
            .expect("invocation lease count underflow");
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
        Self {
            store,
            #[cfg(test)]
            teardown_probe: None,
            _lease: lease,
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

    use super::{InvocationBudget, InvocationLease};

    #[test]
    fn lease_underflow_panics_without_wrapping_the_count() {
        let budget = Arc::new(InvocationBudget::default());
        let lease = InvocationLease {
            budget: budget.clone(),
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
}
