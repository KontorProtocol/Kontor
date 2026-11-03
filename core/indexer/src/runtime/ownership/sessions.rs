use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Result, ensure};
#[cfg(not(kontor_node))]
use futures_util::future::BoxFuture;
use tokio::sync::Notify;

use super::LinkedSession;
#[cfg(not(kontor_node))]
use super::{OwnerService, RootOutcome, Runtime};

struct SessionSlot<T> {
    value: Mutex<Option<T>>,
    available: Notify,
    failed: AtomicBool,
    description: &'static str,
}

impl<T> SessionSlot<T> {
    fn new(value: T, description: &'static str) -> Self {
        Self {
            value: Mutex::new(Some(value)),
            available: Notify::new(),
            failed: AtomicBool::new(false),
            description,
        }
    }

    async fn checkout(&self) -> Result<T> {
        loop {
            let available = self.available.notified();
            tokio::pin!(available);
            // Register before inspecting the slot so return/quarantine cannot
            // wake us between the inspection and registration.
            available.as_mut().enable();
            ensure!(
                !self.failed.load(Ordering::SeqCst),
                "{} is quarantined",
                self.description
            );
            if let Some(value) = self
                .value
                .lock()
                .expect("stateful session lock poisoned")
                .take()
            {
                return Ok(value);
            }
            available.await;
        }
    }

    fn put_back(&self, value: T) {
        let previous = self
            .value
            .lock()
            .expect("stateful session lock poisoned")
            .replace(value);
        assert!(previous.is_none(), "stateful session returned twice");
        self.available.notify_one();
    }

    fn quarantine(&self) {
        self.failed.store(true, Ordering::SeqCst);
        self.available.notify_waiters();
    }
}

#[derive(Clone)]
#[cfg(not(kontor_node))]
pub(crate) struct StatefulSession(Arc<SessionSlot<Runtime>>);

#[derive(Clone)]
#[cfg(not(kontor_node))]
pub(crate) struct OwnedRuntimeSession {
    service: OwnerService,
    pub(super) session: StatefulSession,
}

#[cfg(not(kontor_node))]
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

#[cfg(not(kontor_node))]
pub(super) struct SessionCheckout {
    session: StatefulSession,
    pub(super) runtime: Option<Runtime>,
}

#[cfg(not(kontor_node))]
impl Drop for SessionCheckout {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            self.session.return_runtime(runtime);
        }
    }
}

#[cfg(not(kontor_node))]
impl StatefulSession {
    pub(super) fn new(runtime: Runtime) -> Self {
        Self(Arc::new(SessionSlot::new(
            runtime,
            "stateful runtime session",
        )))
    }

    pub(super) async fn checkout(&self) -> Result<SessionCheckout> {
        Ok(SessionCheckout {
            session: self.clone(),
            runtime: Some(self.0.checkout().await?),
        })
    }

    pub(super) fn return_runtime(&self, runtime: Runtime) {
        self.0.put_back(runtime);
    }

    pub(super) fn quarantine(&self) {
        self.0.quarantine();
    }
}

#[derive(Clone)]
pub(crate) struct LinkedStatefulSession(Arc<SessionSlot<LinkedSession>>);

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Exercised by in-tree ownership compatibility tests"
    )
)]
pub(super) struct LinkedSessionCheckout {
    session: LinkedStatefulSession,
    pub(super) value: Option<LinkedSession>,
}

impl Drop for LinkedSessionCheckout {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            self.session.return_session(value);
        }
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Exercised by in-tree ownership compatibility tests"
    )
)]
impl LinkedStatefulSession {
    pub(crate) fn new(session: LinkedSession) -> Self {
        Self(Arc::new(SessionSlot::new(
            session,
            "linked stateful session",
        )))
    }

    pub(super) async fn checkout(&self) -> Result<LinkedSessionCheckout> {
        Ok(LinkedSessionCheckout {
            session: self.clone(),
            value: Some(self.0.checkout().await?),
        })
    }

    pub(super) fn return_session(&self, value: LinkedSession) {
        self.0.put_back(value);
    }

    pub(super) fn quarantine(&self) {
        self.0.quarantine();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Result;
    use futures_util::poll;
    use tokio::time::timeout;

    use super::SessionSlot;

    #[tokio::test]
    async fn cancelled_waiter_does_not_lose_returned_session() -> Result<()> {
        let slot = SessionSlot::new(7, "test session");
        let value = slot.checkout().await?;
        let mut cancelled = Box::pin(slot.checkout());
        let mut next = Box::pin(slot.checkout());
        assert!(poll!(&mut cancelled).is_pending());
        assert!(poll!(&mut next).is_pending());
        drop(cancelled);
        slot.put_back(value);
        assert_eq!(timeout(Duration::from_secs(1), next).await??, 7);
        Ok(())
    }

    #[tokio::test]
    async fn quarantine_wakes_all_waiters_and_rejects_returned_session() -> Result<()> {
        let slot = SessionSlot::new(7, "test session");
        let value = slot.checkout().await?;
        let mut first = Box::pin(slot.checkout());
        let mut second = Box::pin(slot.checkout());
        assert!(poll!(&mut first).is_pending());
        assert!(poll!(&mut second).is_pending());
        slot.quarantine();
        assert!(timeout(Duration::from_secs(1), first).await?.is_err());
        assert!(timeout(Duration::from_secs(1), second).await?.is_err());
        slot.put_back(value);
        assert!(slot.checkout().await.is_err());
        Ok(())
    }
}
