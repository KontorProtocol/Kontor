use std::any::Any;
use std::fmt;
use std::future::Future;

pub(crate) use crate::protocol::session::{
    BlockingWork, CheckCommit, GuestFactory, HostError, Payload, ReportFailure, RootHooks,
    RootReset, RootSettle, SelectionSource, SessionAction, SharedOwner, SubmitBlocking,
    SubmitGuest,
};

#[derive(Debug)]
pub(crate) struct HostFailure {
    pub(crate) tag: u8,
    pub(crate) message: String,
}

impl From<HostError> for HostFailure {
    fn from(error: HostError) -> Self {
        let (tag, message) = normalize(error);
        Self { tag, message }
    }
}

impl fmt::Display for HostFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for HostFailure {}

#[derive(Clone)]
pub(crate) struct BundleOwner {
    token: SharedOwner,
    submit_guest: SubmitGuest,
    submit_blocking: SubmitBlocking,
    check_commit: CheckCommit,
    report_failure: ReportFailure,
    fuel_yield_interval: Option<u64>,
}

impl BundleOwner {
    pub(crate) fn new(
        token: SharedOwner,
        submit_guest: SubmitGuest,
        submit_blocking: SubmitBlocking,
        check_commit: CheckCommit,
        report_failure: ReportFailure,
        fuel_yield_interval: Option<u64>,
    ) -> Self {
        Self {
            token,
            submit_guest,
            submit_blocking,
            check_commit,
            report_failure,
            fuel_yield_interval,
        }
    }

    pub(crate) fn fuel_yield_interval(&self) -> Option<u64> {
        self.fuel_yield_interval
    }

    pub(crate) async fn run_guest<T, F, Fut>(&self, factory: F) -> Result<(bool, T), HostError>
    where
        T: Any + Send + 'static,
        F: FnOnce(BundleOwner) -> Fut + Send + 'static,
        Fut: Future<Output = (bool, T)> + Send + 'static,
    {
        let parent = self.clone();
        let guest: GuestFactory = Box::new(move |child_token| {
            let child = parent.child(child_token);
            let future = factory(child);
            Box::pin(async move {
                let (host_panicked, value) = future.await;
                (host_panicked, Box::new(value) as Payload)
            })
        });
        let (host_panicked, payload) = (self.submit_guest)(self.token.clone(), guest)
            .await
            .map_err(normalize)?;
        let value = payload
            .downcast::<T>()
            .map_err(|_| self.payload_mismatch())?;
        Ok((host_panicked, *value))
    }

    pub(crate) async fn run_blocking<T, F>(&self, work: F) -> Result<T, HostError>
    where
        T: Any + Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let work: BlockingWork = Box::new(move || Box::new(work()) as Payload);
        let payload = (self.submit_blocking)(self.token.clone(), work)
            .await
            .map_err(normalize)?;
        let value = payload
            .downcast::<T>()
            .map_err(|_| self.payload_mismatch())?;
        Ok(*value)
    }

    pub(crate) fn ensure_commit_authorized(&self) -> Result<(), HostError> {
        (self.check_commit)(self.token.clone()).map_err(normalize)
    }

    pub(crate) fn report_failure(&self, tag: u8) -> Result<(), HostError> {
        (self.report_failure)(self.token.clone(), tag).map_err(normalize)
    }

    fn child(&self, token: SharedOwner) -> Self {
        Self {
            token,
            submit_guest: self.submit_guest.clone(),
            submit_blocking: self.submit_blocking.clone(),
            check_commit: self.check_commit.clone(),
            report_failure: self.report_failure.clone(),
            fuel_yield_interval: self.fuel_yield_interval,
        }
    }

    fn payload_mismatch(&self) -> HostError {
        match (self.report_failure)(self.token.clone(), 2) {
            Ok(()) => (2, "opaque host payload type mismatch".into()),
            Err(error) => normalize(error),
        }
    }
}

fn normalize((tag, message): HostError) -> HostError {
    if tag <= 2 {
        (tag, message)
    } else {
        (0, format!("unknown host failure tag {tag}: {message}"))
    }
}
