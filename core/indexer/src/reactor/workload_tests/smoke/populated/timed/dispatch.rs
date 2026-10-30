use std::sync::Arc;
use std::time::Duration;

#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until};

use super::{Action, Event, Schedule};

#[cfg(target_os = "linux")]
mod external;
pub(super) mod historical;
mod tests;

pub(super) trait Work {
    async fn check_before(&mut self, event: &Event) -> Result<()>;
    async fn execute(&mut self, event: &Event) -> Result<()>;
    async fn check(&mut self, event: &Event) -> Result<()>;
}

#[derive(Debug, Serialize)]
pub(super) struct ReplayObservation {
    event: Event,
    precheck_ns: u64,
    service_ns: u64,
    verification_ns: u64,
}

impl ReplayObservation {
    pub(super) fn new(
        event: &Event,
        before: Instant,
        dispatch: Instant,
        service_done: Instant,
        checked: Instant,
    ) -> Result<Self> {
        Ok(Self {
            event: event.clone(),
            precheck_ns: nanos(dispatch.duration_since(before))?,
            service_ns: nanos(service_done.duration_since(dispatch))?,
            verification_ns: nanos(checked.duration_since(service_done))?,
        })
    }
}

pub(super) async fn replay_event(event: &Event, work: &mut impl Work) -> Result<ReplayObservation> {
    let before = Instant::now();
    work.check_before(event)
        .await
        .with_context(|| format!("precheck event {}", event.ordinal))?;
    let dispatch = Instant::now();
    work.execute(event)
        .await
        .with_context(|| format!("execute event {}", event.ordinal))?;
    let service_done = Instant::now();
    work.check(event)
        .await
        .with_context(|| format!("check event {}", event.ordinal))?;
    let checked = Instant::now();
    ReplayObservation::new(event, before, dispatch, service_done, checked)
}

#[derive(Debug)]
struct Arrival {
    ordinal: usize,
    enqueued: Duration,
}

struct Arrivals {
    schedule: Arc<Schedule>,
    start: Clock,
    receiver: UnboundedReceiver<Arrival>,
    producer: Option<JoinHandle<Result<()>>>,
}

enum Clock {
    Local(Instant),
    #[cfg(target_os = "linux")]
    External(u64),
}

impl Clock {
    fn elapsed(&self) -> Result<Duration> {
        match self {
            Self::Local(start) => Ok(start.elapsed()),
            #[cfg(target_os = "linux")]
            Self::External(epoch) => Ok(Duration::from_nanos(
                external::monotonic_ns()?
                    .checked_sub(*epoch)
                    .context("arrival clock regressed")?,
            )),
        }
    }
}

impl Arrivals {
    async fn new(schedule: Schedule) -> Result<Self> {
        Self::filtered(schedule, false).await
    }

    async fn filtered(schedule: Schedule, api_only: bool) -> Result<Self> {
        schedule.validate()?;
        let schedule = Arc::new(schedule);
        if let Some(path) = std::env::var_os("KONTOR_WORKLOAD_ARRIVAL_SOCKET") {
            #[cfg(target_os = "linux")]
            return external::connect(
                path.to_str().context("non-UTF8 arrival socket path")?,
                schedule,
                api_only,
            )
            .await;
            #[cfg(not(target_os = "linux"))]
            bail!("external arrivals require Linux: {path:?}");
        }
        let source = schedule.clone();
        let (sender, receiver) = unbounded_channel();
        let start = Instant::now();
        let producer = tokio::spawn(async move {
            for event in &source.events {
                if api_only && event.action.canonical() {
                    continue;
                }
                let due = start
                    .checked_add(Duration::from_secs(event.at_seconds))
                    .context("arrival deadline overflow")?;
                sleep_until(due).await;
                sender
                    .send(Arrival {
                        ordinal: event.ordinal,
                        enqueued: start.elapsed(),
                    })
                    .context("arrival receiver closed")?;
            }
            Ok(())
        });
        Ok(Self {
            schedule,
            start: Clock::Local(start),
            receiver,
            producer: Some(producer),
        })
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(producer) = self.producer.take() {
            producer.abort();
            match producer.await {
                Ok(result) => result?,
                Err(error) if error.is_cancelled() => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

impl Drop for Arrivals {
    fn drop(&mut self) {
        // This task owns only the finite arrival queue, never a guest invocation.
        if let Some(producer) = &self.producer {
            producer.abort();
        }
    }
}

fn nanos(duration: Duration) -> Result<u64> {
    u64::try_from(duration.as_nanos()).context("workload duration exceeds recorded range")
}

#[derive(Debug, Serialize)]
pub(super) struct Observation {
    pub(super) ordinal: usize,
    pub(super) intended_ns: u64,
    pub(super) enqueued_ns: u64,
    pub(super) canonical_ready_ns: u64,
    pub(super) ordered_ready_ns: u64,
    pub(super) precheck_ns: u64,
    pub(super) dispatch_ns: u64,
    pub(super) service_done_ns: u64,
    pub(super) checked_ns: u64,
}

#[derive(Debug, Serialize)]
pub(super) struct Report {
    pub(super) events: Vec<Observation>,
    pub(super) completion_ns: u64,
    pub(super) active_service_ns: u64,
    pub(super) scheduled_unconfirmed_transactions: usize,
}

pub(super) async fn drain(schedule: Schedule, work: &mut impl Work) -> Result<Report> {
    ensure!(
        schedule.spec.fresh_backlog == 6,
        "drain requires the six-block backlog"
    );
    let mut arrivals = Arrivals::new(schedule).await?;
    let result = drain_inner(&mut arrivals, work).await;
    let stopped = arrivals.stop().await;
    let report = result?;
    stopped?;
    Ok(report)
}

fn drain_deadline(elapsed: Duration) -> Result<()> {
    ensure!(
        elapsed <= Duration::from_secs(600),
        "backlog drain exceeded 600 seconds"
    );
    Ok(())
}

async fn drain_inner(arrivals: &mut Arrivals, work: &mut impl Work) -> Result<Report> {
    let mut observations: Vec<Observation> = Vec::new();
    let mut active_service_ns = 0u64;
    let mut pending = 0usize;
    loop {
        let observation_time = arrivals.start.elapsed()?;
        drain_deadline(observation_time)?;
        let required = arrivals
            .schedule
            .required_before_validated(observation_time)?;
        if observations.len() >= required && observations.len() >= 6 {
            return Ok(Report {
                events: observations,
                completion_ns: nanos(observation_time)?,
                active_service_ns,
                scheduled_unconfirmed_transactions: pending,
            });
        }
        let arrival = arrivals
            .receiver
            .recv()
            .await
            .context("arrival stream exhausted")?;
        let ordinal = observations.len();
        ensure!(
            arrival.ordinal == ordinal,
            "arrival order differs from frozen schedule"
        );
        let event = arrivals.schedule.event(ordinal)?;
        let intended = Duration::from_secs(event.at_seconds);
        ensure!(
            arrival.enqueued >= intended,
            "event was enqueued before its deadline"
        );
        let canonical_ready_ns = match event.depends_on {
            Some(dependency) => {
                observations
                    .get(dependency)
                    .context("event canonical dependency has not completed")?
                    .checked_ns
            }
            None => 0,
        };
        let ordered_ready_ns = observations
            .last()
            .map_or(0, |previous| previous.checked_ns);
        let precheck = arrivals.start.elapsed()?;
        ensure!(precheck >= arrival.enqueued);
        work.check_before(event)
            .await
            .with_context(|| format!("precheck event {ordinal}"))?;
        let dispatch = arrivals.start.elapsed()?;
        drain_deadline(dispatch)?;
        work.execute(event)
            .await
            .with_context(|| format!("execute event {ordinal}"))?;
        let service_done = arrivals.start.elapsed()?;
        work.check(event)
            .await
            .with_context(|| format!("check event {ordinal}"))?;
        let checked = arrivals.start.elapsed()?;
        match &event.action {
            Action::Batch { transactions, .. } => {
                pending = pending
                    .checked_add(transactions.len())
                    .context("pending count overflow")?;
            }
            Action::Block { block } => {
                pending = pending
                    .checked_sub(arrivals.schedule.blocks[*block].confirmations.len())
                    .context("block confirmed unexecuted schedule transactions")?;
            }
            Action::Simulation { .. } => {}
        }
        let service_done_ns = nanos(service_done)?;
        let dispatch_ns = nanos(dispatch)?;
        active_service_ns = active_service_ns
            .checked_add(service_done_ns - dispatch_ns)
            .context("active service total overflow")?;
        let observation = Observation {
            ordinal,
            intended_ns: nanos(intended)?,
            enqueued_ns: nanos(arrival.enqueued)?,
            canonical_ready_ns,
            ordered_ready_ns,
            precheck_ns: nanos(precheck)?,
            dispatch_ns,
            service_done_ns,
            checked_ns: nanos(checked)?,
        };
        eprintln!(
            "workload_dispatch_event={}",
            serde_json::to_string(&observation)?
        );
        observations.push(observation);
    }
}
