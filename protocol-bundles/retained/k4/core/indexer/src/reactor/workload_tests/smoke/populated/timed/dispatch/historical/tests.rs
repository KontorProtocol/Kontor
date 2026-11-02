use anyhow::{Result, bail, ensure};
use tokio::time::{Instant, sleep, timeout};

use super::super::super::{Action, Profile, Spec};
use super::{Duration, Event, HistoricalWork, ReplayObservation, Schedule, Work, required, run};

#[derive(Default)]
struct RecordingWork {
    ordinal: usize,
    canonical: Vec<usize>,
    skipped: Vec<usize>,
    api: Vec<usize>,
    fail_api: bool,
    fail_checkpoint: bool,
    slow_first: bool,
    slow_final: bool,
}

impl Work for RecordingWork {
    async fn check_before(&mut self, event: &Event) -> Result<()> {
        ensure!(event.ordinal == self.ordinal && event.action.canonical());
        Ok(())
    }

    async fn execute(&mut self, event: &Event) -> Result<()> {
        if self.slow_first && self.canonical.is_empty() {
            sleep(Duration::from_millis(1_050)).await;
        }
        if self.slow_final && matches!(event.action, Action::Block { .. }) {
            sleep(Duration::from_millis(1_050)).await;
        }
        self.canonical.push(event.ordinal);
        Ok(())
    }

    async fn check(&mut self, event: &Event) -> Result<()> {
        ensure!(self.canonical.last() == Some(&event.ordinal));
        self.ordinal += 1;
        Ok(())
    }
}

impl HistoricalWork for RecordingWork {
    async fn skip_historical_api(&mut self, event: &Event) -> Result<()> {
        ensure!(event.ordinal == self.ordinal && !event.action.canonical());
        if self.fail_checkpoint {
            bail!("frozen checkpoint differs");
        }
        self.skipped.push(event.ordinal);
        self.ordinal += 1;
        Ok(())
    }

    async fn external_api(&mut self, event: &Event) -> Result<ReplayObservation> {
        ensure!(!self.canonical.is_empty());
        let Action::Simulation { request, .. } = event.action else {
            bail!("unexpected canonical API event");
        };
        ensure!(request == self.api.len());
        if self.fail_api {
            bail!("external API rollback differs");
        }
        let started = Instant::now();
        sleep(Duration::from_millis(2)).await;
        let dispatch = Instant::now();
        if self.slow_final && self.canonical.len() == 41 && request == 1 {
            sleep(Duration::from_millis(1_050)).await;
        }
        sleep(Duration::from_millis(2)).await;
        let service_done = Instant::now();
        sleep(Duration::from_millis(2)).await;
        self.api.push(request);
        ReplayObservation::new(event, started, dispatch, service_done, Instant::now())
    }
}

fn schedule() -> Result<Schedule> {
    Schedule::new(Spec {
        profile: Profile::Stress,
        fresh_backlog: 0,
        intervals: 1,
    })
}

#[test]
fn workload_historical_api_boundaries_and_exhaustion() -> Result<()> {
    let period = Duration::from_secs(10);
    ensure!(required(Duration::ZERO, period, 60)? == 0);
    ensure!(required(Duration::from_nanos(1), period, 60)? == 1);
    ensure!(required(period, period, 60)? == 1);
    ensure!(required(period + Duration::from_nanos(1), period, 60)? == 2);
    ensure!(required(Duration::from_secs(600), period, 60)? == 60);
    ensure!(
        required(
            Duration::from_secs(600) + Duration::from_nanos(1),
            period,
            60
        )
        .is_err()
    );
    ensure!(required(period, Duration::ZERO, 60).is_err());
    ensure!(required(period, period, 0).is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workload_historical_keeps_canonical_order_and_independent_api_arrivals() -> Result<()> {
    let schedule = schedule()?;
    let mut work = RecordingWork {
        slow_first: true,
        ..Default::default()
    };
    let report = timeout(Duration::from_secs(10), run(schedule.clone(), &mut work)).await??;
    ensure!(work.ordinal == schedule.events.len());
    ensure!(
        work.canonical
            == schedule
                .events
                .iter()
                .filter(|event| event.action.canonical())
                .map(|event| event.ordinal)
                .collect::<Vec<_>>()
    );
    ensure!(work.skipped.len() == 600 && work.api.len() >= 2 && work.api.len() < 10);
    ensure!(report.historical_seconds == 600 && report.canonical.len() == 41);
    ensure!(report.peak_api_pending_at_observation >= 2);
    ensure!(report.api[0].pending_at_start >= 2);
    ensure!(report.api[0].intended_ns == 0 && report.api[1].intended_ns == 1_000_000_000);
    ensure!(report.api[0].started_ns >= 1_050_000_000);
    ensure!(report.canonical_service_ns >= 1_050_000_000);
    for api in &report.api {
        ensure!(api.enqueued_ns >= api.intended_ns && api.started_ns >= api.enqueued_ns);
        ensure!(api.completed_ns >= api.started_ns);
        ensure!(api.timing.precheck_ns >= 2_000_000 && api.timing.verification_ns >= 2_000_000);
    }
    ensure!(report.completion_ns >= report.canonical_completed_ns);
    ensure!(
        required(
            Duration::from_nanos(report.completion_ns),
            Duration::from_secs(1),
            600
        )? == work.api.len()
    );
    Ok(())
}

#[tokio::test]
async fn workload_historical_stops_on_oracle_failure_and_rejects_fresh_backlog() -> Result<()> {
    for api in [false, true] {
        let mut work = RecordingWork {
            fail_api: api,
            fail_checkpoint: !api,
            ..Default::default()
        };
        let error = run(schedule()?, &mut work).await.unwrap_err();
        ensure!(error.to_string().contains(if api {
            "rollback differs"
        } else {
            "checkpoint differs"
        }));
        ensure!(work.canonical == [0]);
    }
    let mut work = RecordingWork::default();
    let backlog = Schedule::new(Spec {
        profile: Profile::Representative,
        fresh_backlog: 6,
        intervals: 1,
    })?;
    ensure!(run(backlog, &mut work).await.is_err());
    ensure!(work.canonical.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workload_historical_drains_arrivals_during_final_api_service() -> Result<()> {
    let mut work = RecordingWork {
        slow_final: true,
        ..Default::default()
    };
    let report = timeout(Duration::from_secs(10), run(schedule()?, &mut work)).await??;
    ensure!(work.api.len() >= 3 && work.api.len() < 10);
    ensure!(report.canonical.len() == 41 && report.historical_seconds == 600);
    ensure!(report.api[1].started_ns >= report.canonical_completed_ns);
    ensure!(report.api[2].intended_ns == 2_000_000_000);
    ensure!(report.api[2].completed_ns <= report.completion_ns);
    ensure!(report.api_service_ns >= 1_050_000_000);
    ensure!(
        required(
            Duration::from_nanos(report.completion_ns),
            Duration::from_secs(1),
            600
        )? == work.api.len()
    );
    Ok(())
}
