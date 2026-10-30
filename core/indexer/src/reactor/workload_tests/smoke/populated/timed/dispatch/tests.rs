use anyhow::{Error, Result, bail, ensure};
use tokio::task::yield_now;
use tokio::time::{Instant, sleep, timeout};

use super::{
    Arrivals, Duration, Event, ReplayObservation, Schedule, Work, drain, drain_deadline,
    replay_event,
};
use crate::reactor::workload_tests::smoke::populated::timed::{Profile, Spec};

fn schedule(profile: Profile) -> Result<Schedule> {
    Schedule::new(Spec {
        profile,
        fresh_backlog: 6,
        intervals: 2,
    })
}

#[derive(Default)]
struct RecordingWork {
    prepared: Vec<usize>,
    executed: Vec<usize>,
    checked: Vec<usize>,
    fail_prepare: bool,
    fail_execute: bool,
    fail_check: bool,
}

impl Work for RecordingWork {
    async fn check_before(&mut self, event: &Event) -> Result<()> {
        ensure!(self.prepared.len() == self.executed.len());
        if self.fail_prepare && event.ordinal == 6 {
            bail!("precheck control");
        }
        sleep(Duration::from_millis(2)).await;
        self.prepared.push(event.ordinal);
        Ok(())
    }

    async fn execute(&mut self, event: &Event) -> Result<()> {
        ensure!(self.executed.len() == self.checked.len());
        self.executed.push(event.ordinal);
        if self.fail_execute && event.ordinal == 6 {
            bail!("execution control");
        }
        Ok(())
    }

    async fn check(&mut self, event: &Event) -> Result<()> {
        ensure!(self.executed.len() == self.checked.len() + 1);
        if self.fail_check && event.ordinal == 6 {
            bail!("check control");
        }
        sleep(Duration::from_millis(2)).await;
        self.checked.push(event.ordinal);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workload_timed_dispatch_preserves_order_and_measures_checks() -> Result<()> {
    let schedule = schedule(Profile::Representative)?;
    let expected = schedule.clone();
    let mut work = RecordingWork::default();
    let report = timeout(Duration::from_secs(5), drain(schedule, &mut work)).await??;
    ensure!(report.events.len() >= 8);
    ensure!(work.prepared == work.executed && work.executed == work.checked);
    ensure!(work.checked == (0..report.events.len()).collect::<Vec<_>>());
    ensure!(
        expected.required_before(Duration::from_nanos(report.completion_ns))?
            <= report.events.len()
    );
    let mut service = 0;
    for (ordinal, observation) in report.events.iter().enumerate() {
        let event = &expected.events[ordinal];
        ensure!(observation.ordinal == ordinal);
        ensure!(observation.intended_ns == event.at_seconds * 1_000_000_000);
        ensure!(observation.enqueued_ns >= observation.intended_ns);
        ensure!(observation.precheck_ns >= observation.enqueued_ns);
        ensure!(observation.dispatch_ns >= observation.precheck_ns + 2_000_000);
        ensure!(observation.dispatch_ns >= observation.ordered_ready_ns);
        ensure!(observation.service_done_ns >= observation.dispatch_ns);
        ensure!(observation.checked_ns >= observation.service_done_ns + 2_000_000);
        ensure!(
            observation.canonical_ready_ns
                == event
                    .depends_on
                    .map_or(0, |previous| report.events[previous].checked_ns)
        );
        ensure!(
            observation.ordered_ready_ns
                == ordinal
                    .checked_sub(1)
                    .map_or(0, |previous| report.events[previous].checked_ns)
        );
        service += observation.service_done_ns - observation.dispatch_ns;
    }
    ensure!(service == report.active_service_ns);
    ensure!(report.completion_ns >= report.events.last().unwrap().checked_ns);
    ensure!(report.scheduled_unconfirmed_transactions > 0);
    Ok(())
}

#[tokio::test]
async fn workload_replay_timing_separates_execution_from_oracle_checks() -> Result<()> {
    let schedule = schedule(Profile::Representative)?;
    let mut work = RecordingWork::default();
    for event in &schedule.events[..6] {
        let report = replay_event(event, &mut work).await?;
        ensure!(&report.event == event);
        ensure!(report.precheck_ns >= 2_000_000 && report.verification_ns >= 2_000_000);
        ensure!(work.prepared == work.executed && work.executed == work.checked);
    }
    ensure!(work.checked == (0..6).collect::<Vec<_>>());
    Ok(())
}

#[test]
fn workload_replay_timing_excludes_checks_from_service_duration() -> Result<()> {
    let schedule = schedule(Profile::Representative)?;
    let start = Instant::now();
    let report = ReplayObservation::new(
        &schedule.events[0],
        start,
        start + Duration::from_secs(2),
        start + Duration::from_secs(5),
        start + Duration::from_secs(12),
    )?;
    ensure!(report.precheck_ns == 2_000_000_000);
    ensure!(report.service_ns == 3_000_000_000);
    ensure!(report.verification_ns == 7_000_000_000);
    Ok(())
}

#[tokio::test]
async fn workload_replay_timing_stops_at_a_failed_stage() -> Result<()> {
    let schedule = schedule(Profile::Representative)?;
    for stage in ["precheck", "execute", "check"] {
        let mut work = RecordingWork {
            fail_prepare: stage == "precheck",
            fail_execute: stage == "execute",
            fail_check: stage == "check",
            ..Default::default()
        };
        for event in &schedule.events[..6] {
            replay_event(event, &mut work).await?;
        }
        let error = replay_event(&schedule.events[6], &mut work)
            .await
            .unwrap_err();
        ensure!(format!("{error:#}").contains(&format!("{stage} event 6")));
        let executed = if stage == "precheck" { 6 } else { 7 };
        ensure!(work.executed == (0..executed).collect::<Vec<_>>());
        ensure!(work.checked == (0..6).collect::<Vec<_>>());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workload_timed_dispatch_arrivals_do_not_wait_for_execution() -> Result<()> {
    let mut arrivals = Arrivals::new(schedule(Profile::Stress)?).await?;
    timeout(Duration::from_secs(5), async {
        // No Work implementation runs here. The next real-clock arrival must
        // still be delivered after the initial backlog and time-zero API work.
        for ordinal in 0..9 {
            let arrival = arrivals.receiver.recv().await.unwrap();
            ensure!(arrival.ordinal == ordinal);
            if ordinal == 8 {
                ensure!(arrival.enqueued >= Duration::from_secs(1));
                ensure!(arrivals.schedule.events[ordinal].at_seconds == 1);
            }
        }
        Ok::<_, Error>(())
    })
    .await??;
    arrivals.stop().await?;
    ensure!(arrivals.producer.is_none() && arrivals.receiver.is_closed());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workload_timed_dispatch_does_not_continue_after_failure() -> Result<()> {
    for stage in ["precheck", "execute", "check"] {
        let mut work = RecordingWork {
            fail_prepare: stage == "precheck",
            fail_execute: stage == "execute",
            fail_check: stage == "check",
            ..Default::default()
        };
        let error = timeout(
            Duration::from_secs(5),
            drain(schedule(Profile::Stress)?, &mut work),
        )
        .await?
        .unwrap_err();
        ensure!(format!("{error:#}").contains(&format!("{stage} event 6")));
        let executed = if stage == "precheck" { 6 } else { 7 };
        ensure!(work.executed == (0..executed).collect::<Vec<_>>());
        ensure!(work.checked == (0..6).collect::<Vec<_>>());
    }
    let arrivals = Arrivals::new(schedule(Profile::Stress)?).await?;
    let producer = arrivals.producer.as_ref().unwrap().abort_handle();
    drop(arrivals);
    timeout(Duration::from_secs(5), async {
        while !producer.is_finished() {
            yield_now().await;
        }
    })
    .await?;
    Ok(())
}

#[test]
fn workload_timed_dispatch_rejects_completion_after_deadline() -> Result<()> {
    drain_deadline(Duration::from_secs(600))?;
    drain_deadline(Duration::from_secs(600) - Duration::from_nanos(1))?;
    ensure!(drain_deadline(Duration::from_secs(600) + Duration::from_nanos(1)).is_err());
    Ok(())
}
