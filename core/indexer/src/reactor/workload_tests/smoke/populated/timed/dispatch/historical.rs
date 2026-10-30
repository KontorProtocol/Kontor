use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::{Arrivals, Duration, Event, ReplayObservation, Schedule, Work, nanos, replay_event};

mod tests;

pub(in super::super) trait HistoricalWork: Work {
    async fn skip_historical_api(&mut self, event: &Event) -> Result<()>;
    async fn external_api(&mut self, event: &Event) -> Result<ReplayObservation>;
}

#[derive(Debug, Serialize)]
pub(in super::super) struct ApiObservation {
    intended_ns: u64,
    enqueued_ns: u64,
    started_ns: u64,
    completed_ns: u64,
    pending_at_start: usize,
    timing: ReplayObservation,
}

#[derive(Debug, Serialize)]
pub(in super::super) struct Report {
    historical_seconds: u64,
    canonical_completed_ns: u64,
    completion_ns: u64,
    canonical_service_ns: u64,
    api_service_ns: u64,
    peak_api_pending_at_observation: usize,
    canonical: Vec<ReplayObservation>,
    api: Vec<ApiObservation>,
}

fn required(elapsed: Duration, period: Duration, capacity: usize) -> Result<usize> {
    ensure!(!period.is_zero() && capacity > 0);
    let horizon = period
        .checked_mul(u32::try_from(capacity)?)
        .context("external API horizon overflow")?;
    ensure!(elapsed <= horizon, "external API input horizon exhausted");
    // Observe before arrivals exactly at the observation timestamp, including
    // the end of the finite input horizon. Never wait for future requests.
    usize::try_from(elapsed.as_nanos().div_ceil(period.as_nanos()))
        .context("external API arrival count overflow")
}

pub(in super::super) async fn run(
    schedule: Schedule,
    work: &mut impl HistoricalWork,
) -> Result<Report> {
    schedule.validate()?;
    ensure!(
        schedule.spec.fresh_backlog == 0,
        "historical replay requires complete mixed intervals, not fresh backlog blocks"
    );
    let mut arrivals = Arrivals::filtered(schedule, true)?;
    let result = run_inner(&mut arrivals, work).await;
    let stopped = arrivals.stop().await;
    let report = result?;
    stopped?;
    Ok(report)
}

async fn run_inner(arrivals: &mut Arrivals, work: &mut impl HistoricalWork) -> Result<Report> {
    let schedule = arrivals.schedule.clone();
    let period = Duration::from_secs(schedule.spec.profile.simulation_seconds());
    let api_ordinals: Vec<_> = schedule
        .events
        .iter()
        .filter(|event| !event.action.canonical())
        .map(|event| event.ordinal)
        .collect();
    let mut report = Report {
        historical_seconds: schedule.horizon_seconds,
        canonical_completed_ns: 0,
        completion_ns: 0,
        canonical_service_ns: 0,
        api_service_ns: 0,
        peak_api_pending_at_observation: 0,
        canonical: Vec::new(),
        api: Vec::new(),
    };
    for event in &schedule.events {
        required(arrivals.start.elapsed(), period, api_ordinals.len())?;
        if !event.action.canonical() {
            work.skip_historical_api(event).await?;
            continue;
        }
        let timing = replay_event(event, work).await?;
        report.canonical_service_ns = report
            .canonical_service_ns
            .checked_add(timing.service_ns)
            .context("canonical service overflow")?;
        report.canonical.push(timing);
        report.canonical_completed_ns = nanos(arrivals.start.elapsed())?;
        // One due request per canonical boundary prevents a growing API queue
        // from starving history. After the last boundary, drain all due work.
        serve_due(arrivals, work, &api_ordinals, period, &mut report).await?;
    }
    while serve_due(arrivals, work, &api_ordinals, period, &mut report).await? {}
    ensure!(
        required(
            Duration::from_nanos(report.completion_ns),
            period,
            api_ordinals.len()
        )? <= report.api.len(),
        "API arrival crossed the final observation"
    );
    Ok(report)
}

async fn serve_due(
    arrivals: &mut Arrivals,
    work: &mut impl HistoricalWork,
    api_ordinals: &[usize],
    period: Duration,
    report: &mut Report,
) -> Result<bool> {
    let observed = arrivals.start.elapsed();
    let pending = required(observed, period, api_ordinals.len())?
        .checked_sub(report.api.len())
        .context("API request ran before its arrival")?;
    report.peak_api_pending_at_observation = report.peak_api_pending_at_observation.max(pending);
    if pending == 0 {
        report.completion_ns = nanos(observed)?;
        return Ok(false);
    }
    let arrival = arrivals
        .receiver
        .recv()
        .await
        .context("external API producer stopped")?;
    ensure!(
        Some(&arrival.ordinal) == api_ordinals.get(report.api.len()),
        "external API order differs"
    );
    let event = arrivals.schedule.event(arrival.ordinal)?;
    let intended = Duration::from_secs(event.at_seconds);
    let started = arrivals.start.elapsed();
    let pending = required(started, period, api_ordinals.len())? - report.api.len();
    ensure!(arrival.enqueued >= intended && started >= arrival.enqueued);
    report.peak_api_pending_at_observation = report.peak_api_pending_at_observation.max(pending);
    let timing = work.external_api(event).await?;
    let completed = arrivals.start.elapsed();
    required(completed, period, api_ordinals.len())?;
    report.api_service_ns = report
        .api_service_ns
        .checked_add(timing.service_ns)
        .context("API service overflow")?;
    let observation = ApiObservation {
        intended_ns: nanos(intended)?,
        enqueued_ns: nanos(arrival.enqueued)?,
        started_ns: nanos(started)?,
        completed_ns: nanos(completed)?,
        pending_at_start: pending,
        timing,
    };
    eprintln!(
        "workload_historical_api={}",
        serde_json::to_string(&observation)?
    );
    report.api.push(observation);
    Ok(true)
}
