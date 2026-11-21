use std::fmt::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use libsql::{Connection, TransactionBehavior};
use metrics::{counter, describe_counter, describe_histogram, histogram};
use tracing::warn;

use super::EngineMetrics;
use super::exposition::gauge;
use crate::bitcoin_client::Client;
use crate::database::canonical_history::{self, HistoryState};
use crate::database::certified_history::{self, eras};
use crate::database::queries::select_block_latest;
use crate::protocol::coordinator::application_closure::WorkItem;
use crate::protocol::coordinator::registry::{self, UnavailableProtocol};
use crate::protocol::identity::ProtocolId;
use crate::protocol_info::{ProtocolAvailability, history_availability};
use crate::stopper::ShutdownSignal;

#[derive(Clone)]
struct Observation {
    availability: ProtocolAvailability,
    authenticated: Option<u64>,
    closed: Option<u64>,
    indexed: Option<u64>,
    timestamp: f64,
}

#[derive(Default)]
struct State {
    installation: Option<(ProtocolId, bool)>,
    observation: Option<Observation>,
    closure: Option<(u64, Instant)>,
    stage: Option<(&'static str, Instant)>,
    heartbeat: Option<f64>,
    completed: Option<f64>,
}

/// Node-local diagnostic state. Never consulted for admission or execution.
#[derive(Clone, Default)]
pub struct Telemetry {
    state: Arc<Mutex<State>>,
    pub(crate) engine: EngineMetrics,
}

fn timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

impl Telemetry {
    pub fn new() -> Self {
        describe_histogram!(
            "kontor_closure_step_duration_seconds",
            "Observed closure step duration in seconds, including planning pages; abandoned does not imply rollback."
        );
        describe_histogram!(
            "kontor_rollback_depth_blocks",
            "Depth in Bitcoin blocks of completed rollback steps."
        );
        describe_histogram!(
            "kontor_recovery_duration_seconds",
            "Successful startup certified recovery duration observed by this process, in seconds."
        );
        describe_counter!("kontor_rollback_total", "Completed rollback steps.");
        describe_counter!(
            "kontor_observation_errors_total",
            "Diagnostic observation failures, by bounded source."
        );
        Self::default()
    }

    pub(crate) fn with_engine(mut self, engine: EngineMetrics) -> Self {
        self.engine = engine;
        self
    }

    pub async fn collect_engine(&self, shutdown: ShutdownSignal) {
        self.engine.run(shutdown).await;
    }

    pub(crate) fn heartbeat(&self) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .heartbeat = Some(timestamp());
    }

    pub(crate) async fn observe(&self, conn: &Connection) {
        let installation = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .installation;
        match read_observation(conn, installation).await {
            Ok((observation, installation)) => {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                state.installation = installation;
                if let (Some(authenticated), Some(closed)) =
                    (observation.authenticated, observation.closed)
                {
                    if authenticated == closed {
                        state.closure = None;
                    } else if state.closure.is_none() {
                        state.closure = Some((closed.saturating_add(1), Instant::now()));
                    }
                }
                state.observation = Some(observation);
            }
            Err(error) => {
                self.state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .observation = None;
                counter!("kontor_observation_errors_total", "source" => "state").increment(1);
                warn!(%error, "Unable to refresh diagnostic state observation");
            }
        }
    }

    pub(crate) fn begin_step(&self, height: u64) -> Step {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state
            .closure
            .as_ref()
            .is_none_or(|(current, _)| *current != height)
        {
            state.closure = Some((height, now));
        }
        state.stage = Some(("preparing", now));
        Step {
            telemetry: self.clone(),
            started: now,
            stage: "preparing",
            outcome: "abandoned",
        }
    }

    pub(crate) fn recovery_complete(&self, started: Instant) {
        histogram!("kontor_recovery_duration_seconds").record(started.elapsed().as_secs_f64());
    }

    pub(crate) fn rollback_complete(&self, before: u64, after: u64) {
        counter!("kontor_rollback_total").increment(1);
        if let Some(depth) = before.checked_sub(after) {
            histogram!("kontor_rollback_depth_blocks").record(depth as f64);
        }
    }

    pub(crate) fn render(&self, bitcoin: &Client, network: Network) -> String {
        let (observation, closure, stage, heartbeat, completed) = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            (
                state.observation.clone(),
                state.closure,
                state.stage,
                state.heartbeat,
                state.completed,
            )
        };
        let mut output = String::new();
        gauge(
            &mut output,
            "kontor_state_observation_valid",
            "The last durable state read succeeded; this is not readiness.",
            u8::from(observation.is_some()),
        );
        let availability = observation.as_ref().map(|o| o.availability);
        output.push_str("# HELP kontor_protocol_state Last observed protocol availability.\n# TYPE kontor_protocol_state gauge\n");
        for (name, value) in [
            ("unknown", None),
            ("uninitialized", Some(ProtocolAvailability::Uninitialized)),
            (
                "history_unavailable",
                Some(ProtocolAvailability::HistoryUnavailable),
            ),
            ("recovering", Some(ProtocolAvailability::Recovering)),
            ("unsupported", Some(ProtocolAvailability::Unsupported)),
            ("ready", Some(ProtocolAvailability::Ready)),
        ] {
            writeln!(
                output,
                "kontor_protocol_state{{state=\"{name}\"}} {}",
                u8::from(availability == value)
            )
            .unwrap();
        }
        let indexed = observation.as_ref().and_then(|o| o.indexed);
        if let Some(observation) = observation {
            gauge(
                &mut output,
                "kontor_state_observation_timestamp_seconds",
                "Unix timestamp of the last successful durable state read.",
                observation.timestamp,
            );
            for (name, help, value) in [
                (
                    "kontor_authenticated_consensus_height",
                    "Last observed authenticated consensus height.",
                    observation.authenticated,
                ),
                (
                    "kontor_closed_consensus_height",
                    "Last observed completed consensus height.",
                    observation.closed,
                ),
                (
                    "kontor_indexed_bitcoin_height",
                    "Last observed committed indexed Bitcoin height, including rollback.",
                    observation.indexed,
                ),
            ] {
                if let Some(value) = value {
                    gauge(&mut output, name, help, value);
                }
            }
        }
        gauge(
            &mut output,
            "kontor_closure_active",
            "Unfinished certified closure observed in this process.",
            u8::from(closure.is_some()),
        );
        if let Some((_, since)) = closure {
            gauge(
                &mut output,
                "kontor_closure_elapsed_seconds",
                "Seconds this process has observed the closure unfinished.",
                since.elapsed().as_secs_f64(),
            );
        }
        output.push_str("# HELP kontor_closure_stage Current observed activity, not proof of commitment.\n# TYPE kontor_closure_stage gauge\n");
        let current = stage.map_or("idle", |(name, _)| name);
        for name in [
            "idle",
            "preparing",
            "reconcile",
            "activate",
            "rollback",
            "execute",
            "replay",
            "finality",
            "observe",
        ] {
            writeln!(
                output,
                "kontor_closure_stage{{stage=\"{name}\"}} {}",
                u8::from(name == current)
            )
            .unwrap();
        }
        if let Some((_, since)) = stage {
            gauge(
                &mut output,
                "kontor_closure_stage_elapsed_seconds",
                "Elapsed seconds of current awaited work.",
                since.elapsed().as_secs_f64(),
            );
        }
        if let Some(heartbeat) = heartbeat {
            gauge(
                &mut output,
                "kontor_reactor_heartbeat_timestamp_seconds",
                "Unix timestamp when the reactor last serviced work.",
                heartbeat,
            );
        }
        if let Some(completed) = completed {
            gauge(
                &mut output,
                "kontor_last_stage_completed_timestamp_seconds",
                "Unix timestamp of the last successfully settled closure step or planning page.",
                completed,
            );
        }
        render_bitcoin(&mut output, bitcoin, network, indexed);
        self.engine.render(&mut output);
        output
    }
}

type Installation = Option<(ProtocolId, bool)>;

async fn read_observation(
    conn: &Connection,
    installation: Installation,
) -> Result<(Observation, Installation)> {
    ensure!(
        conn.is_autocommit(),
        "diagnostic observation requires a settled connection"
    );
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .await?;
    let result = read_projection(&transaction, installation).await?;
    transaction.commit().await?;
    Ok(result)
}

async fn read_projection(
    conn: &Connection,
    mut installation: Installation,
) -> Result<(Observation, Installation)> {
    let tables = conn
        .query(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table'
        AND name IN ('certified_history_state', 'canonical_history_state')",
            (),
        )
        .await?
        .next()
        .await?
        .context("history table count")?
        .get::<u64>(0)?;
    let mut observation = Observation {
        availability: if tables == 0 {
            ProtocolAvailability::Uninitialized
        } else {
            ProtocolAvailability::HistoryUnavailable
        },
        authenticated: None,
        closed: None,
        indexed: None,
        timestamp: timestamp(),
    };
    if tables != 2 {
        return Ok((observation, installation));
    }
    let frontier = certified_history::frontier(conn).await?;
    let history = canonical_history::state(conn).await?;
    observation.authenticated = Some(frontier.authenticated_height);
    observation.closed = Some(frontier.closed_height);
    observation.availability = history_availability(frontier.status, history);
    if observation.availability == ProtocolAvailability::Recovering {
        let HistoryState::Ready(cursor) = history else {
            unreachable!()
        };
        let manifest =
            certified_history::protocol(conn, eras::selected_protocol(conn).await?).await?;
        ensure!(
            manifest.chain == cursor.chain,
            "canonical protocol chain differs"
        );
        let id = manifest.id()?;
        // Installation is immutable for a running binary. Recompute on protocol
        // change, not by decoding/hashing all build references on every page.
        let installed = if let Some((previous, installed)) = installation
            && previous == id
        {
            installed
        } else {
            let installed = match registry::resolve(&manifest) {
                Ok(_) => true,
                Err(error) if error.is::<UnavailableProtocol>() => false,
                Err(error) => return Err(error),
            };
            installation = Some((id, installed));
            installed
        };
        observation.availability = if !installed {
            ProtocolAvailability::Unsupported
        } else if frontier.authenticated_height == frontier.closed_height {
            ProtocolAvailability::Ready
        } else {
            ProtocolAvailability::Recovering
        };
        observation.indexed = select_block_latest(conn).await?.map(|block| block.height);
    }
    Ok((observation, installation))
}

fn render_bitcoin(output: &mut String, bitcoin: &Client, network: Network, indexed: Option<u64>) {
    let observation = bitcoin.chain_observation();
    let valid = observation.as_ref().is_some_and(|o| {
        o.chain == network
            && Instant::now()
                .checked_duration_since(o.observed_at)
                .is_some_and(|age| age <= Duration::from_secs(30))
            && o.headers >= o.blocks
    });
    gauge(
        output,
        "kontor_bitcoin_observation_valid",
        "A fresh, structurally valid backend observation matches the configured network.",
        u8::from(valid),
    );
    let lag = observation
        .as_ref()
        .filter(|_| valid)
        .and_then(|o| indexed.and_then(|h| o.blocks.checked_sub(h)));
    gauge(
        output,
        "kontor_bitcoin_lag_valid",
        "Lag is defined for a fresh backend and an indexed tip no higher than that backend.",
        u8::from(lag.is_some()),
    );
    if let Some(lag) = lag {
        gauge(
            output,
            "kontor_bitcoin_lag_blocks",
            "Backend block height minus indexed height.",
            lag,
        );
    }
    if let Some(observation) = observation {
        gauge(
            output,
            "kontor_bitcoin_observation_age_seconds",
            "Age in seconds of the last successful Bitcoin RPC observation.",
            observation.observed_at.elapsed().as_secs_f64(),
        );
        gauge(
            output,
            "kontor_bitcoin_backend_height",
            "Last observed backend block height; consult validity.",
            observation.blocks,
        );
        gauge(
            output,
            "kontor_bitcoin_headers_height",
            "Last observed backend header height; consult validity.",
            observation.headers,
        );
        gauge(
            output,
            "kontor_bitcoin_initial_block_download",
            "Last observed backend initial-block-download flag.",
            u8::from(observation.initial_block_download),
        );
    }
}

pub(crate) struct Step {
    telemetry: Telemetry,
    started: Instant,
    stage: &'static str,
    outcome: &'static str,
}

impl Step {
    pub(crate) fn action(&mut self, action: WorkItem) {
        self.stage = match action {
            WorkItem::Reconcile => "reconcile",
            WorkItem::Activate { .. } => "activate",
            WorkItem::Rollback { .. } => "rollback",
            WorkItem::Execute { .. } => "execute",
            WorkItem::Replay { .. } => "replay",
            WorkItem::Finality => "finality",
            WorkItem::Observe => "observe",
        };
        self.telemetry
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stage = Some((self.stage, self.started));
    }

    pub(crate) fn finish(mut self, succeeded: bool) {
        self.outcome = if succeeded { "success" } else { "error" };
        if succeeded {
            let mut state = self
                .telemetry
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            state.completed = Some(timestamp());
            state.heartbeat = state.completed;
        }
    }
}

impl Drop for Step {
    fn drop(&mut self) {
        self.telemetry
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stage = None;
        histogram!("kontor_closure_step_duration_seconds", "stage" => self.stage, "outcome" => self.outcome)
            .record(self.started.elapsed().as_secs_f64());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin_client::observation::ChainObservation;
    use crate::metrics::recorder_builder;
    use crate::test_utils::new_test_db;
    use metrics::with_local_recorder;

    fn client() -> Client {
        Client::new(String::new(), String::new(), String::new()).unwrap()
    }

    #[test]
    fn stalled_activity_ages_without_freshening_heartbeat_or_completed_progress() {
        let telemetry = Telemetry::default();
        telemetry.heartbeat();
        let mut step = telemetry.begin_step(7);
        step.action(WorkItem::Finality);
        let old = Instant::now() - Duration::from_secs(20);
        {
            let mut state = telemetry.state.lock().unwrap();
            state.closure = Some((7, old));
            state.stage = Some(("finality", old));
        }
        let client = client();
        let first = telemetry.render(&client, Network::Regtest);
        let second = telemetry.render(&client, Network::Regtest);
        let heartbeat = |text: &str| {
            text.lines()
                .find(|l| l.starts_with("kontor_reactor_heartbeat_timestamp_seconds "))
                .unwrap()
                .to_owned()
        };
        assert_eq!(heartbeat(&first), heartbeat(&second));
        assert!(second.contains("kontor_closure_active 1\n"));
        assert!(second.contains("kontor_closure_stage{stage=\"finality\"} 1\n"));
        assert!(second.contains("kontor_closure_stage_elapsed_seconds 20."));
        assert!(!second.contains("# TYPE kontor_last_stage_completed"));
        drop(step);
        assert!(
            telemetry
                .render(&client, Network::Regtest)
                .contains("kontor_closure_stage{stage=\"idle\"} 1\n")
        );
    }

    #[test]
    fn only_successful_steps_publish_completion_and_outcomes_are_distinct() {
        let recorder = recorder_builder().build_recorder();
        with_local_recorder(&recorder, || {
            let telemetry = Telemetry::new();
            drop(telemetry.begin_step(1));
            assert!(telemetry.state.lock().unwrap().completed.is_none());
            telemetry.begin_step(1).finish(false);
            assert!(telemetry.state.lock().unwrap().completed.is_none());
            telemetry.begin_step(1).finish(true);
            assert!(telemetry.state.lock().unwrap().completed.is_some());
        });
        let output = recorder.handle().render();
        assert!(output.contains("# TYPE kontor_closure_step_duration_seconds histogram\n"));
        for outcome in ["success", "error", "abandoned"] {
            assert!(
                output.contains(&format!("outcome=\"{outcome}\"")),
                "{output}"
            );
        }
    }

    #[test]
    fn backend_freshness_network_and_subtraction_boundaries_are_explicit() {
        let client = client();
        let mut output = String::new();
        render_bitcoin(&mut output, &client, Network::Regtest, Some(10));
        assert!(output.contains("kontor_bitcoin_observation_valid 0\n"));
        assert!(!output.contains("# TYPE kontor_bitcoin_backend_height"));
        for (network, age, blocks, headers, indexed, valid, lag) in [
            (Network::Regtest, 0, 10, 12, Some(9), true, Some(1)),
            (Network::Signet, 0, 10, 10, Some(9), false, None),
            (Network::Regtest, 31, 10, 10, Some(9), false, None),
            (Network::Regtest, 0, 10, 9, Some(9), false, None),
            (Network::Regtest, 0, 10, 10, Some(11), true, None),
            (Network::Regtest, 0, 0, 0, None, true, None),
            (
                Network::Regtest,
                0,
                u64::MAX,
                u64::MAX,
                Some(0),
                true,
                Some(u64::MAX),
            ),
        ] {
            client.set_chain_observation_for_test(ChainObservation {
                chain: network,
                blocks,
                headers,
                initial_block_download: true,
                observed_at: Instant::now() - Duration::from_secs(age),
            });
            output.clear();
            render_bitcoin(&mut output, &client, Network::Regtest, indexed);
            assert!(output.contains(&format!(
                "kontor_bitcoin_observation_valid {}\n",
                u8::from(valid)
            )));
            assert!(output.contains("kontor_bitcoin_initial_block_download 1\n"));
            assert!(output.contains(&format!(
                "kontor_bitcoin_lag_valid {}\n",
                u8::from(lag.is_some())
            )));
            if let Some(lag) = lag {
                assert!(output.contains(&format!("kontor_bitcoin_lag_blocks {lag}\n")));
            } else {
                assert!(!output.contains("# TYPE kontor_bitcoin_lag_blocks"));
            }
        }
    }

    #[tokio::test]
    async fn diagnostic_failure_never_changes_an_existing_transaction() -> Result<()> {
        let (_, writer, _directory) = new_test_db().await?;
        let conn = writer.connection();
        let telemetry = Telemetry::new();
        telemetry.observe(&conn).await;
        assert!(telemetry.state.lock().unwrap().observation.is_some());
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        telemetry.observe(&conn).await;
        assert!(telemetry.state.lock().unwrap().observation.is_none());
        assert!(!conn.is_autocommit());
        conn.execute("ROLLBACK", ()).await?;
        telemetry.observe(&conn).await;
        assert!(telemetry.state.lock().unwrap().observation.is_some());
        Ok(())
    }
}
