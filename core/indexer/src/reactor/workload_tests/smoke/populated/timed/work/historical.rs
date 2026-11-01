use anyhow::{Context, Result, bail, ensure};
use tokio::time::Instant;

use super::super::dispatch::ReplayObservation;
use super::super::dispatch::historical::HistoricalWork;
use super::{Action, Checkpoint, Event, TimedWork, database_projection, filter_map};

impl HistoricalWork for TimedWork<'_> {
    async fn skip_historical_api(&mut self, event: &Event) -> Result<()> {
        ensure!(
            event == self.plan.schedule.event(self.ordinal)?
                && !event.action.canonical()
                && self.before.is_none()
                && !self.executed
        );
        let expected = self
            .expected
            .context("historical replay requires frozen checkpoints")?;
        // The original API call was rolled back. Check its saved state without
        // fabricating an execution or counting it as part of historical work.
        let actual = Checkpoint::capture(
            self.directory,
            &database_projection(&self.reactor.db_conn()).await?,
        )?;
        Checkpoint::record(&mut self.checkpoints, actual, Some(expected))?;
        self.ordinal += 1;
        Ok(())
    }

    async fn external_api(&mut self, event: &Event) -> Result<ReplayObservation> {
        let started = Instant::now();
        ensure!(self.before.is_none() && !self.executed && self.simulation.is_none());
        ensure!(event == self.plan.schedule.event(event.ordinal)?);
        let Action::Simulation {
            request,
            operations,
            ..
        } = event.action
        else {
            bail!("external API event must be a simulation");
        };
        ensure!(
            request == self.external_requests
                && self.plan.api.instructions(request)?.len() == operations
        );
        let before = Checkpoint::capture(
            self.directory,
            &database_projection(&self.reactor.db_conn()).await?,
        )?;
        self.pending.check_unconfirmed(self.reactor).await?;
        self.check_tracking(&self.tracked).await?;
        let tip = (
            self.reactor.execution.last_height,
            self.reactor.execution.last_hash,
        );
        let height = self.reactor.execution.test_runtime().await.storage.height;
        let context = self
            .reactor
            .execution
            .test_runtime()
            .await
            .storage
            .tx_context
            .clone();
        let output = self.reactor.execution.test_runtime().await.previous_output;
        let op_return = self
            .reactor
            .execution
            .test_runtime()
            .await
            .op_return_data
            .clone();
        let counters = {
            let runtime = self.reactor.execution.test_runtime().await;
            (
                runtime.id_generation_counter.get().await,
                runtime.result_id_counter.get().await,
            )
        };
        {
            let runtime = self.reactor.execution.test_runtime().await;
            ensure!(
                !runtime.simulating
                    && runtime.stack.is_empty().await
                    && runtime.storage.savepoint_stack.is_empty().await
            );
        }
        let input = self
            .plan
            .requests
            .get(request)
            .context("external API inputs exhausted")?;
        let txid = input.reveal.compute_txid().to_string();
        let dispatch = Instant::now();
        let transaction =
            filter_map((0, input.reveal.clone())).context("external API input missing")?;
        let results = self.reactor.simulate(transaction).await?;
        let service_done = Instant::now();
        self.plan.api.check(
            request,
            tip.0.checked_add(1).context("API height overflow")?,
            &txid,
            &results,
        )?;
        Checkpoint::capture(
            self.directory,
            &database_projection(&self.reactor.db_conn()).await?,
        )?
        .check(&before)?;
        {
            let runtime = self.reactor.execution.test_runtime().await;
            ensure!(
                (
                    self.reactor.execution.last_height,
                    self.reactor.execution.last_hash
                ) == tip
                    && !runtime.simulating
                    && runtime.storage.height == height
                    && runtime.storage.tx_context == context
                    && runtime.previous_output == output
                    && runtime.op_return_data == op_return
                    && (
                        runtime.id_generation_counter.get().await,
                        runtime.result_id_counter.get().await
                    ) == counters
                    && runtime.stack.is_empty().await
                    && runtime.storage.savepoint_stack.is_empty().await
            );
        }
        self.pending.check_unconfirmed(self.reactor).await?;
        self.check_tracking(&self.tracked).await?;
        let checked = Instant::now();
        self.external_requests += 1;
        eprintln!(
            "workload_historical_api_result={}",
            serde_json::json!({
                "request":request,"anchor_height":tip.0,"results":results
            })
        );
        let mut actual = event.clone();
        actual.action = Action::Simulation {
            request,
            anchor_height: tip.0,
            operations,
        };
        actual.depends_on = self.plan.schedule.events[..self.ordinal]
            .iter()
            .rev()
            .find(|event| event.action.canonical())
            .map(|event| event.ordinal);
        ReplayObservation::new(&actual, started, dispatch, service_done, checked)
    }
}
