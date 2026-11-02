use anyhow::{Result, ensure};

use super::{Reactor, executor::Executor};
use crate::database::certified_history;

#[cfg(kontor_managed)]
use super::consensus_state::certified_startup;
#[cfg(kontor_managed)]
use crate::consensus::PartStreamsMap;
#[cfg(kontor_managed)]
use crate::protocol::coordinator::selection::ApplicationPosition;
#[cfg(kontor_managed)]
use anyhow::Context;
#[cfg(kontor_managed)]
use malachitebft_core_types::Round;
#[cfg(kontor_managed)]
use std::time::{Duration, Instant};

impl<E: Executor> Reactor<E> {
    pub(super) async fn handoff_if_needed(&mut self) -> Result<bool> {
        let frontier = certified_history::frontier(&self.db_conn()).await?;
        if frontier.context == Some(self.consensus.protocol_context) {
            return Ok(false);
        }
        ensure!(
            frontier.closed_height == frontier.authenticated_height,
            "engine handoff attempted before closure completion"
        );
        #[cfg(kontor_managed)]
        {
            self.handoff().await?;
            Ok(true)
        }
        #[cfg(not(kontor_managed))]
        anyhow::bail!("protocol transition requires registered managed consensus engines")
    }

    #[cfg(kontor_managed)]
    async fn handoff(&mut self) -> Result<()> {
        let conn = self.db_conn();
        let (context, height, validators) = certified_startup(&conn).await?;
        let coordinator = self.coordinator.clone().context("missing engine owner")?;
        let mut config = self
            .engine_config
            .clone()
            .context("missing engine configuration")?;
        // In particular, tcp/0 must become the bound port. The persistent
        // process identity and peer addresses remain usable across the handoff.
        config.listen_addr = self
            .consensus
            .engine
            .listen_address()
            .await?
            .context("outgoing engine has no bound listener")?;
        ensure!(
            self.consensus.engine.stop(Duration::from_secs(30)).await?,
            "outgoing consensus engine did not join; replacement was not started"
        );

        // These callbacks and parsed candidates belong to the outgoing era.
        // Keep raw inputs, suppression, fee data and Bitcoin ingestion intact.
        self.io_jobs.clear();
        self.validated_candidates = None;
        self.mempool_preparation = None;
        self.consensus.pending_decision = None;
        self.consensus.pending_next_height = None;
        self.consensus.pending_proposal = None;
        self.consensus.undecided.clear();
        self.consensus.early_proposals.clear();
        self.consensus.part_streams = PartStreamsMap::new();
        self.consensus.mempool.candidates.clear();
        let selection = self
            .execution
            .select_executor(ApplicationPosition::Preparation {
                anchor_height: self.execution.last_height,
                anchor_hash: self.execution.last_hash,
            })
            .await?;
        self.execution.select_session(&selection).await?;
        let prepared = self
            .execution
            .executor
            .parse_mempool(
                &self.execution.recognizer,
                &selection,
                self.consensus.mempool.raw_inputs(),
            )
            .await?;
        for transaction in prepared {
            self.consensus.mempool.finish(transaction);
        }

        let output = coordinator.start(&config, &conn).await?;
        self.consensus.engine = output.engine;
        self.consensus.address = output.address;
        self.consensus.protocol_context = context;
        self.consensus.current_height = height;
        self.consensus.validator_index = validators
            .validators
            .iter()
            .position(|validator| validator.address == output.address);
        self.consensus.current_validator_set = validators;
        self.consensus.current_round = Round::Nil;
        self.consensus.current_proposer = None;
        self.consensus.round_started_at = Instant::now();
        self.execution.protocol_context = context;
        self.engine_config = Some(config);
        Ok(())
    }
}
