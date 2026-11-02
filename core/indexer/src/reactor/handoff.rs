use anyhow::{Result, ensure};

use super::{Reactor, executor::Executor};
use crate::protocol::coordinator::certified_input::EraContext;
use crate::protocol::coordinator::selection::ApplicationPosition;

impl<E: Executor> Reactor<E> {
    pub(super) async fn refresh_protocol_execution(&mut self, context: EraContext) -> Result<()> {
        if self.execution.protocol_context == context {
            return Ok(());
        }
        ensure!(
            self.consensus.pending_decision.is_none(),
            "protocol transition has an unfinished decision callback"
        );
        // The completed height's Finalized callback has already been validated.
        // Retain future proposal streams and the live engine, but reparse raw
        // mempool inputs under the selected execution rules before opening C+1.
        self.io_jobs.clear();
        self.validated_candidates = None;
        self.mempool_preparation = None;
        self.consensus.pending_proposal = None;
        self.consensus.undecided.clear();
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

        self.execution.protocol_context = context;
        Ok(())
    }
}
