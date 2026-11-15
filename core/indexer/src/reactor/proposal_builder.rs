use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use bitcoin::{BlockHash, Transaction};
use futures_util::future::{BoxFuture, pending};
use malachitebft_app_channel::app::types::LocallyProposedValue;
use malachitebft_core_types::Round;
use tokio::sync::oneshot;
use tokio::time::Instant as TimerInstant;

use super::executor::TxPolicy;
use crate::consensus::{Ctx, Height};
use crate::protocol::coordinator::selection::ExecutionSelection;

const DEBOUNCE: Duration = Duration::from_millis(500);

pub(super) type Verdicts = Result<Vec<(Transaction, TxPolicy)>>;

pub(super) struct PendingProposal {
    pub height: Height,
    pub round: Round,
    pub reply: oneshot::Sender<LocallyProposedValue<Ctx>>,
    pub hard_deadline: Instant,
}

struct Request {
    proposal: PendingProposal,
    debounce: Option<TimerInstant>,
}

pub(super) struct BuildContext {
    pub selection: ExecutionSelection,
    pub anchor_height: u64,
    pub anchor_hash: BlockHash,
}

struct BuildJob {
    context: BuildContext,
    verdicts: BoxFuture<'static, Verdicts>,
}

pub(super) struct BuildCompletion {
    pub context: BuildContext,
    pub verdicts: Verdicts,
}

// These verdicts can outlive GetValue. Discarding them on every timeout would
// starve proposals when Bitcoin validation is slower than the proposal window.
// Selection, anchor, exact pool bytes and batch validity must be rechecked at use.
pub(super) struct ValidatedCandidates {
    pub selection: ExecutionSelection,
    pub anchor_height: u64,
    pub anchor_hash: BlockHash,
    pub txs: Vec<Transaction>,
}

#[derive(Default)]
pub(super) struct ProposalBuilder {
    request: Option<Request>,
    build: Option<BuildJob>,
    banked: Option<ValidatedCandidates>,
}

impl ProposalBuilder {
    pub fn request(&self) -> Option<&PendingProposal> {
        self.request.as_ref().map(|request| &request.proposal)
    }

    pub fn start_request(&mut self, proposal: PendingProposal) {
        self.request = Some(Request {
            proposal,
            debounce: None,
        });
    }

    pub fn take_request(&mut self) -> Option<PendingProposal> {
        self.request.take().map(|request| request.proposal)
    }

    pub fn clear_request(&mut self) {
        self.request = None;
    }

    pub fn on_round(&mut self, height: Height, round: Round) {
        if self
            .request()
            .is_some_and(|request| request.height != height || request.round != round)
        {
            self.clear_request();
        }
    }

    pub fn on_mempool_activity(&mut self, now: TimerInstant) {
        if let Some(request) = &mut self.request {
            request.debounce = Some(now + DEBOUNCE);
        }
    }

    pub fn debounce_deadline(&self) -> Option<TimerInstant> {
        self.request.as_ref().and_then(|request| request.debounce)
    }

    pub fn consume_debounce(&mut self) {
        if let Some(request) = &mut self.request {
            request.debounce = None;
        }
    }

    pub fn build_in_flight(&self) -> bool {
        self.build.is_some()
    }

    pub fn start_build(
        &mut self,
        context: BuildContext,
        verdicts: BoxFuture<'static, Verdicts>,
    ) -> Result<()> {
        ensure!(
            self.build.is_none(),
            "local proposal build already in flight"
        );
        self.build = Some(BuildJob { context, verdicts });
        Ok(())
    }

    pub async fn next_build(&mut self) -> BuildCompletion {
        let verdicts = match &mut self.build {
            Some(build) => (&mut build.verdicts).await,
            None => pending().await,
        };
        // Losing select must preserve the owned future. Once ready, remove it
        // before apply can re-enter fulfillment and start the next snapshot.
        let build = self.build.take().expect("completed proposal build");
        BuildCompletion {
            context: build.context,
            verdicts,
        }
    }

    pub fn bank(&mut self, candidates: ValidatedCandidates) {
        self.banked = Some(candidates);
    }

    pub fn take_banked(&mut self) -> Option<ValidatedCandidates> {
        self.banked.take()
    }

    pub fn invalidate_banked(&mut self) {
        self.banked = None;
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    #[cfg(test)]
    pub fn has_banked(&self) -> bool {
        self.banked.is_some()
    }
}

#[cfg(test)]
mod tests;
