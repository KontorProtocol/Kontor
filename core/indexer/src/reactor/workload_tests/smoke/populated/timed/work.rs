use std::collections::BTreeSet;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, ensure};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Block as BitcoinBlock, BlockHash, OutPoint, Transaction, Txid};
use indexer_types::{OpWithResult, ResultRow};

use super::super::super::{apply, database_projection, receipts};
use super::super::batch::BatchProof;
use super::super::batch::pending::Pending;
use super::super::checkpoint::Checkpoint;
use super::super::files::FileProgress;
use super::super::history::{self, HistoryPopulation};
use super::super::mixed::{ApiRecipe, ExecutionSlice, MixedLayout, MixedWorkload};
use super::super::oracle::{Before, root_receipts};
use super::super::pruning::PruningProof;
use super::super::sequence_inputs::BlockInput;
use super::dispatch::Work;
use super::{Action, Event, Schedule};
use crate::block::filter_map;
use crate::consensus::Height;
use crate::consensus::finality_types::FINALITY_WINDOW;
use crate::database::confirmation::get_confirmation_position;
use crate::database::queries::{
    get_transaction_by_txid, select_latest_consensus_height, select_unconfirmed_batch_txs,
};
use crate::reactor::Reactor;
use crate::reactor::batches::BatchOutcome;
use crate::reactor::executor::RuntimeExecutor;
use crate::runtime::TransactionContext;

#[derive(Clone)]
pub(super) struct ApiInput {
    pub(super) commit: Transaction,
    pub(super) reveal: Transaction,
}

pub(super) struct InputPlan {
    pub(super) schedule: Schedule,
    pub(super) blocks: Vec<BlockInput>,
    pub(super) recipes: Vec<MixedWorkload>,
    pub(super) txids: Vec<Vec<String>>,
    pub(super) api: ApiRecipe,
    pub(super) requests: Vec<ApiInput>,
    pub(super) canonical_signer: String,
    pub(super) api_signer: String,
    pub(super) layout: MixedLayout,
}

impl InputPlan {
    pub(super) fn validate(&self) -> Result<()> {
        self.schedule.validate()?;
        ensure!(self.canonical_signer != self.api_signer);
        ensure!(
            self.blocks.len() == self.schedule.blocks.len()
                && self.recipes.len() == self.blocks.len()
                && self.txids.len() == self.blocks.len()
        );
        let mut canonical = BTreeSet::new();
        let mut funding = BTreeSet::new();
        let mut file_ids = BTreeSet::new();
        for (index, input) in self.blocks.iter().enumerate() {
            for id in self.recipes[index].file_ids() {
                ensure!(file_ids.insert(id), "canonical recipes reuse a file ID");
            }
            let block = &self.schedule.blocks[index];
            ensure!(
                input.block.height == block.height
                    && input.reveals.len() == block.transactions().len()
            );
            ensure!(self.txids[index].len() == input.reveals.len());
            let expected = self.recipes[index].instructions();
            let raw: BitcoinBlock = deserialize(&input.raw)?;
            ensure!(
                raw.block_hash() == input.block.hash
                    && raw.header.prev_blockhash == input.block.prev_hash
                    && raw.txdata.len() == input.reveals.len() * 2 + 1
            );
            ensure!(expected.len() == input.reveals.len() * 2);
            for (position, reveal) in input.reveals.iter().enumerate() {
                let txid = reveal.compute_txid().to_string();
                ensure!(canonical.insert(txid.clone()) && self.txids[index][position] == txid);
                let decoded = filter_map((0, reveal.clone())).context("canonical input missing")?;
                ensure!(decoded.inputs.len() == 1 && decoded.inputs[0].insts.aggregate.is_none());
                ensure!(
                    decoded.inputs[0].x_only_pubkey.to_string() == self.canonical_signer
                        && decoded.inputs[0].insts.ops == expected[position * 2..position * 2 + 2]
                );
                ensure!(input.block.transactions[position].txid == reveal.compute_txid());
                let commit = &raw.txdata[position * 2 + 1];
                ensure!(commit.input.len() == 1 && funding.insert(commit.input[0].previous_output));
                ensure!(
                    raw.txdata[position * 2 + 2] == *reveal
                        && reveal.input.len() == 1
                        && reveal.input[0].previous_output.txid == commit.compute_txid()
                        && input.block.transactions[position].index
                            == u32::try_from(position * 2 + 2)?
                );
            }
            if index > 0 {
                ensure!(input.block.prev_hash == self.blocks[index - 1].block.hash);
            }
        }
        let count = self
            .schedule
            .events
            .iter()
            .filter(|event| matches!(event.action, Action::Simulation { .. }))
            .count();
        ensure!(self.requests.len() == count);
        for id in self.api.file_ids() {
            ensure!(file_ids.insert(id), "canonical and API file IDs collide");
        }
        for (request, input) in self.requests.iter().enumerate() {
            ensure!(
                input.commit.input.len() == 1
                    && !funding.contains(&input.commit.input[0].previous_output)
            );
            ensure!(!canonical.contains(&input.reveal.compute_txid().to_string()));
            ensure!(
                input.reveal.input.len() == 1
                    && input.reveal.input[0].previous_output.txid == input.commit.compute_txid()
            );
            let decoded = filter_map((0, input.reveal.clone())).context("API input missing")?;
            ensure!(decoded.inputs.len() == 1 && decoded.inputs[0].insts.aggregate.is_none());
            ensure!(
                decoded.inputs[0].x_only_pubkey.to_string() == self.api_signer,
                "saved timed API signer differs at request {request}"
            );
            ensure!(
                decoded.inputs[0].insts.ops == self.api.instructions(request)?,
                "saved timed API instruction association differs at request {request}"
            );
        }
        Ok(())
    }
}

#[derive(Clone)]
struct TrackedBatch {
    height: u64,
    anchor: u64,
    hash: BlockHash,
    txids: Vec<Txid>,
    bytes: Vec<Vec<u8>>,
    bodies_retained: bool,
}

fn settle_bodies(tracked: &mut [TrackedBatch], previous_tip: u64, tip: u64) {
    if !tracked.iter().any(|batch| {
        batch.anchor + FINALITY_WINDOW > previous_tip && batch.anchor + FINALITY_WINDOW <= tip
    }) {
        return;
    }
    // Body GC runs only at a due settlement and retains the inclusive window,
    // even though in-memory finality removes batches at their deadline.
    let floor = tracked
        .iter()
        .filter(|batch| batch.anchor >= tip.saturating_sub(FINALITY_WINDOW))
        .map(|batch| batch.height)
        .min();
    for batch in tracked {
        if floor.is_none_or(|floor| batch.height < floor) {
            batch.bodies_retained = false;
        }
    }
}

pub(super) struct TimedWork<'a> {
    pub(super) reactor: &'a mut Reactor<RuntimeExecutor>,
    plan: &'a InputPlan,
    model: Before,
    pending: Pending,
    files: FileProgress,
    cursors: Vec<usize>,
    tracked: Vec<TrackedBatch>,
    ordinal: usize,
    last_consensus: u64,
    before: Option<Checkpoint>,
    storage_height: u64,
    transaction_context: Option<TransactionContext>,
    previous_output: Option<OutPoint>,
    op_return_data: Option<Arc<[u8]>>,
    operation_counters: (u64, u64),
    tip: (u64, Option<BlockHash>),
    executed: bool,
    counter: Arc<AtomicU64>,
    history: Option<&'a HistoryPopulation>,
    pruning: Option<PruningProof>,
    simulation: Option<Vec<OpWithResult>>,
    directory: &'a Path,
    expected: Option<&'a [Checkpoint]>,
    pub(super) checkpoints: Vec<Checkpoint>,
    pub(super) api_results: Vec<Vec<OpWithResult>>,
}

impl<'a> TimedWork<'a> {
    pub(super) async fn new(
        reactor: &'a mut Reactor<RuntimeExecutor>,
        plan: &'a InputPlan,
        model: Before,
        directory: &'a Path,
        expected: Option<&'a [Checkpoint]>,
        counter: Arc<AtomicU64>,
        history: Option<&'a HistoryPopulation>,
    ) -> Result<Self> {
        plan.validate()?;
        let files = plan.recipes[0].files()?.initial_progress()?;
        let last_consensus = select_latest_consensus_height(&reactor.db_conn())
            .await?
            .context("timed fixture lacks anchor decision")?;
        let height = reactor.last_height;
        let tip = (height, reactor.last_hash);
        Ok(Self {
            reactor,
            plan,
            model,
            pending: Pending::new(height),
            files,
            cursors: vec![0; plan.blocks.len()],
            tracked: Vec::new(),
            ordinal: 0,
            last_consensus,
            before: None,
            storage_height: height,
            transaction_context: None,
            previous_output: None,
            op_return_data: None,
            operation_counters: (0, 0),
            tip,
            executed: false,
            counter,
            history,
            pruning: None,
            simulation: None,
            directory,
            expected,
            checkpoints: Vec::new(),
            api_results: Vec::new(),
        })
    }

    fn range(&self, block: usize, transactions: &Range<usize>) -> Result<Range<usize>> {
        let declared = &self.plan.schedule.blocks[block];
        ensure!(
            transactions.start >= declared.confirmations.start
                && transactions.end <= declared.fresh.end
        );
        let start = (transactions.start - declared.confirmations.start) * 2;
        let end = (transactions.end - declared.confirmations.start) * 2;
        ensure!(
            start < end && start == self.cursors[block],
            "timed recipe range is not next"
        );
        Ok(start..end)
    }

    async fn check_tracking(&self, tracked: &[TrackedBatch]) -> Result<()> {
        let height = self.reactor.last_height;
        let expected: Vec<_> = tracked
            .iter()
            .filter(|batch| batch.anchor + FINALITY_WINDOW > height)
            .collect();
        let actual = &self.reactor.consensus.unfinalized_batches;
        ensure!(
            actual.len() == expected.len(),
            "tracked finality count changed"
        );
        for (actual, expected) in actual.iter().zip(expected) {
            ensure!(
                actual.consensus_height.as_u64() == expected.height
                    && actual.anchor_height == expected.anchor
                    && actual.anchor_hash == expected.hash
                    && actual.deadline == expected.anchor + FINALITY_WINDOW
                    && actual.txids == expected.txids
            );
        }
        for batch in tracked {
            let mut actual =
                select_unconfirmed_batch_txs(&self.reactor.db_conn(), batch.height).await?;
            let mut expected = if batch.bodies_retained {
                batch.bytes.clone()
            } else {
                Vec::new()
            };
            actual.sort();
            expected.sort();
            ensure!(
                actual == expected,
                "retained batch bodies differ from finality model"
            );
        }
        let mut rows = self
            .reactor
            .db_conn()
            .query("SELECT COUNT(*) FROM excluded_batch_txids", ())
            .await?;
        ensure!(
            rows.next()
                .await?
                .context("missing exclusions count")?
                .get::<u64>(0)?
                == 0
        );
        ensure!(
            self.reactor.consensus.deferred_decisions.is_empty()
                && self.reactor.consensus.pending_next_height.is_none()
        );
        Ok(())
    }

    async fn check_mixed(
        &mut self,
        block: usize,
        range: Range<usize>,
        confirmed: bool,
        rows: &[ResultRow],
    ) -> Result<()> {
        let txids = &self.plan.txids[block][range.start / 2..range.end / 2];
        let selected: BTreeSet<_> = txids.iter().collect();
        let all: Vec<_> = rows
            .iter()
            .filter(|row| row.txid.as_ref().is_some_and(|id| selected.contains(id)))
            .collect();
        let mut roots = Vec::new();
        for txid in txids {
            roots.extend(root_receipts(rows, txid)?);
        }
        self.plan.recipes[block]
            .check_slice(
                &mut self.reactor.runtime,
                &all,
                &roots,
                &ExecutionSlice {
                    operations: range,
                    layout: self.plan.layout,
                    height: self.reactor.last_height,
                    confirmed,
                },
            )
            .await
    }
}

impl Work for TimedWork<'_> {
    async fn check_before(&mut self, event: &Event) -> Result<()> {
        ensure!(
            event == self.plan.schedule.event(self.ordinal)?
                && self.before.is_none()
                && !self.executed
        );
        let before = Checkpoint::capture(
            self.directory,
            &database_projection(&self.reactor.db_conn()).await?,
        )?;
        self.pending.check_unconfirmed(self.reactor).await?;
        ensure!(
            select_latest_consensus_height(&self.reactor.db_conn()).await?
                == Some(self.last_consensus)
        );
        match &event.action {
            Action::Batch {
                block,
                anchor_height,
                transactions,
            } => {
                ensure!(
                    *anchor_height == self.reactor.last_height
                        && self.reactor.last_hash == Some(self.plan.blocks[*block].block.prev_hash)
                );
                self.range(*block, transactions)?;
            }
            Action::Block { block } => {
                let input = &self.plan.blocks[*block];
                ensure!(
                    input.block.height == self.reactor.last_height + 1
                        && self.reactor.last_hash == Some(input.block.prev_hash)
                );
                self.range(*block, &self.plan.schedule.blocks[*block].fresh)?;
                self.pruning = Some(
                    PruningProof::capture(
                        &self.reactor.db_conn(),
                        89,
                        history::prune_height_at(input.block.height),
                    )
                    .await?,
                );
            }
            Action::Simulation {
                request,
                anchor_height,
                operations,
            } => {
                ensure!(
                    *anchor_height == self.reactor.last_height
                        && *request == self.api_results.len()
                );
                ensure!(self.plan.api.instructions(*request)?.len() == *operations);
                ensure!(!self.reactor.runtime.simulating && self.simulation.is_none());
            }
        }
        self.storage_height = self.reactor.runtime.storage.height;
        self.transaction_context = self.reactor.runtime.storage.tx_context.clone();
        self.previous_output = self.reactor.runtime.previous_output;
        self.op_return_data = self.reactor.runtime.op_return_data.clone();
        self.operation_counters = (
            self.reactor.runtime.id_generation_counter.get().await,
            self.reactor.runtime.result_id_counter.get().await,
        );
        self.tip = (self.reactor.last_height, self.reactor.last_hash);
        Checkpoint::capture(
            self.directory,
            &database_projection(&self.reactor.db_conn()).await?,
        )?
        .check(&before)?;
        self.before = Some(before);
        Ok(())
    }

    async fn execute(&mut self, event: &Event) -> Result<()> {
        ensure!(
            event == self.plan.schedule.event(self.ordinal)?
                && self.before.is_some()
                && !self.executed
        );
        match &event.action {
            Action::Batch {
                block,
                anchor_height,
                transactions,
            } => {
                let range = self.range(*block, transactions)?;
                let input = &self.plan.blocks[*block];
                let outcome = self
                    .reactor
                    .process_decided_batch(
                        *anchor_height,
                        input.block.prev_hash,
                        Height::new(
                            self.last_consensus
                                .checked_add(1)
                                .context("consensus height overflow")?,
                        ),
                        &[],
                        &input.reveals[range.start / 2..range.end / 2],
                        None,
                    )
                    .await?;
                ensure!(
                    outcome == BatchOutcome::Executed,
                    "timed batch did not execute"
                );
            }
            Action::Block { block } => {
                apply(self.reactor, self.plan.blocks[*block].block.clone()).await?;
                self.reactor.advance().await?;
            }
            Action::Simulation { request, .. } => {
                let transaction = filter_map((0, self.plan.requests[*request].reveal.clone()))
                    .context("API input missing")?;
                self.simulation = Some(self.reactor.simulate(transaction).await?);
            }
        }
        self.executed = true;
        Ok(())
    }

    async fn check(&mut self, event: &Event) -> Result<()> {
        ensure!(event == self.plan.schedule.event(self.ordinal)? && self.executed);
        let after = Checkpoint::capture(
            self.directory,
            &database_projection(&self.reactor.db_conn()).await?,
        )?;
        let mut model = self.model.clone();
        let mut pending = self.pending.clone();
        let mut files = self.files.clone();
        let mut tracked = self.tracked.clone();
        let mut updated_range = None;
        let mut api_result = None;
        let mut consensus = self.last_consensus;
        match &event.action {
            Action::Batch {
                block,
                anchor_height,
                transactions,
            } => {
                let range = self.range(*block, transactions)?;
                let input = &self.plan.blocks[*block];
                consensus = consensus
                    .checked_add(1)
                    .context("consensus height overflow")?;
                let reveals = &input.reveals[range.start / 2..range.end / 2];
                let proof = BatchProof::capture(
                    self.reactor,
                    reveals,
                    range.start / 2,
                    *anchor_height,
                    consensus,
                    self.directory,
                )
                .await?;
                proof.checkpoint().check(&after)?;
                let confirmations = proof.confirmation_plan(&input.block)?;
                pending.record(proof, confirmations)?;
                let rows = receipts(&self.reactor.db_conn(), *anchor_height).await?;
                self.check_mixed(*block, range.clone(), false, &rows)
                    .await?;
                model = model
                    .check_batch(
                        self.reactor,
                        &rows,
                        &self.plan.txids[*block][range.start / 2..range.end / 2],
                        &self.plan.recipes[*block]
                            .effects_range(self.plan.layout, range.clone())?,
                    )
                    .await?;
                files = files.advance(
                    self.plan.recipes[*block].files()?,
                    self.plan.recipes[*block].files_through(range.end)?,
                    false,
                )?;
                files
                    .check(
                        &mut self.reactor.runtime,
                        self.plan.recipes[*block].files()?,
                    )
                    .await?;
                tracked.push(TrackedBatch {
                    height: consensus,
                    anchor: *anchor_height,
                    hash: input.block.prev_hash,
                    txids: reveals.iter().map(Transaction::compute_txid).collect(),
                    bytes: reveals.iter().map(serialize).collect(),
                    bodies_retained: true,
                });
                updated_range = Some((*block, range.end));
            }
            Action::Block { block } => {
                let input = &self.plan.blocks[*block];
                ensure!(
                    (self.reactor.last_height, self.reactor.last_hash)
                        == (input.block.height, Some(input.block.hash))
                );
                let range = self.range(*block, &self.plan.schedule.blocks[*block].fresh)?;
                pending.check_block(self.reactor, &input.block).await?;
                ensure!(pending.len() == 0);
                let rows = receipts(&self.reactor.db_conn(), input.block.height).await?;
                self.pruning
                    .as_ref()
                    .context("missing pre-block pruning proof")?
                    .check(&self.reactor.db_conn())
                    .await?;
                if let Some(history) = self.history {
                    history
                        .check_at(
                            &self.reactor.db_conn(),
                            Some(history::prune_height_at(input.block.height)),
                        )
                        .await?;
                }
                self.check_mixed(*block, range.clone(), true, &rows).await?;
                model = model
                    .check(
                        self.reactor,
                        &rows,
                        &self.plan.txids[*block][range.start / 2..range.end / 2],
                        &self.plan.recipes[*block]
                            .effects_range(self.plan.layout, range.clone())?,
                    )
                    .await?;
                for (position, txid) in self.plan.txids[*block]
                    .iter()
                    .enumerate()
                    .skip(range.start / 2)
                {
                    let row = get_transaction_by_txid(&self.reactor.db_conn(), txid)
                        .await?
                        .context("fresh transaction missing")?;
                    ensure!(
                        row.height == input.block.height
                            && row.batch_height.is_none()
                            && row.confirmed_height == Some(input.block.height)
                            && row.tx_index == Some(u32::try_from(position)?)
                    );
                    ensure!(
                        get_confirmation_position(&self.reactor.db_conn(), txid).await?
                            == Some(input.block.transactions[position].index)
                    );
                }
                files = files.advance(
                    self.plan.recipes[*block].files()?,
                    self.plan.recipes[*block].files_through(range.end)?,
                    true,
                )?;
                files
                    .check(
                        &mut self.reactor.runtime,
                        self.plan.recipes[*block].files()?,
                    )
                    .await?;
                consensus = consensus
                    .checked_add(1)
                    .context("consensus height overflow")?;
                settle_bodies(&mut tracked, self.tip.0, input.block.height);
                updated_range = Some((*block, range.end));
            }
            Action::Simulation {
                request,
                anchor_height,
                ..
            } => {
                let results = self
                    .simulation
                    .as_ref()
                    .context("API request did not run")?;
                self.plan.api.check(
                    *request,
                    anchor_height + 1,
                    &self.plan.requests[*request]
                        .reveal
                        .compute_txid()
                        .to_string(),
                    results,
                )?;
                after.check(self.before.as_ref().context("missing API prestate")?)?;
                ensure!(
                    (self.reactor.last_height, self.reactor.last_hash) == self.tip
                        && !self.reactor.runtime.simulating
                        && self.reactor.runtime.storage.height == self.storage_height
                        && self.reactor.runtime.storage.tx_context == self.transaction_context
                        && self.reactor.runtime.previous_output == self.previous_output
                        && self.reactor.runtime.op_return_data == self.op_return_data
                        && (
                            self.reactor.runtime.id_generation_counter.get().await,
                            self.reactor.runtime.result_id_counter.get().await,
                        ) == self.operation_counters
                        && self.reactor.runtime.stack.is_empty().await
                        && self
                            .reactor
                            .runtime
                            .storage
                            .savepoint_stack
                            .is_empty()
                            .await
                );
                api_result = Some(results.clone());
            }
        }
        self.check_tracking(&tracked).await?;
        ensure!(select_latest_consensus_height(&self.reactor.db_conn()).await? == Some(consensus));
        Checkpoint::capture(
            self.directory,
            &database_projection(&self.reactor.db_conn()).await?,
        )?
        .check(&after)?;
        let counter = updated_range
            .map(|(block, end)| self.plan.recipes[block].counter_after(end))
            .transpose()?;
        Checkpoint::record(&mut self.checkpoints, after, self.expected)?;
        self.model = model;
        self.pending = pending;
        self.files = files;
        self.tracked = tracked;
        if let Some((block, end)) = updated_range {
            self.cursors[block] = end;
        }
        if let Some(counter) = counter {
            self.counter.store(counter, Ordering::SeqCst);
        }
        if let Some(result) = api_result {
            self.api_results.push(result);
            self.simulation = None;
        }
        self.last_consensus = consensus;
        self.before = None;
        self.pruning = None;
        self.executed = false;
        self.ordinal += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash;

    use super::{TrackedBatch, settle_bodies};

    fn batch(height: u64, anchor: u64) -> TrackedBatch {
        TrackedBatch {
            height,
            anchor,
            hash: BlockHash::all_zeros(),
            txids: Vec::new(),
            bytes: Vec::new(),
            bodies_retained: true,
        }
    }

    #[test]
    fn workload_timed_body_retention_includes_deadline_and_waits_for_settlement() {
        let mut consecutive = vec![batch(20, 101), batch(22, 102)];
        settle_bodies(&mut consecutive, 106, 107);
        assert!(consecutive.iter().all(|batch| batch.bodies_retained));
        settle_bodies(&mut consecutive, 107, 108);
        assert!(!consecutive[0].bodies_retained);
        assert!(consecutive[1].bodies_retained);

        let mut gap = vec![batch(20, 101)];
        settle_bodies(&mut gap, 106, 107);
        settle_bodies(&mut gap, 107, 108);
        assert!(gap[0].bodies_retained);
        gap.push(batch(30, 109));
        settle_bodies(&mut gap, 114, 115);
        assert!(!gap[0].bodies_retained);
        assert!(gap[1].bodies_retained);
        settle_bodies(&mut gap, 115, 116);
        assert!(gap[1].bodies_retained);
    }
}
