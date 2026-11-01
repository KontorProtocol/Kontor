#[cfg(test)]
mod aggregate_error_tests;
mod batches;
mod blocks;
#[cfg(test)]
mod confirmation_position_tests;
pub mod consensus_state;
pub mod engine;
pub mod executor;
mod handlers;
#[cfg(test)]
mod handoff_tests;
#[cfg(feature = "protocol-qualification")]
pub(crate) mod history_qualification;
#[cfg(test)]
pub(crate) mod lite_executor;
mod mempool;
pub mod mempool_fee_index;
#[cfg(test)]
mod mempool_tests;
#[cfg(test)]
pub mod mock_bitcoin;
#[cfg(test)]
mod pruning_tests;
#[cfg(feature = "protocol-qualification")]
pub(crate) mod qualification;
#[cfg(test)]
mod reactor_cluster_tests;
mod session;
#[cfg(test)]
mod simulation_context_tests;
#[cfg(test)]
mod startup_tests;
#[cfg(test)]
mod storage_penalty_tests;
pub mod types;
#[cfg(test)]
mod workload_tests;

use std::collections::VecDeque;
use std::future::Future;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use futures_util::future::{self, pending};
use indexer_types::{BlockRow, Event, Fees, OpWithResult};
use tokio::{
    select,
    sync::{
        mpsc::{self, Receiver},
        oneshot,
    },
    task::JoinHandle,
};

use bitcoin::{BlockHash, Network, Txid};
use malachitebft_app_channel::NetworkMsg;
use malachitebft_app_channel::app::types::LocallyProposedValue;
use malachitebft_core_types::{LinearTimeouts, Round};
use metrics::gauge;
use tracing::{debug, info, warn};

use crate::bitcoin_client::Client;
use crate::consensus::finality_types::StateEvent;
use crate::consensus::{BatchTx, Ctx};
#[cfg(test)]
use crate::database::canonical_history;
use crate::metrics::{DEFERRED_DECISIONS, PENDING_BLOCKS};
#[cfg(test)]
use crate::protocol::coordinator::committee::build_validator_set;
use crate::protocol::coordinator::bootstrap;
use crate::protocol::coordinator::linked::{self, TransactionRecognizer};
use crate::protocol::coordinator::selection::{
    ApplicationPosition, ExecutionSelection, select_legacy_p1,
};
#[cfg(test)]
use crate::protocol::v1::committee::stake_to_voting_power;
use crate::runtime::numerics::decimal_to_string;
use crate::runtime::ownership::OwnerService;
use crate::runtime::pool::LinkedSession;
#[cfg(test)]
use crate::runtime::{ComponentCache, Runtime, Storage};
use crate::stopper::ShutdownSignal;
use crate::{
    bitcoin_follower::event::{BlockEvent, MempoolEvent},
    bitcoin_helpers::new_mock_block_hash,
    consensus::Genesis,
    database::{
        self,
        queries::{
            PRUNE_WATERMARK_KEY, get_meta_u64, insert_block, select_block_at_height,
            select_block_latest, select_unconfirmed_batch_tx,
        },
    },
    runtime::GenesisParameters,
};
use libsql::Connection;

use executor::Executor;
use mempool::MempoolPreparation;

/// High-water mark on `consensus_state::pending_blocks`: the reactor stops
/// draining `block_rx` once this many blocks are buffered ahead of consensus,
/// letting the bounded poller→reactor channel fill and backpressure the Bitcoin
/// poller. Without it, initial catch-up (or any consensus stall) buffers every
/// block up to the chain tip — an unbounded `BTreeMap` of full blocks that
/// OOM-kills the pod, which restarts, stalls consensus further, and grows the
/// buffer again. Consensus always drains from the lowest buffered height, so
/// gating the tail never starves it. At full mainnet blocks 128 caps the buffer
/// near a few hundred MB; on signet it is negligible.
///
/// The gate also delays `BlockEvent::Rollback`: a rollback queued behind a full
/// buffer is processed only after the buffered (possibly orphaned) blocks are
/// decided, so `last_height` can advance up to this cap plus the block channel
/// capacity past a reorg fork before the rollback lands. That self-heals — the
/// rollback truncates and the poller re-sends from the fork — PROVIDED the
/// pruned-state retain window still covers the fork: `prune_retain_blocks` must
/// exceed `MAX_PENDING_BLOCKS` + channel capacity + real reorg headroom, or the
/// deep-reorg bail in `process_block_event` fires on an ordinary shallow reorg.
/// Keep this constant and that config default in lockstep.
const MAX_PENDING_BLOCKS: usize = 128;

/// Ceiling on `consensus_state::deferred_decisions` — decided values parked
/// because their data has not arrived or their turn has not come.
///
/// Unlike [`MAX_PENDING_BLOCKS`] this is not backpressure: there is nothing to
/// slow down, since the queue is fed by consensus itself. It is an OOM backstop
/// for the one state that cannot resolve itself — a node whose execution has
/// fallen behind heights the network already decided, which parks one entry per
/// decided value from then on. Set far above any legitimate backlog: a healthy
/// node idles near zero and drains within a block, and a tight bound would turn
/// a transient stall into the crash loop this bound exists to avoid.
const MAX_DEFERRED_DECISIONS: usize = 4096;

pub type SimulationOutcome = std::result::Result<Vec<OpWithResult>, String>;

pub type Simulation = (Vec<u8>, oneshot::Sender<Result<SimulationOutcome>>);

/// State-pruning settings for the reactor (see `project_state_pruning`).
#[derive(Clone, Copy, Debug)]
pub struct PruneConfig {
    /// `false` = archive node: full version history retained, no GC.
    pub enabled: bool,
    /// Blocks below the tip to retain before a version is prunable. Floored at
    /// the retained coordinator rules' minimum pruning floor at use so it
    /// cannot reach into a required rollback window.
    pub retain_blocks: u64,
}

pub(crate) struct Reactor<E: Executor> {
    executor: E,
    recognizer: TransactionRecognizer,
    session: LinkedSession,
    network: Network,
    node_label: String,
    owner_service: OwnerService,
    shutdown: ShutdownSignal,
    block_rx: Receiver<BlockEvent>,
    mempool_rx: Receiver<MempoolEvent>,
    ready_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
    simulate_rx: Option<Receiver<Simulation>>,
    consensus: consensus_state::ConsensusState,

    prune: PruneConfig,
    /// In-memory mirror of the persisted prune watermark `W_prev` (node_meta) —
    /// the highest height already collapsed to one row per path. Loaded at startup;
    /// advanced (and re-persisted) by each successful prune. See `project_state_pruning`.
    prune_watermark: u64,
    last_height: u64,
    last_hash: Option<BlockHash>,
    /// Shared with the API (`Env.consensus_listen_addr`); written on the first
    /// `Listening` (see `handle_consensus_msg`'s `ConsensusReady` arm).
    consensus_listen_addr: tokio::sync::watch::Sender<Option<String>>,
    /// Consensus I/O in flight — bitcoind validation running off the loop, ALL
    /// raced together as one arm of the root `select!` (`select_all`), so a
    /// stalled job cannot park another. Small, not a fixed size: at most one
    /// BUILD job (the `pending_proposal` is single, and `try_fulfill` refuses a
    /// second build while one is in flight), plus one VALIDATE job per in-flight
    /// proposal round — the `undecided` guard admits one per (height, round), and
    /// a fresh round at the same height can arrive before the previous round's
    /// job has applied. Bounded in practice by concurrent rounds, which the
    /// round-timeout machinery keeps to a handful. A `VecDeque` for cheap
    /// removal-by-index after `select_all`. See `batches::IoJob`.
    io_jobs: VecDeque<batches::IoJob>,
    /// Verdicts that outlived their proposal, banked for the next one — see
    /// `batches::ValidatedCandidates`.
    validated_candidates: Option<batches::ValidatedCandidates>,
    /// An in-flight off-loop mempool fee projection (`spawn_blocking`). The
    /// periodic tick starts one from a snapshot rather than projecting inline;
    /// its result is applied when this completes. `None` when idle — one at a
    /// time, so a slow projection never queues behind itself.
    fee_recompute: Option<tokio::task::JoinHandle<Fees>>,
    mempool_preparation: Option<MempoolPreparation>,
}

impl<E: Executor> Reactor<E> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) fn new(
        executor: E,
        runtime: Runtime,
        owner_service: OwnerService,
        block_rx: Receiver<BlockEvent>,
        mempool_rx: Receiver<MempoolEvent>,
        shutdown: ShutdownSignal,
        ready_tx: Option<oneshot::Sender<bool>>,
        event_tx: Option<mpsc::Sender<Event>>,
        simulate_rx: Option<Receiver<Simulation>>,
        consensus: consensus_state::ConsensusState,
        prune: PruneConfig,
        last_height: u64,
        last_hash: Option<BlockHash>,
        consensus_listen_addr: tokio::sync::watch::Sender<Option<String>>,
    ) -> Self {
        let network = runtime.network;
        let session = LinkedSession::new(
            runtime.get_storage_conn(),
            linked::link_runtime(runtime, true),
        );
        Self::from_session(
            executor,
            session,
            network,
            owner_service,
            block_rx,
            mempool_rx,
            shutdown,
            ready_tx,
            event_tx,
            simulate_rx,
            consensus,
            prune,
            last_height,
            last_hash,
            consensus_listen_addr,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_session(
        executor: E,
        session: LinkedSession,
        network: Network,
        owner_service: OwnerService,
        block_rx: Receiver<BlockEvent>,
        mempool_rx: Receiver<MempoolEvent>,
        shutdown: ShutdownSignal,
        ready_tx: Option<oneshot::Sender<bool>>,
        event_tx: Option<mpsc::Sender<Event>>,
        simulate_rx: Option<Receiver<Simulation>>,
        consensus: consensus_state::ConsensusState,
        prune: PruneConfig,
        last_height: u64,
        last_hash: Option<BlockHash>,
        consensus_listen_addr: tokio::sync::watch::Sender<Option<String>>,
    ) -> Self {
        let node_label = consensus
            .validator_index
            .map(|i| format!("node_{i}"))
            .unwrap_or_else(|| "follower".to_string());
        let recognizer = TransactionRecognizer::new(
            session.origin(),
            network,
            session.executor.operations.recognize.clone(),
        );
        Self {
            executor,
            recognizer,
            session,
            network,
            node_label,
            owner_service,
            shutdown,
            block_rx,
            mempool_rx,
            simulate_rx,
            prune,
            // Loaded from node_meta in `run()` when pruning is enabled; 0 here means
            // "nothing collapsed yet" (safe — the first prune's band (0, W] catches up).
            prune_watermark: 0,
            last_height,
            last_hash,
            ready_tx,
            event_tx,
            consensus,
            consensus_listen_addr,
            io_jobs: VecDeque::new(),
            validated_candidates: None,
            fee_recompute: None,
            mempool_preparation: None,
        }
    }

    fn select_executor(
        &self,
        position: ApplicationPosition,
    ) -> impl Future<Output = Result<ExecutionSelection>> + Send + 'static {
        let conn = self.db_conn();
        let network = self.network;
        async move { select_legacy_p1(&conn, network, position).await }
    }

    fn preparation_selection(
        &self,
    ) -> impl Future<Output = Result<ExecutionSelection>> + Send + 'static {
        self.select_executor(ApplicationPosition::Preparation {
            anchor_height: self.last_height,
            anchor_hash: self.last_hash,
        })
    }

    // Ordering writes and executor callbacks share the unit's physical transaction.
    fn db_conn(&self) -> libsql::Connection {
        self.session.conn.clone()
    }

    /// Check unconfirmed_batch_txs for a raw transaction (DB-level resolution).
    async fn resolve_tx_from_db(
        conn: &libsql::Connection,
        txid: &Txid,
        batch_height: u64,
    ) -> Option<bitcoin::Transaction> {
        if let Ok(Some(raw_bytes)) =
            select_unconfirmed_batch_tx(conn, &txid.to_string(), batch_height).await
            && let Ok(tx) = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&raw_bytes)
        {
            return Some(tx);
        }
        None
    }

    async fn refresh_validator_set_owned(&mut self) -> Result<()> {
        let selection = self.select_executor(ApplicationPosition::Committee).await?;
        let lease = self.begin_unit(&selection, false).await?;
        let result = linked::derive_committee(&self.session, &selection, self.network).await;
        let vs = self
            .finish_unit(lease, result, false)
            .await
            .context("Failed to refresh validator set")?;
        self.consensus.validator_index = vs
            .validators
            .iter()
            .position(|v| v.address == self.consensus.address);
        self.consensus.current_validator_set = vs;
        Ok(())
    }

    async fn send_proposal_parts(
        &mut self,
        proposal: &LocallyProposedValue<Ctx>,
        valid_round: Round,
    ) -> Result<()> {
        for stream_msg in self.consensus.stream_proposal(proposal, valid_round) {
            self.consensus
                .channels
                .network
                .send(NetworkMsg::PublishProposalPart(stream_msg))
                .await
                .context("Failed to send proposal part to network")?;
        }
        Ok(())
    }

    async fn resolve_batch_txs(
        &mut self,
        txs: &[BatchTx],
        batch_height: u64,
    ) -> Result<Vec<bitcoin::Transaction>> {
        let conn = self.db_conn();
        // First pass: everything the pool and DB can answer, in order. Slots that
        // still need bitcoind are left `None` and their txids collected, so the
        // RPC misses go out as ONE batch instead of a round trip per txid — the
        // replay/sync path resolves whole decided histories here.
        let mut resolved: Vec<Option<bitcoin::Transaction>> = Vec::with_capacity(txs.len());
        let mut rpc_slots: Vec<usize> = Vec::new();
        let mut rpc_txids: Vec<Txid> = Vec::new();
        for entry in txs {
            match entry {
                BatchTx::Raw(tx) => resolved.push(Some(tx.clone())),
                BatchTx::Id(txid) => {
                    // The retained body must belong to this decision: the same
                    // txid can carry different witnesses at different heights.
                    // Missing bodies use the pool/RPC fallback for new decisions
                    // or finalized history whose retained bytes were pruned.
                    if let Some(tx) = Self::resolve_tx_from_db(&conn, txid, batch_height).await {
                        resolved.push(Some(tx));
                    } else if let Some((raw, _)) = self.consensus.mempool.candidates.get(txid) {
                        resolved.push(Some(raw.clone()));
                    } else {
                        rpc_slots.push(resolved.len());
                        rpc_txids.push(*txid);
                        resolved.push(None);
                    }
                }
            }
        }
        if !rpc_txids.is_empty() {
            let fetched = self.executor.resolve_transactions(&rpc_txids).await;
            for ((slot, txid), tx) in rpc_slots.iter().zip(&rpc_txids).zip(fetched) {
                match tx {
                    Some(tx) => resolved[*slot] = Some(tx),
                    None => anyhow::bail!("Could not resolve decided batch transaction {txid}"),
                }
            }
        }
        Ok(resolved
            .into_iter()
            .map(|t| t.expect("all slots filled"))
            .collect())
    }

    async fn process_block_event(&mut self, event: BlockEvent) -> Result<()> {
        match event {
            BlockEvent::BlockInsert {
                target_height,
                block,
            } => {
                let txids = block.txids();
                for txid in &txids {
                    self.consensus.mempool.remove(txid);
                }
                info!("Block {}/{} {}", block.height, target_height, block.hash);

                // A block at or below the tip is already applied and can never be
                // proposed or executed again — buffering it is not merely useless,
                // it HALTS THE CHAIN. `pending_block_value` proposes the minimum pending
                // height, peers still hold the block so they vote it valid, and it
                // is decided; the finalize gate then refuses it as out of order and
                // nothing removes it from the buffer. It stays the minimum forever,
                // newer blocks are never proposed, and the only thing that would
                // clear it — a successful block execution — is exactly what the loop
                // prevents.
                //
                // Reachable from the poller: `replay_blocks_after` re-sends stored
                // block events, and the finality path deliberately keeps
                // `pending_blocks` across a rollback, so a replayed block can land
                // after the deferred drain has already carried the tip past it.
                if block.height <= self.last_height {
                    debug!(
                        block_height = block.height,
                        %block.hash,
                        last_height = self.last_height,
                        "Ignoring block at or below the tip — already applied"
                    );
                    return Ok(());
                }

                info!(
                    block_height = block.height,
                    %block.hash,
                    pending_count = self.consensus.pending_blocks.len() + 1,
                    "Adding block to pending_blocks"
                );
                // Move, not clone: `block` is owned here and unused afterward.
                // The catch-up stream can hold up to MAX_PENDING_BLOCKS full
                // blocks, so a per-block deep copy of every transaction, witness,
                // and op_return is pure waste.
                let height = block.height;
                self.consensus.pending_blocks.insert(height, block);
                self.advance()
                    .await
                    .context("advance failed after block insert")?;
                // A pending block may be what we're waiting to propose
                if self.consensus.pending_proposal.is_some() {
                    self.try_fulfill_pending_proposal()
                        .await
                        .context("try_fulfill_pending_proposal failed after block insert")?;
                }
            }
            BlockEvent::Rollback { to_height } => {
                info!(to_height, "Bitcoin rollback — truncating state");
                // A reorg deeper than `retain` would land in pruned territory (the
                // per-height versions needed to rebuild the as-of-`to_height` snapshot
                // are gone), so we BAIL rather than corrupt. This hard exit is the
                // intended behaviour, not a stopgap: `retain` defaults to ~1 day of
                // Bitcoin blocks, and a reorg that deep means Bitcoin itself violated
                // the finality assumption the WHOLE consensus rests on — every node's
                // anchored "finalized" batches are then invalid, pruned or not. There
                // is no local recovery (auto-replay would just rebuild onto the same
                // broken assumption), so halting for operator intervention is correct.
                // Hence the guard keys off `retain` (the assumption) — not the actual
                // prune watermark — because what it really detects is "Bitcoin broke
                // finality", which is catastrophic independent of pruning.
                self.check_rollback_depth(to_height)
                    .context("Bitcoin reorg too deep")?;
                self.rollback(to_height)
                    .await
                    .context("rollback failed during Bitcoin reorg")?;
                // Decided values above the fork are anchored to blocks that no
                // longer exist — they are deliberately forgotten here (their
                // rows stay in the batches table as consensus history) and the
                // network re-decides against the new chain; their txs return
                // via the mempool. Do NOT reload them into deferred_decisions:
                // old-chain entries would order ahead of new-chain decisions in
                // the drain queue and wedge it (a batch waiting on an anchor
                // whose only block decision is queued behind it).
                self.consensus
                    .clear_on_rollback(&self.db_conn(), to_height)
                    .await
                    .context("clear_on_rollback failed during Bitcoin reorg")?;
                let checkpoint = self.consensus.get_checkpoint(&self.db_conn()).await;
                self.consensus
                    .emit_state_event(StateEvent::RollbackExecuted {
                        to_anchor: to_height,
                        entries_removed: 0,
                        checkpoint,
                    });
            }
        }
        Ok(())
    }

    async fn run_event_loop(&mut self) -> Result<()> {
        self.ready_tx.take().map(|tx| tx.send(true));

        let debounce_duration = std::time::Duration::from_millis(500);
        let mut debounce_deadline: Option<tokio::time::Instant> = None;

        // Periodic recompute + publish of fee tiers. 2s matches
        // mempool.space's POLL_RATE_MS in production; staleness ≤2s is
        // imperceptible for fee estimation. The tick is the *only*
        // recompute path — sync readers (consensus
        // `compute_fee_threshold`, the API) read whatever this tick
        // last published. Skip catch-up ticks if the reactor was busy.
        let mut fee_publish_ticker = tokio::time::interval(std::time::Duration::from_secs(2));
        fee_publish_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        fee_publish_ticker.tick().await; // consume the immediate first tick

        loop {
            // Drain pending block events before entering select, but stop at the
            // high-water mark so the bounded channel backpressures the poller
            // instead of buffering to the chain tip.
            while self.consensus.pending_blocks.len() < MAX_PENDING_BLOCKS {
                match self.block_rx.try_recv() {
                    Ok(event) => self
                        .process_block_event(event)
                        .await
                        .context("process_block_event failed (try_recv drain)")?,
                    Err(_) => break,
                }
            }

            // Publish the backlog gauges from the one point every state change
            // passes through, rather than from each mutation site. Both queues
            // matter most exactly when nothing is happening — a wedged node
            // executes no blocks and decides no batches, so a gauge hung off
            // either of those paths would go stale precisely when it is needed.
            gauge!(PENDING_BLOCKS).set(self.consensus.pending_blocks.len() as f64);
            gauge!(DEFERRED_DECISIONS).set(self.consensus.deferred_decisions.len() as f64);

            let hard_deadline_instant = self.consensus.pending_proposal.as_ref().map(|p| {
                let deadline = p.hard_deadline;
                let remaining = deadline.saturating_duration_since(Instant::now());
                tokio::time::Instant::now() + remaining
            });

            // Pre-existing quirk, noted rather than fixed here: if the API
            // side of this channel closes, `recv()` returns `None` and the arm
            // fires on every loop iteration. The API is a supervised subsystem,
            // so its death stops the node through `first_exit` anyway.
            let simulate_rx = async {
                if let Some(rx) = self.simulate_rx.as_mut() {
                    rx.recv().await
                } else {
                    pending().await
                }
            };

            let consensus_rx = self.consensus.channels.consensus.recv();

            // EVERY in-flight I/O job's verdict future, raced — or never.
            // All of them, not just the front: a stalled BuildProposal against
            // a slow bitcoind must not park a ValidateProposal whose oneshot
            // reply the consensus engine is waiting on, or the node stops
            // voting for the front job's whole retry budget. Polling through
            // `&mut` retains each future's progress when another arm wins the
            // select; dropping the loop (shutdown) drops the in-flight RPCs.
            let io_verdicts = async {
                if self.io_jobs.is_empty() {
                    pending().await
                } else {
                    future::select_all(self.io_jobs.iter_mut().map(|j| &mut j.verdicts)).await
                }
            };

            // The off-loop fee projection's result, or never. Same shape as
            // `io_verdicts`: polled through `&mut` so it survives losing the
            // select, dropped with the loop at shutdown.
            let fee_recompute = async {
                match self.fee_recompute.as_mut() {
                    Some(handle) => handle.await,
                    None => pending().await,
                }
            };

            let can_read_mempool = self.mempool_preparation.is_none();
            let mempool_preparation = async {
                match self.mempool_preparation.as_mut() {
                    Some(preparation) => (&mut preparation.result).await,
                    None => pending().await,
                }
            };

            let debounce_sleep = async {
                match debounce_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => pending().await,
                }
            };

            let hard_deadline_sleep = async {
                match hard_deadline_instant {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => pending().await,
                }
            };

            select! {
                _ = self.shutdown.cancelled() => {
                    info!("Cancelled");
                    break;
                }
                Some(event) = self.block_rx.recv(),
                    if self.consensus.pending_blocks.len() < MAX_PENDING_BLOCKS => {
                    self.process_block_event(event)
                        .await
                        .context("process_block_event failed")?;
                }
                // Preserve snapshot/delta order and channel backpressure while
                // the owned parser runs, without parking consensus or blocks.
                Some(event) = self.mempool_rx.recv(), if can_read_mempool => {
                    match event {
                        MempoolEvent::Sync { transactions, fees, mempool_min_fee_sat_per_vb } => {
                            self.consensus.mempool.stage_snapshot(&transactions);
                            let selection = self.preparation_selection().await?;
                            self.mempool_preparation = Some(MempoolPreparation {
                                result: self.executor.parse_mempool(&self.recognizer, &selection, transactions), selection,
                            });
                            self.consensus.mempool_fee_index.replace(fees, mempool_min_fee_sat_per_vb);
                            self.consensus.mempool_fee_index.recompute();
                            info!("MempoolSync: recognition started");
                            if self.consensus.pending_proposal.is_some() {
                                debounce_deadline = Some(tokio::time::Instant::now() + debounce_duration);
                            }
                        },
                        MempoolEvent::TransactionAdded { txid, tx, fee } => {
                            self.consensus.mempool.stage(&tx);
                            let selection = self.preparation_selection().await?;
                            self.mempool_preparation = Some(MempoolPreparation {
                                result: self.executor.parse_mempool(&self.recognizer, &selection, vec![tx]), selection,
                            });
                            self.consensus.mempool_fee_index.insert(txid, fee);
                        },
                        MempoolEvent::MempoolFeeSample { txid, fee } => {
                            self.consensus.mempool_fee_index.insert(txid, fee);
                            // No debounce reset — non-Kontor activity doesn't
                            // affect what we can propose.
                        },
                        MempoolEvent::Remove(txid) => {
                            self.consensus.mempool.remove(&txid);
                            self.consensus.mempool_fee_index.remove(&txid);
                            debug!("MempoolRemove {}", txid);
                        },
                    }
                }
                prepared = mempool_preparation => {
                    let previous = self.mempool_preparation.take().expect("completed preparation");
                    let prepared = prepared?;
                    let selection = self.preparation_selection().await?;
                    if !previous.selection.same_recognition_rules(&selection) {
                        self.mempool_preparation = Some(MempoolPreparation {
                            result: self.executor.parse_mempool(&self.recognizer, &selection, self.consensus.mempool.raw_inputs()),
                            selection,
                        });
                        continue;
                    }
                    let mut recognized = false;
                    for transaction in prepared {
                        recognized |= self.consensus.mempool.finish(transaction);
                    }
                    if recognized && self.consensus.pending_proposal.is_some() {
                        debounce_deadline = Some(tokio::time::Instant::now() + debounce_duration);
                    }
                }
                _ = debounce_sleep => {
                    debounce_deadline = None;
                    self.try_fulfill_pending_proposal().await
                        .context("try_fulfill_pending_proposal failed (debounce)")?;
                }
                _ = hard_deadline_sleep => {
                    self.try_fulfill_pending_proposal().await
                        .context("try_fulfill_pending_proposal failed (hard deadline)")?;
                }
                msg = consensus_rx => {
                    // A closed engine channel is the consensus engine DYING —
                    // for a validator that is the third route to the silent
                    // desync of 2026-08-04, and it must be fatal. Unless we are
                    // being stopped: teardown races this arm against the cancel
                    // arm above, so consult the signal instead of guessing.
                    //
                    // The asymmetry with `block_rx`/`mempool_rx` is deliberate:
                    // their `Some(...)` patterns can stay, because their
                    // producers are SUPERVISED subsystems — a dead follower
                    // surfaces through the supervisor's `first_exit`, while the
                    // in-process Malachite actor has no handle of its own and
                    // this channel is the only way its death reaches anyone.
                    let Some(msg) = msg else {
                        return if self.shutdown.is_cancelled() {
                            Ok(())
                        } else {
                            Err(anyhow::anyhow!("consensus engine channel closed"))
                        };
                    };
                    debug!("REACTOR: processing consensus msg");
                    let consensus_result = self.handle_consensus_msg(msg)
                        .await
                        .context("handle_consensus_msg failed")?;
                    if let consensus_state::ConsensusResult::BatchProcessed { txids } = &consensus_result
                        && let Some(tx) = &self.event_tx
                        && tx
                            .send(Event::BatchProcessed {
                                txids: txids.clone(),
                            })
                            .await
                            .is_err()
                    {
                        warn!("Event receiver dropped, cannot send BatchProcessed event");
                    }
                    self.advance()
                        .await
                        .context("advance failed after consensus message")?;
                    // Yield to allow other channels (block_rx, mempool_rx) to be polled
                    tokio::task::yield_now().await;
                }
                option_event = simulate_rx => {
                    if let Some((tx, ret_tx)) = option_event {
                        let result = self.simulate_raw(tx).await;
                        let err_msg = result.as_ref().err().map(|e| format!("{e:#}"));
                        let _ = ret_tx.send(result);
                        if let Some(msg) = err_msg {
                            // Fatal on purpose, and NOT user-triggerable: an
                            // `Err` out of `simulate_raw` is infrastructure-only by
                            // construction (savepoint, DB, executor plumbing) —
                            // user-level op failures ride inside `Ok(results)`
                            // as per-op error fields; malformed/unrecognized input
                            // is an ordinary rejection in the inner result.
                            // I5: this node's own I/O
                            // failing must stop this node.
                            bail!("simulation failed: {msg}");
                        }
                    }
                }
                (verdicts, index, _) = io_verdicts => {
                    let job = self
                        .io_jobs
                        .remove(index)
                        .expect("io arm fired with this job's index");
                    self.apply_io_verdicts(job.apply, verdicts)
                        .await
                        .context("apply_io_verdicts failed")?;
                }
                _ = fee_publish_ticker.tick() => {
                    // Project OFF the loop: at mainnet mempool sizes the
                    // projection is tens to hundreds of ms, and running it inline
                    // here stalls every Malachite reply, block, and finality check
                    // for that long every 2s. One job at a time — a mutation
                    // arriving mid-projection re-sets `dirty` and the next tick
                    // re-runs. The Sync arm and startup still recompute inline:
                    // they are infrequent and must establish the fresh threshold
                    // synchronously before the node reports available.
                    if self.fee_recompute.is_none()
                        && self.consensus.mempool_fee_index.take_dirty()
                    {
                        let (entries, min) = self.consensus.mempool_fee_index.snapshot();
                        self.fee_recompute = Some(tokio::task::spawn_blocking(move || {
                            mempool_fee_index::project_fees(&entries, min)
                        }));
                    }
                }
                result = fee_recompute => {
                    self.fee_recompute = None;
                    match result {
                        Ok(fees) => self.consensus.mempool_fee_index.store_recomputed(fees),
                        // The blocking task panicked or was cancelled. It carries
                        // no state — the cached fees simply stay put and the next
                        // tick re-projects — so log and move on rather than exit.
                        Err(e) => warn!(error = %e, "Fee projection task failed; keeping the last fees"),
                    }
                }
            }
        }
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(node = %self.node_label))]
    pub(crate) async fn run(&mut self) -> Result<()> {
        // A startup mutation is part of the reactor's owned durable unit. It
        // must finish before shutdown can release the writer or runtime.
        self.maintain_executor(None).await?;
        self.advance()
            .await
            .context("advance failed during startup finality settle")?;

        let result = if self.shutdown.is_cancelled() {
            Ok(())
        } else {
            self.run_event_loop().await
        };

        // Gracefully stop the Malachite consensus engine — BOUNDED. This wait
        // sits between a reactor fatal and the exit status that reports it, so
        // an engine that never acknowledges the stop must not stand there
        // indefinitely: that is the immortal green-probed node again, one layer
        // down. On timeout, say so and go — the process is exiting either way,
        // and the loop result, not the engine's teardown, is the story.
        if let Err(e) = self
            .consensus
            .engine_handle
            .actor
            .get_cell()
            .stop_and_wait(
                Some("Reactor shutting down".to_string()),
                Some(std::time::Duration::from_secs(5)),
            )
            .await
        {
            warn!(error = %e, "Malachite engine did not stop cleanly within 5s; exiting without it");
        }

        result
    }
}

/// Build a Genesis from the staking contract's active validator set.
#[cfg(test)]
async fn build_genesis_from_staking(runtime: &mut Runtime) -> Result<Genesis> {
    let validator_set = build_validator_set(runtime).await?;
    Ok(Genesis { validator_set })
}

async fn prepare_executor_startup(
    starting_block_height: u64,
    writer: &database::Writer,
) -> Result<(u64, Option<BlockHash>)> {
    let conn = writer.connection();
    let (last_height, last_hash) = match select_block_latest(&conn)
        .await
        .context("Failed to query latest block during startup")?
    {
        // The native block at height 0 is inserted by this function on
        // first boot (below). On subsequent boots — if no real bitcoin
        // blocks have been indexed yet — `select_block_latest` returns
        // it. Treat that case as a fresh start, since `starting_block_height`
        // is allowed to be (and typically is) much higher than 0.
        Some(block) if block.height == 0 => {
            info!(
                "Only native block found, starting from height {}",
                starting_block_height
            );
            (starting_block_height - 1, None)
        }
        Some(block) => {
            let block_height = block.height;
            if block_height < starting_block_height - 1 {
                bail!(
                    "Latest block has height {}, less than start height {}",
                    block_height,
                    starting_block_height
                );
            }

            info!(
                "Continuing from block height {} ({})",
                block_height, block.hash
            );
            (block_height, Some(block.hash))
        }
        None => {
            info!(
                "No previous blocks found, starting from height {}",
                starting_block_height
            );
            (starting_block_height - 1, None)
        }
    };

    // ensure 0 (native) block exists
    if select_block_at_height(&conn, 0)
        .await
        .context("Failed to check for native block at height 0")?
        .is_none()
    {
        info!("Creating native block");
        insert_block(
            &conn,
            BlockRow::builder()
                .height(0)
                .hash(new_mock_block_hash(0))
                .relevant(true)
                .build(),
        )
        .await
        .context("Failed to insert native block at height 0")?;
    }
    Ok((last_height, last_hash))
}

fn new_runtime_executor(
    bitcoin_client: Client,
    replay_tx: Option<mpsc::Sender<u64>>,
) -> executor::RuntimeExecutor {
    let exec = executor::RuntimeExecutor::new(bitcoin_client);
    if let Some(tx) = replay_tx {
        exec.with_replay_tx(tx)
    } else {
        exec
    }
}

#[cfg(test)]
async fn create_uninitialized_runtime_executor(
    starting_block_height: u64,
    writer: &database::Writer,
    owner_service: &OwnerService,
    bitcoin_client: Client,
    replay_tx: Option<mpsc::Sender<u64>>,
    network: Network,
) -> Result<(executor::RuntimeExecutor, Runtime, u64, Option<BlockHash>)> {
    let (last_height, last_hash) = prepare_executor_startup(starting_block_height, writer).await?;
    let storage = Storage::builder()
        .height(0)
        .conn(writer.connection())
        .build();
    let mut runtime = Runtime::new(ComponentCache::new(), storage)
        .await
        .context("Failed to initialize runtime")?;
    owner_service.apply_startup_compile_gate(&mut runtime);
    runtime.network = network;
    Ok((
        new_runtime_executor(bitcoin_client, replay_tx),
        runtime,
        last_height,
        last_hash,
    ))
}

#[cfg(test)]
pub(crate) async fn create_runtime_executor(
    starting_block_height: u64,
    writer: &database::Writer,
    owner_service: &OwnerService,
    bitcoin_client: Client,
    replay_tx: Option<mpsc::Sender<u64>>,
    genesis: &GenesisParameters,
    network: Network,
) -> Result<(executor::RuntimeExecutor, Runtime, u64, Option<BlockHash>)> {
    let (exec, mut runtime, height, hash) = create_uninitialized_runtime_executor(
        starting_block_height,
        writer,
        owner_service,
        bitcoin_client,
        replay_tx,
        network,
    )
    .await?;
    runtime
        .publish_native_contracts_owned(genesis, owner_service)
        .await?;
    // Compatibility fixtures bypass the coordinator's genesis journal.
    canonical_history::initialize(&runtime.storage.conn).await?;
    Ok((exec, runtime, height, hash))
}

pub(crate) async fn create_executor_session(
    starting_block_height: u64,
    writer: &database::Writer,
    owner_service: &OwnerService,
    bitcoin_client: Client,
    replay_tx: Option<mpsc::Sender<u64>>,
    genesis: &GenesisParameters,
    network: Network,
) -> Result<(
    executor::RuntimeExecutor,
    LinkedSession,
    u64,
    Option<BlockHash>,
)> {
    let genesis = (
        decimal_to_string(genesis.sigma_min),
        genesis
            .validators
            .iter()
            .map(|v| {
                (
                    v.x_only_pubkey.clone(),
                    decimal_to_string(v.stake),
                    v.ed25519_pubkey.clone(),
                )
            })
            .collect(),
    );
    let (baseline, initialize) = bootstrap::prepare(
        &writer.connection(),
        network,
        starting_block_height,
        &genesis,
    )
    .await?;
    let (height, hash) = prepare_executor_startup(starting_block_height, writer).await?;
    let exec = new_runtime_executor(bitcoin_client, replay_tx);
    let session = linked::canonical_session(writer.connection(), network)
        .await
        .context("Failed to initialize retained executor session")?;
    #[cfg(test)]
    owner_service
        .apply_linked_startup_compile_gate(&session)
        .await?;
    if initialize {
        linked::initialize(
            owner_service,
            &session,
            network,
            starting_block_height,
            genesis,
        )
        .await
        .context("Failed to publish native contracts")?;
    }
    bootstrap::complete(owner_service, &session, network, &baseline).await?;
    Ok((exec, session, height, hash))
}

#[cfg(test)]
pub(crate) async fn start_consensus(
    engine_config: engine::EngineConfig,
    runtime: &mut Runtime,
    observation_channels: Option<consensus_state::ObservationChannels>,
    timeouts: Option<LinearTimeouts>,
    last_block_height: u64,
    mempool_fee_index: mempool_fee_index::MempoolFeeIndex,
) -> Result<consensus_state::ConsensusState> {
    let genesis = build_genesis_from_staking(runtime)
        .await
        .context("Failed to build genesis from staking contract")?;

    start_consensus_with_genesis(
        engine_config,
        runtime.get_storage_conn(),
        genesis,
        observation_channels,
        timeouts,
        last_block_height,
        mempool_fee_index,
    )
    .await
}

async fn start_linked_consensus(
    engine_config: engine::EngineConfig,
    session: &LinkedSession,
    service: &OwnerService,
    network: Network,
    observation_channels: Option<consensus_state::ObservationChannels>,
    timeouts: Option<LinearTimeouts>,
    last_block_height: u64,
    mempool_fee_index: mempool_fee_index::MempoolFeeIndex,
) -> Result<consensus_state::ConsensusState> {
    let selection =
        select_legacy_p1(&session.conn, network, ApplicationPosition::Committee).await?;
    let lease = linked::begin_canonical_unit(service, session, &selection, network, false).await?;
    let result = linked::derive_committee(session, &selection, network).await;
    let validator_set = linked::finish_canonical_unit(lease, result, false)
        .await
        .context("Failed to build genesis from staking contract")?;
    start_consensus_with_genesis(
        engine_config,
        session.conn.clone(),
        Genesis { validator_set },
        observation_channels,
        timeouts,
        last_block_height,
        mempool_fee_index,
    )
    .await
}

async fn start_consensus_with_genesis(
    engine_config: engine::EngineConfig,
    conn: Connection,
    genesis: Genesis,
    observation_channels: Option<consensus_state::ObservationChannels>,
    timeouts: Option<LinearTimeouts>,
    last_block_height: u64,
    mempool_fee_index: mempool_fee_index::MempoolFeeIndex,
) -> Result<consensus_state::ConsensusState> {
    let engine_output = engine::start(engine_config)
        .await
        .context("Failed to start Malachite consensus engine")?;
    info!(address = %engine_output.address, "Consensus engine started");

    let validator_index = genesis
        .validator_set
        .validators
        .iter()
        .position(|v| v.address == engine_output.address);

    let mut state = consensus_state::ConsensusState::new(
        conn,
        engine_output.signing_provider,
        genesis,
        engine_output.address,
        last_block_height,
        engine_output.channels,
        engine_output._handle,
        validator_index,
        mempool_fee_index,
    )
    .await
    .context("Failed to build consensus state")?;
    state.observation = observation_channels;
    if let Some(t) = timeouts {
        state.timeouts = t;
    }

    Ok(state)
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    starting_block_height: u64,
    shutdown: ShutdownSignal,
    owner_service: OwnerService,
    writer: database::Writer,
    block_rx: Receiver<BlockEvent>,
    mempool_rx: Receiver<MempoolEvent>,
    ready_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
    simulate_rx: Option<Receiver<Simulation>>,
    engine_config: engine::EngineConfig,
    bitcoin_client: Client,
    replay_tx: Option<mpsc::Sender<u64>>,
    genesis: GenesisParameters,
    observation_channels: Option<consensus_state::ObservationChannels>,
    consensus_propose_timeout_ms: u64,
    fee_tx: Option<tokio::sync::watch::Sender<Fees>>,
    consensus_listen_addr: tokio::sync::watch::Sender<Option<String>>,
    network: bitcoin::Network,
    prune: PruneConfig,
) -> JoinHandle<Result<()>> {
    tokio::spawn({
        async move {
            let result: Result<()> = async {
                // Native publication and its guest work finish before this task
                // releases the writer, even when shutdown arrives during setup.
                let (exec, session, last_height, last_hash) = create_executor_session(
                    starting_block_height,
                    &writer,
                    &owner_service,
                    bitcoin_client,
                    replay_tx,
                    &genesis,
                    network,
                )
                .await
                .context("create_runtime_executor failed")?;

                // Existing databases need a one-time conversion before pruning.
                if prune.enabled {
                    database::init::ensure_incremental_auto_vacuum(&session.conn)
                        .await
                        .context("ensure_incremental_auto_vacuum failed")?;
                }
                if shutdown.is_cancelled() {
                    return Ok(());
                }

                let timeouts = Some(LinearTimeouts {
                    propose: std::time::Duration::from_millis(consensus_propose_timeout_ms),
                    ..LinearTimeouts::default()
                });

                // Gate consensus startup on the first MempoolEvent::Sync
                // arriving from the listener. The fee index must be
                // populated before we participate in voting/proposing,
                // otherwise we'd validate proposals against an empty index
                // (effectively no threshold check). Followers benefit too:
                // a slightly delayed startup is preferable to running with
                // a stale or absent mempool view.
                //
                // The listener guarantees Sync as the first event after
                // its startup snapshot — anything else here means a bug.
                let mut mempool_rx = mempool_rx;
                // The index owns the fee watch sender — every
                // `recompute()` publishes automatically, so the call
                // sites in the reactor don't have to remember to.
                let mut fee_index = mempool_fee_index::MempoolFeeIndex::new(fee_tx);
                info!("Waiting for initial mempool sync before starting consensus");
                // Periodic log so operators can tell the wait isn't a deadlock
                // when bitcoind is slow to reach handshake.
                let mut log_ticker = tokio::time::interval(std::time::Duration::from_secs(30));
                log_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                log_ticker.tick().await; // consume the immediate first tick
                let initial_raw_txs = loop {
                    select! {
                        event = mempool_rx.recv() => match event {
                            Some(MempoolEvent::Sync {
                                transactions,
                                fees,
                                mempool_min_fee_sat_per_vb,
                            }) => {
                                fee_index.replace(fees, mempool_min_fee_sat_per_vb);
                                info!(
                                    "Initial mempool sync complete: {} raw txs, {} fee entries",
                                    transactions.len(),
                                    fee_index.len()
                                );
                                break transactions;
                            }
                            Some(other) => {
                                bail!("Mempool delta event before initial Sync: {other:?}");
                            }
                            None => {
                                bail!("Mempool channel closed before initial Sync");
                            }
                        },
                        _ = log_ticker.tick() => {
                            warn!("Still waiting for initial mempool sync — bitcoind/listener not ready");
                        }
                        _ = shutdown.cancelled() => {
                            return Ok(());
                        }
                    }
                };

                // Compute the first projection from the freshly-synced
                // index, *before* anything signals readiness.
                // `recompute()` populates the cache, clears the dirty
                // flag, and publishes via the index's owned watch
                // sender — establishing the invariant that by the time
                // `available = true`, the watch channel carries real
                // bitcoind-derived data (never the `Fees::floor(1)`
                // placeholder).
                fee_index.recompute();

                let selection = select_legacy_p1(&session.conn, network,
                    ApplicationPosition::Preparation { anchor_height: last_height, anchor_hash: last_hash }).await?;
                let recognizer = TransactionRecognizer::new(session.origin(), network, session.executor.operations.recognize.clone());
                let initial_mempool = exec.parse_mempool(&recognizer, &selection, initial_raw_txs).await?;
                let mut consensus = start_linked_consensus(engine_config, &session, &owner_service, network,
                    observation_channels, timeouts, last_height, fee_index).await.context("start_consensus failed")?;

                consensus.mempool.replace(initial_mempool);

                let mut reactor = Reactor::from_session(
                    exec,
                    session,
                    network,
                    owner_service,
                    block_rx,
                    mempool_rx,
                    shutdown.clone(),
                    ready_tx,
                    event_tx,
                    simulate_rx,
                    consensus,
                    prune,
                    last_height,
                    last_hash,
                    consensus_listen_addr,
                );

                // Disabling pruning or increasing retention does not restore
                // deleted history. Rollback must still respect this boundary.
                reactor.prune_watermark =
                    get_meta_u64(&reactor.db_conn(), PRUNE_WATERMARK_KEY, 0)
                        .await
                        .context("loading prune watermark failed")?;

                reactor.run().await
            }
            .await;

            // Neither logged nor cancelled here: the reactor reports by
            // returning, and the supervisor in `main` owns what that means for
            // the process. Cancelling from inside a subsystem is what made a
            // fatal error indistinguishable from a requested stop.
            info!("Exited");
            result
        }
    })
}
