mod batches;
mod blocks;
pub mod consensus_state;
pub mod engine;
pub mod executor;
mod handlers;
#[cfg(test)]
pub(crate) mod lite_executor;
pub mod mempool_fee_index;
pub mod mock_bitcoin;
#[cfg(test)]
mod reactor_cluster_tests;
pub mod types;

use std::time::Instant;

use anyhow::{Context, Result, bail};
use futures_util::future::pending;
use indexer_types::{BlockRow, Event, Fees, OpWithResult};
use tokio::{
    select,
    sync::{
        mpsc::{self, Receiver},
        oneshot,
    },
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use bitcoin::{BlockHash, Txid};
use malachitebft_app_channel::NetworkMsg;
use malachitebft_app_channel::app::types::LocallyProposedValue;
use malachitebft_app_channel::app::types::core::VotingPower;
use malachitebft_core_types::{LinearTimeouts, Round};
use tracing::{debug, error, info, warn};

use crate::consensus::finality_types::StateEvent;
use crate::consensus::{BatchTx, Ctx};
use crate::{
    bitcoin_follower::event::{BlockEvent, MempoolEvent},
    consensus::{Genesis, Validator, ValidatorSet, signing::PublicKey},
    database::{
        self,
        queries::{
            insert_block, select_block_at_height, select_block_latest, select_unconfirmed_batch_tx,
        },
    },
    runtime::{
        ComponentCache, Decimal, Runtime, Storage, numerics::decimal_to_string,
        staking::api::get_active_set,
    },
    test_utils::new_mock_block_hash,
};

use executor::Executor;

pub type Simulation = (
    indexer_types::Transaction,
    oneshot::Sender<Result<Vec<OpWithResult>>>,
);

pub struct Reactor<E: Executor> {
    executor: E,
    runtime: Runtime,
    cancel_token: CancellationToken,
    block_rx: Receiver<BlockEvent>,
    mempool_rx: Receiver<MempoolEvent>,
    ready_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
    simulate_rx: Option<Receiver<Simulation>>,
    consensus: consensus_state::ConsensusState,
    /// Optional sink for the latest fee tier snapshot. Published from
    /// the reactor's periodic tick when the index is dirty so the API
    /// (and other read-side consumers) can serve fee tiers without
    /// touching the mempool index directly.
    fee_tx: Option<tokio::sync::watch::Sender<Fees>>,

    last_height: u64,
    last_hash: Option<BlockHash>,
}

impl<E: Executor> Reactor<E> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        executor: E,
        runtime: Runtime,
        block_rx: Receiver<BlockEvent>,
        mempool_rx: Receiver<MempoolEvent>,
        cancel_token: CancellationToken,
        ready_tx: Option<oneshot::Sender<bool>>,
        event_tx: Option<mpsc::Sender<Event>>,
        simulate_rx: Option<Receiver<Simulation>>,
        consensus: consensus_state::ConsensusState,
        last_height: u64,
        last_hash: Option<BlockHash>,
        fee_tx: Option<tokio::sync::watch::Sender<Fees>>,
    ) -> Self {
        let mut runtime = runtime;
        runtime.node_label = consensus
            .validator_index
            .map(|i| format!("node_{i}"))
            .unwrap_or_else(|| "follower".to_string());
        Self {
            executor,
            runtime,
            cancel_token,
            block_rx,
            mempool_rx,
            simulate_rx,
            last_height,
            last_hash,
            ready_tx,
            event_tx,
            consensus,
            fee_tx,
        }
    }

    /// Clone of the shared write connection from Runtime.storage.
    /// All DB connections in the reactor (Reactor, ConsensusState, Storage)
    /// share the same underlying connection via Arc.
    fn db_conn(&self) -> libsql::Connection {
        self.runtime.storage.conn.clone()
    }

    /// Check unconfirmed_batch_txs for a raw transaction (DB-level resolution).
    async fn resolve_tx_from_db(
        conn: &libsql::Connection,
        txid: &Txid,
    ) -> Option<bitcoin::Transaction> {
        if let Ok(Some(raw_bytes)) = select_unconfirmed_batch_tx(conn, &txid.to_string()).await
            && let Ok(tx) = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&raw_bytes)
        {
            return Some(tx);
        }
        None
    }

    async fn refresh_validator_set(&mut self) -> Result<()> {
        let vs = build_validator_set(&mut self.runtime)
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

    async fn resolve_batch_txs(&mut self, txs: &[BatchTx]) -> Result<Vec<bitcoin::Transaction>> {
        let conn = self.db_conn();
        let mut resolved = Vec::with_capacity(txs.len());
        for entry in txs {
            match entry {
                BatchTx::Raw(tx) => resolved.push(tx.clone()),
                BatchTx::Id(txid) => {
                    if let Some((raw, _)) = self.consensus.pending_transactions.get(txid) {
                        resolved.push(raw.clone());
                    } else if let Some(tx) = Self::resolve_tx_from_db(&conn, txid).await {
                        resolved.push(tx);
                    } else if let Some(tx) = self.executor.resolve_transaction(txid).await {
                        resolved.push(tx);
                    } else {
                        anyhow::bail!("Could not resolve decided batch transaction {txid}");
                    }
                }
            }
        }
        Ok(resolved)
    }

    async fn process_block_event(&mut self, event: BlockEvent) -> Result<()> {
        match event {
            BlockEvent::BlockInsert {
                target_height,
                block,
            } => {
                let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid).collect();
                for txid in &txids {
                    self.consensus.pending_transactions.remove(txid);
                }
                info!("Block {}/{} {}", block.height, target_height, block.hash);

                info!(
                    block_height = block.height,
                    %block.hash,
                    pending_count = self.consensus.pending_blocks.len() + 1,
                    "Adding block to pending_blocks"
                );
                self.consensus
                    .pending_blocks
                    .insert(block.height, block.clone());
                self.drain_deferred_decisions()
                    .await
                    .context("drain_deferred_decisions failed after block insert")?;
                // A pending block may be what we're waiting to propose
                if self.consensus.pending_proposal.is_some() {
                    self.try_fulfill_pending_proposal()
                        .await
                        .context("try_fulfill_pending_proposal failed after block insert")?;
                }
            }
            BlockEvent::Rollback { to_height } => {
                info!(to_height, "Bitcoin rollback — truncating state");
                self.rollback(to_height)
                    .await
                    .context("rollback failed during Bitcoin reorg")?;
                self.consensus.clear_on_rollback();
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
            // Drain pending block events before entering select
            while let Ok(event) = self.block_rx.try_recv() {
                self.process_block_event(event)
                    .await
                    .context("process_block_event failed (try_recv drain)")?;
            }

            let hard_deadline_instant = self.consensus.pending_proposal.as_ref().map(|p| {
                let deadline = p.hard_deadline();
                let remaining = deadline.saturating_duration_since(Instant::now());
                tokio::time::Instant::now() + remaining
            });

            let simulate_rx = async {
                if let Some(rx) = self.simulate_rx.as_mut() {
                    rx.recv().await
                } else {
                    pending().await
                }
            };

            let consensus_rx = self.consensus.channels.consensus.recv();

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
                _ = self.cancel_token.cancelled() => {
                    info!("Cancelled");
                    break;
                }
                Some(event) = self.block_rx.recv() => {
                    self.process_block_event(event)
                        .await
                        .context("process_block_event failed")?;
                }
                Some(event) = self.mempool_rx.recv() => {
                    match event {
                        MempoolEvent::Sync { kontor_txs, fees, mempool_min_fee_sat_per_vb } => {
                            let kontor_count = kontor_txs.len();
                            let fee_count = fees.len();
                            self.consensus.pending_transactions.clear();
                            for (txid, tx) in kontor_txs {
                                self.consensus.pending_transactions.insert(
                                    txid,
                                    (tx.raw, tx.parsed),
                                );
                            }
                            self.consensus
                                .mempool_fee_index
                                .replace(fees, mempool_min_fee_sat_per_vb);
                            info!(
                                "MempoolSync: {} Kontor txs, {} fee entries, min fee {} sat/vB",
                                kontor_count, fee_count, mempool_min_fee_sat_per_vb
                            );
                            if self.consensus.pending_proposal.is_some() {
                                debounce_deadline = Some(tokio::time::Instant::now() + debounce_duration);
                            }
                        },
                        MempoolEvent::KontorTxAdded { txid, tx, fee } => {
                            self.consensus.pending_transactions.insert(txid, (tx.raw, tx.parsed));
                            self.consensus.mempool_fee_index.insert(txid, fee);
                            debug!("MempoolInsert (Kontor) {}", txid);
                            if self.consensus.pending_proposal.is_some() {
                                debounce_deadline = Some(tokio::time::Instant::now() + debounce_duration);
                            }
                        },
                        MempoolEvent::MempoolFeeSample { txid, fee } => {
                            self.consensus.mempool_fee_index.insert(txid, fee);
                            // No debounce reset — non-Kontor activity doesn't
                            // affect what we can propose.
                        },
                        MempoolEvent::Remove(txid) => {
                            self.consensus.pending_transactions.remove(&txid);
                            self.consensus.mempool_fee_index.remove(&txid);
                            debug!("MempoolRemove {}", txid);
                        },
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
                Some(msg) = consensus_rx => {
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
                    if let consensus_state::ConsensusResult::Block(block, decision) = consensus_result {
                        self.handle_block_with_decision(block, &decision)
                            .await
                            .context("handle_block_with_decision failed after consensus block")?;
                        self.drain_deferred_decisions()
                            .await
                            .context("drain_deferred_decisions failed after consensus block")?;
                        // Check finality after block execution — batch txids may now be confirmed
                        let conn = self.db_conn();
                        if self.consensus
                            .unfinalized_batches
                            .iter()
                            .any(|b| b.deadline <= self.last_height)
                            && let Some((rollback_anchor, excluded)) = self.consensus.run_finality_checks(&conn, self.last_height).await {
                                // Read replay decisions from DB before deleting state
                                self.initiate_rollback(
                                    rollback_anchor,
                                    excluded,
                                ).await
                                .context("initiate_rollback failed")?;

                                // Rollback to before the invalid anchor so all state at the
                                // anchor height (including invalid tx effects) is wiped cleanly.
                                self.rollback(rollback_anchor.saturating_sub(1))
                                    .await
                                    .context("rollback failed during finality rollback")?;

                                // Emit rollback event
                                let checkpoint = self.consensus.get_checkpoint(&conn).await;
                                self.consensus.emit_state_event(StateEvent::RollbackExecuted {
                                    to_anchor: rollback_anchor,
                                    entries_removed: 0,
                                    checkpoint,
                                });

                                // Process deferred decisions using already-cached blocks
                                self.drain_deferred_decisions()
                                    .await
                                    .context("drain_deferred_decisions failed after finality rollback")?;
                            }
                    }
                    // Yield to allow other channels (block_rx, mempool_rx) to be polled
                    tokio::task::yield_now().await;
                }
                option_event = simulate_rx => {
                    if let Some((tx, ret_tx)) = option_event {
                        let result = self.simulate(tx).await;
                        let err_msg = result.as_ref().err().map(|e| format!("{e:#}"));
                        let _ = ret_tx.send(result);
                        if let Some(msg) = err_msg {
                            bail!("simulation failed: {msg}");
                        }
                    }
                }
                _ = fee_publish_ticker.tick() => {
                    if self.consensus.mempool_fee_index.take_dirty() {
                        let fees = self.consensus.mempool_fee_index.recompute();
                        if let Some(tx) = self.fee_tx.as_ref() {
                            // watch::Sender::send only errors when all
                            // receivers have dropped — fine for the
                            // reactor to keep running.
                            let _ = tx.send(fees);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(node = %self.runtime.node_label))]
    pub async fn run(&mut self) -> Result<()> {
        let result = self.run_event_loop().await;

        // Gracefully stop the Malachite consensus engine and wait for cleanup
        let _ = self
            .consensus
            .engine_handle
            .actor
            .get_cell()
            .stop_and_wait(Some("Reactor shutting down".to_string()), None)
            .await;

        result
    }
}

/// Query the staking contract and build a ValidatorSet from the active validators.
async fn build_validator_set(runtime: &mut Runtime) -> Result<ValidatorSet> {
    let active_set = get_active_set(runtime)
        .await
        .context("Failed to query active validator set from staking contract")?;

    let validators: Vec<Validator> = active_set
        .into_iter()
        .map(|v| {
            anyhow::ensure!(
                v.ed25519_pubkey.len() == 32,
                "Validator {} has invalid ed25519 pubkey length {}",
                v.x_only_pubkey,
                v.ed25519_pubkey.len()
            );
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&v.ed25519_pubkey);
            let public_key = PublicKey::from_bytes(key_bytes);
            let voting_power = stake_to_voting_power(v.stake)
                .with_context(|| format!("Invalid stake for validator {}", v.x_only_pubkey))?;
            Ok(Validator::new(public_key, voting_power))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ValidatorSet::new(validators))
}

fn stake_to_voting_power(stake: Decimal) -> Result<VotingPower> {
    let s = decimal_to_string(stake);
    let integer_part = s
        .split('.')
        .next()
        .context("decimal string missing integer part")?;
    let power = integer_part
        .parse::<u64>()
        .context("stake integer part is not a valid u64")?;
    Ok(power)
}

/// Build a Genesis from the staking contract's active validator set.
async fn build_genesis_from_staking(runtime: &mut Runtime) -> Result<Genesis> {
    let validator_set = build_validator_set(runtime).await?;
    Ok(Genesis { validator_set })
}

pub async fn create_runtime_executor(
    starting_block_height: u64,
    writer: &database::Writer,
    cancel_token: CancellationToken,
    bitcoin_client: crate::bitcoin_client::Client,
    replay_tx: Option<mpsc::Sender<u64>>,
    genesis_validators: &[crate::runtime::GenesisValidator],
) -> Result<(executor::RuntimeExecutor, Runtime, u64, Option<BlockHash>)> {
    let conn = writer.connection();
    let (last_height, last_hash) = match select_block_latest(&conn)
        .await
        .context("Failed to query latest block during startup")?
    {
        Some(block) => {
            let block_height = block.height as u64;
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
    let storage = Storage::builder()
        .height(0)
        .conn(writer.connection())
        .build();

    let mut runtime = Runtime::new(ComponentCache::new(), storage)
        .await
        .context("Failed to initialize runtime")?;
    runtime
        .publish_native_contracts(genesis_validators)
        .await
        .context("Failed to publish native contracts")?;

    let mut exec = executor::RuntimeExecutor::new(cancel_token, bitcoin_client);
    if let Some(tx) = replay_tx {
        exec = exec.with_replay_tx(tx);
    }

    Ok((exec, runtime, last_height, last_hash))
}

pub async fn start_consensus(
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
        runtime.get_storage_conn(),
        engine_output.signing_provider,
        genesis,
        engine_output.address,
        last_block_height,
        engine_output.channels,
        engine_output._handle,
        validator_index,
        mempool_fee_index,
    )
    .await;
    state.observation = observation_channels;
    if let Some(t) = timeouts {
        state.timeouts = t;
    }

    Ok(state)
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    starting_block_height: u64,
    cancel_token: CancellationToken,
    writer: database::Writer,
    block_rx: Receiver<BlockEvent>,
    mempool_rx: Receiver<MempoolEvent>,
    ready_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
    simulate_rx: Option<Receiver<Simulation>>,
    engine_config: engine::EngineConfig,
    bitcoin_client: crate::bitcoin_client::Client,
    replay_tx: Option<mpsc::Sender<u64>>,
    genesis_validators: Vec<crate::runtime::GenesisValidator>,
    observation_channels: Option<consensus_state::ObservationChannels>,
    consensus_propose_timeout_ms: Option<u64>,
    fee_tx: Option<tokio::sync::watch::Sender<Fees>>,
) -> JoinHandle<()> {
    tokio::spawn({
        async move {
            let result: Result<()> = async {
                let (exec, mut runtime, last_height, last_hash) = create_runtime_executor(
                    starting_block_height,
                    &writer,
                    cancel_token.clone(),
                    bitcoin_client,
                    replay_tx,
                    &genesis_validators,
                )
                .await
                .context("create_runtime_executor failed")?;

                let timeouts = consensus_propose_timeout_ms.map(|ms| LinearTimeouts {
                    propose: std::time::Duration::from_millis(ms),
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
                let mut fee_index = mempool_fee_index::MempoolFeeIndex::new();
                info!("Waiting for initial mempool sync before starting consensus");
                // Periodic log so operators can tell the wait isn't a deadlock
                // when bitcoind is slow to reach handshake.
                let mut log_ticker = tokio::time::interval(std::time::Duration::from_secs(30));
                log_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                log_ticker.tick().await; // consume the immediate first tick
                let initial_kontor_txs = loop {
                    select! {
                        event = mempool_rx.recv() => match event {
                            Some(MempoolEvent::Sync {
                                kontor_txs,
                                fees,
                                mempool_min_fee_sat_per_vb,
                            }) => {
                                fee_index.replace(fees, mempool_min_fee_sat_per_vb);
                                info!(
                                    "Initial mempool sync complete: {} Kontor txs, {} fee entries",
                                    kontor_txs.len(),
                                    fee_index.len()
                                );
                                break kontor_txs;
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
                        _ = cancel_token.cancelled() => {
                            return Ok(());
                        }
                    }
                };

                // Compute and publish the first projection from the
                // freshly-synced index, *before* anything signals
                // readiness. Establishes the invariant: by the time
                // `available = true`, the watch channel carries a
                // projection derived from real bitcoind data — never
                // the `Fees::floor(1)` placeholder. `take_dirty()`
                // clears the flag so the first 2s tick doesn't
                // immediately re-do the same compute.
                let initial_fees = fee_index.recompute();
                let _ = fee_index.take_dirty();
                if let Some(tx) = fee_tx.as_ref() {
                    let _ = tx.send(initial_fees);
                }

                let mut consensus = start_consensus(
                    engine_config,
                    &mut runtime,
                    observation_channels,
                    timeouts,
                    last_height,
                    fee_index,
                )
                .await
                .context("start_consensus failed")?;

                // Seed pending_transactions with the Kontor txs captured
                // from the initial Sync.
                for (txid, tx) in initial_kontor_txs {
                    consensus
                        .pending_transactions
                        .insert(txid, (tx.raw, tx.parsed));
                }

                let mut reactor = Reactor::new(
                    exec,
                    runtime,
                    block_rx,
                    mempool_rx,
                    cancel_token.clone(),
                    ready_tx,
                    event_tx,
                    simulate_rx,
                    consensus,
                    last_height,
                    last_hash,
                    fee_tx,
                );

                reactor.run().await
            }
            .await;

            if let Err(e) = result {
                error!("Reactor error: {e:#}, exiting");
                cancel_token.cancel();
            }

            info!("Exited");
        }
    })
}
