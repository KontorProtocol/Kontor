pub mod block_handler;
pub mod consensus;
pub mod engine;
pub mod executor;
#[cfg(test)]
pub(crate) mod lite_executor;
pub mod mock_bitcoin;
#[cfg(test)]
mod reactor_cluster_tests;
pub mod types;

use anyhow::{Result, bail};
use futures_util::future::pending;
use indexer_types::{Block, BlockRow, Event, OpWithResult};
use tokio::{
    select,
    sync::{
        mpsc::{self, Receiver},
        oneshot,
    },
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};
use malachitebft_app_channel::Channels;
use malachitebft_app_channel::app::types::core::VotingPower;
use malachitebft_core_types::LinearTimeouts;
use tracing::{debug, error, info, warn};

use crate::consensus::finality_types::StateEvent;
use crate::{
    bitcoin_follower::event::{BlockEvent, MempoolEvent},
    consensus::{Ctx, Genesis, Validator, ValidatorSet, signing::PublicKey},
    database::{
        self,
        queries::{
            confirm_transaction, get_transaction_by_txid, insert_batch, insert_block,
            insert_transaction, rollback_to_height, select_block_at_height, select_block_latest,
            select_unconfirmed_batch_tx,
        },
    },
    runtime::{
        ComponentCache, Decimal, Runtime, Storage,
        filestorage::api::{expire_challenges, generate_challenges_for_block},
        numerics::decimal_to_string,
        staking::api::{get_active_set, process_pending_validators},
        wit::Signer,
    },
    test_utils::new_mock_block_hash,
};

pub use block_handler::{block_handler, simulate_handler};
use executor::Executor;

pub type Simulation = (
    bitcoin::Transaction,
    oneshot::Sender<Result<Vec<OpWithResult>>>,
);

/// Handle to the Malachite engine + consensus state, present only when consensus is configured.
pub struct ConsensusHandle {
    pub state: consensus::ConsensusState,
    pub channels: Channels<Ctx>,
    pub _engine_handle: malachitebft_app_channel::EngineHandle,
    pub validator_index: Option<usize>,
}

pub struct ReactorCaches {
    pub mempool: std::collections::HashMap<Txid, bitcoin::Transaction>,
}

impl ReactorCaches {
    pub fn new() -> Self {
        Self {
            mempool: std::collections::HashMap::new(),
        }
    }

    pub fn remove_confirmed_txids(&mut self, txids: &[Txid]) {
        for txid in txids {
            self.mempool.remove(txid);
        }
    }

    pub fn track_mempool_insert(&mut self, tx: bitcoin::Transaction) {
        self.mempool.insert(tx.compute_txid(), tx);
    }

    pub fn track_mempool_remove(&mut self, txid: &Txid) {
        self.mempool.remove(txid);
    }

    pub fn track_mempool_sync(&mut self, txs: impl Iterator<Item = bitcoin::Transaction>) {
        self.mempool.clear();
        for tx in txs {
            self.mempool.insert(tx.compute_txid(), tx);
        }
    }
}

pub struct Reactor<E: Executor> {
    executor: E,
    runtime: Runtime,
    cancel_token: CancellationToken,
    block_rx: Receiver<BlockEvent>,
    mempool_rx: Receiver<MempoolEvent>,
    ready_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
    simulate_rx: Option<Receiver<Simulation>>,
    caches: ReactorCaches,
    consensus_handle: Option<ConsensusHandle>,

    last_height: u64,
    last_hash: Option<BlockHash>,
}

impl<E: Executor> Reactor<E> {
    pub fn new(
        executor: E,
        runtime: Runtime,
        block_rx: Receiver<BlockEvent>,
        mempool_rx: Receiver<MempoolEvent>,
        cancel_token: CancellationToken,
        ready_tx: Option<oneshot::Sender<bool>>,
        event_tx: Option<mpsc::Sender<Event>>,
        simulate_rx: Option<Receiver<Simulation>>,
        consensus_handle: Option<ConsensusHandle>,
        last_height: u64,
        last_hash: Option<BlockHash>,
    ) -> Self {
        let mut runtime = runtime;
        if let Some(handle) = &consensus_handle {
            runtime.node_label = handle
                .validator_index
                .map(|i| format!("node_{i}"))
                .unwrap_or_else(|| "follower".to_string());
        }
        Self {
            executor,
            runtime,
            cancel_token,
            block_rx,
            mempool_rx,
            simulate_rx,
            caches: ReactorCaches::new(),
            last_height,
            last_hash,
            ready_tx,
            event_tx,
            consensus_handle,
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

    async fn rollback(&mut self, height: u64) -> Result<()> {
        rollback_to_height(&self.db_conn(), height).await?;
        if let Err(e) = self
            .runtime
            .file_ledger
            .force_resync_from_db(&self.runtime.storage.conn)
            .await
        {
            error!("file_ledger resync after rollback failed: {e}");
        }
        self.last_height = height;

        if let Ok(Some(row)) = select_block_at_height(&self.db_conn(), height as i64).await {
            self.last_hash = Some(row.hash);
            info!("Rollback to height {} ({})", height, row.hash);
        } else {
            self.last_hash = None;
            warn!("Rollback to height {}, no previous block found", height);
        }

        // Refresh cached validator set — rolled-back state may have different active set
        if let Some(handle) = &mut self.consensus_handle
            && let Ok(vs) = build_validator_set(&mut self.runtime).await
        {
            handle.validator_index = vs
                .validators
                .iter()
                .position(|v| v.address == handle.state.address);
            handle.state.cached_validator_set = vs;
        }

        if let Some(tx) = &self.event_tx {
            let _ = tx.send(Event::Rolledback { height }).await;
        }

        Ok(())
    }

    /// Run block lifecycle operations: challenge expiry/generation and epoch transitions.
    async fn run_block_lifecycle(&mut self, block: &Block) {
        let core_signer = Signer::Core(Box::new(Signer::Nobody));
        let block_hash: Vec<u8> = block.hash.to_byte_array().to_vec();
        self.runtime
            .set_context(block.height as i64, None, None, None)
            .await;
        expire_challenges(&mut self.runtime, &core_signer, block.height)
            .await
            .expect("Failed to expire challenges");
        let challenges = generate_challenges_for_block(
            &mut self.runtime,
            &core_signer,
            block.height,
            block_hash,
        )
        .await
        .expect("Failed to generate challenges");
        if !challenges.is_empty() {
            info!(
                "Generated {} challenges at block height {}",
                challenges.len(),
                block.height
            );
        }

        let change = process_pending_validators(&mut self.runtime, &core_signer, block.height)
            .await
            .expect("Failed to call process_pending_validators")
            .expect("process_pending_validators returned error");
        if change.activated > 0 || change.deactivated > 0 {
            info!(
                "Validator set change at height {}: {} activated, {} deactivated",
                block.height, change.activated, change.deactivated
            );
        }
    }

    async fn handle_block_with_decision(
        &mut self,
        block: Block,
        decision: &consensus::DeferredDecision,
    ) -> Result<()> {
        if let Err(e) = insert_batch(
            &self.db_conn(),
            decision.consensus_height.as_u64() as i64,
            block.height as i64,
            &block.hash.to_string(),
            &decision.certificate,
            true,
        )
        .await
        {
            error!("insert_batch (block) error: {e}");
        }
        self.handle_block(block).await
    }

    async fn handle_block(&mut self, block: Block) -> Result<()> {
        let height = block.height;
        let hash = block.hash;
        let prev_hash = block.prev_hash;
        if height != self.last_height + 1 {
            bail!(
                "Unexpected block height {}, expected {}",
                height,
                self.last_height + 1
            );
        }

        if let Some(last_hash) = self.last_hash {
            if prev_hash != last_hash {
                bail!(
                    "Block at height {} has prev_hash {} but expected {}",
                    height,
                    prev_hash,
                    last_hash
                );
            }
        } else {
            info!(
                "Initial block received at height {} (hash {})",
                height, hash
            );
        }

        self.last_height = height;
        self.last_hash = Some(hash);

        self.runtime
            .storage
            .savepoint()
            .await
            .expect("Failed to begin block transaction");

        let _ = insert_block(
            &self.db_conn(),
            BlockRow::builder()
                .height(block.height as i64)
                .hash(block.hash)
                .relevant(!block.transactions.is_empty())
                .build(),
        )
        .await;

        let mut unbatched_count = 0;
        for (i, t) in block.transactions.iter().enumerate() {
            if let Ok(Some(_)) = get_transaction_by_txid(&self.db_conn(), &t.txid.to_string()).await
            {
                let _ = confirm_transaction(
                    &self.db_conn(),
                    &t.txid.to_string(),
                    block.height as i64,
                    i as i64,
                )
                .await;
                continue;
            }

            unbatched_count += 1;
            let tx_id = match insert_transaction(
                &self.db_conn(),
                indexer_types::TransactionRow::builder()
                    .height(block.height as i64)
                    .tx_index(i as i64)
                    .confirmed_height(block.height as i64)
                    .txid(t.txid.to_string())
                    .build(),
            )
            .await
            {
                Ok(id) => id,
                Err(e) => {
                    error!("insert_transaction error: {e}");
                    continue;
                }
            };

            self.executor
                .execute_transaction(&mut self.runtime, block.height as i64, tx_id, t)
                .await;
        }

        self.run_block_lifecycle(&block).await;

        self.runtime
            .storage
            .commit()
            .await
            .expect("Failed to commit block transaction");

        if let Some(handle) = &mut self.consensus_handle {
            // Update cached validator set after block execution
            // (process_pending_validators may have activated/deactivated validators)
            if let Ok(vs) = build_validator_set(&mut self.runtime).await {
                handle.validator_index = vs
                    .validators
                    .iter()
                    .position(|v| v.address == handle.state.address);
                handle.state.cached_validator_set = vs;
            }

            let checkpoint = handle.state.get_checkpoint().await;
            handle.state.emit_state_event(StateEvent::BlockProcessed {
                height,
                unbatched_count,
                checkpoint,
            });
        }

        if let Some(tx) = &self.event_tx {
            let txids = block
                .transactions
                .iter()
                .map(|t| t.txid.to_string())
                .collect();
            let _ = tx
                .send(Event::Processed {
                    block: (&block).into(),
                    txids,
                })
                .await;
        }
        info!("Block processed (unbatched_count={unbatched_count})");

        Ok(())
    }

    async fn drain_deferred_decisions(&mut self) -> Result<()> {
        if self.consensus_handle.is_none() {
            return Ok(());
        }

        loop {
            let handle = self.consensus_handle.as_mut().unwrap();
            let Some(decision) = handle.state.deferred_decisions.pop_front() else {
                break;
            };

            match &decision.value {
                crate::consensus::Value::Block { height: bh, .. } => {
                    let bh = *bh;
                    let block = {
                        let handle = self.consensus_handle.as_mut().unwrap();
                        handle.state.pending_blocks.remove(&bh)
                    };
                    if let Some(block) = block {
                        self.handle_block_with_decision(block, &decision).await?;
                    } else {
                        // Block data not yet available — put back and stop
                        let handle = self.consensus_handle.as_mut().unwrap();
                        handle.state.deferred_decisions.push_front(decision);
                        break;
                    }
                }
                crate::consensus::Value::Batch {
                    anchor_height,
                    anchor_hash,
                    txs,
                    ..
                } => {
                    if *anchor_height <= self.last_height {
                        let anchor_height = *anchor_height;
                        let anchor_hash = *anchor_hash;
                        let mut resolved_txs = Vec::with_capacity(txs.len());
                        for tx in txs {
                            match tx {
                                crate::consensus::BatchTx::Raw(raw) => {
                                    resolved_txs.push(raw.clone());
                                }
                                crate::consensus::BatchTx::Id(txid) => {
                                    if let Some(tx) = self.caches.mempool.get(txid) {
                                        resolved_txs.push(tx.clone());
                                    } else if let Some(tx) =
                                        Self::resolve_tx_from_db(&self.db_conn(), txid).await
                                    {
                                        resolved_txs.push(tx);
                                    } else if let Some(tx) =
                                        self.executor.resolve_transaction(txid).await
                                    {
                                        resolved_txs.push(tx);
                                    } else {
                                        warn!(%txid, "Could not resolve txid during deferred execution — skipping");
                                    }
                                }
                            }
                        }
                        let handle = self.consensus_handle.as_mut().unwrap();
                        handle
                            .state
                            .process_decided_batch(
                                &self.executor,
                                &mut self.runtime,
                                anchor_height,
                                anchor_hash,
                                decision.consensus_height,
                                &decision.certificate,
                                &resolved_txs,
                            )
                            .await;
                        if let Some(tx) = &self.event_tx {
                            let txids: Vec<String> = resolved_txs
                                .iter()
                                .map(|tx| tx.compute_txid().to_string())
                                .collect();
                            let _ = tx.send(Event::BatchProcessed { txids }).await;
                        }
                    } else {
                        // Anchor not yet processed — put back and stop
                        let handle = self.consensus_handle.as_mut().unwrap();
                        handle.state.deferred_decisions.push_front(decision);
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    async fn process_block_event(&mut self, event: BlockEvent) -> Result<()> {
        match event {
            BlockEvent::BlockInsert {
                target_height,
                block,
            } => {
                let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid).collect();
                self.caches.remove_confirmed_txids(&txids);
                info!("Block {}/{} {}", block.height, target_height, block.hash);

                if let Some(handle) = self.consensus_handle.as_mut() {
                    handle
                        .state
                        .pending_blocks
                        .insert(block.height, block.clone());
                    self.drain_deferred_decisions().await?;
                } else {
                    self.handle_block(block).await?;
                }
            }
            BlockEvent::Rollback { to_height } => {
                info!(to_height, "Bitcoin rollback — truncating state");
                self.rollback(to_height).await?;
                if let Some(handle) = &mut self.consensus_handle {
                    handle.state.clear_on_rollback();
                    let checkpoint = handle.state.get_checkpoint().await;
                    handle.state.emit_state_event(StateEvent::RollbackExecuted {
                        to_anchor: to_height,
                        entries_removed: 0,
                        checkpoint,
                    });
                }
            }
        }
        Ok(())
    }

    async fn run_event_loop(&mut self) -> Result<()> {
        self.ready_tx.take().map(|tx| tx.send(true));

        loop {
            // Drain pending block events before entering select
            while let Ok(event) = self.block_rx.try_recv() {
                self.process_block_event(event).await?;
            }

            let simulate_rx = async {
                if let Some(rx) = self.simulate_rx.as_mut() {
                    rx.recv().await
                } else {
                    pending().await
                }
            };

            let consensus_rx = async {
                if let Some(handle) = self.consensus_handle.as_mut() {
                    handle.channels.consensus.recv().await
                } else {
                    pending().await
                }
            };

            select! {
                _ = self.cancel_token.cancelled() => {
                    info!("Cancelled");
                    break;
                }
                Some(event) = self.block_rx.recv() => {
                    self.process_block_event(event).await?;
                }
                Some(event) = self.mempool_rx.recv() => {
                    match event {
                        MempoolEvent::Sync(txs) => {
                            let count = txs.len();
                            self.caches.track_mempool_sync(txs.into_iter());
                            info!("MempoolSync {}", count);
                        },
                        MempoolEvent::Insert(tx) => {
                            let txid = tx.compute_txid();
                            self.caches.track_mempool_insert(tx);
                            debug!("MempoolInsert {}", txid);
                        },
                        MempoolEvent::Remove(txid) => {
                            self.caches.track_mempool_remove(&txid);
                            debug!("MempoolRemove {}", txid);
                        },
                    }
                }
                Some(msg) = consensus_rx => {
                    debug!("REACTOR: processing consensus msg");
                    let handle = self.consensus_handle.as_mut().unwrap();
                    let validator_index = handle.validator_index;
                    let consensus_result = consensus::handle_consensus_msg(
                        &mut handle.state,
                        &self.executor,
                        &mut self.runtime,
                        &mut self.caches,
                        &mut handle.channels,
                        msg,
                        validator_index,
                        self.last_height,
                        self.last_hash.unwrap_or(BlockHash::all_zeros()),
                    ).await?;
                    if let consensus::ConsensusResult::BatchProcessed { txids } = &consensus_result
                        && let Some(tx) = &self.event_tx
                    {
                        let _ = tx
                            .send(Event::BatchProcessed {
                                txids: txids.clone(),
                            })
                            .await;
                    }
                    if let consensus::ConsensusResult::Block(block, decision) = consensus_result {
                        self.handle_block_with_decision(block, &decision).await?;
                        self.drain_deferred_decisions().await?;
                        // Check finality after block execution — batch txids may now be confirmed
                        let handle = self.consensus_handle.as_mut().unwrap();
                        if handle.state
                            .pending_batches
                            .iter()
                            .any(|b| b.deadline <= self.last_height)
                            && let Some((rollback_anchor, excluded)) = handle.state.run_finality_checks(self.last_height).await {
                                // Read replay decisions from DB before deleting state
                                let handle = self.consensus_handle.as_mut().unwrap();
                                handle.state.initiate_rollback(
                                    &mut self.executor,
                                    rollback_anchor,
                                    excluded,
                                ).await;

                                // Rollback to before the invalid anchor so all state at the
                                // anchor height (including invalid tx effects) is wiped cleanly.
                                self.rollback(rollback_anchor - 1).await?;

                                // Emit rollback event
                                let handle = self.consensus_handle.as_mut().unwrap();
                                let checkpoint = handle.state.get_checkpoint().await;
                                handle.state.emit_state_event(StateEvent::RollbackExecuted {
                                    to_anchor: rollback_anchor,
                                    entries_removed: 0,
                                    checkpoint,
                                });

                                // Process deferred decisions using already-cached blocks
                                self.drain_deferred_decisions().await?;
                            }
                    }
                    // Yield to allow other channels (block_rx, mempool_rx) to be polled
                    tokio::task::yield_now().await;
                }
                option_event = simulate_rx => {
                    if let Some((btx, ret_tx)) = option_event {
                        let _ = ret_tx.send(
                            simulate_handler(&mut self.runtime, btx).await
                        );
                    }
                }

            }
        }
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        self.run_event_loop().await
    }
}

/// Query the staking contract and build a ValidatorSet from the active validators.
async fn build_validator_set(runtime: &mut Runtime) -> Result<ValidatorSet> {
    let active_set = get_active_set(runtime).await?;

    let validators: Vec<Validator> = active_set
        .into_iter()
        .filter_map(|v| {
            if v.ed25519_pubkey.len() != 32 {
                warn!(
                    xonly = v.x_only_pubkey,
                    "Skipping validator with invalid ed25519 pubkey length"
                );
                return None;
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&v.ed25519_pubkey);
            let public_key = PublicKey::from_bytes(key_bytes);
            let voting_power = stake_to_voting_power(v.stake);
            Some(Validator::new(public_key, voting_power))
        })
        .collect();

    Ok(ValidatorSet::new(validators))
}

fn stake_to_voting_power(stake: Decimal) -> VotingPower {
    let s = decimal_to_string(stake);
    s.split('.')
        .next()
        .expect("decimal string should have integer part")
        .parse::<u64>()
        .expect("stake should be a valid u64")
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
    bitcoin_client: Option<&crate::bitcoin_client::Client>,
    replay_tx: Option<mpsc::Sender<u64>>,
    genesis_validators: &[crate::runtime::GenesisValidator],
) -> Result<(executor::RuntimeExecutor, Runtime, u64, Option<BlockHash>)> {
    let conn = writer.connection();
    let (last_height, last_hash) = match select_block_latest(&conn).await? {
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
        .expect("Failed to select block at height 0")
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
        .await?;
    }
    let storage = Storage::builder()
        .height(0)
        .conn(writer.connection())
        .build();

    let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
    runtime.publish_native_contracts(genesis_validators).await?;

    let mut exec = executor::RuntimeExecutor::new(cancel_token);

    if let Some(client) = bitcoin_client {
        exec = exec.with_bitcoin_client(client.clone());
    }
    if let Some(tx) = replay_tx {
        exec = exec.with_replay_tx(tx);
    }

    Ok((exec, runtime, last_height, last_hash))
}

pub async fn start_consensus(
    engine_config: engine::EngineConfig,
    runtime: &mut Runtime,
    observation_channels: Option<consensus::ObservationChannels>,
    timeouts: Option<LinearTimeouts>,
) -> Result<ConsensusHandle> {
    let genesis = build_genesis_from_staking(runtime).await?;

    let engine_output = engine::start(engine_config, &genesis).await?;
    info!(address = %engine_output.address, "Consensus engine started");

    let validator_index = genesis
        .validator_set
        .validators
        .iter()
        .position(|v| v.address == engine_output.address);

    let mut state = consensus::ConsensusState::new(
        runtime.get_storage_conn(),
        engine_output.signing_provider,
        genesis,
        engine_output.address,
    );
    state.observation = observation_channels;
    if let Some(t) = timeouts {
        state.timeouts = t;
    }

    Ok(ConsensusHandle {
        state,
        channels: engine_output.channels,
        _engine_handle: engine_output._handle,
        validator_index,
    })
}

pub fn run(
    starting_block_height: u64,
    cancel_token: CancellationToken,
    writer: database::Writer,
    block_rx: Receiver<BlockEvent>,
    mempool_rx: Receiver<MempoolEvent>,
    ready_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
    simulate_rx: Option<Receiver<Simulation>>,
    engine_config: Option<engine::EngineConfig>,
    bitcoin_client: Option<crate::bitcoin_client::Client>,
    replay_tx: Option<mpsc::Sender<u64>>,
    genesis_validators: Vec<crate::runtime::GenesisValidator>,
    observation_channels: Option<consensus::ObservationChannels>,
    consensus_propose_timeout_ms: Option<u64>,
) -> JoinHandle<()> {
    tokio::spawn({
        async move {
            let result: Result<()> = async {
                let (exec, mut runtime, last_height, last_hash) = create_runtime_executor(
                    starting_block_height,
                    &writer,
                    cancel_token.clone(),
                    bitcoin_client.as_ref(),
                    replay_tx,
                    &genesis_validators,
                )
                .await?;

                let timeouts = consensus_propose_timeout_ms.map(|ms| LinearTimeouts {
                    propose: std::time::Duration::from_millis(ms),
                    ..LinearTimeouts::default()
                });
                let consensus_handle = if let Some(engine_cfg) = engine_config {
                    Some(
                        start_consensus(engine_cfg, &mut runtime, observation_channels, timeouts)
                            .await?,
                    )
                } else {
                    None
                };

                let mut reactor = Reactor::new(
                    exec,
                    runtime,
                    block_rx,
                    mempool_rx,
                    cancel_token.clone(),
                    ready_tx,
                    event_tx,
                    simulate_rx,
                    consensus_handle,
                    last_height,
                    last_hash,
                );

                reactor.run().await
            }
            .await;

            if let Err(e) = result {
                error!("Reactor error: {}, exiting", e);
                cancel_token.cancel();
            }

            info!("Exited");
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        bitcoin_follower::event::BlockEvent,
        bls::{
            KONTOR_BLS_DST, RegistrationProof, bls_derivation_path, derive_bls_secret_key_eip2333,
            taproot_derivation_path,
        },
        database::queries,
        reactor,
        reg_tester::derive_taproot_keypair_from_seed,
        test_utils::{gen_random_blocks, new_mock_block_hash, new_random_blockchain, new_test_db},
    };
    use anyhow::Result;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, Network, OutPoint, Txid};
    use indexer_types::{AggregateInfo, Event, Inst, Insts, Signer, Transaction, TransactionInput};
    use indexmap::IndexMap;
    use libsql::params;
    use tokio::sync::mpsc;
    use tokio::time::{Duration, sleep};
    use tokio_util::sync::CancellationToken;

    async fn await_block_hash(conn: &libsql::Connection, height: i64, hash: BlockHash) {
        loop {
            if let Ok(Some(block)) = queries::select_block_at_height(conn, height).await
                && block.hash == hash
            {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    async fn send_block_and_wait(
        tx: &mpsc::Sender<BlockEvent>,
        conn: &libsql::Connection,
        block: &indexer_types::Block,
        target_height: u64,
    ) {
        let hash = block.hash;
        let height = block.height as i64;
        tx.send(BlockEvent::BlockInsert {
            target_height,
            block: block.clone(),
        })
        .await
        .unwrap();
        await_block_hash(conn, height, hash).await;
    }

    #[tokio::test]
    async fn test_reactor_fetching() -> Result<()> {
        let cancel_token = CancellationToken::new();
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = &writer.connection();

        let blocks = new_random_blockchain(5);

        let (event_tx, block_rx) = mpsc::channel(10);
        let (_mempool_tx, mempool_rx) = mpsc::channel(10);
        let handle = reactor::run(
            1,
            cancel_token.clone(),
            writer,
            block_rx,
            mempool_rx,
            None,
            None,
            None,
            None,
            None,
            None,
            vec![],
            None,
            None,
        );

        let target = 5;
        for block in &blocks {
            send_block_and_wait(&event_tx, conn, block, target).await;
        }

        for (i, expected) in blocks.iter().enumerate() {
            let block = queries::select_block_at_height(conn, (i + 1) as i64)
                .await?
                .unwrap();
            assert_eq!(block.hash, expected.hash);
        }

        cancel_token.cancel();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn test_reactor_rollback_and_reinsert() -> Result<()> {
        let cancel_token = CancellationToken::new();
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = &writer.connection();

        let blocks = new_random_blockchain(3);

        let (event_tx, block_rx) = mpsc::channel(10);
        let (_mempool_tx, mempool_rx) = mpsc::channel(10);
        let handle = reactor::run(
            1,
            cancel_token.clone(),
            writer,
            block_rx,
            mempool_rx,
            None,
            None,
            None,
            None,
            None,
            None,
            vec![],
            None,
            None,
        );

        // Insert blocks 1-3
        let target = 3;
        for block in &blocks {
            send_block_and_wait(&event_tx, conn, block, target).await;
        }

        let initial_block_3_hash = blocks[2].hash;

        // Rollback to height 2 (remove block 3), then insert new blocks 3-5
        event_tx.send(BlockEvent::Rollback { to_height: 2 }).await?;

        let new_blocks = gen_random_blocks(2, 5, Some(blocks[1].hash));
        let target = 5;
        for block in &new_blocks {
            send_block_and_wait(&event_tx, conn, block, target).await;
        }

        // Block 3 should have a different hash now
        let block = queries::select_block_at_height(conn, 3).await?.unwrap();
        assert_eq!(block.hash, new_blocks[0].hash);
        assert_ne!(block.hash, initial_block_3_hash);

        // Blocks 4-5 should exist with new hashes
        let block = queries::select_block_at_height(conn, 5).await?.unwrap();
        assert_eq!(block.hash, new_blocks[2].hash);

        cancel_token.cancel();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn test_reactor_deep_rollback() -> Result<()> {
        let cancel_token = CancellationToken::new();
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = &writer.connection();

        let blocks = new_random_blockchain(4);

        let (event_tx, block_rx) = mpsc::channel(10);
        let (_mempool_tx, mempool_rx) = mpsc::channel(10);
        let handle = reactor::run(
            1,
            cancel_token.clone(),
            writer,
            block_rx,
            mempool_rx,
            None,
            None,
            None,
            None,
            None,
            None,
            vec![],
            None,
            None,
        );

        // Insert blocks 1-4
        let target = 4;
        for block in &blocks {
            send_block_and_wait(&event_tx, conn, block, target).await;
        }

        // Roll back to height 1 (remove blocks 2-4)
        event_tx.send(BlockEvent::Rollback { to_height: 1 }).await?;

        // Insert new chain from block 1
        let new_blocks = gen_random_blocks(1, 4, Some(blocks[0].hash));
        let target = 4;
        for block in &new_blocks {
            send_block_and_wait(&event_tx, conn, block, target).await;
        }

        // Block 1 should be preserved
        let block = queries::select_block_at_height(conn, 1).await?.unwrap();
        assert_eq!(block.hash, blocks[0].hash);

        // Block 2 should have new hash
        let block = queries::select_block_at_height(conn, 2).await?.unwrap();
        assert_eq!(block.hash, new_blocks[0].hash);

        cancel_token.cancel();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn test_reactor_rollback_then_extend() -> Result<()> {
        let cancel_token = CancellationToken::new();
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = &writer.connection();

        let blocks = new_random_blockchain(2);

        let (event_tx, block_rx) = mpsc::channel(10);
        let (_mempool_tx, mempool_rx) = mpsc::channel(10);
        let handle = reactor::run(
            1,
            cancel_token.clone(),
            writer,
            block_rx,
            mempool_rx,
            None,
            None,
            None,
            None,
            None,
            None,
            vec![],
            None,
            None,
        );

        // Insert blocks 1-2
        let target = 2;
        for block in &blocks {
            send_block_and_wait(&event_tx, conn, block, target).await;
        }

        // Extend with blocks 3-4
        let more_blocks = gen_random_blocks(2, 4, Some(blocks[1].hash));
        let target = 4;
        for block in &more_blocks {
            send_block_and_wait(&event_tx, conn, block, target).await;
        }

        let block = queries::select_block_at_height(conn, 4).await?.unwrap();
        assert_eq!(block.hash, more_blocks[1].hash);

        // Roll back to height 1, insert entirely new chain
        event_tx.send(BlockEvent::Rollback { to_height: 1 }).await?;

        let new_blocks = gen_random_blocks(1, 4, Some(blocks[0].hash));
        let target = 4;
        for block in &new_blocks {
            send_block_and_wait(&event_tx, conn, block, target).await;
        }

        // Verify block 2 has new hash
        let block = queries::select_block_at_height(conn, 2).await?.unwrap();
        assert_eq!(block.hash, new_blocks[0].hash);

        // Verify block 4 has new hash
        let block = queries::select_block_at_height(conn, 4).await?.unwrap();
        assert_eq!(block.hash, new_blocks[2].hash);

        cancel_token.cancel();
        let _ = handle.await;
        Ok(())
    }

    /// Sends a block through the reactor's event channel and waits for the
    /// `Event::Processed` acknowledgement on the output channel. Unlike the
    /// DB-polling `send_block_and_wait`, this uses the reactor's own event
    /// stream so we know the block has been fully processed (including all
    /// WASM contract execution) before continuing.
    async fn send_block_and_await_event(
        event_tx: &mpsc::Sender<BlockEvent>,
        output_rx: &mut mpsc::Receiver<Event>,
        block: indexer_types::Block,
        target_height: u64,
    ) {
        let expected_height = block.height as i64;
        event_tx
            .send(BlockEvent::BlockInsert {
                target_height,
                block,
            })
            .await
            .unwrap();
        match output_rx.recv().await.unwrap() {
            Event::Processed { block, .. } => assert_eq!(block.height, expected_height),
            other => panic!("expected Processed at height {expected_height}, got {other:?}"),
        }
    }

    /// Proves that rolling back a block containing a BLS key registration
    /// reverts the registry contract_state created by that registration.
    ///
    /// This exercises the full pipeline: reactor → block_handler →
    /// process_transaction → WASM runtime (registry contract execution) →
    /// contract_state write, then rollback → CASCADE delete → state gone.
    #[tokio::test]
    async fn test_reactor_rollback_reverts_registration_state() -> Result<()> {
        let cancel_token = CancellationToken::new();
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = &writer.connection();

        let (event_tx, block_rx) = mpsc::channel(10);
        let (_mempool_tx, mempool_rx) = mpsc::channel(10);
        let (output_tx, mut output_rx) = mpsc::channel(10);
        let handle = reactor::run(
            1,
            cancel_token.clone(),
            writer,
            block_rx,
            mempool_rx,
            None,
            Some(output_tx),
            None,
            None,
            None,
            None,
            vec![],
            None,
            None,
        );

        let seed = [42u8; 64];
        let keypair =
            derive_taproot_keypair_from_seed(&seed, &taproot_derivation_path(Network::Regtest))?;
        let (x_only_public_key, _) = keypair.x_only_public_key();
        let bls_sk = derive_bls_secret_key_eip2333(&seed, &bls_derivation_path(Network::Regtest))?;
        let proof = RegistrationProof::new(&keypair, &bls_sk.to_bytes())?;

        let block1_hash = new_mock_block_hash(11);
        let block1 = indexer_types::Block {
            height: 1,
            hash: block1_hash,
            prev_hash: new_mock_block_hash(0),
            transactions: vec![Transaction {
                txid: Txid::from_slice(&[0xAA; 32]).unwrap(),
                index: 0,
                inputs: vec![TransactionInput {
                    previous_output: OutPoint::null(),
                    input_index: 0,
                    witness_signer: Signer::XOnlyPubKey(x_only_public_key.to_string()),
                    insts: Insts::single(Inst::RegisterBlsKey {
                        bls_pubkey: proof.bls_pubkey.to_vec(),
                        schnorr_sig: proof.schnorr_sig.to_vec(),
                        bls_sig: proof.bls_sig.to_vec(),
                    }),
                }],
                op_return_data: IndexMap::new(),
            }],
        };
        send_block_and_await_event(&event_tx, &mut output_rx, block1, 2).await;

        let state_count: u64 = conn
            .query(
                "SELECT COUNT(*) FROM contract_state WHERE height = 1",
                params![],
            )
            .await?
            .next()
            .await?
            .unwrap()
            .get(0)?;
        assert!(
            state_count > 0,
            "registration must write contract_state at height 1"
        );

        event_tx.send(BlockEvent::Rollback { to_height: 0 }).await?;
        match output_rx.recv().await.unwrap() {
            Event::Rolledback { height } => assert_eq!(height, 0),
            other => panic!("expected Rolledback, got {other:?}"),
        }

        let state_count_after: u64 = conn
            .query(
                "SELECT COUNT(*) FROM contract_state WHERE height = 1",
                params![],
            )
            .await?
            .next()
            .await?
            .unwrap()
            .get(0)?;
        assert_eq!(
            state_count_after, 0,
            "rollback must remove all contract_state from deleted block"
        );

        cancel_token.cancel();
        let _ = handle.await;
        Ok(())
    }

    /// End-to-end nonce rollback: register a key (nonce=0 at height 1),
    /// advance the nonce via BlsBulk (nonce→1 at height 2), roll back
    /// height 2, and verify the nonce reverts to 0.
    #[tokio::test]
    async fn test_reactor_rollback_reverts_nonce_advance() -> Result<()> {
        let cancel_token = CancellationToken::new();
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = &writer.connection();

        let (event_tx, block_rx) = mpsc::channel(10);
        let (_mempool_tx, mempool_rx) = mpsc::channel(10);
        let (output_tx, mut output_rx) = mpsc::channel(10);
        let handle = reactor::run(
            1,
            cancel_token.clone(),
            writer,
            block_rx,
            mempool_rx,
            None,
            Some(output_tx),
            None,
            None,
            None,
            None,
            vec![],
            None,
            None,
        );

        let seed = [42u8; 64];
        let keypair =
            derive_taproot_keypair_from_seed(&seed, &taproot_derivation_path(Network::Regtest))?;
        let (x_only_public_key, _) = keypair.x_only_public_key();
        let bls_sk = derive_bls_secret_key_eip2333(&seed, &bls_derivation_path(Network::Regtest))?;
        let proof = RegistrationProof::new(&keypair, &bls_sk.to_bytes())?;

        // -- Block 1: register the BLS key (creates signer_id=0, next_nonce=0) --
        let block1_hash = new_mock_block_hash(11);
        let block1 = indexer_types::Block {
            height: 1,
            hash: block1_hash,
            prev_hash: new_mock_block_hash(0),
            transactions: vec![Transaction {
                txid: Txid::from_slice(&[0xAA; 32]).unwrap(),
                index: 0,
                inputs: vec![TransactionInput {
                    previous_output: OutPoint::null(),
                    input_index: 0,
                    witness_signer: Signer::XOnlyPubKey(x_only_public_key.to_string()),
                    insts: Insts::single(Inst::RegisterBlsKey {
                        bls_pubkey: proof.bls_pubkey.to_vec(),
                        schnorr_sig: proof.schnorr_sig.to_vec(),
                        bls_sig: proof.bls_sig.to_vec(),
                    }),
                }],
                op_return_data: IndexMap::new(),
            }],
        };
        send_block_and_await_event(&event_tx, &mut output_rx, block1, 3).await;

        let state_at_h1: u64 = conn
            .query(
                "SELECT COUNT(*) FROM contract_state WHERE height = 1",
                params![],
            )
            .await?
            .next()
            .await?
            .unwrap()
            .get(0)?;
        assert!(state_at_h1 > 0, "registration must write state at height 1");

        // -- Block 2: BlsBulk Call that advances the nonce --
        let call_op = Inst::Call {
            gas_limit: 100_000,
            contract: indexer_types::ContractAddress {
                name: "registry".to_string(),
                height: 0,
                tx_index: 0,
            },
            nonce: Some(0),
            expr: "get-signer-count()".to_string(),
        };
        let msg = call_op.aggregate_signing_message(0)?;
        let sk = blst::min_sig::SecretKey::from_bytes(&bls_sk.to_bytes()).unwrap();
        let sig = sk.sign(&msg, KONTOR_BLS_DST, &[]);

        let block2_hash = new_mock_block_hash(22);
        let block2 = indexer_types::Block {
            height: 2,
            hash: block2_hash,
            prev_hash: block1_hash,
            transactions: vec![Transaction {
                txid: Txid::from_slice(&[0xBB; 32]).unwrap(),
                index: 0,
                inputs: vec![TransactionInput {
                    previous_output: OutPoint::null(),
                    input_index: 0,
                    witness_signer: Signer::Nobody,
                    insts: Insts {
                        ops: vec![call_op],
                        aggregate: Some(AggregateInfo {
                            signer_ids: vec![0],
                            signature: sig.to_bytes().to_vec(),
                        }),
                    },
                }],
                op_return_data: IndexMap::new(),
            }],
        };
        send_block_and_await_event(&event_tx, &mut output_rx, block2, 3).await;

        let state_at_h2: u64 = conn
            .query(
                "SELECT COUNT(*) FROM contract_state WHERE height = 2",
                params![],
            )
            .await?
            .next()
            .await?
            .unwrap()
            .get(0)?;
        assert!(
            state_at_h2 > 0,
            "nonce advance must write contract_state at height 2"
        );

        // -- Rollback to height 1: block 2 is deleted, nonce reverts --
        event_tx.send(BlockEvent::Rollback { to_height: 1 }).await?;
        match output_rx.recv().await.unwrap() {
            Event::Rolledback { height } => assert_eq!(height, 1),
            other => panic!("expected Rolledback, got {other:?}"),
        }

        let state_at_h2_after: u64 = conn
            .query(
                "SELECT COUNT(*) FROM contract_state WHERE height = 2",
                params![],
            )
            .await?
            .next()
            .await?
            .unwrap()
            .get(0)?;
        assert_eq!(
            state_at_h2_after, 0,
            "rollback must remove all contract_state from height 2 (including nonce advance)"
        );

        let state_at_h1_after: u64 = conn
            .query(
                "SELECT COUNT(*) FROM contract_state WHERE height = 1",
                params![],
            )
            .await?
            .next()
            .await?
            .unwrap()
            .get(0)?;
        assert!(
            state_at_h1_after > 0,
            "registration state at height 1 must survive rollback to height 1"
        );

        cancel_token.cancel();
        let _ = handle.await;
        Ok(())
    }

    /// Rollback of an attempted bundled BLS key registration.
    ///
    /// The existing `test_reactor_rollback_reverts_registration_state` covers
    /// the direct `Inst::RegisterBlsKey` path. In the Insts/AggregateInfo model,
    /// aggregate registration is rejected before execution, so this path should
    /// not write any state that rollback would need to remove.
    #[tokio::test]
    async fn test_reactor_rollback_reverts_bls_bulk_registration() -> Result<()> {
        let cancel_token = CancellationToken::new();
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = &writer.connection();

        let (event_tx, block_rx) = mpsc::channel(10);
        let (_mempool_tx, mempool_rx) = mpsc::channel(10);
        let (output_tx, mut output_rx) = mpsc::channel(10);
        let handle = reactor::run(
            1,
            cancel_token.clone(),
            writer,
            block_rx,
            mempool_rx,
            None,
            Some(output_tx),
            None,
            None,
            None,
            None,
            vec![],
            None,
            None,
        );

        let seed = [55u8; 64];
        let keypair =
            derive_taproot_keypair_from_seed(&seed, &taproot_derivation_path(Network::Regtest))?;
        let bls_sk = derive_bls_secret_key_eip2333(&seed, &bls_derivation_path(Network::Regtest))?;
        let proof = RegistrationProof::new(&keypair, &bls_sk.to_bytes())?;

        let register_op = Inst::RegisterBlsKey {
            bls_pubkey: proof.bls_pubkey.to_vec(),
            schnorr_sig: proof.schnorr_sig.to_vec(),
            bls_sig: proof.bls_sig.to_vec(),
        };
        let msg = register_op.aggregate_signing_message(0)?;
        let sk = blst::min_sig::SecretKey::from_bytes(&bls_sk.to_bytes()).unwrap();
        let sig = sk.sign(&msg, KONTOR_BLS_DST, &[]);

        let block1_hash = new_mock_block_hash(33);
        let block1 = indexer_types::Block {
            height: 1,
            hash: block1_hash,
            prev_hash: new_mock_block_hash(0),
            transactions: vec![Transaction {
                txid: Txid::from_slice(&[0xCC; 32]).unwrap(),
                index: 0,
                inputs: vec![TransactionInput {
                    previous_output: OutPoint::null(),
                    input_index: 0,
                    witness_signer: Signer::Nobody,
                    insts: Insts {
                        ops: vec![register_op.clone()],
                        aggregate: Some(AggregateInfo {
                            signer_ids: vec![0],
                            signature: sig.to_bytes().to_vec(),
                        }),
                    },
                }],
                op_return_data: IndexMap::new(),
            }],
        };
        send_block_and_await_event(&event_tx, &mut output_rx, block1.clone(), 2).await;

        let state_count: u64 = conn
            .query(
                "SELECT COUNT(*) FROM contract_state WHERE height = 1",
                params![],
            )
            .await?
            .next()
            .await?
            .unwrap()
            .get(0)?;
        assert_eq!(
            state_count, 0,
            "aggregate RegisterBlsKey should be rejected before writing state"
        );

        // -- Rollback to height 0: block 1 is deleted --
        event_tx.send(BlockEvent::Rollback { to_height: 0 }).await?;
        match output_rx.recv().await.unwrap() {
            Event::Rolledback { height } => assert_eq!(height, 0),
            other => panic!("expected Rolledback, got {other:?}"),
        }

        let state_after_rollback: u64 = conn
            .query(
                "SELECT COUNT(*) FROM contract_state WHERE height = 1",
                params![],
            )
            .await?
            .next()
            .await?
            .unwrap()
            .get(0)?;
        assert_eq!(
            state_after_rollback, 0,
            "rollback must remove contract_state from BlsBulk registration"
        );

        // -- Re-insert the same block: registration must succeed again --
        send_block_and_await_event(&event_tx, &mut output_rx, block1, 2).await;

        let state_reinserted: u64 = conn
            .query(
                "SELECT COUNT(*) FROM contract_state WHERE height = 1",
                params![],
            )
            .await?
            .next()
            .await?
            .unwrap()
            .get(0)?;
        assert_eq!(
            state_reinserted, 0,
            "re-inserted aggregate RegisterBlsKey must still be rejected"
        );

        cancel_token.cancel();
        let _ = handle.await;
        Ok(())
    }
}
