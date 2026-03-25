pub mod bitcoin_state;
pub mod block_handler;
pub mod consensus;
pub mod engine;
pub mod executor;
pub mod mock_bitcoin;
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
use tracing::{debug, error, info, warn};

use crate::consensus::finality_types::StateEvent;
use crate::{
    bitcoin_follower::event::{BlockEvent, MempoolEvent},
    consensus::{Ctx, Genesis, Validator, ValidatorSet, signing::PublicKey},
    database::{
        self,
        queries::{
            confirm_transaction, get_transaction_by_txid, insert_block, insert_processed_block,
            insert_transaction, rollback_to_height, select_block_at_height, select_block_latest,
            select_unconfirmed_batch_tx, set_block_processed,
        },
    },
    runtime::{
        ComponentCache, Runtime, Storage,
        filestorage::api::{expire_challenges, generate_challenges_for_block},
        staking::api::{get_active_set, transition_epoch},
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
    pub _wal_dir: tempfile::TempDir,
    pub node_index: usize,
}

pub struct Reactor<E: Executor> {
    executor: E,
    runtime: Runtime,
    conn: libsql::Connection,
    cancel_token: CancellationToken,
    block_rx: Receiver<BlockEvent>,
    mempool_rx: Receiver<MempoolEvent>,
    ready_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
    simulate_rx: Option<Receiver<Simulation>>,
    bitcoin_state: bitcoin_state::BitcoinState,
    consensus_handle: Option<ConsensusHandle>,

    last_height: u64,
    last_hash: Option<BlockHash>,
}

impl<E: Executor> Reactor<E> {
    pub fn new(
        executor: E,
        runtime: Runtime,
        conn: libsql::Connection,
        block_rx: Receiver<BlockEvent>,
        mempool_rx: Receiver<MempoolEvent>,
        cancel_token: CancellationToken,
        ready_tx: Option<oneshot::Sender<bool>>,
        event_tx: Option<mpsc::Sender<Event>>,
        simulate_rx: Option<Receiver<Simulation>>,
        bitcoin_state: bitcoin_state::BitcoinState,
        consensus_handle: Option<ConsensusHandle>,
        last_height: u64,
        last_hash: Option<BlockHash>,
    ) -> Self {
        Self {
            executor,
            runtime,
            conn,
            cancel_token,
            block_rx,
            mempool_rx,
            simulate_rx,
            bitcoin_state,
            last_height,
            last_hash,
            ready_tx,
            event_tx,
            consensus_handle,
        }
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
        rollback_to_height(&self.conn, height).await?;
        if let Err(e) = self
            .runtime
            .file_ledger
            .force_resync_from_db(&self.runtime.storage.conn)
            .await
        {
            error!("file_ledger resync after rollback failed: {e}");
        }
        self.last_height = height;

        if let Ok(Some(row)) = select_block_at_height(&self.conn, height as i64).await {
            self.last_hash = Some(row.hash);
            info!("Rollback to height {} ({})", height, row.hash);
        } else {
            self.last_hash = None;
            warn!("Rollback to height {}, no previous block found", height);
        }

        // Callers handle consensus state cleanup:
        // - Reorg: clear_on_rollback + emit RollbackExecuted
        // - Finality: initiate_rollback (selective retain + replay queue)

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

        let epoch_result = transition_epoch(&mut self.runtime, &core_signer, block.height)
            .await
            .expect("Failed to call transition_epoch")
            .expect("transition_epoch returned error");
        if epoch_result.activated > 0 || epoch_result.deactivated > 0 {
            info!(
                "Epoch {} transition: {} activated, {} deactivated",
                epoch_result.new_epoch, epoch_result.activated, epoch_result.deactivated
            );
        }
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

        let _ = insert_block(
            &self.conn,
            BlockRow::builder()
                .height(block.height as i64)
                .hash(block.hash)
                .relevant(!block.transactions.is_empty())
                .build(),
        )
        .await;

        let mut unbatched_count = 0;
        for (i, t) in block.transactions.iter().enumerate() {
            if let Ok(Some(_)) = get_transaction_by_txid(&self.conn, &t.txid.to_string()).await {
                let _ = confirm_transaction(
                    &self.conn,
                    &t.txid.to_string(),
                    block.height as i64,
                    i as i64,
                )
                .await;
                continue;
            }

            unbatched_count += 1;
            let tx_id = match insert_transaction(
                &self.conn,
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
        let _ = set_block_processed(&self.conn, block.height as i64).await;

        if let Some(handle) = &self.consensus_handle {
            let checkpoint = handle.state.get_checkpoint().await;
            handle.state.emit_state_event(StateEvent::BlockProcessed {
                height,
                unbatched_count,
                checkpoint,
            });
        }

        if let Some(tx) = &self.event_tx {
            let _ = tx
                .send(Event::Processed {
                    block: (&block).into(),
                })
                .await;
        }
        info!("Block processed (unbatched_count={unbatched_count})");

        Ok(())
    }

    async fn process_replay_queue(&mut self) {
        loop {
            let Some(handle) = self.consensus_handle.as_mut() else {
                return;
            };
            if handle
                .state
                .replay_queue
                .front()
                .is_none_or(|(_, v)| v.block_height() > self.last_height)
            {
                break;
            }
            let (height, value) = handle.state.next_replay_batch().unwrap();

            match &value {
                crate::consensus::Value::Batch {
                    anchor_height,
                    anchor_hash,
                    txs,
                    ..
                } => {
                    let txids: Vec<Txid> = txs.iter().map(|t| t.txid()).collect();
                    let mut resolved_txs = Vec::with_capacity(txids.len());
                    for txid in &txids {
                        if let Some(tx) = self.bitcoin_state.mempool.get(txid) {
                            resolved_txs.push(tx.clone());
                        } else if let Some(tx) = Self::resolve_tx_from_db(&self.conn, txid).await {
                            resolved_txs.push(tx);
                        } else if let Some(tx) = self.executor.resolve_transaction(txid).await {
                            resolved_txs.push(tx);
                        } else {
                            warn!(%txid, "Could not resolve txid during replay — skipping");
                        }
                    }
                    let handle = self.consensus_handle.as_mut().unwrap();
                    handle.state.record_decided_batch(height, &value);
                    handle
                        .state
                        .process_decided_batch(
                            &self.executor,
                            &mut self.runtime,
                            *anchor_height,
                            *anchor_hash,
                            height,
                            &[],
                            &resolved_txs,
                        )
                        .await;
                }
                crate::consensus::Value::Block { height: bh, .. } => {
                    let block = {
                        let handle = self.consensus_handle.as_mut().unwrap();
                        handle.state.block_cache.remove(bh)
                    };
                    if let Some(block) = block
                        && let Err(e) = self.handle_block(block).await
                    {
                        error!("replay block execution error: {e}");
                    }
                }
            }
        }
    }

    async fn process_block_event(&mut self, event: BlockEvent) -> Result<()> {
        match event {
            BlockEvent::BlockInsert {
                target_height,
                block,
            } => {
                let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid).collect();
                self.bitcoin_state.remove_confirmed_txids(&txids);
                info!("Block {}/{} {}", block.height, target_height, block.hash);

                if let Some(handle) = self.consensus_handle.as_mut() {
                    // Check if this block was already decided (arrived late)
                    if handle.state.missed_block_decisions.remove(&block.height) {
                        info!(
                            "Block {} arrived after consensus decision — executing immediately",
                            block.height
                        );
                        self.handle_block(block).await?;
                    } else {
                        handle.state.block_cache.insert(block.height, block.clone());
                        handle
                            .state
                            .pending_blocks
                            .push_back((block.height, block.hash));
                    }
                } else {
                    self.handle_block(block).await?;
                }
                // Process replay queue entries whose anchor has been reached
                self.process_replay_queue().await;
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
                            self.bitcoin_state.track_mempool_sync(txs.into_iter()).await;
                            info!("MempoolSync {}", count);
                        },
                        MempoolEvent::Insert(tx) => {
                            let txid = tx.compute_txid();
                            self.bitcoin_state.track_mempool_insert(tx).await;
                            debug!("MempoolInsert {}", txid);
                        },
                        MempoolEvent::Remove(txid) => {
                            self.bitcoin_state.track_mempool_remove(&txid).await;
                            debug!("MempoolRemove {}", txid);
                        },
                    }
                }
                Some(msg) = consensus_rx => {
                    debug!("REACTOR: processing consensus msg");
                    let handle = self.consensus_handle.as_mut().unwrap();
                    let node_index = handle.node_index;
                    let decided_block = consensus::handle_consensus_msg(
                        &mut handle.state,
                        &self.executor,
                        &mut self.runtime,
                        &mut self.bitcoin_state,
                        &mut handle.channels,
                        msg,
                        node_index,
                        self.last_height,
                        self.last_hash.unwrap_or(BlockHash::all_zeros()),
                    ).await?;
                    if let Some(block) = decided_block {
                        self.handle_block(block).await?;
                        // Check finality after block execution — batch txids may now be confirmed
                        let handle = self.consensus_handle.as_mut().unwrap();
                        if handle.state
                            .pending_batches
                            .iter()
                            .any(|b| b.deadline <= self.last_height)
                            && let Some((rollback_anchor, excluded)) = handle.state.run_finality_checks(self.last_height).await {
                                // DB truncation + executor resync + notify clients
                                self.rollback(rollback_anchor).await?;

                                // Emit rollback event
                                let handle = self.consensus_handle.as_mut().unwrap();
                                let checkpoint = handle.state.get_checkpoint().await;
                                handle.state.emit_state_event(StateEvent::RollbackExecuted {
                                    to_anchor: rollback_anchor,
                                    entries_removed: 0,
                                    checkpoint,
                                });

                                // Consensus state rollback (replay queue, pending batches)
                                let handle = self.consensus_handle.as_mut().unwrap();
                                handle.state.initiate_rollback(
                                    &mut self.executor,
                                    rollback_anchor,
                                    excluded,
                                ).await;

                                // Process replay queue entries using already-cached blocks
                                self.process_replay_queue().await;
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

/// Build a Genesis from the staking contract's active validator set.
async fn build_genesis_from_staking(runtime: &mut Runtime) -> Result<Genesis> {
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
            // Convert stake to voting power (use 1 for now, refine later)
            let voting_power = 1 as VotingPower;
            Some(Validator::new(public_key, voting_power))
        })
        .collect();

    let validator_set = ValidatorSet::new(validators);
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
        insert_processed_block(
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
) -> Result<ConsensusHandle> {
    let genesis = build_genesis_from_staking(runtime).await?;

    let engine_output = engine::start(engine_config, &genesis).await?;
    info!(address = %engine_output.address, "Consensus engine started");

    let node_index = genesis
        .validator_set
        .validators
        .iter()
        .position(|v| v.address == engine_output.address)
        .expect("Our address not found in genesis validator set");

    let mut state = consensus::ConsensusState::new(
        runtime.get_storage_conn(),
        engine_output.signing_provider,
        genesis,
        engine_output.address,
    );
    state.observation = observation_channels;

    Ok(ConsensusHandle {
        state,
        channels: engine_output.channels,
        _engine_handle: engine_output._handle,
        _wal_dir: engine_output._wal_dir,
        node_index,
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

                let mut bs = bitcoin_state::BitcoinState::new();
                if let Some(client) = &bitcoin_client {
                    bs = bs.with_tx_cache(client.tx_cache().clone());
                }

                let consensus_handle = if let Some(engine_cfg) = engine_config {
                    Some(start_consensus(engine_cfg, &mut runtime, observation_channels).await?)
                } else {
                    None
                };

                let mut reactor = Reactor::new(
                    exec,
                    runtime,
                    writer.connection(),
                    block_rx,
                    mempool_rx,
                    cancel_token.clone(),
                    ready_tx,
                    event_tx,
                    simulate_rx,
                    bs,
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
