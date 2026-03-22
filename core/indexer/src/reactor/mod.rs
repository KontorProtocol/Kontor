pub mod bitcoin_state;
pub mod block_handler;
pub mod consensus;
pub mod engine;
pub mod executor;
pub mod mock_bitcoin;
pub mod mock_executor;
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

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use malachitebft_app_channel::Channels;
use tracing::{debug, error, info, warn};

use crate::{
    bitcoin_follower::event::{BlockEvent, MempoolEvent},
    consensus::Ctx,
    database::{
        self,
        queries::{
            insert_processed_block, rollback_to_height, select_block_at_height, select_block_latest,
        },
    },
    runtime::{ComponentCache, Runtime, Storage},
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
    conn: libsql::Connection,
    cancel_token: CancellationToken,
    block_rx: Receiver<BlockEvent>,
    mempool_rx: Receiver<MempoolEvent>,
    init_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
    simulate_rx: Option<Receiver<Simulation>>,
    bitcoin_state: bitcoin_state::BitcoinState,
    consensus_handle: Option<ConsensusHandle>,

    last_height: u64,
    option_last_hash: Option<BlockHash>,
}

impl<E: Executor> Reactor<E> {
    pub fn new(
        executor: E,
        conn: libsql::Connection,
        block_rx: Receiver<BlockEvent>,
        mempool_rx: Receiver<MempoolEvent>,
        cancel_token: CancellationToken,
        init_tx: Option<oneshot::Sender<bool>>,
        event_tx: Option<mpsc::Sender<Event>>,
        simulate_rx: Option<Receiver<Simulation>>,
        bitcoin_state: bitcoin_state::BitcoinState,
        consensus_handle: Option<ConsensusHandle>,
        last_height: u64,
        option_last_hash: Option<BlockHash>,
    ) -> Self {
        Self {
            executor,
            conn,
            cancel_token,
            block_rx,
            mempool_rx,
            simulate_rx,
            bitcoin_state,
            last_height,
            option_last_hash,
            init_tx,
            event_tx,
            consensus_handle,
        }
    }

    async fn rollback(&mut self, height: u64) -> Result<()> {
        rollback_to_height(&self.conn, height).await?;
        self.last_height = height;

        if let Ok(Some(row)) = select_block_at_height(&self.conn, height as i64).await {
            if let Ok(decoded) = hex::decode(row.hash)
                && decoded.len() == 32
            {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&decoded);
                self.option_last_hash = Some(BlockHash::from_byte_array(bytes));
                info!("Rollback to height {} ({})", height, row.hash);
            }
        } else {
            self.option_last_hash = None;
            warn!("Rollback to height {}, no previous block found", height);
        }

        if let Some(tx) = &self.event_tx {
            let _ = tx.send(Event::Rolledback { height }).await;
        }

        Ok(())
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

        if let Some(last_hash) = self.option_last_hash {
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
        self.option_last_hash = Some(hash);

        // DB orchestration for block execution
        use crate::database::queries::{
            confirm_transaction, get_transaction_by_txid, insert_block, insert_transaction,
            set_block_processed,
        };

        let _ = insert_block(
            &self.conn,
            BlockRow::builder()
                .height(block.height as i64)
                .hash(block.hash)
                .relevant(!block.transactions.is_empty())
                .build(),
        )
        .await;

        for (i, t) in block.transactions.iter().enumerate() {
            // Dedup: skip execution for already-batched txs
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
                .execute_transaction(block.height as i64, tx_id, t)
                .await;
        }

        self.executor.on_block_completed(&block).await;
        let _ = set_block_processed(&self.conn, block.height as i64).await;

        if let Some(tx) = &self.event_tx {
            let _ = tx
                .send(Event::Processed {
                    block: (&block).into(),
                })
                .await;
        }
        info!("Block processed");

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
                    txids,
                    ..
                } => {
                    let mut resolved_txs = Vec::with_capacity(txids.len());
                    for txid in txids {
                        if let Some(tx) = self.bitcoin_state.mempool.get(txid) {
                            resolved_txs.push(tx.clone());
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
                            &mut self.executor,
                            &mut self.bitcoin_state,
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
                    handle.state.block_cache.insert(block.height, block.clone());
                    handle
                        .state
                        .pending_blocks
                        .push_back((block.height, block.hash));
                }
                // Process replay queue entries whose anchor has been reached
                self.process_replay_queue().await;
                if self.consensus_handle.is_none() {
                    self.handle_block(block).await?;
                }
            }
            BlockEvent::Rollback { to_height } => {
                info!(to_height, "Bitcoin rollback — truncating state");
                self.rollback(to_height).await?;
            }
        }
        Ok(())
    }

    async fn run_event_loop(&mut self) -> Result<()> {
        self.init_tx.take().map(|tx| tx.send(true));

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
                        &mut self.executor,
                        &mut self.bitcoin_state,
                        &mut handle.channels,
                        msg,
                        node_index,
                        self.last_height,
                        self.option_last_hash.unwrap_or(BlockHash::all_zeros()),
                    ).await?;
                    if let Some(block) = decided_block {
                        self.handle_block(block).await?;
                        // Check finality after block execution — batch txids may now be confirmed
                        let handle = self.consensus_handle.as_mut().unwrap();
                        if handle.state
                            .pending_batches
                            .iter()
                            .any(|b| b.deadline <= self.last_height)
                            && let Some(rollback_anchor) = handle.state.run_finality_checks(&mut self.executor, self.last_height).await {
                                self.last_height = rollback_anchor;
                                self.option_last_hash = handle.state.block_hash_at_height(rollback_anchor).await;

                                // Process replay queue entries using already-cached blocks
                                self.process_replay_queue().await;
                            }
                    }
                    // Yield to allow other channels (block_rx, mempool_rx) to be polled
                    tokio::task::yield_now().await;
                }
                option_event = simulate_rx => {
                    if let Some((btx, ret_tx)) = option_event {
                        let _ = ret_tx.send(self.executor.simulate(btx).await);
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
async fn build_genesis_from_staking(runtime: &mut Runtime) -> Result<crate::consensus::Genesis> {
    use crate::consensus::signing::PublicKey;
    use crate::consensus::{Validator, ValidatorSet};
    use malachitebft_app_channel::app::types::core::VotingPower;

    let active_set = crate::runtime::staking::api::get_active_set(runtime).await?;

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
    Ok(crate::consensus::Genesis { validator_set })
}

pub async fn create_runtime_executor(
    starting_block_height: u64,
    writer: &database::Writer,
    cancel_token: CancellationToken,
    bitcoin_client: Option<&crate::bitcoin_client::Client>,
    replay_tx: Option<mpsc::Sender<u64>>,
    genesis_validators: &[crate::runtime::GenesisValidator],
) -> Result<(executor::RuntimeExecutor, u64, Option<BlockHash>)> {
    let conn = writer.connection();
    let (last_height, option_last_hash) = match select_block_latest(&conn).await? {
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

    let mut exec = executor::RuntimeExecutor::new(runtime, writer.clone(), cancel_token);

    if let Some(client) = bitcoin_client {
        exec = exec.with_bitcoin_client(client.clone());
    }
    if let Some(tx) = replay_tx {
        exec = exec.with_replay_tx(tx);
    }

    Ok((exec, last_height, option_last_hash))
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
    init_tx: Option<oneshot::Sender<bool>>,
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
                let (mut exec, last_height, option_last_hash) = create_runtime_executor(
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
                    Some(
                        start_consensus(engine_cfg, &mut exec.runtime, observation_channels)
                            .await?,
                    )
                } else {
                    None
                };

                let mut reactor = Reactor::new(
                    exec,
                    writer.connection(),
                    block_rx,
                    mempool_rx,
                    cancel_token.clone(),
                    init_tx,
                    event_tx,
                    simulate_rx,
                    bs,
                    consensus_handle,
                    last_height,
                    option_last_hash,
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
