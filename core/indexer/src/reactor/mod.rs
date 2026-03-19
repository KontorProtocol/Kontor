pub mod bitcoin_state;
pub mod block_handler;
pub mod consensus;
pub mod engine;
pub mod executor;
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
use malachitebft_app_channel::Channels;
use tracing::{debug, error, info, warn};

use crate::{
    bitcoin_follower::event::{BlockEvent, MempoolEvent},
    consensus::Ctx,
    database::{
        self,
        queries::{insert_processed_block, select_block_at_height, select_block_latest},
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
struct ConsensusHandle {
    state: consensus::ConsensusState,
    channels: Channels<Ctx>,
    _engine_handle: malachitebft_app_channel::EngineHandle,
    _wal_dir: tempfile::TempDir,
    node_index: usize,
}

struct Reactor {
    executor: executor::RuntimeExecutor,
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

impl Reactor {
    pub async fn new(
        starting_block_height: u64,
        writer: database::Writer,
        block_rx: Receiver<BlockEvent>,
        mempool_rx: Receiver<MempoolEvent>,
        cancel_token: CancellationToken,
        init_tx: Option<oneshot::Sender<bool>>,
        event_tx: Option<mpsc::Sender<Event>>,
        simulate_rx: Option<Receiver<Simulation>>,
        engine_config: Option<engine::EngineConfig>,
        bitcoin_client: Option<crate::bitcoin_client::Client>,
        replay_tx: Option<mpsc::Sender<u64>>,
        genesis_validators: Vec<crate::runtime::GenesisValidator>,
        observation_channels: Option<consensus::ObservationChannels>,
    ) -> Result<Self> {
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
        runtime
            .publish_native_contracts(&genesis_validators)
            .await?;

        // Start consensus engine if configured
        let consensus_handle = if let Some(engine_cfg) = engine_config {
            let genesis = build_genesis_from_staking(&mut runtime).await?;

            let engine_output = engine::start(engine_cfg, &genesis).await?;
            info!(address = %engine_output.address, "Consensus engine started");

            let mut state = consensus::ConsensusState::new(
                engine_output.signing_provider,
                genesis,
                engine_output.address,
            );
            state.observation = observation_channels;

            Some(ConsensusHandle {
                state,
                channels: engine_output.channels,
                _engine_handle: engine_output._handle,
                _wal_dir: engine_output._wal_dir,
                node_index: 0,
            })
        } else {
            None
        };

        let mut executor = executor::RuntimeExecutor::new(runtime, writer, cancel_token.clone());
        let mut bs = bitcoin_state::BitcoinState::new();

        if let Some(client) = bitcoin_client {
            bs = bs.with_tx_cache(client.tx_cache().clone());
            executor = executor.with_bitcoin_client(client);
        }
        if let Some(tx) = replay_tx {
            executor = executor.with_replay_tx(tx);
        }

        Ok(Self {
            executor,
            cancel_token,
            block_rx,
            mempool_rx,
            simulate_rx,
            bitcoin_state: bs,
            last_height,
            option_last_hash,
            init_tx,
            event_tx,
            consensus_handle,
        })
    }

    async fn rollback(&mut self, height: u64) -> Result<()> {
        self.executor.rollback_state(height).await;
        self.last_height = height;

        let conn = self.executor.connection();
        if let Some(block) = select_block_at_height(&conn, height as i64).await? {
            self.option_last_hash = Some(block.hash);
            info!("Rollback to height {} ({})", height, block.hash);
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

        self.executor.execute_block(&block).await;

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

    async fn run_event_loop(&mut self) -> Result<()> {
        self.init_tx.take().map(|tx| tx.send(true));

        loop {
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
                    match event {
                        BlockEvent::BlockInsert { target_height, block } => {
                            let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid).collect();
                            self.bitcoin_state.track_block(block.height, block.hash, &txids);
                            info!("Block {}/{} {}", block.height,
                                  target_height, block.hash);

                            // When consensus is active, check finality deadlines on new blocks
                            if let Some(handle) = &mut self.consensus_handle
                                && handle.state.pending_batches.iter().any(|b| {
                                    b.deadline <= self.bitcoin_state.chain_tip
                                })
                            {
                                handle.state.run_finality_checks(&mut self.executor, &mut self.bitcoin_state).await;
                            }

                            // In follower mode (no consensus), execute blocks immediately
                            if self.consensus_handle.is_none() {
                                self.handle_block(block).await?;
                            }
                        },
                        BlockEvent::Rollback { to_height } => {
                            self.rollback(to_height).await?;
                        },
                    }
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
                    let handle = self.consensus_handle.as_mut().unwrap();
                    let node_index = handle.node_index;
                    consensus::handle_consensus_msg(
                        &mut handle.state,
                        &mut self.executor,
                        &mut self.bitcoin_state,
                        &mut handle.channels,
                        msg,
                        node_index,
                    ).await?;
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
            let mut reactor = match Reactor::new(
                starting_block_height,
                writer,
                block_rx,
                mempool_rx,
                cancel_token.clone(),
                init_tx,
                event_tx,
                simulate_rx,
                engine_config,
                bitcoin_client,
                replay_tx,
                genesis_validators,
                observation_channels,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    error!("Failed to create Reactor: {}, exiting", e);
                    cancel_token.cancel();
                    return;
                }
            };

            if let Err(e) = reactor.run().await {
                error!("Reactor error: {}, exiting", e);
                cancel_token.cancel();
            }

            info!("Exited");
        }
    })
}
