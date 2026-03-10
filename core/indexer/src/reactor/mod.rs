pub mod bitcoin_state;
pub mod block_handler;
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
use tracing::{debug, error, info, warn};

use crate::{
    bitcoin_follower::event::BitcoinEvent,
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

pub type Simulation = (
    bitcoin::Transaction,
    oneshot::Sender<Result<Vec<OpWithResult>>>,
);

struct Reactor {
    writer: database::Writer,
    cancel_token: CancellationToken,
    bitcoin_event_rx: Receiver<BitcoinEvent>,
    init_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
    runtime: Runtime,
    simulate_rx: Option<Receiver<Simulation>>,
    bitcoin_state: bitcoin_state::BitcoinState,

    last_height: u64,
    option_last_hash: Option<BlockHash>,
}

impl Reactor {
    pub async fn new(
        starting_block_height: u64,
        writer: database::Writer,
        bitcoin_event_rx: Receiver<BitcoinEvent>,
        cancel_token: CancellationToken,
        init_tx: Option<oneshot::Sender<bool>>,
        event_tx: Option<mpsc::Sender<Event>>,
        simulate_rx: Option<Receiver<Simulation>>,
    ) -> Result<Self> {
        let conn = &writer.connection();
        let (last_height, option_last_hash) = match select_block_latest(conn).await? {
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
        if select_block_at_height(conn, 0)
            .await
            .expect("Failed to select block at height 0")
            .is_none()
        {
            info!("Creating native block");
            insert_processed_block(
                conn,
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
        runtime.publish_native_contracts().await?;
        Ok(Self {
            writer,
            cancel_token,
            bitcoin_event_rx,
            simulate_rx,
            bitcoin_state: bitcoin_state::BitcoinState::new(12),
            last_height,
            option_last_hash,
            init_tx,
            event_tx,
            runtime,
        })
    }

    async fn rollback(&mut self, height: u64) -> Result<()> {
        rollback_to_height(&self.writer.connection(), height).await?;
        self.last_height = height;

        self.runtime
            .file_ledger
            .force_resync_from_db(&self.runtime.storage.conn)
            .await?;

        let conn = &self.writer.connection();
        if let Some(block) = select_block_at_height(conn, height as i64).await? {
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

        info!("# Block Kontor Transactions: {}", block.transactions.len());

        block_handler(&mut self.runtime, &block).await?;

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

            select! {
                _ = self.cancel_token.cancelled() => {
                    info!("Cancelled");
                    break;
                }
                option_event = self.bitcoin_event_rx.recv() => {
                    match option_event {
                        Some(event) => {
                            match event {
                                BitcoinEvent::BlockInsert { target_height, block } => {
                                    let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid).collect();
                                    self.bitcoin_state.track_block(block.height, &txids);
                                    info!("Block {}/{} {}", block.height,
                                          target_height, block.hash);
                                    self.handle_block(block).await?;
                                },
                                BitcoinEvent::Rollback { to_height } => {
                                    self.rollback(to_height).await?;
                                },
                                BitcoinEvent::MempoolSync(txs) => {
                                    self.bitcoin_state.track_mempool_sync(txs.iter().map(|tx| tx.txid));
                                    info!("MempoolSync {}", txs.len());
                                },
                                BitcoinEvent::MempoolInsert(tx) => {
                                    self.bitcoin_state.track_mempool_insert(tx.txid);
                                    debug!("MempoolInsert {}", tx.txid);
                                },
                                BitcoinEvent::MempoolRemove(txid) => {
                                    self.bitcoin_state.track_mempool_remove(&txid);
                                    debug!("MempoolRemove {}", txid);
                                },
                            }
                        },
                        None => {
                            info!("Received None event, exiting");
                            break;
                        },
                    }
                }
                option_event = simulate_rx => {
                    if let Some((btx, ret_tx)) = option_event {
                        let _ = ret_tx.send(simulate_handler(&mut self.runtime, btx).await);
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

pub fn run(
    starting_block_height: u64,
    cancel_token: CancellationToken,
    writer: database::Writer,
    bitcoin_event_rx: Receiver<BitcoinEvent>,
    init_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
    simulate_rx: Option<Receiver<Simulation>>,
) -> JoinHandle<()> {
    tokio::spawn({
        async move {
            let mut reactor = match Reactor::new(
                starting_block_height,
                writer,
                bitcoin_event_rx,
                cancel_token.clone(),
                init_tx,
                event_tx,
                simulate_rx,
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
