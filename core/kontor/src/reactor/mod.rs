pub mod events;

use anyhow::{Result, bail};
use tokio::{select, sync::mpsc::Receiver, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use bitcoin::BlockHash;
use tracing::{debug, error, info, warn};

use crate::{
    bitcoin_follower::{
        events::{BlockId, Event},
        seek::SeekChannel,
    },
    block::{Block, Tx},
    database::{
        self,
        queries::{
            insert_block, rollback_to_height, select_block_at_height, select_block_latest,
            select_block_with_hash,
        },
        types::BlockRow,
    },
};

struct Reactor<T: Tx + 'static> {
    reader: database::Reader,
    writer: database::Writer,
    cancel_token: CancellationToken, // currently not used due to relaxed error handling
    ctrl: SeekChannel<T>,
    event_rx: Option<Receiver<Event<T>>>,

    last_height: u64,
    option_last_hash: Option<BlockHash>,
}

impl<T: Tx + 'static> Reactor<T> {
    pub async fn new(
        starting_block_height: u64,
        reader: database::Reader,
        writer: database::Writer,
        ctrl: SeekChannel<T>,
        cancel_token: CancellationToken,
    ) -> Result<Self> {
        let conn = &*reader.connection().await?;
        match select_block_latest(conn).await? {
            Some(block) => {
                if block.height < starting_block_height - 1 {
                    bail!(
                        "Latest block has height {}, less than start height {}",
                        block.height,
                        starting_block_height
                    );
                }

                info!(
                    "Continuing from block height {} ({})",
                    block.height, block.hash
                );

                Ok(Self {
                    reader,
                    writer,
                    cancel_token,
                    ctrl,
                    event_rx: None,
                    last_height: block.height,
                    option_last_hash: Some(block.hash),
                })
            }
            None => {
                info!(
                    "No previous blocks found, starting from height {}",
                    starting_block_height
                );

                Ok(Self {
                    reader,
                    writer,
                    cancel_token,
                    ctrl,
                    event_rx: None,
                    last_height: starting_block_height - 1,
                    option_last_hash: None,
                })
            }
        }
    }

    async fn rollback(&mut self, height: u64) -> Result<()> {
        rollback_to_height(&self.writer.connection(), height).await?;
        self.last_height = height;

        let conn = &self.reader.connection().await?;
        if let Some(block) = select_block_at_height(conn, height).await? {
            self.option_last_hash = Some(block.hash);
            info!("Rollback to height {} ({})", height, block.hash);
        } else {
            warn!("Rollback to height {}, no previous block found", height);
        }

        info!("Seek: start fetching from height {}", self.last_height + 1);
        match self
            .ctrl
            .clone()
            .seek(self.last_height + 1, self.option_last_hash)
            .await
        {
            Ok(event_rx) => {
                // close and drain old channel before switching to the new one
                if let Some(rx) = self.event_rx.as_mut() {
                    rx.close();
                    while rx.recv().await.is_some() {}
                }
                self.event_rx = Some(event_rx);
                Ok(())
            }
            Err(e) => {
                bail!("Failed to execute seek: {}", e);
            }
        }
    }

    async fn rollback_hash(&mut self, hash: BlockHash) -> Result<()> {
        let conn = &self.writer.connection();
        let block_row = select_block_with_hash(conn, &hash).await?;
        if let Some(row) = block_row {
            self.rollback(row.height - 1).await
        } else {
            error!("attemped rollback to hash {} failed, block not found", hash);
            Ok(())
        }
    }

    async fn handle_block(&mut self, block: Block<T>) -> Result<()> {
        let height = block.height;
        let hash = block.hash;
        let prev_hash = block.prev_hash;

        if height < self.last_height + 1 {
            warn!(
                "Rollback required; received block at height {} below expected height {}",
                height,
                self.last_height + 1,
            );

            self.rollback(height - 1).await?;
            return Ok(());
        }
        if height > self.last_height + 1 {
            bail!(
                "Order exception, received block at height {}, expected height {}",
                height,
                self.last_height + 1
            );
        }

        if let Some(last_hash) = self.option_last_hash {
            if prev_hash != last_hash {
                warn!(
                    "Rollback required; received block at height {} with prev_hash {} \
                         not matching last hash {}",
                    height, prev_hash, last_hash
                );

                // roll back 2 steps since we know both the received block and the
                // last one stored must be bad.
                self.rollback(height - 2).await?;
                return Ok(());
            }
        } else {
            info!(
                "Initial block received at height {} (hash {})",
                height, hash
            );
        }

        self.last_height = height;
        self.option_last_hash = Some(hash);

        insert_block(&self.writer.connection(), BlockRow { height, hash }).await?;

        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        let rx = match self
            .ctrl
            .clone()
            .seek(self.last_height + 1, self.option_last_hash)
            .await
        {
            Ok(rx) => rx,
            Err(e) => {
                bail!("initial seek failed: {}", e);
            }
        };

        self.event_rx = Some(rx);

        loop {
            let event_rx = match self.event_rx.as_mut() {
                Some(rx) => rx,
                None => {
                    bail!("handler loop started with missing event channel");
                }
            };

            select! {
                _ = self.cancel_token.cancelled() => {
                    info!("Cancelled");
                    break;
                }
                option_event = event_rx.recv() => {
                    match option_event {
                        Some(event) => {
                            match event {
                                Event::Block((target_height, block)) => {
                                    info!("Block {}/{} {}", block.height,
                                          target_height, block.hash);
                                    self.handle_block(block).await?;
                                },
                                Event::Rollback(BlockId::Height(height)) => {
                                    self.rollback(height).await?;
                                },
                                Event::Rollback(BlockId::Hash(block_hash)) => {
                                    self.rollback_hash(block_hash).await?;
                                },
                                Event::MempoolUpdate {removed, added} => {
                                    debug!("MempoolUpdates removed {} added {}",
                                           removed.len(), added.len());
                                },
                                Event::MempoolSet(txs) => {
                                    info!("MempoolSet {}", txs.len());
                                }
                            }
                        },
                        None => {
                            info!("Received None event, exiting");
                            break;
                        },
                    }
                }
            }
        }

        if let Some(rx) = self.event_rx.as_mut() {
            rx.close();
            while rx.recv().await.is_some() {}
        }
        Ok(())
    }
}

pub fn run<T: Tx + 'static>(
    starting_block_height: u64,
    cancel_token: CancellationToken,
    reader: database::Reader,
    writer: database::Writer,
    ctrl: SeekChannel<T>,
) -> JoinHandle<()> {
    tokio::spawn({
        async move {
            let mut reactor = match Reactor::new(
                starting_block_height,
                reader,
                writer,
                ctrl.clone(),
                cancel_token.clone(),
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
