pub mod events;

use anyhow::Result;
use tokio::{select, sync::mpsc::Receiver, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use bitcoin::BlockHash;
use tracing::{debug, info, warn};

use crate::{
    bitcoin_follower::{events::Event, seek::SeekChannel},
    block::{Block, Tx},
    database::{
        self,
        queries::{insert_block, rollback_to_height, select_block_at_height, select_block_latest},
        types::BlockRow,
    },
};

struct Reactor<T: Tx> {
    reader: database::Reader,
    writer: database::Writer,
    cancel_token: CancellationToken, // currently not used due to relaxed error handling
    ctrl: SeekChannel<T>,
    event_rx: Option<Receiver<Event<T>>>,

    last_height: u64,
    option_last_hash: Option<BlockHash>,
}

impl<T: Tx> Reactor<T> {
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
                    panic!(
                        "Latest block has height {}, less than start height {}",
                        block.height, starting_block_height
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

    async fn rollback(&mut self, height: u64) {
        rollback_to_height(&self.writer.connection(), height)
            .await
            .unwrap();
        self.last_height = height;

        if let Some(block) =
            select_block_at_height(&self.reader.connection().await.unwrap(), height)
                .await
                .unwrap()
        {
            self.option_last_hash = Some(block.hash);
            info!("Rollback to height {} ({})", height, block.hash);
        } else {
            warn!("Rollback to height {}, no previous block found", height);
        }

        info!("Seek: start fetching from height {}", self.last_height + 1);
        let event_rx = self
            .ctrl
            .clone()
            .seek(self.last_height + 1, self.option_last_hash)
            .await;

        // close and drain old channel before switching to the new one
        if let Some(rx) = self.event_rx.as_mut() {
            rx.close();
            while rx.recv().await.is_some() {}
        }
        self.event_rx = Some(event_rx);
    }

    async fn handle_block(&mut self, block: Block<T>) {
        let height = block.height;
        let hash = block.hash;
        let prev_hash = block.prev_hash;

        if height < self.last_height + 1 {
            warn!(
                "Rollback required; received block at height {} below expected height {}",
                height,
                self.last_height + 1,
            );

            self.rollback(height - 1).await;
            return;
        } else if height > self.last_height + 1 {
            warn!(
                "Order exception, received block at height {}, expected height {}",
                height,
                self.last_height + 1
            );
            self.cancel_token.cancel();
            return;
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
                self.rollback(height - 2).await;
                return;
            }
        } else {
            info!(
                "Initial block received at height {} (hash {})",
                height, hash
            );
        }

        self.last_height = height;
        self.option_last_hash = Some(hash);

        insert_block(&self.writer.connection(), BlockRow { height, hash })
            .await
            .unwrap();
    }

    pub async fn run_event_handler(&mut self) {
        let rx = self
            .ctrl
            .clone()
            .seek(self.last_height + 1, self.option_last_hash)
            .await;
        self.event_rx = Some(rx);

        loop {
            let event_rx = self
                .event_rx
                .as_mut()
                .expect("event channel must exist to run handler loop");

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
                                    self.handle_block(block).await;
                                },
                                Event::Rollback(height) => {
                                    self.rollback(height).await;
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
            let mut reactor = Reactor::new(
                starting_block_height,
                reader,
                writer,
                ctrl.clone(),
                cancel_token.clone(),
            )
            .await
            .expect("Failed to create Reactor, exiting");

            reactor.run_event_handler().await;

            info!("Exited");
        }
    })
}
