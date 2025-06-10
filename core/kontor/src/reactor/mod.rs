pub mod events;

use anyhow::Result;
use tokio::{
    select,
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use bitcoin::BlockHash;
use tracing::{debug, info, warn};

use crate::{
    bitcoin_follower::events::{Event, Signal},
    block::{Block, Tx},
    database::{
        self,
        queries::{insert_block, rollback_to_height, select_block_at_height, select_block_latest},
        types::BlockRow,
    },
};

struct Reactor {
    reader: database::Reader,
    writer: database::Writer,
    _cancel_token: CancellationToken, // currently not used due to relaxed error handling
    ctrl_tx: Sender<Signal>,

    last_height: u64,
    option_last_hash: Option<BlockHash>,
}

impl Reactor {
    pub async fn new(
        starting_block_height: u64,
        reader: database::Reader,
        writer: database::Writer,
        ctrl_tx: Sender<Signal>,
        _cancel_token: CancellationToken,
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
                    _cancel_token,
                    ctrl_tx,
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
                    _cancel_token,
                    ctrl_tx,
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
        if self
            .ctrl_tx
            .send(Signal::Seek((self.last_height + 1, self.option_last_hash)))
            .await
            .is_err()
        {
            info!("Ctrl channel closed, exiting");
            return;
        }
    }

    async fn handle_block<T: Tx + 'static>(&mut self, block: Block<T>) {
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
            // Receiving a block at a higher height than expected can happen
            // during a rollback so we can't crash here. For the time being
            // we'll throw the block away and hope that we eventually get
            // the expected block.
            warn!(
                "Order exception, received block at height {}, expected height {}",
                height,
                self.last_height + 1
            );
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
}

pub fn run<T: Tx + 'static>(
    starting_block_height: u64,
    cancel_token: CancellationToken,
    reader: database::Reader,
    writer: database::Writer,
    ctrl: Sender<Signal>,
    mut rx: Receiver<Event<T>>,
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

            if ctrl
                .send(Signal::Seek((
                    reactor.last_height + 1,
                    reactor.option_last_hash,
                )))
                .await
                .is_err()
            {
                info!("Ctrl channel closed, exiting");
                return;
            }

            loop {
                select! {
                    _ = cancel_token.cancelled() => {
                        info!("Cancelled");
                        break;
                    }
                    option_event = rx.recv() => {
                        match option_event {
                            Some(event) => {
                                match event {
                                    Event::Block((target_height, block)) => {
                                        info!("Block {}/{} {}", block.height,
                                              target_height, block.hash);
                                        reactor.handle_block(block).await;
                                    },
                                    Event::Rollback(height) => {
                                        reactor.rollback(height).await;
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

            rx.close();
            while rx.recv().await.is_some() {}

            info!("Exited");
        }
    })
}
