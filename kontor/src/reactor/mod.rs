pub mod events;

use tokio::{select, sync::mpsc::Receiver, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use bitcoin::BlockHash;

use crate::{
    bitcoin_follower::events::Event,
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
    cancel_token: CancellationToken,

    option_last_height: Option<u64>,
    option_last_hash: Option<BlockHash>,
}

impl Reactor {
    pub fn new(
        reader: database::Reader,
        writer: database::Writer,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            reader,
            writer,
            cancel_token,
            option_last_height: None,
            option_last_hash: None,
        }
    }

    async fn init(&mut self, starting_block_height: u64) {
        let conn = &*self.reader.connection().await.unwrap();
        match select_block_latest(conn).await.unwrap() {
            Some(block) => {
                if block.height < starting_block_height {
                    panic!(
                        "Latest block has height {}, less than start height {}",
                        block.height, starting_block_height
                    );
                }

                info!(
                    "Continuing from block height {} ({})",
                    block.height, block.hash
                );

                self.option_last_height = Some(block.height);
                self.option_last_hash = Some(block.hash);
            }
            None => {
                info!(
                    "No previous blocks found, starting from height {}",
                    starting_block_height
                );
                self.option_last_height = Some(starting_block_height);
            }
        }
    }

    async fn rollback(&mut self, height: u64) {
        rollback_to_height(&self.writer.connection(), height)
            .await
            .unwrap();
        self.option_last_height = Some(height);

        if let Some(block) =
            select_block_at_height(&*self.reader.connection().await.unwrap(), height)
                .await
                .unwrap()
        {
            self.option_last_hash = Some(block.hash);
            info!("Rollback to height {} ({})", height, block.hash);
        } else {
            warn!("Rollback to height {}, no previous block found", height);
        }
    }

    async fn handle_block<T: Tx + 'static>(&mut self, block: Block<T>) {
        let height = block.height;
        let hash = block.hash;
        let prev_hash = block.prev_hash;

        let last_height = self.option_last_height.unwrap();
        if height != last_height + 1 {
            error!(
                "Order exception, received block at height {}, expected height {}",
                height,
                last_height + 1
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
            }
        }

        self.option_last_height = Some(height);
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
    mut rx: Receiver<Event<T>>,
) -> JoinHandle<()> {
    let mut reactor = Reactor::new(reader, writer, cancel_token.clone());

    tokio::spawn({
        async move {
            reactor.init(starting_block_height).await;

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
