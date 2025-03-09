use tokio::{select, sync::mpsc::Receiver, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{
    bitcoin_follower::events::Event,
    block::Tx,
    database::{self, types::BlockRow},
};

pub fn run<T: Tx + 'static>(
    cancel_token: CancellationToken,
    _reader: database::Reader,
    writer: database::Writer,
    mut rx: Receiver<Event<T>>,
) -> JoinHandle<()> {
    tokio::spawn({
        let mut option_last_height = None;
        async move {
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
                                    Event::Block(block) => {
                                        let height = block.height;
                                        let hash = block.hash;
                                        if let Some(last_height) = option_last_height {
                                            if height != last_height + 1 {
                                                error!("Order exception");
                                                cancel_token.cancel();
                                            }
                                        }
                                        option_last_height = Some(height);
                                        writer.insert_block(
                                            BlockRow {
                                                height,
                                                hash,
                                            }
                                        ).await.unwrap();
                                        info!("Block {} {}", height, hash);
                                    },
                                    Event::Rollback(height) => {
                                        writer.rollback_to_height(height).await.unwrap();
                                        option_last_height = Some(height);
                                        info!("Rollback {}" ,height);
                                    },
                                    Event::MempoolUpdate {removed, added} => {
                                        info!("MempoolUpdates removed {} added {}", removed.len(), added.len());
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
