use std::{collections::HashSet, path::Path};

use anyhow::Result;
use kontor::{
    bitcoin_client,
    bitcoin_follower::{self, event::Event},
    config::Config,
    database::{self, types::BlockRow},
    logging, stopper,
};
use tokio::{select, sync::mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    logging::setup();
    info!("Hello, World!");
    let config = Config::load()?;
    let bitcoin = bitcoin_client::Client::new_from_config(config.clone())?;
    let cancel_token = CancellationToken::new();
    let stopper_handle = stopper::run(cancel_token.clone());
    let (tx, mut rx) = mpsc::unbounded_channel();
    let db_path = Path::new("~/Desktop/test.db");
    let reader = database::Reader::new(db_path).await?;
    let writer = database::Writer::new(db_path).await?;
    let reconciler_handle = tokio::spawn({
        let cancel_token = cancel_token.clone();
        let reader = reader.clone();
        async move {
            let _ = bitcoin_follower::reconciler::run(
                config.clone(),
                cancel_token.clone(),
                reader,
                bitcoin.clone(),
                HashSet::new(),
                |t| t,
                tx,
            )
            .await
            .await;
            cancel_token.cancel();
        }
    });
    let consumer_handle = tokio::spawn({
        let cancel_token = cancel_token.clone();
        let mut option_last_height = None;
        async move {
            loop {
                select! {
                    _ = cancel_token.cancelled() => {
                        info!("Consumer cancelled");
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
                                        info!("Rollback {}" ,height);
                                    },
                                    Event::MempoolUpdates {added, removed} => {
                                        info!("MempoolUpdates added {} removed {}", added.len(), removed.len());
                                    },
                                }
                            },
                            None => {
                                info!("Consumer received None event, exiting");
                                break;
                            },
                        }
                    }
                }
            }
            info!("Consumer exiting");
        }
    });
    let _ = consumer_handle.await;
    let _ = reconciler_handle.await;
    let _ = stopper_handle.await;
    info!("Goodbye.");
    Ok(())
}
