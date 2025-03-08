use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use bitcoin::Transaction;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tokio::{
    select,
    sync::{
        Semaphore,
        mpsc::{self, Sender},
    },
    task::JoinHandle,
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{
    bitcoin_client,
    block::{Block, Tx},
    retry::{new_backoff_unlimited, retry},
};

#[derive(Debug)]
pub struct Fetcher<T: Tx> {
    handle: Option<JoinHandle<()>>,
    cancel_token: CancellationToken,
    bitcoin: bitcoin_client::Client,
    f: fn(Transaction) -> T,
    tx: Sender<(u64, Block<T>)>,
}

impl<T: Tx + 'static> Fetcher<T> {
    pub fn new(
        bitcoin: bitcoin_client::Client,
        f: fn(Transaction) -> T,
        tx: Sender<(u64, Block<T>)>,
    ) -> Self {
        Self {
            handle: None,
            cancel_token: CancellationToken::new(),
            bitcoin,
            f,
            tx,
        }
    }

    pub fn start(&mut self, start_height: u64) {
        info!("Starting at height: {}", start_height);
        self.handle = Some(tokio::spawn({
            let bitcoin = self.bitcoin.clone();
            let cancel_token = self.cancel_token.clone();
            let (tx_1, mut rx_1) = mpsc::channel(10);
            let (tx_2, mut rx_2) = mpsc::channel(10);
            let (tx_3, mut rx_3) = mpsc::channel(10);
            let f = self.f;
            let tx = self.tx.clone();
            async move {
                let producer = tokio::spawn({
                    let cancel_token = cancel_token.clone();
                    let bitcoin = bitcoin.clone();
                    async move {
                        let mut height = start_height;
                        let mut target_height = height;
                        loop {
                            if cancel_token.is_cancelled() {
                                info!("Producer cancelled");
                                break;
                            }

                            if target_height == height {
                                if target_height != start_height {
                                    sleep(Duration::from_secs(10)).await;
                                }

                                match retry(
                                    || bitcoin.get_blockchain_info(),
                                    "get blockchain info",
                                    new_backoff_unlimited(),
                                    cancel_token.clone(),
                                )
                                .await
                                {
                                    Ok(info) => {
                                        target_height = info.blocks;
                                    }
                                    Err(e) => {
                                        info!(
                                            "Producer cancelled while fetching blockchain info: {}",
                                            e
                                        );
                                    }
                                }

                                continue;
                            }

                            if tx_1.send((target_height, height)).await.is_err() {
                                info!("Producer send channel closed, exiting");
                                break;
                            }

                            height += 1;
                        }

                        info!("Producer exiting");
                    }
                });

                let fetcher = tokio::spawn({
                    let cancel_token = cancel_token.clone();
                    let bitcoin = bitcoin.clone();
                    async move {
                        let semaphore = Arc::new(Semaphore::new(10));
                        loop {
                            select! {
                                _ = cancel_token.cancelled() => {
                                    info!("Fetcher cancelled");
                                    break;
                                }
                                option_height = rx_1.recv() => {
                                    match option_height {
                                        Some((target_height, height)) => {
                                            let bitcoin = bitcoin.clone();
                                            let cancel_token = cancel_token.clone();
                                            let tx = tx_2.clone();
                                            let permit = semaphore.clone().acquire_owned().await.unwrap();
                                            tokio::spawn(
                                                async move {
                                                    let _permit = permit;
                                                    if let Ok(block_hash) = retry(
                                                        || bitcoin.get_block_hash(height),
                                                        "get block hash",
                                                        new_backoff_unlimited(),
                                                        cancel_token.clone(),
                                                    )
                                                    .await {
                                                        if let Ok(block) = retry(
                                                            || bitcoin.get_block(&block_hash),
                                                            "get block",
                                                            new_backoff_unlimited(),
                                                            cancel_token.clone(),
                                                        )
                                                        .await {
                                                            let _ = tx.send((target_height, height, block)).await;
                                                        }
                                                    }
                                                }
                                            );
                                        },
                                        None => {
                                            info!("Fetcher received None message, exiting");
                                            break;
                                        },
                                    }
                                }
                            }
                        }

                        rx_1.close();
                        while rx_1.recv().await.is_some() {}
                        info!("Fetcher exited");
                    }
                });

                let processor = tokio::spawn({
                    let cancel_token = cancel_token.clone();
                    async move {
                        let semaphore = Arc::new(Semaphore::new(10));
                        loop {
                            select! {
                                _ = cancel_token.cancelled() => {
                                    info!("Processor cancelled");
                                    break;
                                }
                                option_block = rx_2.recv() => {
                                    match option_block {
                                        Some((target_height, height, block)) => {
                                            let tx = tx_3.clone();
                                            let permit = semaphore.clone().acquire_owned().await.unwrap();
                                            tokio::spawn(
                                                async move {
                                                    let _permit = permit;
                                                    let _ = tx.send((
                                                        target_height,
                                                        Block {
                                                            height,
                                                            hash: block.block_hash(),
                                                            prev_hash: block.header.prev_blockhash,
                                                            transactions: block.txdata.into_par_iter().map(f).collect(),
                                                        })
                                                    ).await;
                                                }
                                            );
                                        },
                                        None => {
                                            info!("Procesor received None message, exiting");
                                            break;
                                        },
                                    }
                                }
                            }
                        }

                        rx_2.close();
                        while rx_2.recv().await.is_some() {}
                        info!("Processor exited");
                    }
                });

                let orderer = tokio::spawn({
                    let cancel_token = cancel_token.clone();
                    async move {
                        let mut heap = BinaryHeap::new();
                        let mut next_index = start_height;
                        let mut pending_blocks = HashMap::new();
                        loop {
                            let mut target_height = 0;
                            select! {
                                _ = cancel_token.cancelled() => {
                                    info!("Orderer cancelled");
                                    break;
                                }
                                option_pair = rx_3.recv() => {
                                    match option_pair {
                                        Some((new_target_height, block)) => {
                                            if new_target_height > target_height {
                                                target_height = new_target_height;
                                            }
                                            heap.push(Reverse(block.height));
                                            pending_blocks.insert(block.height, block);
                                            while let Some(&Reverse(maybe_next_index)) = heap.peek() {
                                                if maybe_next_index == next_index {
                                                    heap.pop();
                                                    if let Some(block) = pending_blocks.remove(&next_index) {
                                                        if tx.send((target_height, block)).await.is_err() {
                                                            info!("Orderer send channel closed, exiting");
                                                            break;
                                                        };
                                                        next_index += 1;
                                                    }
                                                } else {
                                                    break;
                                                }
                                            }
                                        },
                                        None => {
                                            info!("Orderer received None message, exiting");
                                            break;
                                        },
                                    }
                                }
                            }
                        }

                        rx_3.close();
                        while rx_3.recv().await.is_some() {}
                        info!("Orderer exited");
                    }
                });

                for handle in [producer, fetcher, processor, orderer] {
                    if let Err(e) = handle.await {
                        error!("Fetcher sub task panicked on join: {}", e);
                    }
                }
            }
        }));
    }

    pub async fn stop(&mut self) -> Result<()> {
        if let Some(handle) = self.handle.take() {
            info!("Exiting");
            self.cancel_token.cancel();
            handle.await?;
        }
        info!("Exited");
        Ok(())
    }
}
