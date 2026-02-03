use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use indexer_types::{Block, Transaction};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use tokio::{
    select,
    sync::{
        Semaphore,
        mpsc::{self, Receiver, Sender},
    },
    task::JoinHandle,
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{
    bitcoin_client::client::BitcoinRpc,
    block::TransactionFilterMap,
    retry::{new_backoff_limited, new_backoff_unlimited, retry},
};

pub fn run_producer<C: BitcoinRpc>(
    start_height: u64,
    bitcoin: C,
    cancel_token: CancellationToken,
) -> (JoinHandle<()>, Receiver<(u64, u64)>) {
    let (tx, rx) = mpsc::channel(10);

    let producer = tokio::spawn({
        async move {
            let mut height = start_height;
            let mut target_height = height - 1;
            loop {
                if cancel_token.is_cancelled() {
                    info!("Producer cancelled");
                    break;
                }

                if target_height < height {
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
                            info!("Producer cancelled while fetching blockchain info: {}", e);
                        }
                    }
                }

                if target_height < height {
                    select! {
                        _ = sleep(Duration::from_secs(10)) => {}
                        _ = cancel_token.cancelled() => {}
                    }

                    continue;
                }

                if tx.send((target_height, height)).await.is_err() {
                    info!("Producer send channel closed, exiting");
                    break;
                }

                height += 1;
            }

            info!("Producer exiting");
        }
    });

    (producer, rx)
}

pub fn run_fetcher<C: BitcoinRpc>(
    mut rx_in: Receiver<(u64, u64)>,
    bitcoin: C,
    cancel_token: CancellationToken,
) -> (JoinHandle<()>, Receiver<(u64, u64, bitcoin::Block)>) {
    let (tx_out, rx_out) = mpsc::channel(10);

    let fetcher = tokio::spawn({
        async move {
            let semaphore = Arc::new(Semaphore::new(10));
            loop {
                select! {
                    _ = cancel_token.cancelled() => {
                        info!("Fetcher cancelled");
                        break;
                    }
                    option_height = rx_in.recv() => {
                        match option_height {
                            Some((target_height, height)) => {
                                let bitcoin = bitcoin.clone();
                                let cancel_token = cancel_token.clone();
                                let tx = tx_out.clone();
                                let permit = semaphore
                                    .clone()
                                    .acquire_owned()
                                    .await
                                    .expect("semaphore.acquired_owned failed despite never being closed");
                                tokio::spawn(
                                    async move {
                                        if let Ok(block_hash) = retry(
                                            || bitcoin.get_block_hash(height),
                                            "get block hash",
                                            new_backoff_unlimited(),
                                            cancel_token.clone(),
                                        )
                                        .await
                                            && let Ok(block) = retry(
                                                || bitcoin.get_block(&block_hash),
                                                "get block",
                                                new_backoff_unlimited(),
                                                cancel_token.clone(),
                                            )
                                            .await {
                                                let _ = tx.send((target_height, height, block)).await;
                                            }
                                        drop(permit);
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

            rx_in.close();
            while rx_in.recv().await.is_some() {} // drain messages to free up blocked senders
            info!("Fetcher exited");
        }
    });

    (fetcher, rx_out)
}

pub fn run_processor(
    mut rx_in: Receiver<(u64, u64, bitcoin::Block)>,
    f: TransactionFilterMap,
    cancel_token: CancellationToken,
) -> (JoinHandle<()>, Receiver<(u64, Block)>) {
    let (tx_out, rx_out) = mpsc::channel(10);

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
                    option_block = rx_in.recv() => {
                        match option_block {
                            Some((target_height, height, block)) => {
                                let tx = tx_out.clone();
                                let permit = semaphore
                                    .clone()
                                    .acquire_owned()
                                    .await
                                    .expect("semaphore.acquired_owned failed despite never being closed");
                                tokio::spawn(async move {
                                    let _ = tx
                                        .send((
                                            target_height,
                                            Block {
                                                height,
                                                hash: block.block_hash(),
                                                prev_hash: block.header.prev_blockhash,
                                                transactions: tokio::task::spawn_blocking(move || {
                                                    let mut txs: Vec<Transaction> = block
                                                        .txdata
                                                        .into_par_iter()
                                                        .enumerate()
                                                        .filter_map(f)
                                                        .collect();
                                                    txs.sort_by_key(|t| t.index);
                                                    txs
                                                })
                                                .await
                                                .expect("spawn_blocking failed in rpc block processing"),
                                            },
                                        ))
                                        .await;
                                    drop(permit);
                                });
                            },
                            None => {
                                info!("Processor received None message, exiting");
                                break;
                            },
                        }
                    }
                }
            }

            rx_in.close();
            while rx_in.recv().await.is_some() {}
            info!("Processor exited");
        }
    });

    (processor, rx_out)
}

pub fn run_orderer(
    start_height: u64,
    mut rx: Receiver<(u64, Block)>,
    tx: Sender<(u64, Block)>,
    cancel_token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn({
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
                    option_pair = rx.recv() => {
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

            rx.close();
            while rx.recv().await.is_some() {}
            info!("Orderer exited");
        }
    })
}

#[derive(Debug)]
pub struct Fetcher<C: BitcoinRpc> {
    handle: Option<JoinHandle<()>>,
    cancel_token: CancellationToken,
    bitcoin: C,
    f: TransactionFilterMap,
    tx: Sender<(u64, Block)>,
}

impl<C: BitcoinRpc> Fetcher<C> {
    pub fn new(bitcoin: C, f: TransactionFilterMap, tx: Sender<(u64, Block)>) -> Self {
        Self {
            handle: None,
            cancel_token: CancellationToken::new(),
            bitcoin,
            f,
            tx,
        }
    }

    pub fn running(&self) -> bool {
        self.handle.is_some()
    }

    pub fn start(&mut self, start_height: u64) {
        info!("Starting at height: {}", start_height);
        self.handle = Some(tokio::spawn({
            let bitcoin = self.bitcoin.clone();
            let cancel_token = self.cancel_token.clone();
            let f = self.f;
            let tx = self.tx.clone();

            async move {
                let (producer, rx_1) =
                    run_producer(start_height, bitcoin.clone(), cancel_token.clone());
                let (fetcher, rx_2) = run_fetcher(rx_1, bitcoin.clone(), cancel_token.clone());
                let (processor, rx_3) = run_processor(rx_2, f, cancel_token.clone());
                let orderer = run_orderer(start_height, rx_3, tx, cancel_token.clone());

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
            self.cancel_token = CancellationToken::new();
        }
        info!("Exited");
        Ok(())
    }
}

pub trait BlockFetcher {
    fn running(&self) -> bool;
    fn start(&mut self, start_height: u64);
    fn stop(&mut self) -> impl Future<Output = Result<()>>;
}

impl<C: BitcoinRpc> BlockFetcher for Fetcher<C> {
    fn running(&self) -> bool {
        self.running()
    }

    fn start(&mut self, start_height: u64) {
        self.start(start_height);
    }

    async fn stop(&mut self) -> Result<()> {
        self.stop().await
    }
}

#[derive(Debug)]
pub struct MempoolFetcherImpl<C: BitcoinRpc> {
    cancel_token: CancellationToken,
    bitcoin: C,
    f: TransactionFilterMap,
}

impl<C: BitcoinRpc> MempoolFetcherImpl<C> {
    pub fn new(cancel_token: CancellationToken, bitcoin: C, f: TransactionFilterMap) -> Self {
        Self {
            cancel_token,
            bitcoin,
            f,
        }
    }

    pub async fn get_mempool(&mut self) -> Result<Vec<Transaction>> {
        let mempool_txids = retry(
            || self.bitcoin.get_raw_mempool(),
            "get raw mempool",
            new_backoff_limited(),
            self.cancel_token.clone(),
        )
        .await?;

        info!("Getting mempool transactions: {}", mempool_txids.len());
        let mut txs: Vec<bitcoin::Transaction> = vec![];
        for txids in mempool_txids.chunks(100) {
            if self.cancel_token.is_cancelled() {
                break;
            }

            let results = retry(
                || self.bitcoin.get_raw_transactions(txids),
                "get raw transactions",
                new_backoff_limited(),
                self.cancel_token.clone(),
            )
            .await?;
            txs.extend(results.into_iter().filter_map(Result::ok));
            info!(
                "Got mempool transaction: {}/{}",
                txs.len(),
                mempool_txids.len()
            );
        }

        Ok(tokio::task::spawn_blocking({
            let f = self.f;
            move || txs.into_par_iter().enumerate().filter_map(f).collect()
        })
        .await?)
    }
}

pub trait MempoolFetcher {
    fn get_mempool(&mut self) -> impl Future<Output = Result<Vec<Transaction>>>;
}

impl<C: BitcoinRpc> MempoolFetcher for MempoolFetcherImpl<C> {
    async fn get_mempool(&mut self) -> Result<Vec<Transaction>> {
        self.get_mempool().await
    }
}
