pub mod results;
pub mod types;

use anyhow::{Result, bail};
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
    bitcoin_follower::{
        ctrl::CtrlChannel,
        events::{BlockId, Event},
    },
    block::Block,
    database::{
        self,
        queries::{
            insert_block, insert_transaction, rollback_to_height, select_block_at_height,
            select_block_latest, select_block_with_hash, set_block_processed,
        },
        types::{BlockRow, TransactionRow},
    },
    reactor::{results::ResultEvent, types::Op},
    runtime::{ComponentCache, Runtime, Storage},
};

struct Reactor {
    reader: database::Reader,
    writer: database::Writer,
    cancel_token: CancellationToken, // currently not used due to relaxed error handling
    ctrl: CtrlChannel,
    bitcoin_event_rx: Option<Receiver<Event>>,
    init_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<ResultEvent>>,
    runtime: Runtime,

    last_height: u64,
    option_last_hash: Option<BlockHash>,
}

impl Reactor {
    pub async fn new(
        starting_block_height: u64,
        reader: database::Reader,
        writer: database::Writer,
        ctrl: CtrlChannel,
        cancel_token: CancellationToken,
        init_tx: Option<oneshot::Sender<bool>>,
        event_tx: Option<mpsc::Sender<ResultEvent>>,
    ) -> Result<Self> {
        let conn = &*reader.connection().await?;
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

        let storage = Storage::builder().conn(writer.connection()).build();
        storage.store_native_contracts().await?;
        let runtime = Runtime::new(storage, ComponentCache::new()).await?;
        Ok(Self {
            reader,
            writer,
            cancel_token,
            ctrl,
            bitcoin_event_rx: None,
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

        let conn = &self.reader.connection().await?;
        if let Some(block) = select_block_at_height(conn, height as i64).await? {
            self.option_last_hash = Some(block.hash);
            info!("Rollback to height {} ({})", height, block.hash);
        } else {
            self.option_last_hash = None;
            warn!("Rollback to height {}, no previous block found", height);
        }

        info!("Seek: start fetching from height {}", self.last_height + 1);
        match self
            .ctrl
            .clone()
            .start(self.last_height + 1, self.option_last_hash)
            .await
        {
            Ok(bitcoin_event_rx) => {
                // close and drain old channel before switching to the new one
                if let Some(rx) = self.bitcoin_event_rx.as_mut() {
                    rx.close();
                    while rx.recv().await.is_some() {}
                }
                self.bitcoin_event_rx = Some(bitcoin_event_rx);
                Ok(())
            }
            Err(e) => {
                bail!("Failed to execute start: {}", e);
            }
        }
    }

    async fn rollback_hash(&mut self, hash: BlockHash) -> Result<()> {
        let conn = &self.writer.connection();
        let block_row = select_block_with_hash(conn, &hash).await?;
        if let Some(row) = block_row {
            self.rollback((row.height as u64) - 1).await
        } else {
            error!("attemped rollback to hash {} failed, block not found", hash);
            Ok(())
        }
    }

    async fn handle_block(&mut self, block: Block) -> Result<()> {
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

        let conn = self.writer.connection();
        insert_block(
            &conn,
            BlockRow {
                height: height as i64,
                hash,
            },
        )
        .await?;

        info!("# Block Kontor Transactions: {}", block.transactions.len());

        for t in block.transactions {
            insert_transaction(
                &conn,
                TransactionRow::builder()
                    .height(height as i64)
                    .tx_index(t.index)
                    .txid(t.txid.to_string())
                    .build(),
            )
            .await?;
            for op in t.ops {
                let input_index = op.metadata().input_index;
                self.runtime
                    .set_context(height as i64, t.index, input_index, 0, t.txid)
                    .await;

                match op {
                    Op::Publish {
                        metadata,
                        name,
                        bytes,
                    } => {
                        let _ = self.runtime.publish(&metadata.signer, &name, &bytes).await;
                    }
                    Op::Call {
                        metadata,
                        contract,
                        expr,
                    } => {
                        let _ = self
                            .runtime
                            .execute(Some(&metadata.signer), &contract, &expr)
                            .await;
                    }
                    Op::Issuance { metadata, .. } => {
                        let _ = self.runtime.issuance(&metadata.signer).await;
                    }
                };

                if let Some(tx) = self.event_tx.clone() {
                    for event in self.runtime.events.take_all().await {
                        tx.send(event).await?;
                    }
                }
            }
        }

        set_block_processed(&conn, height as i64).await?;

        Ok(())
    }

    async fn run_event_loop(&mut self) -> Result<()> {
        let rx = match self
            .ctrl
            .clone()
            .start(self.last_height + 1, self.option_last_hash)
            .await
        {
            Ok(rx) => rx,
            Err(e) => {
                bail!("initial start failed: {}", e);
            }
        };

        self.bitcoin_event_rx = Some(rx);
        self.init_tx.take().map(|tx| tx.send(true));

        loop {
            let bitcoin_event_rx = match self.bitcoin_event_rx.as_mut() {
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
                option_event = bitcoin_event_rx.recv() => {
                    match option_event {
                        Some(event) => {
                            match event {
                                Event::BlockInsert((target_height, block)) => {
                                    info!("Block {}/{} {}", block.height,
                                          target_height, block.hash);
                                    debug!("(implicit) MempoolRemove {}", block.transactions.len());
                                    self.handle_block(block).await?;
                                },
                                Event::BlockRemove(BlockId::Height(height)) => {
                                    info!("(implicit) MempoolClear");
                                    self.rollback(height).await?;
                                },
                                Event::BlockRemove(BlockId::Hash(block_hash)) => {
                                    info!("(implicit) MempoolClear");
                                    self.rollback_hash(block_hash).await?;
                                },
                                Event::MempoolRemove(removed) => {
                                    debug!("MempoolRemove {}", removed.len());
                                },
                                Event::MempoolInsert(added) => {
                                    debug!("MempoolInsert {}", added.len());
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
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        let res = self.run_event_loop().await;

        if let Some(rx) = self.bitcoin_event_rx.as_mut() {
            rx.close();
            while rx.recv().await.is_some() {}
        }

        res
    }
}

pub fn run(
    starting_block_height: u64,
    cancel_token: CancellationToken,
    reader: database::Reader,
    writer: database::Writer,
    ctrl: CtrlChannel,
    init_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<ResultEvent>>,
) -> JoinHandle<()> {
    tokio::spawn({
        async move {
            let mut reactor = match Reactor::new(
                starting_block_height,
                reader,
                writer,
                ctrl.clone(),
                cancel_token.clone(),
                init_tx,
                event_tx,
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
