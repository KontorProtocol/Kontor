pub mod types;

use anyhow::{Result, bail};
use indexer_types::{Block, BlockRow, Event, Op, TransactionRow};
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
        events::{BlockId, Event as FollowerEvent},
    },
    database::{
        self,
        queries::{
            insert_block, insert_processed_block, insert_transaction, rollback_to_height,
            select_block_at_height, select_block_latest, select_block_with_hash,
            set_block_processed,
        },
    },
    runtime::{ComponentCache, FileLedger, Runtime, Storage, storage_protocol},
    test_utils::new_mock_block_hash,
};

struct Reactor {
    reader: database::Reader,
    writer: database::Writer,
    cancel_token: CancellationToken,
    ctrl: CtrlChannel,
    bitcoin_event_rx: Option<Receiver<FollowerEvent>>,
    init_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
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
        event_tx: Option<mpsc::Sender<Event>>,
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
            .tx_index(0)
            .conn(writer.connection())
            .build();

        // Rebuild FileLedger from database (for PoR verification)
        let file_ledger = FileLedger::rebuild_from_db(&storage.clone()).await?;

        let mut runtime =
            Runtime::new_with_file_ledger(storage, ComponentCache::new(), file_ledger).await?;
        runtime.publish_native_contracts().await?;
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

        // Resync FileLedger after rollback (DB entries deleted via CASCADE)
        self.runtime
            .file_ledger
            .resync_from_db(&self.runtime.storage)
            .await?;

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
                if let Some(tx) = &self.event_tx {
                    let _ = tx.send(Event::Rolledback { height }).await;
                }
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
        insert_block(&conn, (&block).into()).await?;

        info!("# Block Kontor Transactions: {}", block.transactions.len());

        for t in &block.transactions {
            insert_transaction(
                &conn,
                TransactionRow::builder()
                    .height(height as i64)
                    .tx_index(t.index)
                    .txid(t.txid.to_string())
                    .build(),
            )
            .await?;
            for op in &t.ops {
                let metadata = op.metadata();
                let input_index = metadata.input_index;
                let op_return_data = t.op_return_data.get(&(input_index as u64)).cloned();
                info!("Op return data: {:#?}", op_return_data);
                self.runtime
                    .set_context(
                        height as i64,
                        t.index,
                        input_index,
                        0,
                        t.txid,
                        Some(metadata.previous_output),
                        op_return_data.map(Into::into),
                    )
                    .await;

                match op {
                    Op::Publish {
                        metadata,
                        gas_limit,
                        name,
                        bytes,
                    } => {
                        self.runtime.set_gas_limit(*gas_limit);
                        let result = self.runtime.publish(&metadata.signer, name, bytes).await;
                        if result.is_err() {
                            warn!("Publish operation failed: {:?}", result);
                        }
                    }
                    Op::Call {
                        metadata,
                        gas_limit,
                        contract,
                        expr,
                    } => {
                        self.runtime.set_gas_limit(*gas_limit);
                        let result = self
                            .runtime
                            .execute(Some(&metadata.signer), &(contract.into()), expr)
                            .await;
                        if result.is_err() {
                            warn!("Call operation failed: {:?}", result);
                        }
                    }
                    Op::Issuance { metadata, .. } => {
                        let result = self.runtime.issuance(&metadata.signer).await;
                        if result.is_err() {
                            warn!("Issuance operation failed: {:?}", result);
                        }
                    }
                    Op::CreateAgreement {
                        metadata: _,
                        file_id,
                        root,
                        tree_depth,
                    } => {
                        let result = storage_protocol::handle_create_agreement(
                            &self.runtime.storage,
                            &self.runtime.file_ledger,
                            file_id.clone(),
                            root.clone(),
                            *tree_depth,
                        )
                        .await;
                        if let Err(e) = result {
                            warn!("CreateAgreement operation failed: {:?}", e);
                        }
                    }
                };
            }
        }

        set_block_processed(&conn, height as i64).await?;
        if !block.transactions.is_empty()
            && let Some(tx) = &self.event_tx
        {
            let _ = tx.send(Event::Processed { block }).await;
        }
        info!("Block processed");

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
                                FollowerEvent::BlockInsert((target_height, block)) => {
                                    info!("Block {}/{} {}", block.height,
                                          target_height, block.hash);
                                    debug!("(implicit) MempoolRemove {}", block.transactions.len());
                                    self.handle_block(block).await?;
                                },
                                FollowerEvent::BlockRemove(BlockId::Height(height)) => {
                                    info!("(implicit) MempoolClear");
                                    self.rollback(height).await?;
                                },
                                FollowerEvent::BlockRemove(BlockId::Hash(block_hash)) => {
                                    info!("(implicit) MempoolClear");
                                    self.rollback_hash(block_hash).await?;
                                },
                                FollowerEvent::MempoolRemove(removed) => {
                                    debug!("MempoolRemove {}", removed.len());
                                },
                                FollowerEvent::MempoolInsert(added) => {
                                    debug!("MempoolInsert {}", added.len());
                                },
                                FollowerEvent::MempoolSet(txs) => {
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
    event_tx: Option<mpsc::Sender<Event>>,
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
