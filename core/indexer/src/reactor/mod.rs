pub mod types;

use anyhow::{Result, anyhow, bail};
use futures_util::future::pending;
use indexer_types::{Block, BlockRow, Event, Op, OpWithResult, TransactionRow};
use tokio::{
    select,
    sync::{
        mpsc::{self, Receiver},
        oneshot,
    },
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use bitcoin::{BlockHash, hashes::Hash};
use tracing::{debug, error, info, warn};

use crate::{
    bitcoin_follower::event::BitcoinEvent,
    block::{filter_map, inspect},
    database::{
        self,
        queries::{
            insert_block, insert_processed_block, insert_transaction, rollback_to_height,
            select_block_at_height, select_block_latest, set_block_processed,
        },
    },
    runtime::{ComponentCache, Runtime, Storage, TransactionContext, filestorage, wit::Signer},
    test_utils::new_mock_block_hash,
};

pub type Simulation = (
    bitcoin::Transaction,
    oneshot::Sender<Result<Vec<OpWithResult>>>,
);

struct Reactor {
    writer: database::Writer,
    cancel_token: CancellationToken,
    bitcoin_event_rx: Receiver<BitcoinEvent>,
    init_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
    runtime: Runtime,
    simulate_rx: Option<Receiver<Simulation>>,

    last_height: u64,
    option_last_hash: Option<BlockHash>,
}

pub async fn simulate_handler(
    runtime: &mut Runtime,
    btx: bitcoin::Transaction,
) -> Result<Vec<OpWithResult>> {
    let tx = filter_map((0, btx.clone())).ok_or(anyhow!("Invalid transaction"))?;
    runtime.storage.savepoint().await?;
    let block_row = select_block_latest(&runtime.storage.conn).await?;
    let height = block_row.as_ref().map_or(1, |row| row.height as u64 + 1);
    block_handler(
        runtime,
        &Block {
            height,
            hash: new_mock_block_hash(height as u32),
            prev_hash: block_row
                .as_ref()
                .map_or(new_mock_block_hash(0), |row| row.hash),
            transactions: vec![tx],
        },
    )
    .await?;
    let result = inspect(&runtime.storage.conn, btx).await;
    runtime
        .storage
        .rollback()
        .await
        .expect("Failed to rollback");
    result
}

pub async fn block_handler(runtime: &mut Runtime, block: &Block) -> Result<()> {
    insert_block(&runtime.storage.conn, block.into()).await?;

    for t in &block.transactions {
        insert_transaction(
            &runtime.storage.conn,
            TransactionRow::builder()
                .height(block.height as i64)
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
            runtime
                .set_context(
                    block.height as i64,
                    Some(TransactionContext {
                        tx_index: t.index,
                        input_index,
                        op_index: 0,
                        txid: t.txid,
                    }),
                    Some(metadata.previous_output),
                    op_return_data.clone().map(Into::into),
                )
                .await;

            match op {
                Op::Publish {
                    metadata,
                    gas_limit,
                    name,
                    bytes,
                } => {
                    runtime.set_gas_limit(*gas_limit);
                    let result = runtime.publish(&metadata.signer, name, bytes).await;
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
                    runtime.set_gas_limit(*gas_limit);
                    let result = runtime
                        .execute(Some(&metadata.signer), &(contract.into()), expr)
                        .await;
                    if result.is_err() {
                        warn!("Call operation failed: {:?}", result);
                    }
                }
                Op::Issuance { metadata, .. } => {
                    let result = runtime.issuance(&metadata.signer).await;
                    if result.is_err() {
                        warn!("Issuance operation failed: {:?}", result);
                    }
                }
                Op::RegisterBlsKey {
                    metadata,
                    bls_pubkey,
                    schnorr_sig,
                    bls_sig,
                } => {
                    if let Err(e) = runtime
                        .register_bls_key(
                            &metadata.signer,
                            bls_pubkey.as_slice(),
                            schnorr_sig.as_slice(),
                            bls_sig.as_slice(),
                        )
                        .await
                    {
                        warn!("RegisterBlsKey failed: {e}");
                    }
                }
                Op::BlsBulk {
                    metadata,
                    signature,
                    ops,
                } => {
                    // TODO(blsbulk): Verify BLS aggregate signature + replay protection before executing.
                    let _sig = signature;

                    for (inner_index, inner_op) in ops.iter().enumerate() {
                        runtime
                            .set_context(
                                block.height as i64,
                                Some(TransactionContext {
                                    tx_index: t.index,
                                    input_index,
                                    op_index: inner_index as i64,
                                    txid: t.txid,
                                }),
                                Some(metadata.previous_output),
                                op_return_data.clone().map(Into::into),
                            )
                            .await;

                        match inner_op {
                            indexer_types::BlsBulkOp::Call {
                                signer,
                                gas_limit,
                                contract,
                                expr,
                            } => {
                                runtime.set_gas_limit(*gas_limit);
                                let result = runtime
                                    .execute(Some(signer), &(contract.into()), expr)
                                    .await;
                                if result.is_err() {
                                    warn!("BlsBulk call operation failed: {:?}", result);
                                }
                            }
                            indexer_types::BlsBulkOp::RegisterBlsKey {
                                signer,
                                bls_pubkey,
                                schnorr_sig,
                                bls_sig,
                            } => {
                                if let Err(e) = runtime
                                    .register_bls_key(
                                        signer,
                                        bls_pubkey.as_slice(),
                                        schnorr_sig.as_slice(),
                                        bls_sig.as_slice(),
                                    )
                                    .await
                                {
                                    warn!("BlsBulk RegisterBlsKey failed: {e}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let core_signer = Signer::Core(Box::new(Signer::Nobody));
    let block_hash: Vec<u8> = block.hash.to_byte_array().to_vec();
    runtime
        .set_context(block.height as i64, None, None, None)
        .await;
    filestorage::api::expire_challenges(runtime, &core_signer, block.height)
        .await
        .expect("Failed to expire challenges");
    let challenges = filestorage::api::generate_challenges_for_block(
        runtime,
        &core_signer,
        block.height,
        block_hash,
    )
    .await
    .expect("Failed to generate challenges");
    if !challenges.is_empty() {
        info!(
            "Generated {} challenges at block height {}",
            challenges.len(),
            block.height
        );
    }

    set_block_processed(&runtime.storage.conn, block.height as i64).await?;

    Ok(())
}

impl Reactor {
    pub async fn new(
        starting_block_height: u64,
        writer: database::Writer,
        bitcoin_event_rx: Receiver<BitcoinEvent>,
        cancel_token: CancellationToken,
        init_tx: Option<oneshot::Sender<bool>>,
        event_tx: Option<mpsc::Sender<Event>>,
        simulate_rx: Option<Receiver<Simulation>>,
    ) -> Result<Self> {
        let conn = &writer.connection();
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
            .conn(writer.connection())
            .build();

        let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
        runtime.publish_native_contracts().await?;
        Ok(Self {
            writer,
            cancel_token,
            bitcoin_event_rx,
            simulate_rx,
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

        self.runtime
            .file_ledger
            .force_resync_from_db(&self.runtime.storage.conn)
            .await?;

        let conn = &self.writer.connection();
        if let Some(block) = select_block_at_height(conn, height as i64).await? {
            self.option_last_hash = Some(block.hash);
            info!("Rollback to height {} ({})", height, block.hash);
        } else {
            self.option_last_hash = None;
            warn!("Rollback to height {}, no previous block found", height);
        }

        if let Some(tx) = &self.event_tx {
            let _ = tx.send(Event::Rolledback { height }).await;
        }

        Ok(())
    }

    async fn handle_block(&mut self, block: Block) -> Result<()> {
        let height = block.height;
        let hash = block.hash;
        let prev_hash = block.prev_hash;

        if height != self.last_height + 1 {
            bail!(
                "Unexpected block height {}, expected {}",
                height,
                self.last_height + 1
            );
        }

        if let Some(last_hash) = self.option_last_hash {
            if prev_hash != last_hash {
                bail!(
                    "Block at height {} has prev_hash {} but expected {}",
                    height,
                    prev_hash,
                    last_hash
                );
            }
        } else {
            info!(
                "Initial block received at height {} (hash {})",
                height, hash
            );
        }

        self.last_height = height;
        self.option_last_hash = Some(hash);

        info!("# Block Kontor Transactions: {}", block.transactions.len());

        block_handler(&mut self.runtime, &block).await?;

        if let Some(tx) = &self.event_tx {
            let _ = tx
                .send(Event::Processed {
                    block: (&block).into(),
                })
                .await;
        }
        info!("Block processed");

        Ok(())
    }

    async fn run_event_loop(&mut self) -> Result<()> {
        self.init_tx.take().map(|tx| tx.send(true));

        loop {
            let simulate_rx = async {
                if let Some(rx) = self.simulate_rx.as_mut() {
                    rx.recv().await
                } else {
                    pending().await
                }
            };

            select! {
                _ = self.cancel_token.cancelled() => {
                    info!("Cancelled");
                    break;
                }
                option_event = self.bitcoin_event_rx.recv() => {
                    match option_event {
                        Some(event) => {
                            match event {
                                BitcoinEvent::BlockInsert { target_height, block } => {
                                    info!("Block {}/{} {}", block.height,
                                          target_height, block.hash);
                                    self.handle_block(block).await?;
                                },
                                BitcoinEvent::Rollback { to_height } => {
                                    self.rollback(to_height).await?;
                                },
                                BitcoinEvent::MempoolSync(txs) => {
                                    info!("MempoolSync {}", txs.len());
                                },
                                BitcoinEvent::MempoolInsert(tx) => {
                                    debug!("MempoolInsert {}", tx.txid);
                                },
                                BitcoinEvent::MempoolRemove(txid) => {
                                    debug!("MempoolRemove {}", txid);
                                },
                            }
                        },
                        None => {
                            info!("Received None event, exiting");
                            break;
                        },
                    }
                }
                option_event = simulate_rx => {
                    if let Some((btx, ret_tx)) = option_event {
                        let _ = ret_tx.send(simulate_handler(&mut self.runtime, btx).await);
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        self.run_event_loop().await
    }
}

pub fn run(
    starting_block_height: u64,
    cancel_token: CancellationToken,
    writer: database::Writer,
    bitcoin_event_rx: Receiver<BitcoinEvent>,
    init_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
    simulate_rx: Option<Receiver<Simulation>>,
) -> JoinHandle<()> {
    tokio::spawn({
        async move {
            let mut reactor = match Reactor::new(
                starting_block_height,
                writer,
                bitcoin_event_rx,
                cancel_token.clone(),
                init_tx,
                event_tx,
                simulate_rx,
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
