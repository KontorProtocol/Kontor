pub mod types;

use anyhow::{Result, anyhow, bail};
use blst::BLST_ERROR;
use blst::min_sig::{PublicKey as BlsPublicKey, Signature as BlsSignature};
use futures_util::future::pending;
use indexer_types::{Block, BlockRow, Event, Op, OpWithResult, TransactionRow};
use std::collections::{HashMap, HashSet};
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
    bitcoin_follower::{
        ctrl::CtrlChannel,
        events::{BlockId, Event as FollowerEvent},
    },
    block::{filter_map, inspect},
    database::{
        self,
        queries::{
            insert_block, insert_processed_block, insert_signer_nonce, insert_signer_registry,
            insert_transaction, rollback_to_height, select_block_at_height, select_block_latest,
            select_block_with_hash, select_signer_registry_by_bls_pubkey,
            select_signer_registry_by_id, set_block_processed, signer_nonce_exists,
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
    reader: database::Reader,
    writer: database::Writer,
    cancel_token: CancellationToken,
    ctrl: CtrlChannel,
    bitcoin_event_rx: Option<Receiver<FollowerEvent>>,
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
                Op::BlsBatch { metadata, payload } => {
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

                    runtime.storage.savepoint().await?;

                    let result: Result<()> = async {
                        let batch = crate::bls_batch::parse_kbl1_batch(payload)?;
                        let decompressed =
                            crate::bls_batch::decompress_calls_zstd(&batch.compressed_calls)?;
                        let calls = crate::bls_batch::parse_concatenated_calls(&decompressed)?;

                        // Deserialize + subgroup-check new signer public keys.
                        let mut new_signer_pks = Vec::with_capacity(batch.new_signers.len());
                        for pk_bytes in &batch.new_signers {
                            let pk = BlsPublicKey::from_bytes(pk_bytes)
                                .map_err(|e| anyhow!("invalid BLS pubkey bytes in new_signers: {e:?}"))?;
                            pk.validate()
                                .map_err(|e| anyhow!("invalid BLS pubkey in new_signers: {e:?}"))?;
                            new_signer_pks.push(pk);
                        }

                        // Resolve registry IDs to public keys (with caching).
                        let mut registry_pk_cache: HashMap<u32, BlsPublicKey> = HashMap::new();
                        async fn get_registry_pk(
                            conn: &libsql::Connection,
                            cache: &mut HashMap<u32, BlsPublicKey>,
                            id: u32,
                        ) -> Result<BlsPublicKey> {
                            if let Some(pk) = cache.get(&id) {
                                return Ok(pk.clone());
                            }
                            let row = select_signer_registry_by_id(conn, i64::from(id))
                                .await?
                                .ok_or_else(|| anyhow!("unknown signer_id in batch: {id}"))?;
                            if row.bls_pubkey.len() != crate::bls_batch::BLS_PUBKEY_LEN {
                                bail!("invalid BLS pubkey length in registry for signer_id {id}");
                            }
                            let pk = BlsPublicKey::from_bytes(&row.bls_pubkey).map_err(|e| {
                                anyhow!(
                                    "invalid BLS pubkey bytes in registry for signer_id {id}: {e:?}"
                                )
                            })?;
                            pk.validate().map_err(|e| {
                                anyhow!("invalid BLS pubkey in registry for signer_id {id}: {e:?}")
                            })?;
                            cache.insert(id, pk.clone());
                            Ok(pk)
                        }

                        // Build (message, pk) pairs in deterministic order:
                        // 1) PoP messages for new_signers
                        // 2) Operation messages for each call in order
                        let mut message_bufs: Vec<Vec<u8>> = Vec::new();
                        let mut pk_bufs: Vec<BlsPublicKey> = Vec::new();

                        for (i, pk_bytes) in batch.new_signers.iter().enumerate() {
                            message_bufs.push(crate::bls_batch::pop_message(pk_bytes));
                            pk_bufs.push(new_signer_pks[i].clone());
                        }

                        for (op_i, parsed) in calls.iter().enumerate() {
                            message_bufs.push(crate::bls_batch::op_message(
                                op_i as u32,
                                &parsed.bytes,
                            ));

                            let pk = match parsed.call.signer {
                                crate::bls_batch::SignerRef::RegistryId(id) => {
                                    get_registry_pk(&runtime.storage.conn, &mut registry_pk_cache, id)
                                        .await?
                                }
                                crate::bls_batch::SignerRef::BundleIndex(i) => new_signer_pks
                                    .get(i as usize)
                                    .cloned()
                                    .ok_or_else(|| anyhow!("BundleIndex out of bounds: {i}"))?,
                            };
                            pk_bufs.push(pk);
                        }

                        let msg_refs: Vec<&[u8]> =
                            message_bufs.iter().map(|m| m.as_slice()).collect();
                        let pk_refs: Vec<&BlsPublicKey> =
                            pk_bufs.iter().collect();

                        let sig = BlsSignature::from_bytes(&batch.aggregate_signature).map_err(
                            |e| anyhow!("invalid aggregate signature bytes: {e:?}"),
                        )?;

                        let verify = sig.aggregate_verify(
                            true,
                            msg_refs.as_slice(),
                            crate::bls_batch::PROTOCOL_BLS_DST,
                            pk_refs.as_slice(),
                            true,
                        );
                        if verify != BLST_ERROR::BLST_SUCCESS {
                            bail!("BLS aggregate verification failed: {verify:?}");
                        }

                        // Inline registration: insert new_signers deterministically in order.
                        let mut bundle_index_to_id: Vec<u32> =
                            Vec::with_capacity(batch.new_signers.len());
                        for pk_bytes in &batch.new_signers {
                            if select_signer_registry_by_bls_pubkey(
                                &runtime.storage.conn,
                                pk_bytes,
                            )
                            .await?
                            .is_some()
                            {
                                bail!("new_signer already registered");
                            }
                            let inserted_id = insert_signer_registry(
                                &runtime.storage.conn,
                                pk_bytes,
                                block.height as i64,
                                t.index,
                            )
                            .await?;
                            let inserted_id_u32 = u32::try_from(inserted_id)
                                .map_err(|_| anyhow!("signer_registry id overflow"))?;
                            bundle_index_to_id.push(inserted_id_u32);
                        }

                        // Replay protection: reject if any (signer_id, nonce) already exists or repeats within the batch.
                        let mut seen: HashSet<(u32, u64)> = HashSet::new();
                        for parsed in &calls {
                            let signer_id = match parsed.call.signer {
                                crate::bls_batch::SignerRef::RegistryId(id) => id,
                                crate::bls_batch::SignerRef::BundleIndex(i) => *bundle_index_to_id
                                    .get(i as usize)
                                    .ok_or_else(|| anyhow!("BundleIndex out of bounds: {i}"))?,
                            };
                            let nonce = parsed.call.nonce;
                            if !seen.insert((signer_id, nonce)) {
                                bail!("duplicate (signer_id, nonce) within batch");
                            }
                            if signer_nonce_exists(&runtime.storage.conn, i64::from(signer_id), nonce)
                                .await?
                            {
                                bail!("replayed (signer_id, nonce) detected");
                            }
                        }

                        let mut seen_vec: Vec<(u32, u64)> = seen.into_iter().collect();
                        seen_vec.sort_by_key(|(signer_id, nonce)| (*signer_id, *nonce));
                        for (signer_id, nonce) in seen_vec {
                            insert_signer_nonce(
                                &runtime.storage.conn,
                                i64::from(signer_id),
                                nonce,
                                block.height as i64,
                            )
                            .await?;
                        }

                        // Execute each call (best-effort, like legacy Op::Call). Each call gets a
                        // distinct op_index for deterministic result IDs and unique DB rows.
                        for (op_index, parsed) in calls.iter().enumerate() {
                            let signer_id = match parsed.call.signer {
                                crate::bls_batch::SignerRef::RegistryId(id) => id,
                                crate::bls_batch::SignerRef::BundleIndex(i) => *bundle_index_to_id
                                    .get(i as usize)
                                    .ok_or_else(|| anyhow!("BundleIndex out of bounds: {i}"))?,
                            };
                            let signer = Signer::XOnlyPubKey(format!("@{}", signer_id));

                            runtime
                                .set_context(
                                    block.height as i64,
                                    Some(TransactionContext {
                                        tx_index: t.index,
                                        input_index,
                                        op_index: op_index as i64,
                                        txid: t.txid,
                                    }),
                                    Some(metadata.previous_output),
                                    op_return_data.clone().map(Into::into),
                                )
                                .await;

                            let result = runtime
                                .execute_binary(
                                    Some(&signer),
                                    i64::from(parsed.call.contract_id),
                                    parsed.call.function_index,
                                    &parsed.call.args,
                                    parsed.call.gas_limit,
                                )
                                .await;
                            if let Err(e) = result {
                                warn!(
                                    "BinaryCallV1 failed signer_id={} contract_id={} function_index={} op_index={}: {e:?}",
                                    signer_id,
                                    parsed.call.contract_id,
                                    parsed.call.function_index,
                                    op_index,
                                );
                            }
                        }
                        Ok(())
                    }
                    .await;

                    if let Err(e) = result {
                        runtime.storage.rollback().await?;
                        warn!("BLS batch failed: {e:?}");
                    } else {
                        runtime.storage.commit().await?;
                    }
                }
            };
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
        reader: database::Reader,
        writer: database::Writer,
        ctrl: CtrlChannel,
        cancel_token: CancellationToken,
        init_tx: Option<oneshot::Sender<bool>>,
        event_tx: Option<mpsc::Sender<Event>>,
        simulate_rx: Option<Receiver<Simulation>>,
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
            .conn(writer.connection())
            .build();

        let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
        runtime.publish_native_contracts().await?;
        Ok(Self {
            reader,
            writer,
            cancel_token,
            ctrl,
            bitcoin_event_rx: None,
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

        // Resync FileLedger after rollback (DB entries deleted via CASCADE)
        self.runtime
            .file_ledger
            .force_resync_from_db(&self.runtime.storage.conn)
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
    simulate_rx: Option<Receiver<Simulation>>,
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
