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
    batch,
    bitcoin_follower::{
        ctrl::CtrlChannel,
        events::{BlockId, Event as FollowerEvent},
    },
    block::{filter_map, inspect},
    bls,
    database::{
        self,
        queries::{
            assign_or_get_signer_id_by_xonly, insert_block, insert_processed_block,
            insert_transaction, reserve_signer_nonce, rollback_to_height, select_block_at_height,
            select_block_latest, select_block_with_hash, select_signer_registry_by_id,
            select_signer_registry_by_xonly, set_block_processed,
        },
    },
    runtime::{ComponentCache, Runtime, Storage, TransactionContext, filestorage, wit::Signer},
    signer_registry,
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
                    let signer = match &metadata.signer {
                        Signer::XOnlyPubKey(xonly_str) => {
                            // Canonicalize direct Schnorr signers to a deterministic registry ID so
                            // contract-visible signer identity is shared across direct + BLS paths.
                            let xonly = xonly_str
                                .parse::<bitcoin::XOnlyPublicKey>()
                                .map_err(|e| anyhow!("invalid xonly pubkey signer: {e}"))?;
                            let signer_id = assign_or_get_signer_id_by_xonly(
                                &runtime.storage.conn,
                                &xonly.serialize(),
                                block.height as i64,
                                t.index,
                            )
                            .await?;
                            Signer::new_registry_id(signer_id)
                        }
                        _ => metadata.signer.clone(),
                    };

                    let result = runtime.publish(&signer, name, bytes).await;
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
                    let signer = match &metadata.signer {
                        Signer::XOnlyPubKey(xonly_str) => {
                            let xonly = xonly_str
                                .parse::<bitcoin::XOnlyPublicKey>()
                                .map_err(|e| anyhow!("invalid xonly pubkey signer: {e}"))?;
                            let signer_id = assign_or_get_signer_id_by_xonly(
                                &runtime.storage.conn,
                                &xonly.serialize(),
                                block.height as i64,
                                t.index,
                            )
                            .await?;
                            Signer::new_registry_id(signer_id)
                        }
                        _ => metadata.signer.clone(),
                    };
                    let result = runtime
                        .execute(Some(&signer), &(contract.into()), expr)
                        .await;
                    if result.is_err() {
                        warn!("Call operation failed: {:?}", result);
                    }
                }
                Op::Issuance { metadata, .. } => {
                    let signer = match &metadata.signer {
                        Signer::XOnlyPubKey(xonly_str) => {
                            let xonly = xonly_str
                                .parse::<bitcoin::XOnlyPublicKey>()
                                .map_err(|e| anyhow!("invalid xonly pubkey signer: {e}"))?;
                            let signer_id = assign_or_get_signer_id_by_xonly(
                                &runtime.storage.conn,
                                &xonly.serialize(),
                                block.height as i64,
                                t.index,
                            )
                            .await?;
                            Signer::new_registry_id(signer_id)
                        }
                        _ => metadata.signer.clone(),
                    };

                    let result = runtime.issuance(&signer).await;
                    if result.is_err() {
                        warn!("Issuance operation failed: {:?}", result);
                    }
                }
                Op::Batch { metadata, payload } => {
                    let decoded = match batch::decode_kbl1_batch(payload) {
                        Ok(d) => d,
                        Err(e) => {
                            warn!("KBL1 batch decode failed: {e}");
                            continue;
                        }
                    };

                    // -------------------------------------------------------------------------
                    // Signature-atomic batching:
                    //
                    // - If aggregate signature verification fails, reject the entire batch with
                    //   no side effects (no registry writes, no nonce reservations, no execution).
                    // - If aggregate verification succeeds, process ops sequentially. Per-op
                    //   failures do not roll back earlier ops.
                    // -------------------------------------------------------------------------

                    // Pre-validate registrations in-memory (no DB writes) so we can use any
                    // new BLS pubkeys for signature verification.
                    let mut in_batch_bls_by_xonly: std::collections::HashMap<[u8; 32], [u8; 96]> =
                        std::collections::HashMap::new();
                    for op in decoded.ops.iter() {
                        let batch::BatchOpV1::RegisterSigner {
                            xonly_pubkey,
                            bls_pubkey,
                            schnorr_sig,
                            bls_sig,
                        } = op
                        else {
                            continue;
                        };

                        let bls_pubkey: [u8; 96] = match bls_pubkey.as_slice().try_into() {
                            Ok(v) => v,
                            Err(_) => {
                                warn!("invalid RegisterSigner bls_pubkey length (expected 96)");
                                continue;
                            }
                        };
                        let schnorr_sig: [u8; 64] = match schnorr_sig.as_slice().try_into() {
                            Ok(v) => v,
                            Err(_) => {
                                warn!("invalid RegisterSigner schnorr_sig length (expected 64)");
                                continue;
                            }
                        };
                        let bls_sig: [u8; 48] = match bls_sig.as_slice().try_into() {
                            Ok(v) => v,
                            Err(_) => {
                                warn!("invalid RegisterSigner bls_sig length (expected 48)");
                                continue;
                            }
                        };
                        let xonly = match bitcoin::XOnlyPublicKey::from_slice(xonly_pubkey) {
                            Ok(x) => x,
                            Err(e) => {
                                warn!("invalid RegisterSigner xonly pubkey: {e}");
                                continue;
                            }
                        };

                        if let Err(e) = signer_registry::verify_registration_proofs(
                            &xonly,
                            &bls_pubkey,
                            &schnorr_sig,
                            &bls_sig,
                        ) {
                            warn!("invalid RegisterSigner proofs: {e}");
                            continue;
                        }

                        in_batch_bls_by_xonly.insert(*xonly_pubkey, bls_pubkey);
                    }

                    // Collect the signed BinaryCall ops and verify the aggregate signature.
                    struct CallForVerification {
                        bls_pubkey: [u8; 96],
                        message: Vec<u8>,
                    }

                    let mut calls: Vec<CallForVerification> = Vec::new();
                    let mut reject_batch = false;
                    for (op, range) in decoded.ops.iter().zip(decoded.op_ranges.iter()) {
                        let batch::BatchOpV1::Call { signer, .. } = op else {
                            continue;
                        };

                        // Resolve which BLS pubkey should be used for verifying this op.
                        // Priority:
                        // 1) If the signer has a BLS pubkey bound in the registry, use it.
                        // 2) Otherwise, fall back to a valid in-batch RegisterSigner binding.
                        let (xonly_pubkey, bls_pubkey) = match signer {
                            batch::SignerRefV1::Id(id) => {
                                let row =
                                    match select_signer_registry_by_id(&runtime.storage.conn, *id)
                                        .await
                                    {
                                        Ok(Some(r)) => r,
                                        Ok(None) => {
                                            warn!("unknown signer_id {id} (not in registry)");
                                            reject_batch = true;
                                            break;
                                        }
                                        Err(e) => {
                                            warn!("failed to look up signer_id {id}: {e}");
                                            reject_batch = true;
                                            break;
                                        }
                                    };
                                let xonly: [u8; 32] = match row.xonly_pubkey.as_slice().try_into() {
                                    Ok(v) => v,
                                    Err(_) => {
                                        warn!("registry xonly_pubkey has invalid length");
                                        reject_batch = true;
                                        break;
                                    }
                                };
                                let bls_pk: [u8; 96] = match row.bls_pubkey.as_deref() {
                                    Some(bytes) => match bytes.try_into() {
                                        Ok(v) => v,
                                        Err(_) => {
                                            warn!("registry bls_pubkey has invalid length");
                                            reject_batch = true;
                                            break;
                                        }
                                    },
                                    None => match in_batch_bls_by_xonly.get(&xonly) {
                                        Some(pk) => *pk,
                                        None => {
                                            warn!("signer_id {id} has no BLS pubkey bound");
                                            reject_batch = true;
                                            break;
                                        }
                                    },
                                };
                                (xonly, bls_pk)
                            }
                            batch::SignerRefV1::XOnly(xonly) => {
                                let maybe_row = match select_signer_registry_by_xonly(
                                    &runtime.storage.conn,
                                    xonly,
                                )
                                .await
                                {
                                    Ok(r) => r,
                                    Err(e) => {
                                        warn!("failed to look up xonly signer: {e}");
                                        reject_batch = true;
                                        break;
                                    }
                                };
                                let bls_pk: [u8; 96] = match maybe_row
                                    .as_ref()
                                    .and_then(|r| r.bls_pubkey.as_deref())
                                {
                                    Some(bytes) => match bytes.try_into() {
                                        Ok(v) => v,
                                        Err(_) => {
                                            warn!("registry bls_pubkey has invalid length");
                                            reject_batch = true;
                                            break;
                                        }
                                    },
                                    None => match in_batch_bls_by_xonly.get(xonly) {
                                        Some(pk) => *pk,
                                        None => {
                                            warn!("xonly signer has no BLS pubkey bound");
                                            reject_batch = true;
                                            break;
                                        }
                                    },
                                };
                                (*xonly, bls_pk)
                            }
                        };

                        let op_bytes = &decoded.decompressed_ops[range.clone()];
                        let message = batch::kbl1_message_for_op_bytes(op_bytes);

                        let _ = xonly_pubkey; // keep available for future auditing/debug
                        calls.push(CallForVerification {
                            bls_pubkey,
                            message,
                        });
                    }

                    if reject_batch {
                        warn!(
                            "Rejected KBL1 batch (unable to resolve signer pubkeys for signature verification)"
                        );
                        continue;
                    }

                    if calls.is_empty() {
                        warn!("KBL1 batch contains no signed ops");
                        continue;
                    }

                    let public_keys: Vec<[u8; 96]> = calls.iter().map(|c| c.bls_pubkey).collect();
                    let message_refs: Vec<&[u8]> =
                        calls.iter().map(|c| c.message.as_slice()).collect();
                    if let Err(e) = bls::verify_aggregate_signature(
                        &decoded.aggregate_signature,
                        &public_keys,
                        &message_refs,
                    ) {
                        warn!("KBL1 aggregate signature verification failed: {e}");
                        continue;
                    }

                    // Aggregate signature verified: apply side effects and execute ops sequentially.
                    let mut call_index: i64 = 0;
                    for op in decoded.ops.iter() {
                        match op {
                            batch::BatchOpV1::RegisterSigner {
                                xonly_pubkey,
                                bls_pubkey,
                                schnorr_sig,
                                bls_sig,
                            } => {
                                let bls_pubkey: [u8; 96] = match bls_pubkey.as_slice().try_into() {
                                    Ok(v) => v,
                                    Err(_) => {
                                        warn!(
                                            "invalid RegisterSigner bls_pubkey length (expected 96)"
                                        );
                                        continue;
                                    }
                                };
                                let schnorr_sig: [u8; 64] = match schnorr_sig.as_slice().try_into()
                                {
                                    Ok(v) => v,
                                    Err(_) => {
                                        warn!(
                                            "invalid RegisterSigner schnorr_sig length (expected 64)"
                                        );
                                        continue;
                                    }
                                };
                                let bls_sig: [u8; 48] = match bls_sig.as_slice().try_into() {
                                    Ok(v) => v,
                                    Err(_) => {
                                        warn!(
                                            "invalid RegisterSigner bls_sig length (expected 48)"
                                        );
                                        continue;
                                    }
                                };
                                let xonly = match bitcoin::XOnlyPublicKey::from_slice(xonly_pubkey)
                                {
                                    Ok(x) => x,
                                    Err(e) => {
                                        warn!("invalid RegisterSigner xonly pubkey: {e}");
                                        continue;
                                    }
                                };

                                if let Err(e) = signer_registry::register_signer(
                                    &runtime.storage.conn,
                                    &xonly,
                                    &bls_pubkey,
                                    &schnorr_sig,
                                    &bls_sig,
                                    block.height as i64,
                                    t.index,
                                )
                                .await
                                {
                                    warn!("RegisterSigner failed: {e}");
                                }
                            }
                            batch::BatchOpV1::Call {
                                signer,
                                nonce,
                                gas_limit,
                                contract_id,
                                function_index,
                                args,
                            } => {
                                let op_index = call_index;
                                call_index += 1;

                                runtime
                                    .set_context(
                                        block.height as i64,
                                        Some(TransactionContext {
                                            tx_index: t.index,
                                            input_index: metadata.input_index,
                                            op_index,
                                            txid: t.txid,
                                        }),
                                        Some(metadata.previous_output),
                                        op_return_data.clone().map(Into::into),
                                    )
                                    .await;

                                // Resolve canonical signer_id for execution (creating x-only rows on first use).
                                let signer_id: u32 = match signer {
                                    batch::SignerRefV1::Id(id) => *id,
                                    batch::SignerRefV1::XOnly(xonly) => {
                                        assign_or_get_signer_id_by_xonly(
                                            &runtime.storage.conn,
                                            xonly,
                                            block.height as i64,
                                            t.index,
                                        )
                                        .await
                                        .unwrap_or(0)
                                    }
                                };
                                if signer_id == 0 {
                                    warn!("Rejected batched op (unable to resolve signer_id)");
                                    continue;
                                }

                                // For execution, require the signer to have a BLS pubkey bound in the registry
                                // (either pre-existing or via an earlier RegisterSigner op in this batch).
                                let signer_row = match select_signer_registry_by_id(
                                    &runtime.storage.conn,
                                    signer_id,
                                )
                                .await
                                {
                                    Ok(Some(r)) => r,
                                    Ok(None) => {
                                        warn!("Rejected batched op (unknown signer_id)");
                                        continue;
                                    }
                                    Err(e) => {
                                        warn!("Rejected batched op (failed to load signer): {e}");
                                        continue;
                                    }
                                };
                                if signer_row.bls_pubkey.is_none() {
                                    warn!("Rejected batched op (signer has no BLS pubkey bound)");
                                    continue;
                                }

                                if let Err(e) = reserve_signer_nonce(
                                    &runtime.storage.conn,
                                    signer_id,
                                    *nonce,
                                    block.height as i64,
                                    t.index,
                                    metadata.input_index,
                                    op_index,
                                )
                                .await
                                {
                                    warn!("Rejected batched op (nonce reservation failed): {e}");
                                    continue;
                                }

                                let signer = Signer::new_registry_id(signer_id);
                                runtime.set_gas_limit(*gas_limit);
                                let result = runtime
                                    .execute_binary(
                                        Some(&signer),
                                        *contract_id,
                                        *function_index,
                                        args,
                                    )
                                    .await;
                                if result.is_err() {
                                    warn!("Batched BinaryCall operation failed: {:?}", result);
                                }
                            }
                        }
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
