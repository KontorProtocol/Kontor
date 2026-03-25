use anyhow::{Result, anyhow};
use bitcoin::hashes::Hash;
use indexer_types::{Block, Inst, Op, OpMetadata, OpWithResult, Transaction, TransactionInput, TransactionRow};
use tracing::{info, warn};

use crate::{
    bls,
    block::{filter_map, inspect, op_from_inst},
    consensus::Height,
    database::queries::{
        confirm_transaction, get_transaction_by_txid, insert_batch, insert_block,
        insert_transaction, insert_unconfirmed_batch_tx, select_block_latest, set_batch_processed,
        set_block_processed,
    },
    runtime::{Runtime, TransactionContext, filestorage, registry, staking, wit::Signer},
    test_utils::new_mock_block_hash,
};

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
        process_transaction(runtime, block.height, t).await?;
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

    let epoch_result = staking::api::transition_epoch(runtime, &core_signer, block.height)
        .await
        .expect("Failed to call transition_epoch")
        .expect("transition_epoch returned error");
    if epoch_result.activated > 0 || epoch_result.deactivated > 0 {
        info!(
            "Epoch {} transition: {} activated, {} deactivated",
            epoch_result.new_epoch, epoch_result.activated, epoch_result.deactivated
        );
    }

    set_block_processed(&runtime.storage.conn, block.height as i64).await?;

    Ok(())
}

pub async fn batch_handler(
    runtime: &mut Runtime,
    anchor_height: u64,
    anchor_hash: bitcoin::BlockHash,
    consensus_height: Height,
    certificate: &[u8],
    txs: &[Transaction],
    raw_txs: &[bitcoin::Transaction],
) -> Result<()> {
    insert_batch(
        &runtime.storage.conn,
        consensus_height.as_u64() as i64,
        anchor_height as i64,
        &anchor_hash.to_string(),
        certificate,
        false,
    )
    .await?;

    for raw_tx in raw_txs {
        let txid = raw_tx.compute_txid();
        let serialized = bitcoin::consensus::serialize(raw_tx);
        insert_unconfirmed_batch_tx(
            &runtime.storage.conn,
            &txid.to_string(),
            consensus_height.as_u64() as i64,
            &serialized,
        )
        .await?;
    }

    for t in txs {
        let tx_id = insert_transaction(
            &runtime.storage.conn,
            TransactionRow::builder()
                .height(anchor_height as i64)
                .batch_height(consensus_height.as_u64() as i64)
                .txid(t.txid.to_string())
                .build(),
        )
        .await?;

        for input in &t.inputs {
            let op_return_data = t.op_return_data.get(&(input.input_index as u64)).cloned();
            process_input(
                runtime,
                input,
                anchor_height as i64,
                Some(tx_id),
                t.index,
                t.txid,
                op_return_data,
            )
            .await;
        }
    }

    set_batch_processed(&runtime.storage.conn, consensus_height.as_u64() as i64).await?;

    info!(
        consensus_height = %consensus_height,
        anchor_height,
        tx_count = txs.len(),
        "Batch executed"
    );

    Ok(())
}

pub async fn process_transaction(
    runtime: &mut Runtime,
    block_height: u64,
    t: &Transaction,
) -> Result<()> {
    // Dedup: if this tx was already executed via batch_handler, just mark it
    // as confirmed on-chain (for finality checks) and skip re-execution.
    if let Some(_existing) =
        get_transaction_by_txid(&runtime.storage.conn, &t.txid.to_string()).await?
    {
        confirm_transaction(
            &runtime.storage.conn,
            &t.txid.to_string(),
            block_height as i64,
            t.index,
        )
        .await?;
        info!(txid = %t.txid, "Transaction already batched — confirmed on chain, skipping execution");
        return Ok(());
    }

    let tx_id = insert_transaction(
        &runtime.storage.conn,
        TransactionRow::builder()
            .height(block_height as i64)
            .confirmed_height(block_height as i64)
            .tx_index(t.index)
            .txid(t.txid.to_string())
            .build(),
    )
    .await?;

    for input in &t.inputs {
        let op_return_data = t.op_return_data.get(&(input.input_index as u64)).cloned();
        process_input(
            runtime,
            input,
            block_height as i64,
            Some(tx_id),
            t.index,
            t.txid,
            op_return_data,
        )
        .await;
    }

    Ok(())
}

pub async fn process_input(
    runtime: &mut Runtime,
    input: &TransactionInput,
    height: i64,
    tx_id: Option<i64>,
    tx_index: i64,
    txid: bitcoin::Txid,
    op_return_data: Option<indexer_types::OpReturnData>,
) {
    if input.insts.is_aggregate() {
        process_aggregate_input(runtime, input, height, tx_id, tx_index, txid, op_return_data)
            .await;
    } else {
        process_direct_input(runtime, input, height, tx_id, tx_index, txid, op_return_data).await;
    }
}

async fn process_direct_input(
    runtime: &mut Runtime,
    input: &TransactionInput,
    height: i64,
    tx_id: Option<i64>,
    tx_index: i64,
    txid: bitcoin::Txid,
    op_return_data: Option<indexer_types::OpReturnData>,
) {
    let metadata = OpMetadata {
        previous_output: input.previous_output,
        input_index: input.input_index,
        signer: input.witness_signer.clone(),
    };

    for (op_index, inst) in input.insts.ops.iter().enumerate() {
        let op = op_from_inst(inst.clone(), metadata.clone());

        runtime
            .set_context(
                height,
                Some(TransactionContext {
                    tx_id,
                    tx_index,
                    input_index: input.input_index,
                    op_index: op_index as i64,
                    txid,
                }),
                Some(input.previous_output),
                op_return_data.clone().map(Into::into),
            )
            .await;

        execute_op(runtime, &op, op_return_data.clone()).await;
    }
}

async fn process_aggregate_input(
    runtime: &mut Runtime,
    input: &TransactionInput,
    height: i64,
    tx_id: Option<i64>,
    tx_index: i64,
    txid: bitcoin::Txid,
    op_return_data: Option<indexer_types::OpReturnData>,
) {
    let signer_map = match bls::verify_aggregate(runtime, &input.insts).await {
        Ok(map) => map,
        Err(e) => {
            warn!("Aggregate verification failed: {e}");
            return;
        }
    };

    let agg = input.insts.aggregate.as_ref().unwrap();

    for (op_index, (inst, &signer_id)) in
        input.insts.ops.iter().zip(agg.signer_ids.iter()).enumerate()
    {
        let x_only = match signer_map.get(&signer_id) {
            Some(x) => x.clone(),
            None => {
                warn!("signer_id {signer_id} not in signer_map after verification");
                continue;
            }
        };

        runtime
            .set_context(
                height,
                Some(TransactionContext {
                    tx_id,
                    tx_index,
                    input_index: input.input_index,
                    op_index: op_index as i64,
                    txid,
                }),
                Some(input.previous_output),
                op_return_data.clone().map(Into::into),
            )
            .await;

        if let Inst::Call { nonce, .. } = inst {
            let nonce_val = match nonce {
                Some(n) => *n,
                None => {
                    warn!("aggregate Call for signer {signer_id} missing nonce");
                    continue;
                }
            };
            let nonce_result = registry::api::advance_nonce(
                runtime,
                &Signer::Core(Box::new(Signer::Nobody)),
                signer_id,
                nonce_val,
            )
            .await;
            match nonce_result {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    warn!("aggregate nonce check failed for signer {signer_id}: {e:?}");
                    continue;
                }
                Err(e) => {
                    warn!("aggregate nonce advance error for signer {signer_id}: {e}");
                    continue;
                }
            }
        }

        let signer = Signer::XOnlyPubKey(x_only);
        let metadata = OpMetadata {
            previous_output: input.previous_output,
            input_index: input.input_index,
            signer: signer.clone(), // TODO
        };
        let op = op_from_inst(inst.clone(), metadata);
        execute_op(runtime, &op, op_return_data.clone()).await;
    }
}

pub async fn execute_op(
    runtime: &mut Runtime,
    op: &Op,
    op_return_data: Option<indexer_types::OpReturnData>,
) {
    if let Signer::XOnlyPubKey(x_only) = &op.metadata().signer
        && let Err(e) = runtime.ensure_signer(x_only).await
    {
        warn!("Failed to ensure signer for {x_only}: {e}");
        return;
    }

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
            ..
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
    }
}
