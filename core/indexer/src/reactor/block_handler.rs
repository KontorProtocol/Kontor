use anyhow::{Result, anyhow};
use bitcoin::hashes::Hash;
use indexer_types::{
    Block, Inst, Op, OpMetadata, OpWithResult, Transaction, TransactionInput, TransactionRow,
};
use tracing::{info, warn};

use crate::{
    block::{filter_map, inspect, op_from_inst},
    bls,
    consensus::Height,
    database::queries::{
        confirm_transaction, get_transaction_by_txid, insert_batch, insert_block,
        insert_transaction, insert_unconfirmed_batch_tx, select_block_latest,
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
        // Dedup: if this tx was already executed via batch_handler, just mark it
        // as confirmed on-chain (for finality checks) and skip re-execution.
        if get_transaction_by_txid(&runtime.storage.conn, &t.txid.to_string())
            .await?
            .is_some()
        {
            confirm_transaction(
                &runtime.storage.conn,
                &t.txid.to_string(),
                block.height as i64,
                t.index,
            )
            .await?;
            info!(txid = %t.txid, "Transaction already batched — confirmed on chain, skipping execution");
            continue;
        }
        process_transaction(
            runtime,
            t,
            block.height as i64,
            Some(block.height as i64),
            None,
        )
        .await?;
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

    let change = staking::api::process_pending_validators(runtime, &core_signer, block.height)
        .await
        .expect("Failed to call process_pending_validators")
        .expect("process_pending_validators returned error");
    if change.activated > 0 || change.deactivated > 0 {
        info!(
            "Validator set change at height {}: {} activated, {} deactivated",
            block.height, change.activated, change.deactivated
        );
    }

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
        process_transaction(
            runtime,
            t,
            anchor_height as i64,
            None,
            Some(consensus_height.as_u64() as i64),
        )
        .await?;
    }

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
    t: &Transaction,
    height: i64,
    confirmed_height: Option<i64>,
    batch_height: Option<i64>,
) -> Result<()> {
    let tx_id = insert_transaction(
        &runtime.storage.conn,
        TransactionRow {
            id: 0,
            txid: t.txid.to_string(),
            height,
            confirmed_height,
            tx_index: confirmed_height.map(|_| t.index),
            batch_height,
        },
    )
    .await?;

    for input in &t.inputs {
        let op_return_data = t.op_return_data.get(&(input.input_index as u64)).cloned();
        process_input(
            runtime,
            input,
            height,
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
        process_aggregate_input(
            runtime,
            input,
            height,
            tx_id,
            tx_index,
            txid,
            op_return_data,
        )
        .await;
    } else {
        process_direct_input(
            runtime,
            input,
            height,
            tx_id,
            tx_index,
            txid,
            op_return_data,
        )
        .await;
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

        execute_op(runtime, &op).await;
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

    for (op_index, (inst, &signer_id)) in input
        .insts
        .ops
        .iter()
        .zip(agg.signer_ids.iter())
        .enumerate()
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
        execute_op(runtime, &op).await;
    }
}

pub async fn execute_op(runtime: &mut Runtime, op: &Op) {
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

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use indexer_types::{Block, BlockRow};

    use super::{batch_handler, block_handler};
    use crate::consensus::Height;
    use crate::database::queries::{get_transaction_by_txid, insert_block};
    use crate::test_utils::{new_mock_block_hash, new_mock_transaction, test_runtime};

    #[tokio::test]
    async fn batch_then_block_deduplicates_transaction() -> Result<()> {
        let (mut runtime, _db_dir, _) = test_runtime().await?;
        let conn = runtime.get_storage_conn();

        let mock_tx = new_mock_transaction(42);
        let txid_str = mock_tx.txid.to_string();

        let cert = vec![0u8; 8];
        batch_handler(
            &mut runtime,
            1,
            new_mock_block_hash(1),
            Height::new(1),
            &cert,
            std::slice::from_ref(&mock_tx),
            &[],
        )
        .await?;

        let row = get_transaction_by_txid(&conn, &txid_str)
            .await?
            .expect("Transaction should exist after batch");
        assert!(row.batch_height.is_some());
        assert!(row.confirmed_height.is_none());

        insert_block(
            &conn,
            BlockRow::builder()
                .height(2)
                .hash(new_mock_block_hash(2))
                .relevant(true)
                .build(),
        )
        .await?;

        let block = Block {
            height: 2,
            hash: new_mock_block_hash(2),
            prev_hash: new_mock_block_hash(1),
            transactions: vec![mock_tx],
        };
        block_handler(&mut runtime, &block).await?;

        let row = get_transaction_by_txid(&conn, &txid_str)
            .await?
            .expect("Transaction should still exist");
        assert_eq!(row.confirmed_height, Some(2));
        assert_eq!(row.tx_index, Some(0));
        assert!(row.batch_height.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_reactor_generate_challenges_with_lucky_hash() -> Result<()> {
        use crate::runtime::{Decimal, filestorage, token, wit::Signer};
        use crate::test_utils::{LUCKY_HASH_100000, lucky_hash, make_descriptor};
        use bitcoin::{BlockHash, hashes::Hash};

        let (mut runtime, _temp_dir, _) = crate::test_utils::test_runtime().await?;

        let descriptor = make_descriptor(
            "reactor_lucky".to_string(),
            vec![1u8; 32],
            16,
            100,
            "reactor_lucky.txt".to_string(),
        );
        let core_signer = Signer::Core(Box::new(Signer::Nobody));
        token::api::issuance(&mut runtime, &core_signer, Decimal::from(100u64)).await??;

        let signer = Signer::Nobody;
        let created =
            filestorage::api::create_agreement(&mut runtime, &signer, descriptor).await??;
        let min_nodes = filestorage::api::get_min_nodes(&mut runtime).await?;
        for node_index in 0..min_nodes {
            let node_id = format!("node_{}", node_index);
            filestorage::api::join_agreement(
                &mut runtime,
                &signer,
                &created.agreement_id,
                &node_id,
            )
            .await??;
        }

        let block_height = 100000u64;
        let block = Block {
            height: block_height,
            hash: BlockHash::from_byte_array(lucky_hash(LUCKY_HASH_100000)),
            prev_hash: BlockHash::from_byte_array([0x00; 32]),
            transactions: vec![],
        };
        block_handler(&mut runtime, &block).await?;

        let after = filestorage::api::get_active_challenges(&mut runtime).await?;
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].agreement_id, created.agreement_id);
        assert_eq!(after[0].block_height, block_height);

        Ok(())
    }
}
