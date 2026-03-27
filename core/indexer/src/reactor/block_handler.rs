use anyhow::{Result, anyhow};
use bitcoin::hashes::Hash;
use indexer_types::{Block, Op, OpWithResult, Transaction, TransactionRow};
use tracing::{info, warn};

use crate::{
    block::{filter_map, inspect},
    consensus::Height,
    database::queries::{
        confirm_transaction, get_transaction_by_txid, insert_batch, insert_block,
        insert_transaction, insert_unconfirmed_batch_tx, select_block_latest,
    },
    runtime::{Runtime, TransactionContext, filestorage, staking, wit::Signer},
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

    // Store raw bitcoin txs for unconfirmed batch recovery/sync
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

        for op in &t.ops {
            let metadata = op.metadata();
            let input_index = metadata.input_index;
            let op_return_data = t.op_return_data.get(&(input_index as u64)).cloned();

            runtime
                .set_context(
                    anchor_height as i64,
                    Some(TransactionContext {
                        tx_id: Some(tx_id),
                        tx_index: t.index,
                        input_index,
                        op_index: 0,
                        txid: t.txid,
                    }),
                    Some(metadata.previous_output),
                    op_return_data.clone().map(Into::into),
                )
                .await;

            execute_op(runtime, op, op_return_data).await;
        }
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

    for op in &t.ops {
        let metadata = op.metadata();
        let input_index = metadata.input_index;
        let op_return_data = t.op_return_data.get(&(input_index as u64)).cloned();
        info!("Op return data: {:#?}", op_return_data);

        runtime
            .set_context(
                block_height as i64,
                Some(TransactionContext {
                    tx_id: Some(tx_id),
                    tx_index: t.index,
                    input_index,
                    op_index: 0,
                    txid: t.txid,
                }),
                Some(metadata.previous_output),
                op_return_data.clone().map(Into::into),
            )
            .await;

        execute_op(runtime, op, op_return_data).await;
    }

    Ok(())
}

pub async fn execute_op(
    runtime: &mut Runtime,
    op: &Op,
    op_return_data: Option<indexer_types::OpReturnData>,
) {
    let input_index = op.metadata().input_index;

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
            ops,
            signature,
        } => {
            if let Err(e) = runtime
                .execute_bls_bulk(
                    ops,
                    signature,
                    metadata.previous_output,
                    input_index,
                    op_return_data,
                )
                .await
            {
                warn!("BlsBulk failed: {e}");
            }
        }
    }
}
