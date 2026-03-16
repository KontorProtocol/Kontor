use anyhow::{Result, anyhow};
use bitcoin::hashes::Hash;
use indexer_types::{Block, Op, OpWithResult, Transaction, TransactionRow};
use tracing::{info, warn};

use crate::{
    block::{filter_map, inspect},
    database::queries::{
        insert_block, insert_transaction, select_block_latest, set_block_processed,
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

pub async fn process_transaction(
    runtime: &mut Runtime,
    block_height: u64,
    t: &Transaction,
) -> Result<()> {
    insert_transaction(
        &runtime.storage.conn,
        TransactionRow::builder()
            .height(block_height as i64)
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

async fn execute_op(
    runtime: &mut Runtime,
    op: &Op,
    op_return_data: Option<indexer_types::OpReturnData>,
) {
    if let Signer::XOnlyPubKey(x_only) = &op.metadata().signer {
        if let Err(e) = runtime.ensure_signer(x_only).await {
            warn!("Failed to ensure signer for {x_only}: {e}");
            return;
        }
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
                    metadata.input_index,
                    op_return_data,
                )
                .await
            {
                warn!("BlsBulk failed: {e}");
            }
        }
    }
}
