use anyhow::Result;
use indexer_types::{Inst, Op, OpMetadata, Transaction, TransactionInput, TransactionRow};
use tracing::warn;

use crate::{
    block::op_from_inst,
    bls,
    database::queries::insert_transaction,
    runtime::{Runtime, TransactionContext, registry, wit::Signer},
};

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
