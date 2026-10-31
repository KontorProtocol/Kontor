use anyhow::Result;
use bitcoin::Txid;
use indexer_types::{Input, Op, OpKind, Transaction};
use tracing::warn;

use super::storage_identity::IdentityError;
use super::transactions::TxWalker;
use crate::bls::{AggregateVerificationError, verify_aggregate};
use crate::database::types::Identity;
use crate::runtime::wit::Signer;
use crate::runtime::{ExecutionError, Runtime, TransactionContext, system};

pub async fn execute_transaction(
    runtime: &mut Runtime,
    height: u64,
    tx_id: u64,
    tx: &Transaction,
) -> Result<Vec<Vec<Option<anyhow::Error>>>> {
    let mut all = Vec::with_capacity(tx.inputs.len());
    // `TxWalker` owns the cross-input Sponsor state machine + the
    // payment-override computation; the same instance walks every
    // input, capturing Sponsor Ops and advancing at each input
    // boundary. Shared with `block::inspect` so simulate's zip stays
    // aligned.
    let mut walker = TxWalker::new();
    // The contract-facing OP_RETURN surface is the tx's raw payload — the
    // same for every input — so borrow it once instead of re-cloning per
    // input. The runtime clones it only where it actually stores it (per
    // op, in `set_context`).
    let op_return_data = tx.op_return_raw.as_deref();
    for input in &tx.inputs {
        let per_input = process_input(
            runtime,
            &mut walker,
            input,
            height,
            Some(tx_id),
            tx.index,
            tx.txid,
            op_return_data,
        )
        .await?;
        all.push(per_input);
    }
    Ok(all)
}

/// Process every op in one Bitcoin-input's `Insts`. Returns the
/// positional failure vector aligned with `input.insts.ops` — `None` at
/// position j means the j-th op executed without a deterministic failure,
/// `Some(err)` means rejection or in-execution failure. `OpKind::Sponsor`
/// ops short-circuit `execute_op` (no contract dispatch, no result row
/// outside this in-memory vec) and contribute `None`.
///
/// `walker` carries the cross-input Sponsor state across calls — the
/// caller (`execute_transaction`) owns it and reuses the same instance
/// for every input; this function captures any Sponsor in `input` and
/// advances at the input boundary.
pub async fn process_input(
    runtime: &mut Runtime,
    walker: &mut TxWalker,
    input: &Input,
    height: u64,
    tx_id: Option<u64>,
    tx_index: u32,
    txid: Txid,
    op_return_data: Option<&[u8]>,
) -> Result<Vec<Option<anyhow::Error>>> {
    // Pin the execution height BEFORE anything resolves a signer — both branches do,
    // ahead of the first `set_context`. `get_or_create_identity` inserts
    // `signers(height = storage.height)`, and that column has a foreign key to
    // `blocks`; reading it ambiently lands the row at whatever height the previous
    // caller left behind. After a rollback (or a rolled-back simulation block) that
    // height has no `blocks` row, so the insert trips the FK, which is classified
    // non-deterministic and kills the reactor.
    runtime.storage.height = height;

    let errors = if input.insts.is_aggregate() {
        process_aggregate_input(
            runtime,
            walker,
            input,
            height,
            tx_id,
            tx_index,
            txid,
            op_return_data,
        )
        .await?
    } else {
        process_direct_input(
            runtime,
            walker,
            input,
            height,
            tx_id,
            tx_index,
            txid,
            op_return_data,
        )
        .await?
    };
    walker.next_input();
    Ok(errors)
}

async fn process_direct_input(
    runtime: &mut Runtime,
    walker: &mut TxWalker,
    input: &Input,
    height: u64,
    tx_id: Option<u64>,
    tx_index: u32,
    txid: Txid,
    op_return_data: Option<&[u8]>,
) -> Result<Vec<Option<anyhow::Error>>> {
    let identity = runtime
        .get_or_create_identity(&input.x_only_pubkey.to_string())
        .await?;

    let signer_id = identity.signer_id();
    let mut errors: Vec<Option<anyhow::Error>> = Vec::with_capacity(input.insts.ops.len());
    for (op_index, inst) in input.insts.ops.iter().enumerate() {
        // Direct inputs have no publisher — only a cross-input Sponsor
        // (held in `walker.active`) can override the input signer's
        // self-pay default. `walker.materialize` handles that internally.
        let op = match walker.materialize(input, op_index, signer_id, None, inst) {
            Ok(op) => op,
            Err(e) => {
                warn!("Rejected direct op: {e:#}");
                errors.push(Some(e));
                continue;
            }
        };

        // Sponsor Op short-circuits — it's a directive, not a contract
        // call. Its terms have already been captured by `walker.materialize`
        // and will drive the next input's payment overrides.
        if matches!(op.kind, OpKind::Sponsor) {
            errors.push(None);
            continue;
        }

        runtime
            .set_context(
                height,
                Some(TransactionContext {
                    tx_id,
                    tx_index,
                    input_index: input.input_index,
                    op_index: op_index as u32,
                    txid,
                }),
                Some(input.previous_output),
                op_return_data.map(|b| b.to_vec()),
            )
            .await;

        errors.push(execute_op(runtime, &op).await?);
    }
    Ok(errors)
}

async fn process_aggregate_input(
    runtime: &mut Runtime,
    walker: &mut TxWalker,
    input: &Input,
    height: u64,
    tx_id: Option<u64>,
    tx_index: u32,
    txid: Txid,
    op_return_data: Option<&[u8]>,
) -> Result<Vec<Option<anyhow::Error>>> {
    let n_ops = input.insts.ops.len();
    let resolved = match verify_aggregate(runtime, &input.insts).await {
        Ok(r) => r,
        Err(AggregateVerificationError::Infrastructure(error)) => {
            return Err(error.context("aggregate verification infrastructure failure"));
        }
        Err(AggregateVerificationError::Rejected(e)) => {
            warn!("Aggregate verification failed: {e}");
            // Fan the input-wide rejection across every op slot so the
            // positional vector remains length-aligned with input.insts.ops.
            // Aggregates can't carry `Sponsor` (BLS shape validation rejects),
            // so the walker has nothing to capture this input.
            let msg = format!("aggregate verification failed: {e:#}");
            return Ok((0..n_ops).map(|_| Some(anyhow::anyhow!("{msg}"))).collect());
        }
    };

    let agg = input
        .insts
        .aggregate
        .as_ref()
        .expect("aggregate must be present after successful verification");

    // Resolve the publisher's signer_id once — payer for any op with
    // `AggregateSigner.sponsored = true`. The publisher is the Bitcoin
    // input's x_only_pubkey, ensured into the signers table.
    let publisher_signer_id = {
        let identity = runtime
            .get_or_create_identity(&input.x_only_pubkey.to_string())
            .await?;
        identity.signer_id()
    };

    let mut errors: Vec<Option<anyhow::Error>> = Vec::with_capacity(n_ops);
    for (op_index, ((inst, agg_signer), &signer_id)) in input
        .insts
        .ops
        .iter()
        .zip(agg.signers.iter())
        .zip(resolved.signer_ids.iter())
        .enumerate()
    {
        if !resolved.signer_map.contains_key(&signer_id) {
            warn!("signer_id {signer_id} not in signer_map after verification");
            errors.push(Some(anyhow::anyhow!(
                "signer_id {signer_id} not in signer_map after verification"
            )));
            continue;
        };

        runtime
            .set_context(
                height,
                Some(TransactionContext {
                    tx_id,
                    tx_index,
                    input_index: input.input_index,
                    op_index: op_index as u32,
                    txid,
                }),
                Some(input.previous_output),
                op_return_data.map(|b| b.to_vec()),
            )
            .await;

        // Every aggregate op advances the signer's nonce. The variant restriction
        // ("Call only") is enforced separately in validate_aggregate_shape; here
        // we just consume the nonce the co-signer committed to in their BLS sig.
        match runtime
            .storage
            .advance_nonce(signer_id, agg_signer.nonce, height)
            .await
        {
            Ok(_) => {}
            Err(IdentityError::InvalidData(msg)) => {
                warn!("aggregate nonce check failed for signer {signer_id}: {msg}");
                errors.push(Some(anyhow::anyhow!(
                    "nonce check failed for signer {signer_id}: {msg}"
                )));
                continue;
            }
            Err(e) => {
                anyhow::bail!("aggregate nonce advance error for signer {signer_id}: {e}");
            }
        }

        // `walker.materialize` handles the precedence: cross-input
        // Sponsor (`walker.active`) wins over the aggregate's per-op
        // publisher offer, which it computes from `signer.sponsored` +
        // the publisher's signer_id we pass in. Capture is a no-op in
        // practice — BLS shape validation rejects Sponsor in aggregates.
        let op =
            match walker.materialize(input, op_index, signer_id, Some(publisher_signer_id), inst) {
                Ok(op) => op,
                Err(e) => {
                    warn!("Rejected aggregate op for signer {signer_id}: {e:#}");
                    errors.push(Some(e));
                    continue;
                }
            };
        errors.push(execute_op(runtime, &op).await?);
    }
    Ok(errors)
}

/// Execute one op against the runtime.
///
/// Returns `Ok(None)` for success; `Ok(Some(e))` for a deterministic
/// failure (the op didn't take effect, but the failure is determinable
/// from chain state — every node will reach the same conclusion);
/// `Err(_)` for a non-deterministic infrastructure failure that
/// crashes the reactor (returning Err propagates upward and aborts).
async fn execute_op(runtime: &mut Runtime, op: &Op) -> Result<Option<anyhow::Error>> {
    let identity = Identity::new(op.metadata.signer_id);
    let signer = Signer::Id(identity);
    let payment = op.metadata.payment.clone();

    match &op.kind {
        OpKind::Publish {
            name,
            bytes,
            provenance,
        } => {
            match runtime
                .publish(&signer, payment, name, bytes, provenance)
                .await
            {
                Ok(_) => Ok(None),
                Err(ExecutionError::Deterministic(e)) => {
                    warn!("Publish operation failed: {e:#}");
                    Ok(Some(e))
                }
                Err(ExecutionError::NonDeterministic(e)) => {
                    Err(e.context("Publish operation infrastructure failure"))
                }
            }
        }
        OpKind::Call { contract, expr, .. } => {
            match runtime
                .execute(Some(&signer), Some(payment), contract, expr)
                .await
            {
                Ok(_) => Ok(None),
                Err(ExecutionError::Deterministic(e)) => {
                    warn!("Call operation failed: {e:#}");
                    Ok(Some(e))
                }
                Err(ExecutionError::NonDeterministic(e)) => {
                    Err(e.context("Call operation infrastructure failure"))
                }
            }
        }
        OpKind::UpdateProvenance {
            contract,
            provenance,
        } => {
            // Charge + result plumbing through the system contract (a no-op
            // proc), mirroring RegisterBlsKey; then the host-side owner authz
            // check and the provenance-log append.
            match runtime
                .execute(
                    Some(&signer),
                    Some(payment),
                    &system::address(),
                    "provenance-updated()",
                )
                .await
            {
                Ok(_) => {}
                Err(ExecutionError::Deterministic(e)) => {
                    warn!("system.provenance-updated failed: {e:#}");
                    return Ok(Some(e));
                }
                Err(ExecutionError::NonDeterministic(e)) => {
                    return Err(e.context("system.provenance-updated infrastructure failure"));
                }
            }
            let address = contract.clone();
            match runtime
                .update_provenance(op.metadata.signer_id, &address, provenance)
                .await
            {
                Ok(_) => Ok(None),
                Err(ExecutionError::Deterministic(e)) => {
                    warn!("UpdateProvenance failed: {e:#}");
                    Ok(Some(e))
                }
                Err(ExecutionError::NonDeterministic(e)) => {
                    Err(e.context("UpdateProvenance infrastructure failure"))
                }
            }
        }
        OpKind::Issuance => match runtime.issuance(&signer).await {
            Ok(_) => Ok(None),
            Err(ExecutionError::Deterministic(e)) => {
                warn!("Issuance operation failed: {e:#}");
                Ok(Some(e))
            }
            Err(ExecutionError::NonDeterministic(e)) => {
                Err(e.context("Issuance infrastructure failure"))
            }
        },
        // Sponsor is a payer-redirection directive: no contract dispatch,
        // no gas held against the runtime. The per-input loop captures
        // `op.metadata.payment` from the materialized Op into
        // `pending_for_next` before reaching `execute_op` (see
        // `process_direct_input`), so this branch is the no-op success
        // that keeps the failure vector positionally aligned.
        OpKind::Sponsor => Ok(None),
        OpKind::RegisterBlsKey {
            bls_pubkey,
            schnorr_sig,
            bls_sig,
        } => {
            // Charge the payer for the registration via the system contract
            // first. If the hold fails (insufficient tokens), the host-side
            // register_bls_key DB write below is skipped.
            match runtime
                .execute(
                    Some(&signer),
                    Some(payment),
                    &system::address(),
                    "registered()",
                )
                .await
            {
                Ok(_) => {}
                Err(ExecutionError::Deterministic(e)) => {
                    warn!("system.registered failed: {e:#}");
                    return Ok(Some(e));
                }
                Err(ExecutionError::NonDeterministic(e)) => {
                    return Err(e.context("system.registered infrastructure failure"));
                }
            }
            match runtime
                .register_bls_key(
                    &signer,
                    bls_pubkey.as_slice(),
                    schnorr_sig.as_slice(),
                    bls_sig.as_slice(),
                )
                .await
            {
                Ok(_) => Ok(None),
                Err(ExecutionError::Deterministic(e)) => {
                    warn!("RegisterBlsKey failed: {e:#}");
                    Ok(Some(e))
                }
                Err(ExecutionError::NonDeterministic(e)) => {
                    Err(e.context("RegisterBlsKey infrastructure failure"))
                }
            }
        }
    }
}
