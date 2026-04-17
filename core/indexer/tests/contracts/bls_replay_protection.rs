//! BLS nonce / replay protection tests.
//!
//! Verifies that the indexer correctly enforces sequential nonce consumption
//! and rejects duplicate or replayed operations.

use anyhow::{Result, anyhow};
use bitcoin::consensus::encode::deserialize_hex;
use blst::min_sig::AggregateSignature;
use indexer::bls::KONTOR_BLS_DST;
use indexer::database::types::OpResultId;
use indexer_types::{AggregateInfo, ContractAddress as IndexerContractAddress, Inst, Insts};
use testlib::*;

interface!(name = "arith", path = "../../test-contracts/arith/wit",);

fn aggregate_call(
    nonce: u64,
    gas_limit: u64,
    contract: IndexerContractAddress,
    expr: String,
) -> Inst {
    Inst::Call {
        gas_limit,
        contract,
        nonce: Some(nonce),
        expr,
    }
}

fn aggregate_insts(ops: Vec<Inst>, signer_ids: Vec<u64>, signature: Vec<u8>) -> Insts {
    Insts {
        ops,
        aggregate: Some(AggregateInfo {
            signer_ids,
            signature,
        }),
    }
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_bulk_duplicate_nonce_within_bundle_skips_op_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let signer = rt.identity().await?;
    let mut publisher = rt.identity().await?;

    let arith_bytes = runtime
        .contract_reader
        .read("arith")
        .await?
        .expect("arith contract bytes not found");
    let publish = rt
        .instruction(
            &mut publisher,
            Inst::Publish {
                gas_limit: 50_000,
                name: "arith".to_string(),
                bytes: arith_bytes,
            },
        )
        .await?;
    let arith_contract: IndexerContractAddress = publish.result.contract.parse().map_err(|e| {
        anyhow!(
            "invalid contract address {}: {}",
            publish.result.contract,
            e
        )
    })?;

    let signer_id = rt
        .get_signer_id(&signer.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer"))?;

    let nonce = 0u64;
    let op0 = aggregate_call(
        nonce,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(1, arith::Op::Id),
    );
    let op1 = aggregate_call(
        nonce,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(2, arith::Op::Id),
    );
    let msg0 = op0.aggregate_signing_message(signer_id)?;
    let msg1 = op1.aggregate_signing_message(signer_id)?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let sig0 = sk.sign(&msg0, KONTOR_BLS_DST, &[]);
    let sig1 = sk.sign(&msg1, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&sig0, &sig1], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;

    let res = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(
                vec![op0, op1],
                vec![signer_id, signer_id],
                aggregate.to_signature().to_bytes().to_vec(),
            ),
        )
        .await?;

    // Op0 (nonce=0) executes successfully.
    let v0 = res
        .result
        .value
        .as_deref()
        .ok_or_else(|| anyhow!("expected a return value for op0"))?;
    let decoded0 = arith::wave::eval_parse_return_expr(v0);
    assert_eq!(decoded0.value, 1);

    // Op1 (duplicate nonce=0) was skipped; nonce advanced to 1 from op0 only.
    let client = rt.kontor_client().await;
    assert_eq!(
        client
            .registry_entry(&signer_id.to_string())
            .await?
            .next_nonce,
        1
    );

    // Follow-up op must use nonce=1 (op0 consumed nonce=0).
    let op2 = aggregate_call(
        1,
        50_000,
        arith_contract,
        arith::wave::eval_call_expr(3, arith::Op::Id),
    );
    let msg2 = op2.aggregate_signing_message(signer_id)?;
    let sig2 = sk.sign(&msg2, KONTOR_BLS_DST, &[]);
    let ok = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(vec![op2], vec![signer_id], sig2.to_bytes().to_vec()),
        )
        .await?;
    let v = ok
        .result
        .value
        .as_deref()
        .ok_or_else(|| anyhow!("expected a return value for op"))?;
    let decoded = arith::wave::eval_parse_return_expr(v);
    assert_eq!(decoded.value, 3);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_bulk_replay_nonce_across_blocks_rejects_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let signer = rt.identity().await?;
    let mut publisher = rt.identity().await?;

    let arith_bytes = runtime
        .contract_reader
        .read("arith")
        .await?
        .expect("arith contract bytes not found");
    let publish = rt
        .instruction(
            &mut publisher,
            Inst::Publish {
                gas_limit: 50_000,
                name: "arith".to_string(),
                bytes: arith_bytes,
            },
        )
        .await?;
    let arith_contract: IndexerContractAddress = publish.result.contract.parse().map_err(|e| {
        anyhow!(
            "invalid contract address {}: {}",
            publish.result.contract,
            e
        )
    })?;

    let signer_id = rt
        .get_signer_id(&signer.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer"))?;

    let nonce = 0u64;
    let op0 = aggregate_call(
        nonce,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(5, arith::Op::Id),
    );
    let msg0 = op0.aggregate_signing_message(signer_id)?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let sig0 = sk.sign(&msg0, KONTOR_BLS_DST, &[]);
    rt.instruction_insts(
        &mut publisher,
        aggregate_insts(vec![op0], vec![signer_id], sig0.to_bytes().to_vec()),
    )
    .await?;

    let arith_runtime_contract: indexer::runtime::ContractAddress = arith_contract
        .to_string()
        .parse()
        .map_err(|e| anyhow!("invalid runtime contract address: {e}"))?;
    let last_op_before_wave = rt
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op_before = arith::wave::last_op_parse_return_expr(&last_op_before_wave);

    let op1 = aggregate_call(
        nonce,
        50_000,
        arith_contract,
        arith::wave::eval_call_expr(6, arith::Op::Id),
    );
    let msg1 = op1.aggregate_signing_message(signer_id)?;
    let sig1 = sk.sign(&msg1, KONTOR_BLS_DST, &[]);
    let _replay = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(vec![op1], vec![signer_id], sig1.to_bytes().to_vec()),
        )
        .await;

    // Replay op was skipped (nonce mismatch); contract state unchanged.
    let last_op_after_wave = rt
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op_after = arith::wave::last_op_parse_return_expr(&last_op_after_wave);
    assert_eq!(last_op_after, last_op_before);

    // Nonce stays at 1 (only the first bundle's op consumed it).
    let client = rt.kontor_client().await;
    assert_eq!(
        client
            .registry_entry(&signer_id.to_string())
            .await?
            .next_nonce,
        1
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_bulk_failed_execution_still_consumes_nonce_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let signer = rt.identity().await?;
    let mut publisher = rt.identity().await?;

    let signer_id = rt
        .get_signer_id(&signer.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer"))?;
    let missing_contract = IndexerContractAddress {
        name: "arith".to_string(),
        height: 999_999,
        tx_index: 0,
    };
    let failing_op = aggregate_call(
        0,
        50_000,
        missing_contract,
        arith::wave::eval_call_expr(9, arith::Op::Id),
    );
    let failing_msg = failing_op.aggregate_signing_message(signer_id)?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let failing_sig = sk.sign(&failing_msg, KONTOR_BLS_DST, &[]);

    let _failed = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(
                vec![failing_op],
                vec![signer_id],
                failing_sig.to_bytes().to_vec(),
            ),
        )
        .await;

    let client = rt.kontor_client().await;
    assert_eq!(
        client
            .registry_entry(&signer_id.to_string())
            .await?
            .next_nonce,
        1
    );

    let arith_bytes = runtime
        .contract_reader
        .read("arith")
        .await?
        .expect("arith contract bytes not found");
    let publish = rt
        .instruction(
            &mut publisher,
            Inst::Publish {
                gas_limit: 50_000,
                name: "arith".to_string(),
                bytes: arith_bytes,
            },
        )
        .await?;
    let arith_contract: IndexerContractAddress = publish.result.contract.parse().map_err(|e| {
        anyhow!(
            "invalid contract address {}: {}",
            publish.result.contract,
            e
        )
    })?;

    let recovery_op = aggregate_call(
        1,
        50_000,
        arith_contract,
        arith::wave::eval_call_expr(12, arith::Op::Id),
    );
    let recovery_msg = recovery_op.aggregate_signing_message(signer_id)?;
    let recovery_sig = sk.sign(&recovery_msg, KONTOR_BLS_DST, &[]);
    let recovery = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(
                vec![recovery_op],
                vec![signer_id],
                recovery_sig.to_bytes().to_vec(),
            ),
        )
        .await?;
    let v = recovery
        .result
        .value
        .as_deref()
        .ok_or_else(|| anyhow!("expected a return value for recovery op"))?;
    let decoded = arith::wave::eval_parse_return_expr(v);
    assert_eq!(decoded.value, 12);
    assert_eq!(
        client
            .registry_entry(&signer_id.to_string())
            .await?
            .next_nonce,
        2
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_bulk_interleaved_multi_signer_nonces_advance_independently_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let signer1 = rt.identity().await?;
    let signer2 = rt.identity().await?;
    let mut publisher = rt.identity().await?;

    let arith_bytes = runtime
        .contract_reader
        .read("arith")
        .await?
        .expect("arith contract bytes not found");
    let publish = rt
        .instruction(
            &mut publisher,
            Inst::Publish {
                gas_limit: 50_000,
                name: "arith".to_string(),
                bytes: arith_bytes,
            },
        )
        .await?;
    let arith_contract: IndexerContractAddress = publish.result.contract.parse().map_err(|e| {
        anyhow!(
            "invalid contract address {}: {}",
            publish.result.contract,
            e
        )
    })?;

    let signer1_id = rt
        .get_signer_id(&signer1.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer1"))?;
    let signer2_id = rt
        .get_signer_id(&signer2.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer2"))?;

    let op0 = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(1, arith::Op::Id),
    );
    let op1 = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(2, arith::Op::Id),
    );
    let op2 = aggregate_call(
        1,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(3, arith::Op::Sum(arith::Operand { y: 4 })),
    );
    let op3 = aggregate_call(
        1,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(5, arith::Op::Sum(arith::Operand { y: 6 })),
    );

    let sk1 = blst::min_sig::SecretKey::from_bytes(&signer1.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer1 BLS secret key: {e:?}"))?;
    let sk2 = blst::min_sig::SecretKey::from_bytes(&signer2.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer2 BLS secret key: {e:?}"))?;
    let msg0 = op0.aggregate_signing_message(signer1_id)?;
    let msg1 = op1.aggregate_signing_message(signer2_id)?;
    let msg2 = op2.aggregate_signing_message(signer1_id)?;
    let msg3 = op3.aggregate_signing_message(signer2_id)?;
    let sig0 = sk1.sign(&msg0, KONTOR_BLS_DST, &[]);
    let sig1 = sk2.sign(&msg1, KONTOR_BLS_DST, &[]);
    let sig2 = sk1.sign(&msg2, KONTOR_BLS_DST, &[]);
    let sig3 = sk2.sign(&msg3, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&sig0, &sig1, &sig2, &sig3], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;

    let res = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(
                vec![op0, op1, op2, op3],
                vec![signer1_id, signer2_id, signer1_id, signer2_id],
                aggregate.to_signature().to_bytes().to_vec(),
            ),
        )
        .await?;

    let reveal_tx = deserialize_hex::<bitcoin::Transaction>(&res.reveal_tx_hex)?;
    let client = rt.kontor_client().await;
    let op3_id = OpResultId::builder()
        .txid(reveal_tx.compute_txid().to_string())
        .op_index(3)
        .build();
    let result3 = client
        .result(&op3_id)
        .await?
        .ok_or_else(|| anyhow!("missing result for inner op 3"))?;
    let v3 = result3
        .value
        .as_deref()
        .ok_or_else(|| anyhow!("expected a return value for inner op 3"))?;
    let decoded3 = arith::wave::eval_parse_return_expr(v3);
    assert_eq!(decoded3.value, 11);
    assert_eq!(
        client
            .registry_entry(&signer1_id.to_string())
            .await?
            .next_nonce,
        2
    );
    assert_eq!(
        client
            .registry_entry(&signer2_id.to_string())
            .await?
            .next_nonce,
        2
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_bulk_out_of_order_nonce_skips_op_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let signer = rt.identity().await?;
    let mut publisher = rt.identity().await?;

    let arith_bytes = runtime
        .contract_reader
        .read("arith")
        .await?
        .expect("arith contract bytes not found");
    let publish = rt
        .instruction(
            &mut publisher,
            Inst::Publish {
                gas_limit: 50_000,
                name: "arith".to_string(),
                bytes: arith_bytes,
            },
        )
        .await?;
    let arith_contract: IndexerContractAddress = publish.result.contract.parse().map_err(|e| {
        anyhow!(
            "invalid contract address {}: {}",
            publish.result.contract,
            e
        )
    })?;

    let signer_id = rt
        .get_signer_id(&signer.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer"))?;

    let client = rt.kontor_client().await;
    assert_eq!(
        client
            .registry_entry(&signer_id.to_string())
            .await?
            .next_nonce,
        0,
        "precondition: nonce starts at 0"
    );

    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;

    // First, submit a valid nonce=0 op to advance nonce to 1.
    let valid_op = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(42, arith::Op::Id),
    );
    let valid_msg = valid_op.aggregate_signing_message(signer_id)?;
    let valid_sig = sk.sign(&valid_msg, KONTOR_BLS_DST, &[]);
    let res = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(
                vec![valid_op],
                vec![signer_id],
                valid_sig.to_bytes().to_vec(),
            ),
        )
        .await?;
    let v = res
        .result
        .value
        .as_deref()
        .ok_or_else(|| anyhow!("expected a return value"))?;
    let decoded = arith::wave::eval_parse_return_expr(v);
    assert_eq!(decoded.value, 42);
    assert_eq!(
        client
            .registry_entry(&signer_id.to_string())
            .await?
            .next_nonce,
        1,
        "nonce must advance after valid op"
    );

    // Now submit nonce=0 again (replay) — must be rejected.
    let replay_op = aggregate_call(
        0,
        50_000,
        arith_contract,
        arith::wave::eval_call_expr(99, arith::Op::Id),
    );
    let replay_msg = replay_op.aggregate_signing_message(signer_id)?;
    let replay_sig = sk.sign(&replay_msg, KONTOR_BLS_DST, &[]);

    let _ = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(
                vec![replay_op],
                vec![signer_id],
                replay_sig.to_bytes().to_vec(),
            ),
        )
        .await;

    // Nonce must remain at 1 — the replayed op was rejected.
    assert_eq!(
        client
            .registry_entry(&signer_id.to_string())
            .await?
            .next_nonce,
        1,
        "replayed nonce must not advance"
    );

    Ok(())
}

/// Byte-for-byte replay: takes the exact same signed operation and aggregate
/// signature from a confirmed bundle and resubmits them in a new bundle.
/// The nonce has already been consumed, so the replayed op must be skipped
/// and contract state must not change.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_bulk_exact_bytes_replay_across_blocks_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let signer = rt.identity().await?;
    let mut publisher = rt.identity().await?;

    let arith_bytes = runtime
        .contract_reader
        .read("arith")
        .await?
        .expect("arith contract bytes not found");
    let publish = rt
        .instruction(
            &mut publisher,
            Inst::Publish {
                gas_limit: 50_000,
                name: "arith".to_string(),
                bytes: arith_bytes,
            },
        )
        .await?;
    let arith_contract: IndexerContractAddress = publish.result.contract.parse().map_err(|e| {
        anyhow!(
            "invalid contract address {}: {}",
            publish.result.contract,
            e
        )
    })?;

    let signer_id = rt
        .get_signer_id(&signer.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer"))?;

    // Build and submit the original operation.
    let op = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(7, arith::Op::Id),
    );
    let msg = op.aggregate_signing_message(signer_id)?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let sig = sk.sign(&msg, KONTOR_BLS_DST, &[]);
    let sig_bytes = sig.to_bytes().to_vec();

    rt.instruction_insts(
        &mut publisher,
        aggregate_insts(vec![op.clone()], vec![signer_id], sig_bytes.clone()),
    )
    .await?;

    let client = rt.kontor_client().await;
    assert_eq!(
        client
            .registry_entry(&signer_id.to_string())
            .await?
            .next_nonce,
        1
    );

    let arith_runtime_contract: indexer::runtime::ContractAddress = arith_contract
        .to_string()
        .parse()
        .map_err(|e| anyhow!("invalid runtime contract address: {e}"))?;
    let state_before_wave = rt
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let state_before = arith::wave::last_op_parse_return_expr(&state_before_wave);

    // Replay the exact same op + signature bytes in a new bundle.
    let _ = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(vec![op], vec![signer_id], sig_bytes),
        )
        .await;

    // Nonce unchanged — the replayed op was rejected.
    assert_eq!(
        client
            .registry_entry(&signer_id.to_string())
            .await?
            .next_nonce,
        1,
        "byte-for-byte replay must not advance nonce"
    );

    // Contract state unchanged.
    let state_after_wave = rt
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let state_after = arith::wave::last_op_parse_return_expr(&state_after_wave);
    assert_eq!(
        state_after, state_before,
        "byte-for-byte replay must not change contract state"
    );

    Ok(())
}
