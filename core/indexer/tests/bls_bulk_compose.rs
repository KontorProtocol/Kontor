use anyhow::{Result, anyhow};
use bitcoin::consensus::encode::deserialize_hex;
use blst::BLST_ERROR;
use blst::min_sig::AggregateSignature;
use indexer::bls::KONTOR_BLS_DST;
use indexer::database::types::OpResultId;
use indexer_types::{BlsBulkOp, ContractAddress as IndexerContractAddress, Inst};
use testlib::*;

interface!(name = "arith", path = "../../test-contracts/arith/wit",);
import!(
    name = "registry",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/registry/wit",
);

const KONTOR_OP_PREFIX: &[u8] = b"KONTOR-OP-V1";

fn build_kontor_op_message(op: &BlsBulkOp) -> Result<Vec<u8>> {
    let op_bytes = indexer_types::serialize(op)?;
    let mut msg = Vec::with_capacity(KONTOR_OP_PREFIX.len() + op_bytes.len());
    msg.extend_from_slice(KONTOR_OP_PREFIX);
    msg.extend_from_slice(&op_bytes);
    Ok(msg)
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_bulk_compose_and_execute_regtest() -> Result<()> {
    // Two distinct signers inside the bundle; a third identity publishes the Bitcoin tx.
    let mut signer1 = reg_tester.identity().await?;
    let mut signer2 = reg_tester.identity().await?;
    let mut publisher = reg_tester.identity().await?;

    // Ensure all participants have KOR to pay gas.
    reg_tester.instruction(&mut signer1, Inst::Issuance).await?;
    reg_tester.instruction(&mut signer2, Inst::Issuance).await?;
    reg_tester
        .instruction(&mut publisher, Inst::Issuance)
        .await?;

    // Publish the `arith` contract on-chain so we can call it.
    let arith_bytes = runtime
        .contract_reader
        .read("arith")
        .await?
        .expect("arith contract bytes not found");
    let publish = reg_tester
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

    let signer1_id = registry::get_signer_id(runtime, &signer1.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer1"))?;
    let signer2_id = registry::get_signer_id(runtime, &signer2.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer2"))?;

    // Build two inner ops.
    let op0 = BlsBulkOp::Call {
        signer_id: signer1_id,
        nonce: 0,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(10, arith::Op::Id),
    };
    let op1 = BlsBulkOp::Call {
        signer_id: signer2_id,
        nonce: 0,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(10, arith::Op::Sum(arith::Operand { y: 8 })),
    };

    // Each signer signs their op message; publisher aggregates.
    let msg0 = build_kontor_op_message(&op0)?;
    let msg1 = build_kontor_op_message(&op1)?;

    let sk1 = blst::min_sig::SecretKey::from_bytes(&signer1.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer1 BLS secret key: {e:?}"))?;
    let sk2 = blst::min_sig::SecretKey::from_bytes(&signer2.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer2 BLS secret key: {e:?}"))?;
    let pk1 = sk1.sk_to_pk();
    let pk2 = sk2.sk_to_pk();

    let sig0 = sk1.sign(&msg0, KONTOR_BLS_DST, &[]);
    let sig1 = sk2.sign(&msg1, KONTOR_BLS_DST, &[]);

    let aggregate = AggregateSignature::aggregate(&[&sig0, &sig1], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;
    let aggregate_sig = aggregate.to_signature();

    // Sanity-check the aggregated signature before going on-chain.
    let msg_refs: Vec<&[u8]> = vec![msg0.as_slice(), msg1.as_slice()];
    let pk_refs = [&pk1, &pk2];
    let verify_result =
        aggregate_sig.aggregate_verify(true, msg_refs.as_slice(), KONTOR_BLS_DST, &pk_refs, true);
    assert_eq!(
        verify_result,
        BLST_ERROR::BLST_SUCCESS,
        "aggregate signature verification failed"
    );

    // Compose + publish the BlsBulk container.
    let bls_bulk_inst = Inst::BlsBulk {
        ops: vec![op0, op1],
        signature: aggregate_sig.to_bytes().to_vec(),
    };
    let res = reg_tester
        .instruction(&mut publisher, bls_bulk_inst)
        .await?;

    // Result for inner op 0 should decode as eval(10, id) = 10.
    let v0 = res
        .result
        .value
        .as_deref()
        .ok_or_else(|| anyhow!("expected a return value for inner op 0"))?;
    let decoded0 = arith::wave::eval_parse_return_expr(v0);
    assert_eq!(decoded0.value, 10);

    // Inner op 1 should exist at op_index=1 and decode as eval(10, sum({y:8})) = 18.
    let reveal_tx = deserialize_hex::<bitcoin::Transaction>(&res.reveal_tx_hex)?;
    let op1_id = OpResultId::builder()
        .txid(reveal_tx.compute_txid().to_string())
        .op_index(1)
        .build();
    let client = reg_tester.kontor_client().await;
    let result1 = client
        .result(&op1_id)
        .await?
        .ok_or_else(|| anyhow!("missing result for inner op 1"))?;
    let v1 = result1
        .value
        .as_deref()
        .ok_or_else(|| anyhow!("expected a return value for inner op 1"))?;
    let decoded1 = arith::wave::eval_parse_return_expr(v1);
    assert_eq!(decoded1.value, 18);

    // The contract's last_op should reflect the *second* inner call.
    let arith_runtime_contract: indexer::runtime::ContractAddress = arith_contract
        .to_string()
        .parse()
        .map_err(|e| anyhow!("invalid runtime contract address: {e}"))?;
    let last_op_wave = reg_tester
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op = arith::wave::last_op_parse_return_expr(&last_op_wave);
    assert_eq!(last_op, Some(arith::Op::Sum(arith::Operand { y: 8 })));

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_bulk_replay_protection_nonce_regtest() -> Result<()> {
    let mut signer = reg_tester.identity().await?;
    let mut publisher = reg_tester.identity().await?;

    reg_tester.instruction(&mut signer, Inst::Issuance).await?;
    reg_tester
        .instruction(&mut publisher, Inst::Issuance)
        .await?;

    let arith_bytes = runtime
        .contract_reader
        .read("arith")
        .await?
        .expect("arith contract bytes not found");
    let publish = reg_tester
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

    let signer_id = registry::get_signer_id(runtime, &signer.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer"))?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;

    let arith_runtime_contract: indexer::runtime::ContractAddress = arith_contract
        .to_string()
        .parse()
        .map_err(|e| anyhow!("invalid runtime contract address: {e}"))?;

    let nonce = 7;

    // First bundle: nonce is fresh → should succeed.
    let op0 = BlsBulkOp::Call {
        signer_id,
        nonce,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(2, arith::Op::Id),
    };
    let msg0 = build_kontor_op_message(&op0)?;
    let sig0 = sk.sign(&msg0, KONTOR_BLS_DST, &[]);
    let aggregate0 = AggregateSignature::aggregate(&[&sig0], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;
    reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![op0],
                signature: aggregate0.to_signature().to_bytes().to_vec(),
            },
        )
        .await?;

    let last_op_wave = reg_tester
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op = arith::wave::last_op_parse_return_expr(&last_op_wave);
    assert_eq!(last_op, Some(arith::Op::Id));

    // Second bundle: reuse the same (signer_id, nonce) → must be rejected (even if the op differs).
    let op1 = BlsBulkOp::Call {
        signer_id,
        nonce,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(3, arith::Op::Sum(arith::Operand { y: 8 })),
    };
    let msg1 = build_kontor_op_message(&op1)?;
    let sig1 = sk.sign(&msg1, KONTOR_BLS_DST, &[]);
    let aggregate1 = AggregateSignature::aggregate(&[&sig1], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;
    let res = reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![op1],
                signature: aggregate1.to_signature().to_bytes().to_vec(),
            },
        )
        .await;
    assert!(res.is_err(), "expected reused nonce to be rejected");

    let last_op_wave = reg_tester
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op = arith::wave::last_op_parse_return_expr(&last_op_wave);
    assert_eq!(last_op, Some(arith::Op::Id));

    // Third bundle: new nonce → should succeed and update state.
    let op2 = BlsBulkOp::Call {
        signer_id,
        nonce: nonce + 1,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(3, arith::Op::Sum(arith::Operand { y: 8 })),
    };
    let msg2 = build_kontor_op_message(&op2)?;
    let sig2 = sk.sign(&msg2, KONTOR_BLS_DST, &[]);
    let aggregate2 = AggregateSignature::aggregate(&[&sig2], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;
    reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![op2],
                signature: aggregate2.to_signature().to_bytes().to_vec(),
            },
        )
        .await?;

    let last_op_wave = reg_tester
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op = arith::wave::last_op_parse_return_expr(&last_op_wave);
    assert_eq!(last_op, Some(arith::Op::Sum(arith::Operand { y: 8 })));

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_bulk_unknown_signer_id_is_skipped_regtest() -> Result<()> {
    let mut signer = reg_tester.identity().await?;
    let mut publisher = reg_tester.identity().await?;
    reg_tester.instruction(&mut signer, Inst::Issuance).await?;
    reg_tester
        .instruction(&mut publisher, Inst::Issuance)
        .await?;

    let arith_bytes = runtime
        .contract_reader
        .read("arith")
        .await?
        .expect("arith contract bytes not found");
    let publish = reg_tester
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
    let signer_id = registry::get_signer_id(runtime, &signer.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer"))?;

    let op0 = BlsBulkOp::Call {
        signer_id,
        nonce: 1,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(5, arith::Op::Id),
    };
    let op1 = BlsBulkOp::Call {
        signer_id: signer_id + 10_000,
        nonce: 0,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(7, arith::Op::Id),
    };
    let op2 = BlsBulkOp::Call {
        signer_id,
        nonce: 2,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(11, arith::Op::Id),
    };

    let msg0 = build_kontor_op_message(&op0)?;
    let msg1 = build_kontor_op_message(&op1)?;
    let msg2 = build_kontor_op_message(&op2)?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let sig0 = sk.sign(&msg0, KONTOR_BLS_DST, &[]);
    let sig1 = sk.sign(&msg1, KONTOR_BLS_DST, &[]);
    let sig2 = sk.sign(&msg2, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&sig0, &sig1, &sig2], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;

    let res = reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![op0, op1, op2],
                signature: aggregate.to_signature().to_bytes().to_vec(),
            },
        )
        .await;
    assert!(res.is_err(), "expected unknown signer_id to reject bundle");
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_bulk_requires_registered_signer_id_regtest() -> Result<()> {
    let mut signer = reg_tester.identity().await?;
    let mut publisher = reg_tester.identity().await?;
    reg_tester.instruction(&mut signer, Inst::Issuance).await?;
    reg_tester
        .instruction(&mut publisher, Inst::Issuance)
        .await?;

    let arith_bytes = runtime
        .contract_reader
        .read("arith")
        .await?
        .expect("arith contract bytes not found");
    let publish = reg_tester
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

    let arith_runtime_contract: indexer::runtime::ContractAddress = arith_contract
        .to_string()
        .parse()
        .map_err(|e| anyhow!("invalid runtime contract address: {e}"))?;
    let last_op_before_wave = reg_tester
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op_before = arith::wave::last_op_parse_return_expr(&last_op_before_wave);

    let op = BlsBulkOp::Call {
        signer_id: 999_999_999,
        nonce: 0,
        gas_limit: 50_000,
        contract: arith_contract,
        expr: arith::wave::eval_call_expr(10, arith::Op::Id),
    };
    let msg = build_kontor_op_message(&op)?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let sig = sk.sign(&msg, KONTOR_BLS_DST, &[]);

    let res = reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![op],
                signature: sig.to_bytes().to_vec(),
            },
        )
        .await;
    assert!(res.is_err(), "expected unregistered signer_id to fail");

    let last_op_after_wave = reg_tester
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op_after = arith::wave::last_op_parse_return_expr(&last_op_after_wave);
    assert_eq!(last_op_after, last_op_before);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_bulk_invalid_aggregate_signature_rejects_bundle_regtest() -> Result<()> {
    let mut signer1 = reg_tester.identity().await?;
    let mut signer2 = reg_tester.identity().await?;
    let mut publisher = reg_tester.identity().await?;
    reg_tester.instruction(&mut signer1, Inst::Issuance).await?;
    reg_tester.instruction(&mut signer2, Inst::Issuance).await?;
    reg_tester
        .instruction(&mut publisher, Inst::Issuance)
        .await?;

    let arith_bytes = runtime
        .contract_reader
        .read("arith")
        .await?
        .expect("arith contract bytes not found");
    let publish = reg_tester
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
    let signer1_id = registry::get_signer_id(runtime, &signer1.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer1"))?;
    let signer2_id = registry::get_signer_id(runtime, &signer2.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer2"))?;

    let op0 = BlsBulkOp::Call {
        signer_id: signer1_id,
        nonce: 0,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(2, arith::Op::Id),
    };
    let op1 = BlsBulkOp::Call {
        signer_id: signer2_id,
        nonce: 0,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(3, arith::Op::Id),
    };
    let op1_tampered = BlsBulkOp::Call {
        signer_id: signer2_id,
        nonce: 0,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(4, arith::Op::Id),
    };

    let msg0 = build_kontor_op_message(&op0)?;
    let msg1 = build_kontor_op_message(&op1)?;
    let sk1 = blst::min_sig::SecretKey::from_bytes(&signer1.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer1 BLS secret key: {e:?}"))?;
    let sk2 = blst::min_sig::SecretKey::from_bytes(&signer2.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer2 BLS secret key: {e:?}"))?;
    let sig0 = sk1.sign(&msg0, KONTOR_BLS_DST, &[]);
    let sig1 = sk2.sign(&msg1, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&sig0, &sig1], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;

    let arith_runtime_contract: indexer::runtime::ContractAddress = arith_contract
        .to_string()
        .parse()
        .map_err(|e| anyhow!("invalid runtime contract address: {e}"))?;
    let last_op_before_wave = reg_tester
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op_before = arith::wave::last_op_parse_return_expr(&last_op_before_wave);

    let res = reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![op0, op1_tampered],
                signature: aggregate.to_signature().to_bytes().to_vec(),
            },
        )
        .await;
    assert!(
        res.is_err(),
        "expected tampered op payload to fail aggregate verification"
    );

    let last_op_after_wave = reg_tester
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op_after = arith::wave::last_op_parse_return_expr(&last_op_after_wave);
    assert_eq!(last_op_after, last_op_before);
    Ok(())
}
