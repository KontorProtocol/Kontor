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
    let msg0 = op0.signing_message()?;
    let msg1 = op1.signing_message()?;

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
    assert_eq!(
        client
            .registry_next_nonce(&signer1_id.to_string())
            .await?
            .next_nonce,
        1
    );
    assert_eq!(
        client
            .registry_next_nonce(&signer2_id.to_string())
            .await?
            .next_nonce,
        1
    );

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
async fn bls_bulk_unknown_signer_id_rejects_bundle_regtest() -> Result<()> {
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
        nonce: 0,
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
        nonce: 1,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(11, arith::Op::Id),
    };

    let msg0 = op0.signing_message()?;
    let msg1 = op1.signing_message()?;
    let msg2 = op2.signing_message()?;
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
    let entry = registry::get_entry_by_id(runtime, signer_id).await?;
    let entry = entry.ok_or_else(|| anyhow!("missing registry entry after rejection"))?;
    assert_eq!(
        entry.next_nonce, 0,
        "unknown signer rejection must not advance nonce"
    );
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
    let msg = op.signing_message()?;
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

    let msg0 = op0.signing_message()?;
    let msg1 = op1.signing_message()?;
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

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_bulk_duplicate_nonce_within_bundle_skips_op_regtest() -> Result<()> {
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

    let nonce = 0u64;
    let op0 = BlsBulkOp::Call {
        signer_id,
        nonce,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(1, arith::Op::Id),
    };
    let op1 = BlsBulkOp::Call {
        signer_id,
        nonce,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(2, arith::Op::Id),
    };
    let msg0 = op0.signing_message()?;
    let msg1 = op1.signing_message()?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let sig0 = sk.sign(&msg0, KONTOR_BLS_DST, &[]);
    let sig1 = sk.sign(&msg1, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&sig0, &sig1], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;

    let res = reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![op0, op1],
                signature: aggregate.to_signature().to_bytes().to_vec(),
            },
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
    let client = reg_tester.kontor_client().await;
    assert_eq!(
        client
            .registry_next_nonce(&signer_id.to_string())
            .await?
            .next_nonce,
        1
    );

    // Follow-up op must use nonce=1 (op0 consumed nonce=0).
    let op2 = BlsBulkOp::Call {
        signer_id,
        nonce: 1,
        gas_limit: 50_000,
        contract: arith_contract,
        expr: arith::wave::eval_call_expr(3, arith::Op::Id),
    };
    let msg2 = op2.signing_message()?;
    let sig2 = sk.sign(&msg2, KONTOR_BLS_DST, &[]);
    let ok = reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![op2],
                signature: sig2.to_bytes().to_vec(),
            },
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

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_bulk_replay_nonce_across_blocks_rejects_regtest() -> Result<()> {
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

    let nonce = 0u64;
    let op0 = BlsBulkOp::Call {
        signer_id,
        nonce,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(5, arith::Op::Id),
    };
    let msg0 = op0.signing_message()?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let sig0 = sk.sign(&msg0, KONTOR_BLS_DST, &[]);
    reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![op0],
                signature: sig0.to_bytes().to_vec(),
            },
        )
        .await?;

    let arith_runtime_contract: indexer::runtime::ContractAddress = arith_contract
        .to_string()
        .parse()
        .map_err(|e| anyhow!("invalid runtime contract address: {e}"))?;
    let last_op_before_wave = reg_tester
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op_before = arith::wave::last_op_parse_return_expr(&last_op_before_wave);

    let op1 = BlsBulkOp::Call {
        signer_id,
        nonce,
        gas_limit: 50_000,
        contract: arith_contract,
        expr: arith::wave::eval_call_expr(6, arith::Op::Id),
    };
    let msg1 = op1.signing_message()?;
    let sig1 = sk.sign(&msg1, KONTOR_BLS_DST, &[]);
    let _replay = reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![op1],
                signature: sig1.to_bytes().to_vec(),
            },
        )
        .await;

    // Replay op was skipped (nonce mismatch); contract state unchanged.
    let last_op_after_wave = reg_tester
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op_after = arith::wave::last_op_parse_return_expr(&last_op_after_wave);
    assert_eq!(last_op_after, last_op_before);

    // Nonce stays at 1 (only the first bundle's op consumed it).
    let client = reg_tester.kontor_client().await;
    assert_eq!(
        client
            .registry_next_nonce(&signer_id.to_string())
            .await?
            .next_nonce,
        1
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_bulk_failed_execution_still_consumes_nonce_regtest() -> Result<()> {
    let mut signer = reg_tester.identity().await?;
    let mut publisher = reg_tester.identity().await?;
    reg_tester.instruction(&mut signer, Inst::Issuance).await?;
    reg_tester
        .instruction(&mut publisher, Inst::Issuance)
        .await?;

    let signer_id = registry::get_signer_id(runtime, &signer.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer"))?;
    let missing_contract = IndexerContractAddress {
        name: "arith".to_string(),
        height: 999_999,
        tx_index: 0,
    };
    let failing_op = BlsBulkOp::Call {
        signer_id,
        nonce: 0,
        gas_limit: 50_000,
        contract: missing_contract,
        expr: arith::wave::eval_call_expr(9, arith::Op::Id),
    };
    let failing_msg = failing_op.signing_message()?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let failing_sig = sk.sign(&failing_msg, KONTOR_BLS_DST, &[]);

    let _failed = reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![failing_op],
                signature: failing_sig.to_bytes().to_vec(),
            },
        )
        .await;

    let client = reg_tester.kontor_client().await;
    assert_eq!(
        client
            .registry_next_nonce(&signer_id.to_string())
            .await?
            .next_nonce,
        1
    );

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

    let recovery_op = BlsBulkOp::Call {
        signer_id,
        nonce: 1,
        gas_limit: 50_000,
        contract: arith_contract,
        expr: arith::wave::eval_call_expr(12, arith::Op::Id),
    };
    let recovery_msg = recovery_op.signing_message()?;
    let recovery_sig = sk.sign(&recovery_msg, KONTOR_BLS_DST, &[]);
    let recovery = reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![recovery_op],
                signature: recovery_sig.to_bytes().to_vec(),
            },
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
            .registry_next_nonce(&signer_id.to_string())
            .await?
            .next_nonce,
        2
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_bulk_interleaved_multi_signer_nonces_advance_independently_regtest() -> Result<()> {
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
        expr: arith::wave::eval_call_expr(1, arith::Op::Id),
    };
    let op1 = BlsBulkOp::Call {
        signer_id: signer2_id,
        nonce: 0,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(2, arith::Op::Id),
    };
    let op2 = BlsBulkOp::Call {
        signer_id: signer1_id,
        nonce: 1,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(3, arith::Op::Sum(arith::Operand { y: 4 })),
    };
    let op3 = BlsBulkOp::Call {
        signer_id: signer2_id,
        nonce: 1,
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        expr: arith::wave::eval_call_expr(5, arith::Op::Sum(arith::Operand { y: 6 })),
    };

    let sk1 = blst::min_sig::SecretKey::from_bytes(&signer1.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer1 BLS secret key: {e:?}"))?;
    let sk2 = blst::min_sig::SecretKey::from_bytes(&signer2.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer2 BLS secret key: {e:?}"))?;
    let msg0 = op0.signing_message()?;
    let msg1 = op1.signing_message()?;
    let msg2 = op2.signing_message()?;
    let msg3 = op3.signing_message()?;
    let sig0 = sk1.sign(&msg0, KONTOR_BLS_DST, &[]);
    let sig1 = sk2.sign(&msg1, KONTOR_BLS_DST, &[]);
    let sig2 = sk1.sign(&msg2, KONTOR_BLS_DST, &[]);
    let sig3 = sk2.sign(&msg3, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&sig0, &sig1, &sig2, &sig3], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;

    let res = reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![op0, op1, op2, op3],
                signature: aggregate.to_signature().to_bytes().to_vec(),
            },
        )
        .await?;

    let reveal_tx = deserialize_hex::<bitcoin::Transaction>(&res.reveal_tx_hex)?;
    let client = reg_tester.kontor_client().await;
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
            .registry_next_nonce(&signer1_id.to_string())
            .await?
            .next_nonce,
        2
    );
    assert_eq!(
        client
            .registry_next_nonce(&signer2_id.to_string())
            .await?
            .next_nonce,
        2
    );

    Ok(())
}
