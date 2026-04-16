use anyhow::{Result, anyhow};
use bitcoin::consensus::encode::deserialize_hex;
use blst::BLST_ERROR;
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
async fn bls_bulk_compose_and_execute_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();

    // Two distinct signers inside the bundle; a third identity publishes the Bitcoin tx.
    let signer1 = rt.identity().await?;
    let signer2 = rt.identity().await?;
    let mut publisher = rt.identity().await?;

    // Publish the `arith` contract on-chain so we can call it.
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

    let signer1_id = rt.get_signer_id( &signer1.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer1"))?;
    let signer2_id = rt.get_signer_id( &signer2.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer2"))?;

    // Build two inner ops.
    let op0 = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(10, arith::Op::Id),
    );
    let op1 = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(10, arith::Op::Sum(arith::Operand { y: 8 })),
    );

    // Each signer signs their op message; publisher aggregates.
    let msg0 = op0.aggregate_signing_message(signer1_id)?;
    let msg1 = op1.aggregate_signing_message(signer2_id)?;

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
    let res = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(
                vec![op0, op1],
                vec![signer1_id, signer2_id],
                aggregate_sig.to_bytes().to_vec(),
            ),
        )
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
    let client = rt.kontor_client().await;
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
            .registry_entry(&signer1_id.to_string())
            .await?
            .next_nonce,
        1
    );
    assert_eq!(
        client
            .registry_entry(&signer2_id.to_string())
            .await?
            .next_nonce,
        1
    );

    // The contract's last_op should reflect the *second* inner call.
    let arith_runtime_contract: indexer::runtime::ContractAddress = arith_contract
        .to_string()
        .parse()
        .map_err(|e| anyhow!("invalid runtime contract address: {e}"))?;
    let last_op_wave = rt
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op = arith::wave::last_op_parse_return_expr(&last_op_wave);
    assert_eq!(last_op, Some(arith::Op::Sum(arith::Operand { y: 8 })));

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_bulk_unknown_signer_id_rejects_bundle_regtest() -> Result<()> {
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
    let signer_id = rt.get_signer_id( &signer.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer"))?;

    let op0 = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(5, arith::Op::Id),
    );
    let op1 = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(7, arith::Op::Id),
    );
    let op2 = aggregate_call(
        1,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(11, arith::Op::Id),
    );

    let msg0 = op0.aggregate_signing_message(signer_id)?;
    let msg1 = op1.aggregate_signing_message(signer_id + 10_000)?;
    let msg2 = op2.aggregate_signing_message(signer_id)?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let sig0 = sk.sign(&msg0, KONTOR_BLS_DST, &[]);
    let sig1 = sk.sign(&msg1, KONTOR_BLS_DST, &[]);
    let sig2 = sk.sign(&msg2, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&sig0, &sig1, &sig2], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;

    let res = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(
                vec![op0, op1, op2],
                vec![signer_id, signer_id + 10_000, signer_id],
                aggregate.to_signature().to_bytes().to_vec(),
            ),
        )
        .await;
    assert!(res.is_err(), "expected unknown signer_id to reject bundle");
    let entry = rt.get_signer_entry(&signer_id.to_string()).await?;
    let entry = entry.ok_or_else(|| anyhow!("missing registry entry after rejection"))?;
    assert_eq!(
        entry.next_nonce, 0,
        "unknown signer rejection must not advance nonce"
    );
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_bulk_requires_registered_signer_id_regtest() -> Result<()> {
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

    let arith_runtime_contract: indexer::runtime::ContractAddress = arith_contract
        .to_string()
        .parse()
        .map_err(|e| anyhow!("invalid runtime contract address: {e}"))?;
    let last_op_before_wave = rt
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op_before = arith::wave::last_op_parse_return_expr(&last_op_before_wave);

    let op = aggregate_call(
        0,
        50_000,
        arith_contract,
        arith::wave::eval_call_expr(10, arith::Op::Id),
    );
    let msg = op.aggregate_signing_message(999_999_999)?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let sig = sk.sign(&msg, KONTOR_BLS_DST, &[]);

    let res = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(vec![op], vec![999_999_999], sig.to_bytes().to_vec()),
        )
        .await;
    assert!(res.is_err(), "expected unregistered signer_id to fail");

    let last_op_after_wave = rt
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op_after = arith::wave::last_op_parse_return_expr(&last_op_after_wave);
    assert_eq!(last_op_after, last_op_before);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_bulk_invalid_aggregate_signature_rejects_bundle_regtest() -> Result<()> {
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
    let signer1_id = rt.get_signer_id( &signer1.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer1"))?;
    let signer2_id = rt.get_signer_id( &signer2.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for signer2"))?;

    let op0 = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(2, arith::Op::Id),
    );
    let op1 = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(3, arith::Op::Id),
    );
    let op1_tampered = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(4, arith::Op::Id),
    );

    let msg0 = op0.aggregate_signing_message(signer1_id)?;
    let msg1 = op1.aggregate_signing_message(signer2_id)?;
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
    let last_op_before_wave = rt
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op_before = arith::wave::last_op_parse_return_expr(&last_op_before_wave);

    let res = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(
                vec![op0, op1_tampered],
                vec![signer1_id, signer2_id],
                aggregate.to_signature().to_bytes().to_vec(),
            ),
        )
        .await;
    assert!(
        res.is_err(),
        "expected tampered op payload to fail aggregate verification"
    );

    let last_op_after_wave = rt
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op_after = arith::wave::last_op_parse_return_expr(&last_op_after_wave);
    assert_eq!(last_op_after, last_op_before);
    Ok(())
}
