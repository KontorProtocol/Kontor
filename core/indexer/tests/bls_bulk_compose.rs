use anyhow::{Result, anyhow};
use blst::BLST_ERROR;
use blst::min_sig::AggregateSignature;
use indexer::bls::KONTOR_BLS_DST;
use indexer::runtime;
use indexer_types::{
    AggregateInfo, ContractAddress as IndexerContractAddress, Inst, Insts, Signer,
};
use testlib::*;

interface!(name = "arith", path = "../../test-contracts/arith/wit",);
import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/token/wit",
);
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

    let signer1_id = signer1
        .signer_id
        .ok_or_else(|| anyhow!("missing signer_id for signer1"))?;
    let signer2_id = signer2
        .signer_id
        .ok_or_else(|| anyhow!("missing signer_id for signer2"))?;

    // Build two inner ops.
    let inst0 = Inst::Call {
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        nonce: Some(0),
        expr: arith::wave::eval_call_expr(10, arith::Op::Id),
    };
    let inst1 = Inst::Call {
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        nonce: Some(0),
        expr: arith::wave::eval_call_expr(10, arith::Op::Sum(arith::Operand { y: 8 })),
    };

    // Each signer signs their op message; publisher aggregates.
    let msg0 = inst0.aggregate_signing_message(signer1_id)?;
    let msg1 = inst1.aggregate_signing_message(signer2_id)?;

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

    // Compose + publish the aggregate batch.
    let res = reg_tester
        .insts_instruction(
            &mut publisher,
            Insts {
                ops: vec![inst0, inst1],
                aggregate: Some(AggregateInfo {
                    signer_ids: vec![signer1_id, signer2_id],
                    signature: aggregate_sig.to_bytes().to_vec(),
                }),
            },
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

    // Inner op 1 should also be returned by the multi-op helper.
    assert_eq!(res.ops.len(), 2);
    let v1 = res.ops[1]
        .result
        .as_ref()
        .ok_or_else(|| anyhow!("missing result for inner op 1"))?
        .value
        .as_deref()
        .ok_or_else(|| anyhow!("expected a return value for inner op 1"))?;
    let decoded1 = arith::wave::eval_parse_return_expr(v1);
    assert_eq!(decoded1.value, 18);
    let client = reg_tester.kontor_client().await;
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
    let last_op_wave = reg_tester
        .view(&arith_runtime_contract, &arith::wave::last_op_call_expr())
        .await?;
    let last_op = arith::wave::last_op_parse_return_expr(&last_op_wave);
    assert_eq!(last_op, Some(arith::Op::Sum(arith::Operand { y: 8 })));

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn direct_and_aggregate_calls_share_signer_id_account_regtest() -> Result<()> {
    let mut signer = reg_tester.identity().await?;
    let mut publisher = reg_tester.identity().await?;

    reg_tester
        .instruction(&mut publisher, Inst::Issuance)
        .await?;

    // Direct path should canonicalize the witness x-only pubkey into the registry signer_id.
    reg_tester.instruction(&mut signer, Inst::Issuance).await?;

    let signer_id = signer
        .signer_id
        .ok_or_else(|| anyhow!("missing signer_id for signer"))?;
    let signer_key = match Signer::new_signer_id(signer_id) {
        Signer::SignerId { signer_key, .. } => signer_key,
        other => return Err(anyhow!("expected SignerId, got {other:?}")),
    };

    // Aggregate path should hit the same logical account, not create a second x-only account.
    let aggregate_call = Inst::Call {
        gas_limit: 50_000,
        contract: runtime::token::address().into(),
        nonce: Some(0),
        expr: token::wave::mint_call_expr(Decimal::from(25)),
    };
    let msg = aggregate_call.aggregate_signing_message(signer_id)?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let sig = sk.sign(&msg, KONTOR_BLS_DST, &[]);

    reg_tester
        .insts_instruction(
            &mut publisher,
            Insts {
                ops: vec![aggregate_call],
                aggregate: Some(AggregateInfo {
                    signer_ids: vec![signer_id],
                    signature: sig.to_bytes().to_vec(),
                }),
            },
        )
        .await?;

    let signer_balance = token::balance(runtime, &signer_key).await?;
    let x_only_balance = token::balance(runtime, &signer.x_only_public_key().to_string()).await?;

    assert_eq!(
        x_only_balance, None,
        "direct execution must no longer create a separate x-only account"
    );
    assert!(
        signer_balance.ok_or_else(|| anyhow!("expected signer-id balance to exist"))?
            > Decimal::from(30),
        "direct issuance and aggregate mint should accumulate on the same signer-id account",
    );

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
    let signer_id = signer
        .signer_id
        .ok_or_else(|| anyhow!("missing signer_id for signer"))?;

    let inst0 = Inst::Call {
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        nonce: Some(0),
        expr: arith::wave::eval_call_expr(5, arith::Op::Id),
    };
    let inst1 = Inst::Call {
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        nonce: Some(0),
        expr: arith::wave::eval_call_expr(7, arith::Op::Id),
    };
    let inst2 = Inst::Call {
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        nonce: Some(1),
        expr: arith::wave::eval_call_expr(11, arith::Op::Id),
    };

    let msg0 = inst0.aggregate_signing_message(signer_id)?;
    let msg1 = inst1.aggregate_signing_message(signer_id + 10_000)?;
    let msg2 = inst2.aggregate_signing_message(signer_id)?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let sig0 = sk.sign(&msg0, KONTOR_BLS_DST, &[]);
    let sig1 = sk.sign(&msg1, KONTOR_BLS_DST, &[]);
    let sig2 = sk.sign(&msg2, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&sig0, &sig1, &sig2], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;

    let res = reg_tester
        .insts_instruction(
            &mut publisher,
            Insts {
                ops: vec![inst0, inst1, inst2],
                aggregate: Some(AggregateInfo {
                    signer_ids: vec![signer_id, signer_id + 10_000, signer_id],
                    signature: aggregate.to_signature().to_bytes().to_vec(),
                }),
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

    let inst = Inst::Call {
        gas_limit: 50_000,
        contract: arith_contract,
        nonce: Some(0),
        expr: arith::wave::eval_call_expr(10, arith::Op::Id),
    };
    let msg = inst.aggregate_signing_message(999_999_999)?;
    let sk = blst::min_sig::SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let sig = sk.sign(&msg, KONTOR_BLS_DST, &[]);

    let res = reg_tester
        .insts_instruction(
            &mut publisher,
            Insts {
                ops: vec![inst],
                aggregate: Some(AggregateInfo {
                    signer_ids: vec![999_999_999],
                    signature: sig.to_bytes().to_vec(),
                }),
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
    let signer1_id = signer1
        .signer_id
        .ok_or_else(|| anyhow!("missing signer_id for signer1"))?;
    let signer2_id = signer2
        .signer_id
        .ok_or_else(|| anyhow!("missing signer_id for signer2"))?;

    let inst0 = Inst::Call {
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        nonce: Some(0),
        expr: arith::wave::eval_call_expr(2, arith::Op::Id),
    };
    let inst1 = Inst::Call {
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        nonce: Some(0),
        expr: arith::wave::eval_call_expr(3, arith::Op::Id),
    };
    let inst1_tampered = Inst::Call {
        gas_limit: 50_000,
        contract: arith_contract.clone(),
        nonce: Some(0),
        expr: arith::wave::eval_call_expr(4, arith::Op::Id),
    };

    let msg0 = inst0.aggregate_signing_message(signer1_id)?;
    let msg1 = inst1.aggregate_signing_message(signer2_id)?;
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
        .insts_instruction(
            &mut publisher,
            Insts {
                ops: vec![inst0, inst1_tampered],
                aggregate: Some(AggregateInfo {
                    signer_ids: vec![signer1_id, signer2_id],
                    signature: aggregate.to_signature().to_bytes().to_vec(),
                }),
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
