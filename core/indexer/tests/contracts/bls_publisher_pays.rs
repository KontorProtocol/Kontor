use anyhow::{Result, anyhow};
use bitcoin::consensus::encode::deserialize_hex;
use blst::BLST_ERROR;
use blst::min_sig::AggregateSignature;
use indexer::bls::KONTOR_BLS_DST;
use indexer::database::types::OpResultId;
use indexer_types::{
    AggregateInfo, AggregateSigner, ContractAddress as IndexerContractAddress, Inst, InstKind,
    Insts, SignerRef,
};
use testlib::*;

interface!(name = "arith", path = "../../test-contracts/arith/wit",);

/// Build an aggregate Insts. Publisher's sponsorship is now per-op on
/// `AggregateSigner.sponsored`; the cap is `Inst.gas_limit` (the publisher
/// signs the bulk including each Inst's gas_limit, so they've committed).
fn aggregate_insts(ops: Vec<Inst>, signers: Vec<AggregateSigner>, signature: Vec<u8>) -> Insts {
    Insts {
        ops,
        aggregate: Some(AggregateInfo { signers, signature }),
    }
}

fn call_with_gas_limit(gas_limit: u64, contract: IndexerContractAddress, expr: String) -> Inst {
    Inst {
        gas_limit,
        kind: InstKind::Call { contract, expr },
    }
}

fn signer_by_id(id: u64, nonce: u64, sponsored: bool) -> AggregateSigner {
    AggregateSigner {
        identity: SignerRef::SignerId(id),
        nonce,
        sponsored,
    }
}

/// Two co-signers, one publisher. Bulk contains two `Sponsored` ops. After
/// execution, both result rows should report `payer_signer_id` = publisher's
/// signer_id (because the publisher funded the gas), not the co-signer's id.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_publisher_pays_all_sponsored_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();

    let signer1 = rt.identity().await?;
    let signer2 = rt.identity().await?;
    let mut publisher = rt.identity().await?;

    // Publish the test contract first.
    let arith_bytes = runtime
        .contract_reader
        .read("arith")
        .await?
        .expect("arith contract bytes not found");
    let publish = rt
        .instruction(
            &mut publisher,
            Inst {
                gas_limit: 50_000,
                kind: InstKind::Publish {
                    name: "arith".to_string(),
                    bytes: arith_bytes,
                },
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
    let publisher_id = rt
        .get_signer_id(&publisher.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for publisher"))?;

    // Two sponsored ops — co-signers commit nothing of their own balance;
    // publisher's offer covers them at per_op_limit = 50_000 each.
    let op0 = call_with_gas_limit(
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(10, arith::Op::Id),
    );
    let op1 = call_with_gas_limit(
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(10, arith::Op::Sum(arith::Operand { y: 8 })),
    );

    // BLS aggregate signing: each co-signer signs their inner op AND
    // their `sponsored` flag (the publisher can't flip it after the fact
    // without invalidating the BLS sig). Both ops sponsored here.
    let signer1_claim = SignerRef::SignerId(signer1_id);
    let signer2_claim = SignerRef::SignerId(signer2_id);
    let msg0 = op0.aggregate_signing_message(&signer1_claim, 0, true)?;
    let msg1 = op1.aggregate_signing_message(&signer2_claim, 0, true)?;
    let sk1 = blst::min_sig::SecretKey::from_bytes(&signer1.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer1 BLS secret key: {e:?}"))?;
    let sk2 = blst::min_sig::SecretKey::from_bytes(&signer2.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer2 BLS secret key: {e:?}"))?;
    let sig0 = sk1.sign(&msg0, KONTOR_BLS_DST, &[]);
    let sig1 = sk2.sign(&msg1, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&sig0, &sig1], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;
    let aggregate_sig = aggregate.to_signature();

    let pk1 = sk1.sk_to_pk();
    let pk2 = sk2.sk_to_pk();
    let msg_refs: Vec<&[u8]> = vec![msg0.as_slice(), msg1.as_slice()];
    let pk_refs = [&pk1, &pk2];
    assert_eq!(
        aggregate_sig.aggregate_verify(true, msg_refs.as_slice(), KONTOR_BLS_DST, &pk_refs, true),
        BLST_ERROR::BLST_SUCCESS,
    );

    let res = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(
                vec![op0, op1],
                vec![
                    signer_by_id(signer1_id, 0, true),
                    signer_by_id(signer2_id, 0, true),
                ],
                aggregate_sig.to_bytes().to_vec(),
            ),
        )
        .await?;

    // The publisher must be charged for both sponsored ops.
    assert_eq!(
        res.result.payer_signer_id,
        Some(publisher_id as i64),
        "sponsored op 0 should be charged to the publisher"
    );

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
    assert_eq!(
        result1.payer_signer_id,
        Some(publisher_id as i64),
        "sponsored op 1 should be charged to the publisher"
    );

    Ok(())
}

/// Mixed bulk: op 0 is `SelfPay` (signer1 pays), op 1 is `Sponsored`
/// (publisher pays). Verify each result row attributes the payment to the
/// right party.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_publisher_pays_mixed_regtest() -> Result<()> {
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
            Inst {
                gas_limit: 50_000,
                kind: InstKind::Publish {
                    name: "arith".to_string(),
                    bytes: arith_bytes,
                },
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
    let publisher_id = rt
        .get_signer_id(&publisher.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for publisher"))?;

    // op0: SelfPay — signer1 pays from their own balance.
    let op0 = call_with_gas_limit(
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(10, arith::Op::Id),
    );
    // op1: Sponsored — publisher covers it.
    let op1 = call_with_gas_limit(
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(10, arith::Op::Sum(arith::Operand { y: 8 })),
    );

    let signer1_claim = SignerRef::SignerId(signer1_id);
    let signer2_claim = SignerRef::SignerId(signer2_id);
    // op0 self-pay (signer1 commits to it), op1 publisher-sponsored
    // (signer2 commits to being sponsored).
    let msg0 = op0.aggregate_signing_message(&signer1_claim, 0, false)?;
    let msg1 = op1.aggregate_signing_message(&signer2_claim, 0, true)?;
    let sk1 = blst::min_sig::SecretKey::from_bytes(&signer1.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer1 BLS secret key: {e:?}"))?;
    let sk2 = blst::min_sig::SecretKey::from_bytes(&signer2.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer2 BLS secret key: {e:?}"))?;
    let sig0 = sk1.sign(&msg0, KONTOR_BLS_DST, &[]);
    let sig1 = sk2.sign(&msg1, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&sig0, &sig1], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;
    let aggregate_sig = aggregate.to_signature();

    let res = rt
        .instruction_insts(
            &mut publisher,
            aggregate_insts(
                vec![op0, op1],
                vec![
                    signer_by_id(signer1_id, 0, false),
                    signer_by_id(signer2_id, 0, true),
                ],
                aggregate_sig.to_bytes().to_vec(),
            ),
        )
        .await?;

    // op 0 (SelfPay) — signer1 must be the payer.
    assert_eq!(
        res.result.payer_signer_id,
        Some(signer1_id as i64),
        "SelfPay op 0 should be charged to signer1, not the publisher"
    );

    // op 1 (Sponsored) — publisher must be the payer.
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
    assert_eq!(
        result1.payer_signer_id,
        Some(publisher_id as i64),
        "Sponsored op 1 should be charged to the publisher, not signer2"
    );

    Ok(())
}
