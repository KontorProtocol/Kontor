use anyhow::anyhow;
use blst::min_sig::{AggregateSignature, SecretKey};
use indexer::bls::KONTOR_BLS_DST;
use indexer_types::{
    AggregateInfo, ContractAddress as IndexerContractAddress, Inst, Insts, Signer, TransactionHex,
};
use testlib::*;

interface!(name = "crypto", path = "../../test-contracts/crypto/wit");
interface!(name = "arith", path = "../../test-contracts/arith/wit");

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_crypto_contract_regtest() -> Result<()> {
    let alice = runtime.identity().await?;
    let crypto = runtime.publish(&alice, "crypto").await?;

    assert!(crypto::get_hash(runtime, &crypto).await?.is_none());

    let mut ident = reg_tester.identity().await?;
    reg_tester.instruction(&mut ident, Inst::Issuance).await?;
    let (_, _, reveal_tx_hex) = reg_tester
        .compose_instruction(
            &mut ident,
            Inst::Call {
                gas_limit: 10_000,
                contract: crypto.clone().into(),
                nonce: None,
                expr: "set-hash(\"foo\")".to_string(),
            },
        )
        .await?;

    let expected_info = reg_tester.info().await?;
    let result = reg_tester
        .kontor_client()
        .await
        .transaction_simulate(TransactionHex { hex: reveal_tx_hex })
        .await?;
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].op.metadata().signer,
        Signer::XOnlyPubKey(ident.x_only_public_key().to_string())
    );
    assert_eq!(
        result[0].clone().result.unwrap().value.unwrap(),
        "[44, 38, 180, 107, 104, 255, 198, 143, 249, 155, 69, 60, 29, 48, 65, 52, 19, 66, 45, 112, 100, 131, 191, 160, 249, 138, 94, 136, 98, 102, 231, 174]"
    );
    assert!(crypto::get_hash(runtime, &crypto).await?.is_none());
    let info = reg_tester.info().await?;
    assert_eq!(info, expected_info);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_simulate_aggregate_insts_returns_signer_ids() -> Result<()> {
    let mut signer = reg_tester.identity().await?;
    let mut publisher = reg_tester.identity().await?;
    reg_tester.instruction(&mut signer, Inst::Issuance).await?;
    reg_tester
        .instruction(&mut publisher, Inst::Issuance)
        .await?;

    let arith_bytes = runtime.contract_reader.read("arith").await?.unwrap();
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
    let arith_contract: IndexerContractAddress = publish
        .result
        .contract
        .parse()
        .map_err(|e| anyhow!("invalid contract address: {e}"))?;

    let signer_id = signer
        .signer_id
        .ok_or_else(|| anyhow!("missing signer_id for aggregate signer"))?;

    let inst = Inst::Call {
        gas_limit: 50_000,
        contract: arith_contract,
        nonce: Some(0),
        expr: arith::wave::eval_call_expr(9, arith::Op::Id),
    };
    let msg = inst.aggregate_signing_message(signer_id)?;
    let sk = SecretKey::from_bytes(&signer.bls_secret_key)
        .map_err(|e| anyhow!("invalid signer BLS secret key: {e:?}"))?;
    let sig = sk.sign(&msg, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&sig], true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;

    let (_, _, reveal_tx_hex) = reg_tester
        .compose_insts(
            &mut publisher,
            Insts {
                ops: vec![inst],
                aggregate: Some(AggregateInfo {
                    signer_ids: vec![signer_id],
                    signature: aggregate.to_signature().to_bytes().to_vec(),
                }),
            },
        )
        .await?;

    let expected_info = reg_tester.info().await?;
    let result = reg_tester
        .kontor_client()
        .await
        .transaction_simulate(TransactionHex { hex: reveal_tx_hex })
        .await?;
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].op.metadata().signer.clone(),
        Signer::new_signer_id(signer_id)
    );
    assert_eq!(
        arith::wave::eval_parse_return_expr(
            result[0].result.as_ref().unwrap().value.as_deref().unwrap()
        )
        .value,
        9
    );

    let info = reg_tester.info().await?;
    assert_eq!(info, expected_info);
    Ok(())
}
