use anyhow::bail;
use bitcoin::consensus::encode::deserialize_hex;
use indexer::reg_tester::InstructionResult;
use indexer_types::{ContractAddress as IndexerContractAddress, Inst, Insts, Op, OpMetadata};
use testlib::*;

interface!(name = "arith", path = "../../test-contracts/arith/wit");

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_get_ops_from_api_regtest() -> Result<()> {
    let name = "token";
    let bytes = runtime.contract_reader.read(name).await?.unwrap();
    let mut ident = reg_tester.identity().await?;
    reg_tester.instruction(&mut ident, Inst::Issuance).await?;
    let InstructionResult { reveal_tx_hex, .. } = reg_tester
        .instruction(
            &mut ident,
            Inst::Publish {
                gas_limit: 10_000,
                name: name.to_string(),
                bytes: bytes.clone(),
            },
        )
        .await?;

    let reveal_tx = deserialize_hex::<bitcoin::Transaction>(&reveal_tx_hex)?;

    let ops = reg_tester.transaction_hex_inspect(&reveal_tx_hex).await?;
    assert_eq!(ops.len(), 1);
    let signer_id = ident.signer_id.expect("identity must be registered");
    assert_eq!(
        ops[0].op,
        Op::Publish {
            metadata: OpMetadata {
                previous_output: reveal_tx.input[0].previous_output,
                input_index: 0,
                signer: Signer::new_signer_id(signer_id),
            },
            gas_limit: 10_000,
            name: name.to_string(),
            bytes
        }
    );
    let result = ops[0].result.as_ref();
    let height = reg_tester.height().await;
    assert!(result.is_some());
    if let Some(result) = result {
        assert_eq!(result.height, height);
        assert_eq!(result.contract, format!("token_{}_{}", height, 2));
        assert_eq!(result.value, Some("".to_string()));
        assert!(result.gas > 0);
    } else {
        bail!("Unexpected result event: {:?}", result);
    }

    assert_eq!(
        ops,
        reg_tester
            .transaction_inspect(&reveal_tx.compute_txid())
            .await?
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_regtester_insts_instruction_returns_all_direct_ops() -> Result<()> {
    let arith_bytes = runtime.contract_reader.read("arith").await?.unwrap();
    let mut ident = reg_tester.identity().await?;
    reg_tester.instruction(&mut ident, Inst::Issuance).await?;
    let publish = reg_tester
        .instruction(
            &mut ident,
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
        .map_err(|e: String| anyhow::anyhow!(e))?;

    let res = reg_tester
        .insts_instruction(
            &mut ident,
            Insts {
                ops: vec![
                    Inst::Call {
                        gas_limit: 50_000,
                        contract: arith_contract.clone(),
                        nonce: None,
                        expr: arith::wave::eval_call_expr(3, arith::Op::Id),
                    },
                    Inst::Call {
                        gas_limit: 50_000,
                        contract: arith_contract,
                        nonce: None,
                        expr: arith::wave::eval_call_expr(
                            3,
                            arith::Op::Sum(arith::Operand { y: 4 }),
                        ),
                    },
                ],
                aggregate: None,
            },
        )
        .await?;

    assert_eq!(res.ops.len(), 2);
    assert_eq!(res.result, res.ops[0].result.clone().unwrap());
    assert_eq!(res.ops[0].result.as_ref().unwrap().op_index, Some(0));
    assert_eq!(res.ops[1].result.as_ref().unwrap().op_index, Some(1));

    let v0 = res.ops[0]
        .result
        .as_ref()
        .unwrap()
        .value
        .as_deref()
        .unwrap();
    let v1 = res.ops[1]
        .result
        .as_ref()
        .unwrap()
        .value
        .as_deref()
        .unwrap();
    assert_eq!(arith::wave::eval_parse_return_expr(v0).value, 3);
    assert_eq!(arith::wave::eval_parse_return_expr(v1).value, 7);

    let reveal_tx = deserialize_hex::<bitcoin::Transaction>(&res.reveal_tx_hex)?;
    assert_eq!(
        res.ops,
        reg_tester
            .transaction_inspect(&reveal_tx.compute_txid())
            .await?
    );

    Ok(())
}
