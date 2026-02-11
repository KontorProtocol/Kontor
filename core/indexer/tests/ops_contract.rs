use anyhow::bail;
use bitcoin::consensus::encode::deserialize_hex;
use indexer::reg_tester::InstructionResult;
use indexer_types::{FileMetadata, Inst, Op, OpMetadata};
use testlib::*;

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
    assert_eq!(
        ops[0].op,
        Op::Publish {
            metadata: OpMetadata {
                previous_output: reveal_tx.input[0].previous_output,
                input_index: 0,
                signer: Signer::XOnlyPubKey(ident.x_only_public_key().to_string())
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
async fn test_get_ops_from_api_create_agreement_regtest() -> Result<()> {
    let mut ident = reg_tester.identity().await?;
    let file_metadata = FileMetadata {
        file_id: "ops_test_file".to_string(),
        object_id: "object_ops_test_file".to_string(),
        nonce: vec![7u8; 32],
        root: vec![7u8; 32],
        padded_len: 16,
        original_size: 13,
        filename: "ops-test.txt".to_string(),
    };

    let (_, _, reveal_tx_hex) = reg_tester
        .compose_instruction(
            &mut ident,
            Inst::CreateAgreement {
                file_metadata: file_metadata.clone(),
            },
        )
        .await?;

    let reveal_tx = deserialize_hex::<bitcoin::Transaction>(&reveal_tx_hex)?;
    let ops = reg_tester.transaction_hex_inspect(&reveal_tx_hex).await?;

    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0].op,
        Op::CreateAgreement {
            metadata: OpMetadata {
                previous_output: reveal_tx.input[0].previous_output,
                input_index: 0,
                signer: Signer::XOnlyPubKey(ident.x_only_public_key().to_string())
            },
            file_metadata
        }
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_get_ops_from_api_join_agreement_regtest() -> Result<()> {
    let mut ident = reg_tester.identity().await?;
    let agreement_id = "agreement_join_test".to_string();
    let node_id = "node_join_test".to_string();

    let (_, _, reveal_tx_hex) = reg_tester
        .compose_instruction(
            &mut ident,
            Inst::JoinAgreement {
                agreement_id: agreement_id.clone(),
                node_id: node_id.clone(),
            },
        )
        .await?;

    let reveal_tx = deserialize_hex::<bitcoin::Transaction>(&reveal_tx_hex)?;
    let ops = reg_tester.transaction_hex_inspect(&reveal_tx_hex).await?;
    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0].op,
        Op::JoinAgreement {
            metadata: OpMetadata {
                previous_output: reveal_tx.input[0].previous_output,
                input_index: 0,
                signer: Signer::XOnlyPubKey(ident.x_only_public_key().to_string())
            },
            agreement_id,
            node_id
        }
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_get_ops_from_api_leave_agreement_regtest() -> Result<()> {
    let mut ident = reg_tester.identity().await?;
    let agreement_id = "agreement_leave_test".to_string();
    let node_id = "node_leave_test".to_string();

    let (_, _, reveal_tx_hex) = reg_tester
        .compose_instruction(
            &mut ident,
            Inst::LeaveAgreement {
                agreement_id: agreement_id.clone(),
                node_id: node_id.clone(),
            },
        )
        .await?;

    let reveal_tx = deserialize_hex::<bitcoin::Transaction>(&reveal_tx_hex)?;
    let ops = reg_tester.transaction_hex_inspect(&reveal_tx_hex).await?;
    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0].op,
        Op::LeaveAgreement {
            metadata: OpMetadata {
                previous_output: reveal_tx.input[0].previous_output,
                input_index: 0,
                signer: Signer::XOnlyPubKey(ident.x_only_public_key().to_string())
            },
            agreement_id,
            node_id
        }
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_get_ops_from_api_verify_proof_regtest() -> Result<()> {
    let mut ident = reg_tester.identity().await?;
    let proof_bytes = vec![1u8, 2, 3, 5, 8];

    let (_, _, reveal_tx_hex) = reg_tester
        .compose_instruction(
            &mut ident,
            Inst::VerifyProof {
                proof_bytes: proof_bytes.clone(),
            },
        )
        .await?;

    let reveal_tx = deserialize_hex::<bitcoin::Transaction>(&reveal_tx_hex)?;
    let ops = reg_tester.transaction_hex_inspect(&reveal_tx_hex).await?;
    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0].op,
        Op::VerifyProof {
            metadata: OpMetadata {
                previous_output: reveal_tx.input[0].previous_output,
                input_index: 0,
                signer: Signer::XOnlyPubKey(ident.x_only_public_key().to_string())
            },
            proof_bytes
        }
    );

    Ok(())
}
