use anyhow::bail;
use bitcoin::consensus::encode::deserialize_hex;
use indexer::reg_tester::InstructionResult;
use indexer_types::{Inst, Op, OpMetadata};
use testlib::*;

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn test_get_ops_from_api() -> Result<()> {
    let name = "test-token";
    let bytes = runtime.contract_reader.read(name).await?.unwrap();

    let mut rt = runtime.reg_tester().unwrap();
    let mut ident = rt.identity().await?;
    rt.instruction(&mut ident, Inst::Issuance).await?;
    let InstructionResult { reveal_tx_hex, .. } = rt
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

    let ops = rt.transaction_hex_inspect(&reveal_tx_hex).await?;
    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0].op,
        Op::Publish {
            metadata: OpMetadata {
                previous_output: reveal_tx.input[0].previous_output,
                input_index: 0,
                signer: Signer::XOnlyPubKey(ident.x_only_public_key().to_string()),
            },
            gas_limit: 10_000,
            name: name.to_string(),
            bytes
        }
    );
    let result = ops[0].result.as_ref();
    assert!(result.is_some());
    if let Some(result) = result {
        assert!(
            result.contract.starts_with("test-token_"),
            "contract address should start with test-token_, got: {}",
            result.contract
        );
        assert_eq!(result.value, Some("".to_string()));
        assert!(result.gas > 0);
    } else {
        bail!("Unexpected result event: {:?}", result);
    }

    assert_eq!(
        ops,
        rt.transaction_inspect(&reveal_tx.compute_txid()).await?
    );

    Ok(())
}
