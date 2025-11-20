use anyhow::bail;
use bitcoin::consensus::encode::deserialize_hex;
use indexer::{
    reactor::types::{Inst, Op, OpMetadata},
    reg_tester::InstructionResult,
};
use testlib::*;

#[testlib::test(contracts_dir = "test-contracts", mode = "regtest")]
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

    let tx = deserialize_hex::<bitcoin::Transaction>(&reveal_tx_hex)?;

    let ops = reg_tester.transaction_hex_inspect(&reveal_tx_hex).await?;
    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0].op,
        Op::Publish {
            metadata: OpMetadata {
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
        reg_tester.transaction_inspect(&tx.compute_txid()).await?
    );

    Ok(())
}
