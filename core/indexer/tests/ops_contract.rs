use indexer::{
    reactor::{
        results::ResultEvent,
        types::{Inst, Op, OpMetadata},
    },
    reg_tester::InstructionResult,
};
use testlib::*;

#[runtime(contracts_dir = "../../contracts", mode = "regtest")]
async fn test_get_ops_from_api_regtest() -> Result<()> {
    let name = "token";
    let bytes = runtime.contract_reader.read(name).await?.unwrap();
    let mut ident = reg_tester.identity().await?;
    let InstructionResult { reveal_tx_hex, .. } = reg_tester
        .instruction(
            &mut ident,
            Inst::Publish {
                name: name.to_string(),
                bytes: bytes.clone(),
            },
        )
        .await?;

    let ops = reg_tester.transaction_ops(&reveal_tx_hex).await?;
    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0].op,
        Op::Publish {
            metadata: OpMetadata {
                input_index: 0,
                signer: Signer::XOnlyPubKey(ident.x_only_public_key().to_string())
            },
            name: name.to_string(),
            bytes
        }
    );
    assert_eq!(
        ops[0].result,
        Some(ResultEvent::Ok {
            value: "{name: \"token\", height: 103, tx-index: 2}".to_string()
        })
    );

    Ok(())
}
