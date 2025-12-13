use indexer_types::{Inst, TransactionHex};
use testlib::*;

interface!(name = "crypto", path = "../test-contracts/crypto/wit");

#[testlib::test(contracts_dir = "test-contracts", mode = "regtest")]
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
        result[0].clone().result.unwrap().value.unwrap(),
        "[44, 38, 180, 107, 104, 255, 198, 143, 249, 155, 69, 60, 29, 48, 65, 52, 19, 66, 45, 112, 100, 131, 191, 160, 249, 138, 94, 136, 98, 102, 231, 174]"
    );
    assert!(crypto::get_hash(runtime, &crypto).await?.is_none());
    let info = reg_tester.info().await?;
    assert_eq!(info, expected_info);
    Ok(())
}
