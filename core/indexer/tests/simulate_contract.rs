use indexer_types::{Inst, TransactionHex};
use testlib::*;

interface!(name = "crypto", path = "../../test-contracts/crypto/wit");

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn test_crypto_contract_simulate() -> Result<()> {
    let alice = runtime.identity().await?;
    let crypto = runtime.publish(&alice, "crypto").await?;

    assert!(crypto::get_hash(runtime, &crypto).await?.is_none());

    let mut rt = runtime.reg_tester().unwrap();
    let mut ident = rt.identity().await?;
    rt.instruction(&mut ident, Inst::Issuance).await?;
    let (_, _, reveal_tx_hex) = rt
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

    let expected_info = rt.info().await?;
    let result = rt
        .kontor_client()
        .await
        .transaction_simulate(TransactionHex { hex: reveal_tx_hex })
        .await?;
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].clone().result.unwrap().value.unwrap(),
        "[44, 38, 180, 107, 104, 255, 198, 143, 249, 155, 69, 60, 29, 48, 65, 52, 19, 66, 45, 112, 100, 131, 191, 160, 249, 138, 94, 136, 98, 102, 231, 174]"
    );
    let info = rt.info().await?;
    assert_eq!(info, expected_info);

    // State unchanged after simulation
    assert!(crypto::get_hash(runtime, &crypto).await?.is_none());

    Ok(())
}
