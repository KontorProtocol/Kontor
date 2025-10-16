use anyhow::Result;
use indexer::{logging, reactor::types::Inst, reg_tester::RegTester};
use testlib::ContractAddress;
use tracing::info;

async fn run_test_regtest(reg_tester: &mut RegTester) -> Result<()> {
    let mut alice = reg_tester.identity("alice").await?;
    let expr = reg_tester
        .instruction(
            &mut alice,
            Inst::Publish {
                name: "test".to_string(),
                bytes: b"test".to_vec(),
            },
        )
        .await?;
    let address: ContractAddress =
        wasm_wave::from_str::<wasm_wave::value::Value>(&ContractAddress::wave_type(), &expr)
            .unwrap()
            .into();
    info!("Contract Address: {}", address);
    Ok(())
}

#[tokio::test]
async fn test_regtest() -> Result<()> {
    logging::setup();
    let mut reg_tester = RegTester::new().await?;
    let r = run_test_regtest(&mut reg_tester).await;
    reg_tester.stop().await?;
    r
}
