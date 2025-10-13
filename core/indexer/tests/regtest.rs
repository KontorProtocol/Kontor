use anyhow::Result;
use indexer::{logging, reg_tester::RegTester};

async fn run_test_regtest(reg_tester: &mut RegTester) -> Result<()> {
    let mut alice = reg_tester.identity("alice").await?;
    reg_tester.test(&mut alice).await?;
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
