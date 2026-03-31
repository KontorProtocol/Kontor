use anyhow::Result;
use indexer::reg_tester::RegTesterCluster;
use testlib::*;

mod counter_contract;
mod fib_contract;

#[tokio::test]
#[serial_test::serial]
async fn regtest_all() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let cluster = RegTesterCluster::setup(3).await?;
    let contracts_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-contracts")
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let contract_reader = ContractReader::new(&contracts_dir).await?;

    // Single RegTester shared across tests — clones share Arc<Mutex> state,
    // so the UTXO chain and published contracts cache stay valid.
    let reg_tester = cluster.reg_tester(0).await?;
    reg_tester.pre_create_identities(100).await?;

    run_test("counter_batching", async {
        let mut runtime = new_runtime(reg_tester.clone(), contract_reader.clone());
        counter_contract::test_counter_batching(&mut runtime).await
    })
    .await;

    run_test("fib_contract", async {
        let mut runtime = new_runtime(reg_tester.clone(), contract_reader.clone());
        fib_contract::test_fib_contract(&mut runtime).await
    })
    .await;

    cluster.teardown().await?;
    Ok(())
}

fn new_runtime(
    reg_tester: indexer::reg_tester::RegTester,
    contract_reader: ContractReader,
) -> Runtime {
    Runtime::new_regtest_with_reader(contract_reader, reg_tester)
}

async fn run_test(name: &str, test: impl std::future::Future<Output = Result<()>>) {
    let start = std::time::Instant::now();
    match test.await {
        Ok(()) => tracing::info!("PASS: {} ({:.1}s)", name, start.elapsed().as_secs_f64()),
        Err(e) => panic!("FAIL: {}: {:?}", name, e),
    }
}
