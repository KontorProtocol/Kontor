use indexer::runtime::ExecutionError;
use testlib::*;

interface!(
    name = "error_test",
    path = "../../test-contracts/error-test/wit"
);

interface!(name = "proxy", path = "../../test-contracts/proxy/wit");

/// Set up proxy pointing at error-test contract
async fn setup_proxy(runtime: &mut testlib::Runtime) -> Result<(ContractAddress, ContractAddress)> {
    let signer = runtime.identity().await?;
    let addrs = runtime
        .publish_many(&signer, &["error-test", "proxy"])
        .await?;
    let error_test = addrs[0].clone();
    let proxy_addr = addrs[1].clone();
    proxy::set_contract_address(runtime, &proxy_addr, &signer, error_test.clone()).await?;
    Ok((proxy_addr, error_test))
}

fn assert_contract_error<T: std::fmt::Debug>(result: &Result<T>) {
    let err = result.as_ref().unwrap_err();
    assert!(
        err.downcast_ref::<ExecutionError>()
            .is_some_and(|e| matches!(e, ExecutionError::Contract(_))),
        "Expected ExecutionError::Contract, got: {err:#}"
    );
}

fn assert_infrastructure_error<T: std::fmt::Debug>(result: &Result<T>) {
    let err = result.as_ref().unwrap_err();
    assert!(
        err.downcast_ref::<ExecutionError>()
            .is_some_and(|e| matches!(e, ExecutionError::Infrastructure(_))),
        "Expected ExecutionError::Infrastructure, got: {err:#}"
    );
}

// --- Direct call tests ---

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_error_case_succeed() -> Result<()> {
    let signer = runtime.identity().await?;
    let contract = runtime.publish(&signer, "error-test").await?;

    let result = error_test::succeed(runtime, &contract).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_error_case_contract_error() -> Result<()> {
    let signer = runtime.identity().await?;
    let contract = runtime.publish(&signer, "error-test").await?;

    let result = error_test::contract_error(runtime, &contract).await;
    assert!(result.is_ok());
    assert_eq!(
        result.unwrap(),
        Err(Error::Message("deliberate error".to_string()))
    );
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_error_case_trap_div_zero() -> Result<()> {
    let signer = runtime.identity().await?;
    let contract = runtime.publish(&signer, "error-test").await?;

    let result = error_test::trap_div_zero(runtime, &contract, &signer).await;
    assert_contract_error(&result);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_error_case_trap_panic() -> Result<()> {
    let signer = runtime.identity().await?;
    let contract = runtime.publish(&signer, "error-test").await?;

    let result = error_test::trap_panic(runtime, &contract, &signer).await;
    assert_contract_error(&result);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_error_case_trap_out_of_fuel() -> Result<()> {
    let signer = runtime.identity().await?;
    let contract = runtime.publish(&signer, "error-test").await?;

    let result = error_test::trap_out_of_fuel(runtime, &contract, &signer).await;
    assert_contract_error(&result);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_error_case_host_error() -> Result<()> {
    let signer = runtime.identity().await?;
    let contract = runtime.publish(&signer, "error-test").await?;

    let result = error_test::host_error(runtime, &contract, &signer).await;
    assert_infrastructure_error(&result);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_error_case_host_panic() -> Result<()> {
    let signer = runtime.identity().await?;
    let contract = runtime.publish(&signer, "error-test").await?;

    let result = error_test::host_panic(runtime, &contract, &signer).await;
    assert_infrastructure_error(&result);
    Ok(())
}

// --- Cross-contract call tests (via proxy) ---

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_cross_contract_trap_div_zero() -> Result<()> {
    let (proxy_addr, _) = setup_proxy(runtime).await?;
    let signer = runtime.identity().await?;

    let result = error_test::trap_div_zero(runtime, &proxy_addr, &signer).await;
    assert_contract_error(&result);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_cross_contract_trap_out_of_fuel() -> Result<()> {
    let (proxy_addr, _) = setup_proxy(runtime).await?;
    let signer = runtime.identity().await?;

    let result = error_test::trap_out_of_fuel(runtime, &proxy_addr, &signer).await;
    assert_contract_error(&result);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_cross_contract_host_error() -> Result<()> {
    let (proxy_addr, _) = setup_proxy(runtime).await?;
    let signer = runtime.identity().await?;

    let result = error_test::host_error(runtime, &proxy_addr, &signer).await;
    assert_infrastructure_error(&result);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_cross_contract_host_panic() -> Result<()> {
    let (proxy_addr, _) = setup_proxy(runtime).await?;
    let signer = runtime.identity().await?;

    let result = error_test::host_panic(runtime, &proxy_addr, &signer).await;
    assert_infrastructure_error(&result);
    Ok(())
}
