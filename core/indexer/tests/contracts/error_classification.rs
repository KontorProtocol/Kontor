use testlib::*;

interface!(name = "error_test", path = "../../test-contracts/error-test/wit");

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_error_case_succeed() -> Result<()> {
    let signer = runtime.identity().await?;
    let contract = runtime.publish(&signer, "error-test").await?;

    let result = error_test::succeed(runtime, &contract).await;
    eprintln!("=== SUCCEED: {:?}", result);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_error_case_contract_error() -> Result<()> {
    let signer = runtime.identity().await?;
    let contract = runtime.publish(&signer, "error-test").await?;

    let result = error_test::contract_error(runtime, &contract).await;
    eprintln!("=== CONTRACT_ERROR: {:?}", result);
    Ok(())
}

fn inspect_error(label: &str, e: &anyhow::Error) {
    eprintln!("=== {label}: Err");
    eprintln!("  display: {}", e);
    eprintln!("  downcast Trap: {:?}", e.downcast_ref::<wasmtime::Trap>());

    // Walk the full error chain with type info
    for (i, cause) in e.chain().enumerate() {
        eprintln!(
            "  chain[{}]: '{}' (is_Trap={}, type={})",
            i,
            cause,
            cause.is::<wasmtime::Trap>(),
            std::any::type_name_of_val(cause)
        );
    }

    // Check root_cause
    let rc = e.root_cause();
    eprintln!("  root_cause: '{rc}'");
    eprintln!("  root_cause is Trap: {}", rc.is::<wasmtime::Trap>());
    eprintln!("  chain len: {}", e.chain().count());
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_error_case_trap_div_zero() -> Result<()> {
    let signer = runtime.identity().await?;
    let contract = runtime.publish(&signer, "error-test").await?;

    let result = error_test::trap_div_zero(runtime, &contract, &signer).await;
    match &result {
        Ok(v) => eprintln!("=== TRAP_DIV_ZERO: Ok({:?})", v),
        Err(e) => inspect_error("TRAP_DIV_ZERO", e),
    }
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_error_case_trap_panic() -> Result<()> {
    let signer = runtime.identity().await?;
    let contract = runtime.publish(&signer, "error-test").await?;

    let result = error_test::trap_panic(runtime, &contract, &signer).await;
    match &result {
        Ok(v) => eprintln!("=== TRAP_PANIC: Ok({:?})", v),
        Err(e) => inspect_error("TRAP_PANIC", e),
    }
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_error_case_trap_out_of_fuel() -> Result<()> {
    let signer = runtime.identity().await?;
    let contract = runtime.publish(&signer, "error-test").await?;

    let result = error_test::trap_out_of_fuel(runtime, &contract, &signer).await;
    match &result {
        Ok(v) => eprintln!("=== TRAP_OUT_OF_FUEL: Ok({:?})", v),
        Err(e) => inspect_error("TRAP_OUT_OF_FUEL", e),
    }
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_error_case_host_error() -> Result<()> {
    let signer = runtime.identity().await?;
    let contract = runtime.publish(&signer, "error-test").await?;

    let result = error_test::host_error(runtime, &contract, &signer).await;
    match &result {
        Ok(v) => eprintln!("=== HOST_ERROR: Ok({:?})", v),
        Err(e) => inspect_error("HOST_ERROR", e),
    }
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_error_case_host_panic_nan() -> Result<()> {
    let signer = runtime.identity().await?;
    let contract = runtime.publish(&signer, "error-test").await?;

    let result = error_test::host_panic_nan(runtime, &contract, &signer).await;
    match &result {
        Ok(v) => eprintln!("=== HOST_PANIC_NAN: Ok({:?})", v),
        Err(e) => inspect_error("HOST_PANIC_NAN", e),
    }
    Ok(())
}
