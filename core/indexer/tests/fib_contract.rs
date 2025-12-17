use testlib::*;

interface!(name = "arith", path = "../../test-contracts/arith/wit",);

interface!(name = "fib", path = "../../test-contracts/fib/wit",);

interface!(name = "proxy", path = "../../test-contracts/proxy/wit",);

async fn run_test_fib_contract(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let fib = runtime.publish(&signer, "fib").await?;
    let arith = runtime.publish(&signer, "arith").await?;
    let proxy = runtime.publish(&signer, "proxy").await?;

    let result = arith::last_op(runtime, &arith).await?;
    assert_eq!(result, Some(arith::Op::Id));

    let n = 8;
    let result = fib::fib(runtime, &fib, &signer, arith.clone(), n).await?;
    assert_eq!(result, 21);

    let last_op = Some(arith::Op::Sum(arith::Operand { y: 8 }));
    let result = arith::last_op(runtime, &arith).await?;
    assert_eq!(result, last_op);

    proxy::set_contract_address(runtime, &proxy, &signer, fib.clone()).await?;

    let result = proxy::get_contract_address(runtime, &proxy).await?;
    assert_eq!(result, Some(fib.clone()));

    let result = fib::fib(runtime, &proxy, &signer, arith.clone(), n).await?;
    assert_eq!(result, 21);

    proxy::set_contract_address(runtime, &proxy, &signer, arith.clone()).await?;

    let result = arith::last_op(runtime, &proxy).await?;
    assert_eq!(result, Some(arith::Op::Sum(arith::Operand { y: 8 })));

    // result
    let x = "5";
    let y = "3";
    let result = arith::checked_sub(runtime, &arith, x, y).await?;
    assert_eq!(result, Ok(2));

    let result = arith::checked_sub(runtime, &arith, y, x).await?;
    assert_eq!(result, Err(Error::Message("less than 0".to_string())));

    // result through import
    let x = "18";
    let y = "10";
    let result = fib::fib_of_sub(runtime, &fib, &signer, arith.clone(), x, y).await?;
    assert_eq!(result, Ok(21));

    let result = fib::fib_of_sub(runtime, &fib, &signer, arith.clone(), y, x).await?;
    assert_eq!(result, Err(Error::Message("less than 0".to_string())));

    // reentrancy prevented
    let result = arith::fib(runtime, &arith, &signer, fib.clone(), 9).await;
    assert!(result.is_err());

    let result = fib::cached_values(runtime, &fib).await?;
    assert_eq!(result, vec![0, 1, 2, 3, 4, 5, 6, 7, 8]);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_fib_contract() -> Result<()> {
    run_test_fib_contract(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_fib_contract_regtest() -> Result<()> {
    run_test_fib_contract(runtime).await
}
