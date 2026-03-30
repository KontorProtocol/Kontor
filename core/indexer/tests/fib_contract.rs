use testlib::*;

interface!(name = "arith", path = "../../test-contracts/arith/wit",);

interface!(name = "fib", path = "../../test-contracts/fib/wit",);

interface!(name = "proxy", path = "../../test-contracts/proxy/wit",);

#[testlib::test(contracts_dir = "../../test-contracts", shared)]
async fn test_fib_contract() -> Result<()> {
    let signer = runtime.identity().await?;
    let addrs = runtime
        .publish_many(&signer, &["fib", "arith", "proxy"])
        .await?;
    let fib = addrs[0].clone();
    let arith = addrs[1].clone();
    let proxy = addrs[2].clone();

    // Verify init state
    let result = arith::last_op(runtime, &arith).await?;
    assert_eq!(result, Some(arith::Op::Id));

    // Batch 1: fib(8) + set proxy → fib (independent mutations)
    let mut batch = runtime.batch();
    let h_fib = batch.push(&signer, fib::fib_call(&fib, arith.clone(), 8));
    batch.push(&signer, proxy::set_contract_address_call(&proxy, fib.clone()));
    let results = batch.execute().await?;
    assert_eq!(results.get(&h_fib), 21);

    // Views after batch 1
    let last_op = Some(arith::Op::Sum(arith::Operand { y: 8 }));
    let result = arith::last_op(runtime, &arith).await?;
    assert_eq!(result, last_op);
    let result = proxy::get_contract_address(runtime, &proxy).await?;
    assert_eq!(result, Some(fib.clone()));

    // Batch 2: fib(8) through proxy (depends on proxy pointing to fib)
    let result = fib::fib(runtime, &proxy, &signer, arith.clone(), 8).await?;
    assert_eq!(result, 21);

    // Batch 3: set proxy → arith
    proxy::set_contract_address(runtime, &proxy, &signer, arith.clone()).await?;
    let result = arith::last_op(runtime, &proxy).await?;
    assert_eq!(result, Some(arith::Op::Sum(arith::Operand { y: 8 })));

    // Views: checked_sub (pure reads, no consensus)
    let result = arith::checked_sub(runtime, &arith, "5", "3").await?;
    assert_eq!(result, Ok(2));
    let result = arith::checked_sub(runtime, &arith, "3", "5").await?;
    assert_eq!(result, Err(Error::Message("less than 0".to_string())));

    // Batch 4: fib_of_sub(18,10) + fib_of_sub(10,18) (independent)
    let mut batch = runtime.batch();
    let h1 = batch.push(&signer, fib::fib_of_sub_call(&fib, arith.clone(), "18", "10"));
    let h2 = batch.push(&signer, fib::fib_of_sub_call(&fib, arith.clone(), "10", "18"));
    let results = batch.execute().await?;
    assert_eq!(results.get(&h1), Ok(21));
    assert_eq!(results.get(&h2), Err(Error::Message("less than 0".to_string())));

    // Reentrancy prevented (expected failure, separate from batch)
    let result = arith::fib(runtime, &arith, &signer, fib.clone(), 9).await;
    assert!(result.is_err());

    // Verify cached values
    let result = fib::cached_values(runtime, &fib).await?;
    assert_eq!(result, vec![0, 1, 2, 3, 4, 5, 6, 7, 8]);

    Ok(())
}
