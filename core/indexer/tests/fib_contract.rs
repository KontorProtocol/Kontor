use testlib::*;

import!(
    name = "arith",
    height = 0,
    tx_index = 0,
    path = "../contracts/arith/wit",
);

import!(
    name = "fib",
    height = 0,
    tx_index = 0,
    path = "../contracts/fib/wit",
);

import!(
    name = "proxy",
    height = 0,
    tx_index = 0,
    path = "../contracts/proxy/wit",
);

import!(
    name = "proxy",
    height = 0,
    tx_index = 0,
    mod_name = "fib_proxied",
    path = "../contracts/fib/wit",
);

import!(
    name = "proxy",
    height = 0,
    tx_index = 0,
    mod_name = "arith_proxied",
    path = "../contracts/arith/wit",
);

#[tokio::test]
async fn test_fib_contract() -> Result<()> {
    let mut runtime = Runtime::new(RuntimeConfig::default()).await?;

    let signer = "test_signer";
    let result = arith::last_op(&mut runtime).await?;
    assert_eq!(result, Some(arith::Op::Id));

    let n = 8;
    let result = fib::fib(&mut runtime, signer, n).await?;
    assert_eq!(result, 21);
    let gauge = runtime.fuel_gauge();
    assert_eq!(gauge.starting_fuel().await, 1000000);
    assert!(gauge.ending_fuel().await < 1000000);

    let last_op = Some(arith::Op::Sum(arith::Operand { y: 8 }));
    let result = arith::last_op(&mut runtime).await?;
    assert_eq!(result, last_op);

    let result = fib_proxied::fib(&mut runtime, signer, n).await?;
    assert_eq!(result, 21);

    let result = proxy::get_contract_address(&mut runtime).await?;
    assert_eq!(
        result,
        ContractAddress {
            name: "fib".to_string(),
            height: 0,
            tx_index: 0
        }
    );

    proxy::set_contract_address(
        &mut runtime,
        signer,
        ContractAddress {
            name: "arith".to_string(),
            height: 0,
            tx_index: 0,
        },
    )
    .await?;

    let result = arith_proxied::last_op(&mut runtime).await?;
    assert_eq!(
        result,
        Some(arith_proxied::Op::Sum(arith_proxied::Operand { y: 8 }))
    );

    // result
    let x = "5";
    let y = "3";
    let result = arith::checked_sub(&mut runtime, x, y).await?;
    assert_eq!(result, Ok(2));

    let result = arith::checked_sub(&mut runtime, y, x).await?;
    assert_eq!(result, Err(Error::Message("less than 0".to_string())));

    // result through import
    let x = "18";
    let y = "10";
    let result = fib::fib_of_sub(&mut runtime, signer, x, y).await?;
    assert_eq!(result, Ok(21));

    let result = fib::fib_of_sub(&mut runtime, signer, y, x).await?;
    assert_eq!(result, Err(Error::Message("less than 0".to_string())));

    // reentrancy prevented
    let result = arith::fib(&mut runtime, signer, 9).await;
    assert!(result.is_err_and(|e| e.root_cause().to_string().contains("reentrancy prevented")));

    let result = fib::cached_values(&mut runtime).await?;
    assert_eq!(result, vec![0, 1, 2, 3, 4, 5, 6, 7, 8]);

    Ok(())
}
