use testlib::*;

interface!(name = "amm", path = "../../test-contracts/amm/wit");

interface!(name = "token", path = "../../test-contracts/token/wit");

async fn run_test_amm_swaps(runtime: &mut Runtime) -> Result<()> {
    tracing::info!("test_amm_swaps");
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;

    let amm = runtime.publish(&admin, "amm").await?;
    let token_a = runtime.publish_as(&admin, "token", "token-a").await?;
    let token_b = runtime.publish_as(&admin, "token", "token-b").await?;

    token::mint(runtime, &token_a, &minter, 1000.into()).await??;
    token::mint(runtime, &token_b, &minter, 1000.into()).await??;

    token::transfer(runtime, &token_a, &minter, &admin, 100.into()).await??;
    token::transfer(runtime, &token_b, &minter, &admin, 500.into()).await??;

    let pair = amm::TokenPair {
        a: token_a.clone(),
        b: token_b.clone(),
    };
    let res = amm::create(
        runtime,
        &amm,
        &admin,
        pair.clone(),
        100.into(),
        500.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(223.into()));

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    assert_eq!(bal_a, Ok(100.into()));
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    assert_eq!(bal_b, Ok(500.into()));
    let k1 = bal_a.unwrap() * bal_b.unwrap();

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_a.clone(), 10.into()).await?;
    assert_eq!(res, Ok(45.into()));

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_a.clone(), 100.into()).await?;
    assert_eq!(res, Ok(250.into()));

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_a.clone(), 1000.into()).await?;
    assert_eq!(res, Ok(454.into()));

    let res = amm::swap(
        runtime,
        &amm,
        &minter,
        pair.clone(),
        token_a.clone(),
        10.into(),
        46.into(),
    )
    .await?;
    assert!(res.is_err()); // below minimum

    let res = amm::swap(
        runtime,
        &amm,
        &minter,
        pair.clone(),
        token_a.clone(),
        10.into(),
        45.into(),
    )
    .await?;
    assert_eq!(res, Ok(45.into()));

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    let k2 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k2 >= k1);

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_b.clone(), 45.into()).await?;
    assert_eq!(res, Ok(9.into()));
    let res = amm::swap(
        runtime,
        &amm,
        &minter,
        pair.clone(),
        token_b.clone(),
        45.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(9.into()));

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    let k3 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k3 >= k2);

    Ok(())
}

async fn run_test_amm_swap_fee(runtime: &mut Runtime) -> Result<()> {
    tracing::info!("test_amm_swap_fee");
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;
    let amm = runtime.publish(&admin, "amm").await?;
    let token_a = runtime.publish_as(&admin, "token", "token-a").await?;
    let token_b = runtime.publish_as(&admin, "token", "token-b").await?;

    token::mint(runtime, &token_a, &minter, 1000.into()).await??;
    token::mint(runtime, &token_b, &minter, 1000.into()).await??;

    token::transfer(runtime, &token_a, &minter, &admin, 100.into()).await??;
    token::transfer(runtime, &token_b, &minter, &admin, 500.into()).await??;

    let pair = amm::TokenPair {
        a: token_a.clone(),
        b: token_b.clone(),
    };
    amm::create(
        runtime,
        &amm,
        &admin,
        pair.clone(),
        100.into(),
        500.into(),
        30.into(),
    )
    .await??;

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    let k1 = bal_a.unwrap() * bal_b.unwrap();

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_a.clone(), 10.into()).await?;
    assert_eq!(res, Ok(41.into()));

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_a.clone(), 100.into()).await?;
    assert_eq!(res, Ok(248.into()));

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_a.clone(), 1000.into()).await?;
    assert_eq!(res, Ok(454.into())); // fee dominated by rounding effect

    let res = amm::swap(
        runtime,
        &amm,
        &minter,
        pair.clone(),
        token_a.clone(),
        10.into(),
        40.into(),
    )
    .await?;
    assert_eq!(res, Ok(41.into()));

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    let k2 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k2 >= k1);

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_b.clone(), 45.into()).await?;
    assert_eq!(res, Ok(9.into()));
    let res = amm::swap(
        runtime,
        &amm,
        &minter,
        pair.clone(),
        token_b.clone(),
        45.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(9.into()));

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    let k3 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k3 >= k2);

    Ok(())
}

async fn run_test_amm_swap_low_slippage(runtime: &mut Runtime) -> Result<()> {
    tracing::info!("test_amm_swap_low_slippage");
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;
    let amm = runtime.publish(&admin, "amm").await?;
    let token_a = runtime.publish_as(&admin, "token", "token-a").await?;
    let token_b = runtime.publish_as(&admin, "token", "token-b").await?;

    token::mint(runtime, &token_a, &minter, 110000.into()).await??;
    token::mint(runtime, &token_b, &minter, 510000.into()).await??;

    token::transfer(runtime, &token_a, &minter, &admin, 100000.into()).await??;
    token::transfer(runtime, &token_b, &minter, &admin, 500000.into()).await??;

    let pair = amm::TokenPair {
        a: token_a.clone(),
        b: token_b.clone(),
    };
    amm::create(
        runtime,
        &amm,
        &admin,
        pair.clone(),
        100000.into(),
        500000.into(),
        30.into(),
    )
    .await??;

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    let k1 = bal_a.unwrap() * bal_b.unwrap();

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_a.clone(), 10.into()).await?;
    assert_eq!(res, Ok(44.into()));

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_a.clone(), 100.into()).await?;
    assert_eq!(res, Ok(494.into()));

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_a.clone(), 1000.into()).await?;
    assert_eq!(res, Ok(4935.into()));

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_a.clone(), 10000.into()).await?;
    assert_eq!(res, Ok(45330.into()));

    let res = amm::swap(
        runtime,
        &amm,
        &minter,
        pair.clone(),
        token_a.clone(),
        10000.into(),
        45000.into(),
    )
    .await?;
    assert_eq!(res, Ok(45330.into()));

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    let k2 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k2 >= k1 + (30 * 450000).into()); // grows with fee amount

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_b.clone(), 45.into()).await?;
    assert_eq!(res, Ok(10.into()));
    let res = amm::swap(
        runtime,
        &amm,
        &minter,
        pair.clone(),
        token_b.clone(),
        45.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(10.into()));

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    let k3 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k3 >= k2);

    Ok(())
}

async fn run_test_amm_deposit_withdraw(runtime: &mut Runtime) -> Result<()> {
    tracing::info!("test_amm_deposit_withdraw");
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;

    let amm = runtime.publish(&admin, "amm").await?;
    let token_a = runtime.publish_as(&admin, "token", "token-a").await?;
    let token_b = runtime.publish_as(&admin, "token", "token-b").await?;

    token::mint(runtime, &token_a, &minter, 1000.into()).await??;
    token::mint(runtime, &token_b, &minter, 1000.into()).await??;

    token::transfer(runtime, &token_a, &minter, &admin, 100.into()).await??;
    token::transfer(runtime, &token_b, &minter, &admin, 500.into()).await??;

    let pair = amm::TokenPair {
        a: token_a.clone(),
        b: token_b.clone(),
    };
    let res = amm::create(
        runtime,
        &amm,
        &admin,
        pair.clone(),
        100.into(),
        500.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(223.into()));

    token::transfer(runtime, &token_a, &minter, &holder, 200.into()).await??;
    token::transfer(runtime, &token_b, &minter, &holder, 200.into()).await??;

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    assert_eq!(bal_a, Ok(100.into()));
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    assert_eq!(bal_b, Ok(500.into()));

    let res = amm::quote_withdraw(runtime, &amm, pair.clone(), 10.into()).await?;
    assert_eq!(
        res,
        Ok(amm::WithdrawResult {
            amount_a: 4.into(),
            amount_b: 22.into(),
        })
    );

    let res = amm::quote_deposit(runtime, &amm, pair.clone(), 10.into(), 100.into()).await?;
    assert_eq!(
        res,
        Ok(amm::DepositResult {
            lp_shares: 22.into(),
            deposit_a: 10.into(),
            deposit_b: 50.into(),
        })
    );

    let res = amm::deposit(runtime, &amm, &holder, pair.clone(), 50.into(), 100.into()).await?;
    assert_eq!(
        res,
        Ok(amm::DepositResult {
            lp_shares: 44.into(),
            deposit_a: 20.into(),
            deposit_b: 99.into(),
        })
    );

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    assert_eq!(bal_a, Ok(120.into()));
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    assert_eq!(bal_b, Ok(599.into()));

    let bal = amm::balance(runtime, &amm, pair.clone(), &admin).await?;
    assert_eq!(bal, Some(223.into()));
    let bal = amm::balance(runtime, &amm, pair.clone(), &holder).await?;
    assert_eq!(bal, Some(44.into()));

    let res = amm::quote_withdraw(runtime, &amm, pair.clone(), 10.into()).await?;
    assert_eq!(
        res,
        Ok(amm::WithdrawResult {
            amount_a: 4.into(),
            amount_b: 22.into(),
        })
    );

    let res = amm::withdraw(runtime, &amm, &holder, pair.clone(), 44.into()).await?;
    assert_eq!(
        res,
        Ok(amm::WithdrawResult {
            amount_a: 19.into(),
            amount_b: 98.into(),
        })
    );

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    assert_eq!(bal_a, Ok(101.into()));
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    assert_eq!(bal_b, Ok(501.into()));

    let bal = amm::balance(runtime, &amm, pair.clone(), &admin).await?;
    assert_eq!(bal, Some(223.into()));
    let bal = amm::balance(runtime, &amm, pair.clone(), &holder).await?;
    assert_eq!(bal, Some(0.into()));

    Ok(())
}

async fn run_test_amm_limits(runtime: &mut Runtime) -> Result<()> {
    tracing::info!("test_amm_limits");
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;

    let amm = runtime.publish(&admin, "amm").await?;
    let token_a = runtime.publish_as(&admin, "token", "token-a").await?;
    let token_b = runtime.publish_as(&admin, "token", "token-b").await?;

    let max_int = "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457";
    let large_value: Integer = "340_282_366_920_938_463_463_374_606_431".into(); // sqrt(MAX_INT) - 1000
    let oversized_value = large_value + 1.into();

    token::mint(runtime, &token_a, &minter, max_int.into()).await??;
    token::mint(runtime, &token_b, &minter, max_int.into()).await??;

    token::transfer(runtime, &token_a, &minter, &admin, 1000.into()).await??;
    token::transfer(runtime, &token_b, &minter, &admin, 1000.into()).await??;

    let pair = amm::TokenPair {
        a: token_a.clone(),
        b: token_b.clone(),
    };
    let res = amm::create(
        runtime,
        &amm,
        &admin,
        pair.clone(),
        1000.into(),
        1000.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(1000.into()));

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    let k1 = bal_a.unwrap() * bal_b.unwrap();

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_a.clone(), large_value).await?;
    assert_eq!(res, Ok(999.into()));
    let res = amm::quote_swap(
        runtime,
        &amm,
        pair.clone(),
        token_a.clone(),
        oversized_value,
    )
    .await?;
    assert!(res.is_err());

    let res = amm::swap(
        runtime,
        &amm,
        &minter,
        pair.clone(),
        token_a.clone(),
        large_value,
        900.into(),
    )
    .await?;
    assert_eq!(res, Ok(999.into()));

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_a.clone(), 1.into()).await?;
    assert!(res.is_err());
    let res = amm::swap(
        runtime,
        &amm,
        &minter,
        pair.clone(),
        token_a.clone(),
        1.into(),
        0.into(),
    )
    .await?;
    assert!(res.is_err());

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    let k2 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k2 >= k1);

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_b.clone(), large_value).await?;
    assert_eq!(res, Ok("340_282_366_920_938_463_463_374_607_429".into()));
    let res = amm::swap(
        runtime,
        &amm,
        &minter,
        pair.clone(),
        token_b.clone(),
        large_value,
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok("340_282_366_920_938_463_463_374_607_429".into()));

    let res = amm::quote_swap(runtime, &amm, pair.clone(), token_b.clone(), 1000.into()).await?;
    assert!(res.is_err());
    let res = amm::swap(
        runtime,
        &amm,
        &minter,
        pair.clone(),
        token_b.clone(),
        1000.into(),
        0.into(),
    )
    .await?;
    assert!(res.is_err());

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone()).await?;
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone()).await?;
    let k3 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k3 >= k2);

    Ok(())
}

async fn run_test_amm_pools(runtime: &mut Runtime) -> Result<()> {
    tracing::info!("test_amm_pools");
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;

    let amm = runtime.publish(&admin, "amm").await?;
    let token_a = runtime.publish_as(&admin, "token", "token-a").await?;
    let token_b = runtime.publish_as(&admin, "token", "token-b").await?;
    let token_c = runtime.publish_as(&admin, "token", "token-c").await?;

    token::mint(runtime, &token_a, &minter, 1000.into()).await??;
    token::mint(runtime, &token_b, &minter, 1000.into()).await??;
    token::mint(runtime, &token_c, &minter, 1000.into()).await??;

    token::transfer(runtime, &token_a, &minter, &admin, 100.into()).await??;
    token::transfer(runtime, &token_b, &minter, &admin, 600.into()).await??;
    token::transfer(runtime, &token_c, &minter, &admin, 200.into()).await??;

    let bad_pair = amm::TokenPair {
        // wrong order
        a: token_b.clone(),
        b: token_a.clone(),
    };
    let res = amm::create(
        runtime,
        &amm,
        &admin,
        bad_pair.clone(),
        100.into(),
        500.into(),
        0.into(),
    )
    .await?;
    assert!(res.is_err());

    let pair1 = amm::TokenPair {
        a: token_a.clone(),
        b: token_b.clone(),
    };
    let pair2 = amm::TokenPair {
        a: token_b.clone(),
        b: token_c.clone(),
    };
    let res = amm::create(
        runtime,
        &amm,
        &admin,
        pair1.clone(),
        100.into(),
        500.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(223.into()));

    let res = amm::create(
        runtime,
        &amm,
        &admin,
        pair1.clone(),
        100.into(),
        500.into(),
        0.into(),
    )
    .await?;
    assert!(res.is_err()); // can't create pool twice

    let res = amm::create(
        runtime,
        &amm,
        &admin,
        pair2.clone(),
        100.into(),
        200.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(141.into()));

    let bal_a = amm::token_balance(runtime, &amm, pair1.clone(), token_a.clone()).await?;
    assert_eq!(bal_a, Ok(100.into()));
    let bal_b = amm::token_balance(runtime, &amm, pair1.clone(), token_b.clone()).await?;
    assert_eq!(bal_b, Ok(500.into()));
    let k1_1 = bal_a.unwrap() * bal_b.unwrap();

    let bal_b = amm::token_balance(runtime, &amm, pair2.clone(), token_b.clone()).await?;
    assert_eq!(bal_b, Ok(100.into()));
    let bal_c = amm::token_balance(runtime, &amm, pair2.clone(), token_c.clone()).await?;
    assert_eq!(bal_c, Ok(200.into()));
    let k2_1 = bal_b.unwrap() * bal_c.unwrap();

    let res = amm::quote_swap(runtime, &amm, pair1.clone(), token_a.clone(), 10.into()).await?;
    assert_eq!(res, Ok(45.into()));

    let res = amm::quote_swap(runtime, &amm, pair1.clone(), token_a.clone(), 100.into()).await?;
    assert_eq!(res, Ok(250.into()));

    let res = amm::quote_swap(runtime, &amm, pair1.clone(), token_a.clone(), 1000.into()).await?;
    assert_eq!(res, Ok(454.into()));

    let res = amm::swap(
        runtime,
        &amm,
        &minter,
        pair1.clone(),
        token_a.clone(),
        10.into(),
        45.into(),
    )
    .await?;
    assert_eq!(res, Ok(45.into()));

    let bal_a = amm::token_balance(runtime, &amm, pair1.clone(), token_a.clone()).await?;
    let bal_b = amm::token_balance(runtime, &amm, pair1.clone(), token_b.clone()).await?;
    let k1_2 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k1_2 >= k1_1);

    let bal_b = amm::token_balance(runtime, &amm, pair2.clone(), token_b.clone()).await?;
    let bal_c = amm::token_balance(runtime, &amm, pair2.clone(), token_c.clone()).await?;
    let k2_2 = bal_b.unwrap() * bal_c.unwrap();
    assert!(k2_2 == k2_1); // unchanged

    let res = amm::quote_swap(runtime, &amm, pair1.clone(), token_b.clone(), 45.into()).await?;
    assert_eq!(res, Ok(9.into()));
    let res = amm::swap(
        runtime,
        &amm,
        &minter,
        pair1.clone(),
        token_b.clone(),
        45.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(9.into()));

    let bal_a = amm::token_balance(runtime, &amm, pair1.clone(), token_a.clone()).await?;
    let bal_b = amm::token_balance(runtime, &amm, pair1.clone(), token_b.clone()).await?;
    let k1_3 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k1_3 >= k1_2);

    let bal_b = amm::token_balance(runtime, &amm, pair2.clone(), token_b.clone()).await?;
    let bal_c = amm::token_balance(runtime, &amm, pair2.clone(), token_c.clone()).await?;
    let k2_3 = bal_b.unwrap() * bal_c.unwrap();
    assert!(k2_3 == k2_1); // unchanged

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_amm_swaps() -> Result<()> {
    run_test_amm_swaps(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_amm_swap_fee() -> Result<()> {
    run_test_amm_swap_fee(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_amm_swap_low_slippage() -> Result<()> {
    run_test_amm_swap_low_slippage(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_amm_deposit_withdraw() -> Result<()> {
    run_test_amm_deposit_withdraw(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_amm_limits() -> Result<()> {
    run_test_amm_limits(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_amm_pools() -> Result<()> {
    run_test_amm_pools(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_amm_contract_regtest() -> Result<()> {
    logging::setup();
    run_test_amm_swaps(runtime).await?;
    run_test_amm_swap_fee(runtime).await?;
    run_test_amm_swap_low_slippage(runtime).await?;
    run_test_amm_deposit_withdraw(runtime).await?;
    run_test_amm_limits(runtime).await?;
    run_test_amm_pools(runtime).await?;
    Ok(())
}
