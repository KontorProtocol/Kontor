#![allow(clippy::too_many_arguments)]
use testlib::*;

interface!(name = "token", path = "../test-contracts/token/wit",);

interface!(name = "pool", path = "../test-contracts/pool/wit",);

async fn run_test_amm_swaps(runtime: &mut Runtime) -> Result<()> {
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;

    let token_a = runtime.publish_as(&admin, "token", "token-a").await?;
    let token_b = runtime.publish_as(&admin, "token", "token-b").await?;
    let pool = runtime.publish(&admin, "pool").await?;

    token::mint(runtime, &token_a, &minter, 1000.into()).await?;
    token::mint(runtime, &token_b, &minter, 1000.into()).await?;

    token::transfer(runtime, &token_a, &minter, &admin, 100.into()).await??;
    token::transfer(runtime, &token_b, &minter, &admin, 500.into()).await??;

    let res = pool::re_init(
        runtime,
        &pool,
        &admin,
        token_a.clone(),
        100.into(),
        token_b.clone(),
        500.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(223.into()));

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    assert_eq!(bal_a, Ok(100.into()));
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    assert_eq!(bal_b, Ok(500.into()));
    let k1 = bal_a.unwrap() * bal_b.unwrap();

    let res = pool::quote_swap(runtime, &pool, token_a.clone(), 10.into()).await?;
    assert_eq!(res, Ok(45.into()));

    let res = pool::quote_swap(runtime, &pool, token_a.clone(), 100.into()).await?;
    assert_eq!(res, Ok(250.into()));

    let res = pool::quote_swap(runtime, &pool, token_a.clone(), 1000.into()).await?;
    assert_eq!(res, Ok(454.into()));

    let res = pool::swap(
        runtime,
        &pool,
        &minter,
        token_a.clone(),
        10.into(),
        46.into(),
    )
    .await?;
    assert!(res.is_err()); // below minimum

    let res = pool::swap(
        runtime,
        &pool,
        &minter,
        token_a.clone(),
        10.into(),
        45.into(),
    )
    .await?;
    assert_eq!(res, Ok(45.into()));

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    let k2 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k2 >= k1);

    let res = pool::quote_swap(runtime, &pool, token_b.clone(), 45.into()).await?;
    assert_eq!(res, Ok(9.into()));
    let res = pool::swap(
        runtime,
        &pool,
        &minter,
        token_b.clone(),
        45.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(9.into()));

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    let k3 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k3 >= k2);

    // use token interface to transfer shares
    let res = token::balance(runtime, &pool, &admin).await?;
    assert_eq!(res, Some(223.into()));
    let res = token::balance(runtime, &pool, &minter).await?;
    assert_eq!(res, None);

    token::transfer(runtime, &pool, &admin, &minter, 23.into()).await??;

    let res = token::balance(runtime, &pool, &admin).await?;
    assert_eq!(res, Some(200.into()));
    let res = token::balance(runtime, &pool, &minter).await?;
    assert_eq!(res, Some(23.into()));

    Ok(())
}

async fn run_test_amm_swap_fee(runtime: &mut Runtime) -> Result<()> {
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;

    let token_a = runtime.publish_as(&admin, "token", "token-a").await?;
    let token_b = runtime.publish_as(&admin, "token", "token-b").await?;
    let pool = runtime.publish(&admin, "pool").await?;

    token::mint(runtime, &token_a, &minter, 1000.into()).await?;
    token::mint(runtime, &token_b, &minter, 1000.into()).await?;

    token::transfer(runtime, &token_a, &minter, &admin, 100.into()).await??;
    token::transfer(runtime, &token_b, &minter, &admin, 500.into()).await??;

    pool::re_init(
        runtime,
        &pool,
        &admin,
        token_a.clone(),
        100.into(),
        token_b.clone(),
        500.into(),
        30.into(),
    )
    .await??;

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    let k1 = bal_a.unwrap() * bal_b.unwrap();

    let res = pool::quote_swap(runtime, &pool, token_a.clone(), 10.into()).await?;
    assert_eq!(res, Ok(41.into()));

    let res = pool::quote_swap(runtime, &pool, token_a.clone(), 100.into()).await?;
    assert_eq!(res, Ok(248.into()));

    let res = pool::quote_swap(runtime, &pool, token_a.clone(), 1000.into()).await?;
    assert_eq!(res, Ok(454.into())); // fee dominated by rounding effect

    let res = pool::swap(
        runtime,
        &pool,
        &minter,
        token_a.clone(),
        10.into(),
        40.into(),
    )
    .await?;
    assert_eq!(res, Ok(41.into()));

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    let k2 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k2 >= k1);

    let res = pool::quote_swap(runtime, &pool, token_b.clone(), 45.into()).await?;
    assert_eq!(res, Ok(9.into()));
    let res = pool::swap(
        runtime,
        &pool,
        &minter,
        token_b.clone(),
        45.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(9.into()));

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    let k3 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k3 >= k2);

    // use token interface to transfer shares
    let res = token::balance(runtime, &pool, &admin).await?;
    assert_eq!(res, Some(223.into()));
    let res = token::balance(runtime, &pool, &minter).await?;
    assert_eq!(res, None);

    token::transfer(runtime, &pool, &admin, &minter, 23.into()).await??;

    let res = token::balance(runtime, &pool, &admin).await?;
    assert_eq!(res, Some(200.into()));
    let res = token::balance(runtime, &pool, &minter).await?;
    assert_eq!(res, Some(23.into()));

    Ok(())
}

async fn run_test_amm_shares_token_interface(runtime: &mut Runtime) -> Result<()> {
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;

    let token_a = runtime.publish_as(&admin, "token", "token-a").await?;
    let token_b = runtime.publish_as(&admin, "token", "token-b").await?;
    let pool = runtime.publish(&admin, "pool").await?;

    token::mint(runtime, &token_a, &minter, 1000.into()).await?;
    token::mint(runtime, &token_b, &minter, 1000.into()).await?;

    token::transfer(runtime, &token_a, &minter, &admin, 100.into()).await??;
    token::transfer(runtime, &token_b, &minter, &admin, 500.into()).await??;

    let res = pool::re_init(
        runtime,
        &pool,
        &admin,
        token_a.clone(),
        100.into(),
        token_b.clone(),
        500.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(223.into()));

    let shares = pool::balance(runtime, &pool, &admin).await?;
    assert_eq!(shares, Some(223.into()));

    pool::transfer(runtime, &pool, &admin, &holder, 40.into()).await??;

    let shares = pool::balance(runtime, &pool, &admin).await?;
    assert_eq!(shares, Some(183.into()));
    let shares = pool::balance(runtime, &pool, &holder).await?;
    assert_eq!(shares, Some(40.into()));

    // holder withdraws the tokens of the pair using the transferred shares
    let res = pool::withdraw(runtime, &pool, &holder, 10.into()).await?;
    assert_eq!(
        res,
        Ok(pool::WithdrawResult {
            amount_a: 4.into(),
            amount_b: 22.into(),
        })
    );

    let bal_a = token::balance(runtime, &token_a, &holder).await?;
    assert_eq!(bal_a, Some(4.into()));
    let bal_b = token::balance(runtime, &token_b, &holder).await?;
    assert_eq!(bal_b, Some(22.into()));

    Ok(())
}

async fn run_test_amm_swap_low_slippage(runtime: &mut Runtime) -> Result<()> {
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;

    let token_a = runtime.publish_as(&admin, "token", "token-a").await?;
    let token_b = runtime.publish_as(&admin, "token", "token-b").await?;
    let pool = runtime.publish(&admin, "pool").await?;

    token::mint(runtime, &token_a, &minter, 110000.into()).await?;
    token::mint(runtime, &token_b, &minter, 510000.into()).await?;

    token::transfer(runtime, &token_a, &minter, &admin, 100000.into()).await??;
    token::transfer(runtime, &token_b, &minter, &admin, 500000.into()).await??;

    pool::re_init(
        runtime,
        &pool,
        &admin,
        token_a.clone(),
        100000.into(),
        token_b.clone(),
        500000.into(),
        30.into(),
    )
    .await??;

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    let k1 = bal_a.unwrap() * bal_b.unwrap();

    let res = pool::quote_swap(runtime, &pool, token_a.clone(), 10.into()).await?;
    assert_eq!(res, Ok(44.into()));

    let res = pool::quote_swap(runtime, &pool, token_a.clone(), 100.into()).await?;
    assert_eq!(res, Ok(494.into()));

    let res = pool::quote_swap(runtime, &pool, token_a.clone(), 1000.into()).await?;
    assert_eq!(res, Ok(4935.into()));

    let res = pool::quote_swap(runtime, &pool, token_a.clone(), 10000.into()).await?;
    assert_eq!(res, Ok(45330.into()));

    let res = pool::swap(
        runtime,
        &pool,
        &minter,
        token_a.clone(),
        10000.into(),
        45000.into(),
    )
    .await?;
    assert_eq!(res, Ok(45330.into()));

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    let k2 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k2 >= k1 + (30 * 450000).into()); // grows with fee amount

    let res = pool::quote_swap(runtime, &pool, token_b.clone(), 45.into()).await?;
    assert_eq!(res, Ok(10.into()));
    let res = pool::swap(
        runtime,
        &pool,
        &minter,
        token_b.clone(),
        45.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(10.into()));

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    let k3 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k3 >= k2);

    Ok(())
}

async fn run_test_amm_deposit_withdraw(runtime: &mut Runtime) -> Result<()> {
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;

    let token_a = runtime.publish_as(&admin, "token", "token-a").await?;
    let token_b = runtime.publish_as(&admin, "token", "token-b").await?;
    let pool = runtime.publish(&admin, "pool").await?;

    token::mint(runtime, &token_a, &minter, 1000.into()).await?;
    token::mint(runtime, &token_b, &minter, 1000.into()).await?;

    token::transfer(runtime, &token_a, &minter, &admin, 100.into()).await??;
    token::transfer(runtime, &token_b, &minter, &admin, 500.into()).await??;

    let res = pool::re_init(
        runtime,
        &pool,
        &admin,
        token_a.clone(),
        100.into(),
        token_b.clone(),
        500.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(223.into()));

    token::transfer(runtime, &token_a, &minter, &holder, 200.into()).await??;
    token::transfer(runtime, &token_b, &minter, &holder, 200.into()).await??;

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    assert_eq!(bal_a, Ok(100.into()));
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    assert_eq!(bal_b, Ok(500.into()));

    let res = pool::quote_withdraw(runtime, &pool, 10.into()).await?;
    assert_eq!(
        res,
        Ok(pool::WithdrawResult {
            amount_a: 4.into(),
            amount_b: 22.into(),
        })
    );

    let res = pool::quote_deposit(runtime, &pool, 10.into(), 100.into()).await?;
    assert_eq!(
        res,
        Ok(pool::DepositResult {
            lp_shares: 22.into(),
            deposit_a: 10.into(),
            deposit_b: 50.into(),
        })
    );

    let res = pool::deposit(runtime, &pool, &holder, 50.into(), 100.into()).await?;
    assert_eq!(
        res,
        Ok(pool::DepositResult {
            lp_shares: 44.into(),
            deposit_a: 20.into(),
            deposit_b: 99.into(),
        })
    );

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    assert_eq!(bal_a, Ok(120.into()));
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    assert_eq!(bal_b, Ok(599.into()));

    let bal = pool::balance(runtime, &pool, &admin).await?;
    assert_eq!(bal, Some(223.into()));
    let bal = pool::balance(runtime, &pool, &holder).await?;
    assert_eq!(bal, Some(44.into()));

    let res = pool::quote_withdraw(runtime, &pool, 10.into()).await?;
    assert_eq!(
        res,
        Ok(pool::WithdrawResult {
            amount_a: 4.into(),
            amount_b: 22.into(),
        })
    );

    let res = pool::withdraw(runtime, &pool, &holder, 44.into()).await?;
    assert_eq!(
        res,
        Ok(pool::WithdrawResult {
            amount_a: 19.into(),
            amount_b: 98.into(),
        })
    );

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    assert_eq!(bal_a, Ok(101.into()));
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    assert_eq!(bal_b, Ok(501.into()));

    let bal = pool::balance(runtime, &pool, &admin).await?;
    assert_eq!(bal, Some(223.into()));
    let bal = pool::balance(runtime, &pool, &holder).await?;
    assert_eq!(bal, Some(0.into()));

    Ok(())
}

async fn run_test_amm_limits(runtime: &mut Runtime) -> Result<()> {
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;

    let token_a = runtime.publish_as(&admin, "token", "token-a").await?;
    let token_b = runtime.publish_as(&admin, "token", "token-b").await?;
    let pool = runtime.publish(&admin, "pool").await?;

    let max_int = "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457";
    let large_value: Integer = "340_282_366_920_938_463_463_374_606_431".into(); // sqrt(MAX_INT) - 1000
    let oversized_value = large_value + 1.into();

    token::mint(runtime, &token_a, &minter, max_int.into()).await?;
    token::mint(runtime, &token_b, &minter, max_int.into()).await?;

    token::transfer(runtime, &token_a, &minter, &admin, 1000.into()).await??;
    token::transfer(runtime, &token_b, &minter, &admin, 1000.into()).await??;

    let res = pool::re_init(
        runtime,
        &pool,
        &admin,
        token_a.clone(),
        1000.into(),
        token_b.clone(),
        1000.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(1000.into()));

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    let k1 = bal_a.unwrap() * bal_b.unwrap();

    let res = pool::quote_swap(runtime, &pool, token_a.clone(), large_value).await?;
    assert_eq!(res, Ok(999.into()));
    let res = pool::quote_swap(runtime, &pool, token_a.clone(), oversized_value).await?;
    assert!(res.is_err());

    let res = pool::swap(
        runtime,
        &pool,
        &minter,
        token_a.clone(),
        large_value,
        900.into(),
    )
    .await?;
    assert_eq!(res, Ok(999.into()));

    let res = pool::quote_swap(runtime, &pool, token_a.clone(), 1.into()).await?;
    assert!(res.is_err());
    let res = pool::swap(runtime, &pool, &minter, token_a.clone(), 1.into(), 0.into()).await?;
    assert!(res.is_err());

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    let k2 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k2 >= k1);

    let res = pool::quote_swap(runtime, &pool, token_b.clone(), large_value).await?;
    assert_eq!(res, Ok("340_282_366_920_938_463_463_374_607_429".into()));
    let res = pool::swap(
        runtime,
        &pool,
        &minter,
        token_b.clone(),
        large_value,
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok("340_282_366_920_938_463_463_374_607_429".into()));

    let res = pool::quote_swap(runtime, &pool, token_b.clone(), 1000.into()).await?;
    assert!(res.is_err());
    let res = pool::swap(
        runtime,
        &pool,
        &minter,
        token_b.clone(),
        1000.into(),
        0.into(),
    )
    .await?;
    assert!(res.is_err());

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone()).await?;
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone()).await?;
    let k3 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k3 >= k2);

    Ok(())
}

#[runtime(contracts_dir = "../../test-contracts")]
async fn test_amm_swaps() -> Result<()> {
    run_test_amm_swaps(runtime).await
}

#[runtime(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_amm_swaps_regtest() -> Result<()> {
    run_test_amm_swaps(runtime).await
}

#[runtime(contracts_dir = "../../test-contracts")]
async fn test_amm_swap_fee() -> Result<()> {
    run_test_amm_swap_fee(runtime).await
}

#[runtime(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_amm_swap_fee_regtest() -> Result<()> {
    run_test_amm_swap_fee(runtime).await
}

#[runtime(contracts_dir = "../../test-contracts")]
async fn test_amm_shares_token_interface() -> Result<()> {
    run_test_amm_shares_token_interface(runtime).await
}

#[runtime(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_amm_shares_token_interface_regtest() -> Result<()> {
    run_test_amm_shares_token_interface(runtime).await
}

#[runtime(contracts_dir = "../../test-contracts")]
async fn test_amm_swap_low_slippage() -> Result<()> {
    run_test_amm_swap_low_slippage(runtime).await
}

#[runtime(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_amm_swap_low_slippage_regtest() -> Result<()> {
    run_test_amm_swap_low_slippage(runtime).await
}

#[runtime(contracts_dir = "../../test-contracts")]
async fn test_amm_deposit_withdraw() -> Result<()> {
    run_test_amm_deposit_withdraw(runtime).await
}

#[runtime(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_amm_deposit_withdraw_regtest() -> Result<()> {
    run_test_amm_deposit_withdraw(runtime).await
}

#[runtime(contracts_dir = "../../test-contracts")]
async fn test_amm_limits() -> Result<()> {
    run_test_amm_limits(runtime).await
}

#[runtime(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_amm_limits_regtest() -> Result<()> {
    run_test_amm_limits(runtime).await
}
