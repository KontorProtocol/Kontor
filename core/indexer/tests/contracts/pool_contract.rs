use testlib::*;
use tracing::info;

interface!(name = "token", path = "../../test-contracts/test-token/wit",);

interface!(name = "pool", path = "../../test-contracts/pool/wit",);

async fn run_test_amm_swaps(runtime: &mut Runtime) -> Result<()> {
    info!("test_amm_swaps");
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;

    let addrs = runtime
        .publish_many(
            &admin,
            &[
                ("test-token", "token-a-swaps"),
                ("test-token", "token-b-swaps"),
                ("pool", "pool-swaps"),
            ],
        )
        .await?;
    let token_a = addrs[0].clone();
    let token_b = addrs[1].clone();
    let pool = addrs[2].clone();

    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token_a, 1000.into()));
    ops.push(token::mint_call(&token_b, 1000.into()));
    ops.push(token::transfer_call(&token_a, &admin, 100.into()));
    ops.push(token::transfer_call(&token_b, &admin, 500.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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
    info!("test_amm_swap_fee");
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;

    let addrs = runtime
        .publish_many(
            &admin,
            &[
                ("test-token", "token-a-fee"),
                ("test-token", "token-b-fee"),
                ("pool", "pool-fee"),
            ],
        )
        .await?;
    let token_a = addrs[0].clone();
    let token_b = addrs[1].clone();
    let pool = addrs[2].clone();

    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token_a, 1000.into()));
    ops.push(token::mint_call(&token_b, 1000.into()));
    ops.push(token::transfer_call(&token_a, &admin, 100.into()));
    ops.push(token::transfer_call(&token_b, &admin, 500.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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
    info!("test_amm_shares_token_interface");
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;

    let addrs = runtime
        .publish_many(
            &admin,
            &[
                ("test-token", "token-a-shares"),
                ("test-token", "token-b-shares"),
                ("pool", "pool-shares"),
            ],
        )
        .await?;
    let token_a = addrs[0].clone();
    let token_b = addrs[1].clone();
    let pool = addrs[2].clone();

    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token_a, 1000.into()));
    ops.push(token::mint_call(&token_b, 1000.into()));
    ops.push(token::transfer_call(&token_a, &admin, 100.into()));
    ops.push(token::transfer_call(&token_b, &admin, 500.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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
    info!("test_amm_swap_low_slippage");
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;

    let addrs = runtime
        .publish_many(
            &admin,
            &[
                ("test-token", "token-a-slippage"),
                ("test-token", "token-b-slippage"),
                ("pool", "pool-slippage"),
            ],
        )
        .await?;
    let token_a = addrs[0].clone();
    let token_b = addrs[1].clone();
    let pool = addrs[2].clone();

    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token_a, 110000.into()));
    ops.push(token::mint_call(&token_b, 510000.into()));
    ops.push(token::transfer_call(&token_a, &admin, 100000.into()));
    ops.push(token::transfer_call(&token_b, &admin, 500000.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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
    info!("test_amm_deposit_withdraw");
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;

    let addrs = runtime
        .publish_many(
            &admin,
            &[
                ("test-token", "token-a-depwith"),
                ("test-token", "token-b-depwith"),
                ("pool", "pool-depwith"),
            ],
        )
        .await?;
    let token_a = addrs[0].clone();
    let token_b = addrs[1].clone();
    let pool = addrs[2].clone();

    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token_a, 1000.into()));
    ops.push(token::mint_call(&token_b, 1000.into()));
    ops.push(token::transfer_call(&token_a, &admin, 100.into()));
    ops.push(token::transfer_call(&token_b, &admin, 500.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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

    let mut ops = Ops::new(&minter);
    ops.push(token::transfer_call(&token_a, &holder, 200.into()));
    ops.push(token::transfer_call(&token_b, &holder, 200.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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
    info!("test_amm_limits");
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;

    let addrs = runtime
        .publish_many(
            &admin,
            &[
                ("test-token", "token-a-limits"),
                ("test-token", "token-b-limits"),
                ("pool", "pool-limits"),
            ],
        )
        .await?;
    let token_a = addrs[0].clone();
    let token_b = addrs[1].clone();
    let pool = addrs[2].clone();

    // Decimal pool now: inputs capped at 1e28 (keeps the constant product in Decimal's
    // whole-number range). Verify the cap is enforced and a large in-bound swap drains
    // toward — never past — the pool and never decreases k. `1e18` is large vs the pool
    // yet within Decimal's 18-digit precision (values near the cap round and break k).
    let large_value: Decimal = "1_000_000_000_000_000_000".into(); // 1e18
    let oversized_value: Decimal = "10_000_000_000_000_000_000_000_000_001".into(); // 1e28 + 1
    let mint_supply: Decimal = format!("1{}", "0".repeat(50)).as_str().into(); // 1e50

    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token_a, mint_supply));
    ops.push(token::mint_call(&token_b, mint_supply));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

    pool::re_init(
        runtime,
        &pool,
        &minter,
        token_a.clone(),
        1000.into(),
        token_b.clone(),
        1000.into(),
        0.into(),
    )
    .await??;

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone())
        .await?
        .unwrap();
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone())
        .await?
        .unwrap();
    let k1 = bal_a * bal_b;

    // Over the cap → rejected by `validate_amount`.
    let res = pool::quote_swap(runtime, &pool, token_a.clone(), oversized_value).await?;
    assert!(res.is_err());

    // A large in-bound swap: positive output, strictly below the pool's out-balance, and
    // k never decreases.
    let out = pool::quote_swap(runtime, &pool, token_a.clone(), large_value)
        .await?
        .unwrap();
    assert!(out > 0.into() && out < 1000.into());
    pool::swap(
        runtime,
        &pool,
        &minter,
        token_a.clone(),
        large_value,
        0.into(),
    )
    .await??;

    let bal_a = pool::token_balance(runtime, &pool, token_a.clone())
        .await?
        .unwrap();
    let bal_b = pool::token_balance(runtime, &pool, token_b.clone())
        .await?
        .unwrap();
    assert!(bal_a * bal_b >= k1);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_pool_swaps() -> Result<()> {
    run_test_amm_swaps(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_pool_swap_fee() -> Result<()> {
    run_test_amm_swap_fee(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_pool_shares_token_interface() -> Result<()> {
    run_test_amm_shares_token_interface(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_pool_swap_low_slippage() -> Result<()> {
    run_test_amm_swap_low_slippage(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_pool_deposit_withdraw() -> Result<()> {
    run_test_amm_deposit_withdraw(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_pool_limits() -> Result<()> {
    run_test_amm_limits(runtime).await
}
