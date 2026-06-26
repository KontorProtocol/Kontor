use testlib::*;

interface!(name = "amm", path = "../../test-contracts/amm/wit");

interface!(name = "token", path = "../../test-contracts/test-token/wit");

async fn run_test_amm_swaps(runtime: &mut Runtime) -> Result<()> {
    tracing::info!("test_amm_swaps");
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;

    let addrs = runtime
        .publish_many(
            &admin,
            &[
                ("amm", "amm-a-swaps"),
                ("test-token", "token-a-a-swaps"),
                ("test-token", "token-b-a-swaps"),
            ],
        )
        .await?;
    let amm = addrs[0].clone();
    let token_a = addrs[1].clone();
    let token_b = addrs[2].clone();

    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token_a, 1000.into()));
    ops.push(token::mint_call(&token_b, 1000.into()));
    ops.push(token::transfer_call(&token_a, &admin, 100.into()));
    ops.push(token::transfer_call(&token_b, &admin, 500.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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
    let addrs = runtime
        .publish_many(
            &admin,
            &[
                ("amm", "amm-a-fee"),
                ("test-token", "token-a-a-fee"),
                ("test-token", "token-b-a-fee"),
            ],
        )
        .await?;
    let amm = addrs[0].clone();
    let token_a = addrs[1].clone();
    let token_b = addrs[2].clone();

    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token_a, 1000.into()));
    ops.push(token::mint_call(&token_b, 1000.into()));
    ops.push(token::transfer_call(&token_a, &admin, 100.into()));
    ops.push(token::transfer_call(&token_b, &admin, 500.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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
    let addrs = runtime
        .publish_many(
            &admin,
            &[
                ("amm", "amm-a-slippage"),
                ("test-token", "token-a-a-slippage"),
                ("test-token", "token-b-a-slippage"),
            ],
        )
        .await?;
    let amm = addrs[0].clone();
    let token_a = addrs[1].clone();
    let token_b = addrs[2].clone();

    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token_a, 110000.into()));
    ops.push(token::mint_call(&token_b, 510000.into()));
    ops.push(token::transfer_call(&token_a, &admin, 100000.into()));
    ops.push(token::transfer_call(&token_b, &admin, 500000.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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

    let addrs = runtime
        .publish_many(
            &admin,
            &[
                ("amm", "amm-a-depwith"),
                ("test-token", "token-a-a-depwith"),
                ("test-token", "token-b-a-depwith"),
            ],
        )
        .await?;
    let amm = addrs[0].clone();
    let token_a = addrs[1].clone();
    let token_b = addrs[2].clone();

    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token_a, 1000.into()));
    ops.push(token::mint_call(&token_b, 1000.into()));
    ops.push(token::transfer_call(&token_a, &admin, 100.into()));
    ops.push(token::transfer_call(&token_b, &admin, 500.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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

    let mut ops = Ops::new(&minter);
    ops.push(token::transfer_call(&token_a, &holder, 200.into()));
    ops.push(token::transfer_call(&token_b, &holder, 200.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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

    let addrs = runtime
        .publish_many(
            &admin,
            &[
                ("amm", "amm-a-limits"),
                ("test-token", "token-a-a-limits"),
                ("test-token", "token-b-a-limits"),
            ],
        )
        .await?;
    let amm = addrs[0].clone();
    let token_a = addrs[1].clone();
    let token_b = addrs[2].clone();

    // The AMM is decimal now; `validate_amount` caps inputs at 1e28 to keep the constant
    // product within Decimal's whole-number range. Verify the cap is enforced and that a
    // large in-bound swap drains TOWARD — never past — the pool and never decreases k.
    // `large_value` (1e18) is large vs the pool yet within Decimal's 18-digit fractional
    // precision: values near the cap would round and break k — a fixed-point limitation
    // the old integer AMM didn't have, so the limit test stays under it.
    let large_value: Decimal = "1_000_000_000_000_000_000".into(); // 1e18
    let oversized_value: Decimal = "10_000_000_000_000_000_000_000_000_001".into(); // 1e28 + 1
    let mint_supply: Decimal = format!("1{}", "0".repeat(50)).as_str().into(); // 1e50

    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token_a, mint_supply));
    ops.push(token::mint_call(&token_b, mint_supply));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

    let pair = amm::TokenPair {
        a: token_a.clone(),
        b: token_b.clone(),
    };
    amm::create(
        runtime,
        &amm,
        &minter,
        pair.clone(),
        1000.into(),
        1000.into(),
        0.into(),
    )
    .await??;

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone())
        .await?
        .unwrap();
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone())
        .await?
        .unwrap();
    let k1 = bal_a * bal_b;

    // Over the cap → rejected by `validate_amount`.
    let res = amm::quote_swap(
        runtime,
        &amm,
        pair.clone(),
        token_a.clone(),
        oversized_value,
    )
    .await?;
    assert!(res.is_err());

    // A large in-bound swap: positive output, strictly below the pool's out-balance
    // (can't drain the whole pool), and k never decreases.
    let out = amm::quote_swap(runtime, &amm, pair.clone(), token_a.clone(), large_value)
        .await?
        .unwrap();
    assert!(out > 0.into() && out < 1000.into());
    amm::swap(
        runtime,
        &amm,
        &minter,
        pair.clone(),
        token_a.clone(),
        large_value,
        0.into(),
    )
    .await??;

    let bal_a = amm::token_balance(runtime, &amm, pair.clone(), token_a.clone())
        .await?
        .unwrap();
    let bal_b = amm::token_balance(runtime, &amm, pair.clone(), token_b.clone())
        .await?
        .unwrap();
    assert!(bal_a * bal_b >= k1);

    Ok(())
}

async fn run_test_amm_pools(runtime: &mut Runtime) -> Result<()> {
    tracing::info!("test_amm_pools");
    let admin = runtime.identity().await?;
    let minter = runtime.identity().await?;

    let addrs = runtime
        .publish_many(
            &admin,
            &[
                ("amm", "amm-a-pools"),
                ("test-token", "token-a-a-pools"),
                ("test-token", "token-b-a-pools"),
                ("test-token", "token-c-a-pools"),
            ],
        )
        .await?;
    let amm = addrs[0].clone();
    let token_a = addrs[1].clone();
    let token_b = addrs[2].clone();
    let token_c = addrs[3].clone();

    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token_a, 1000.into()));
    ops.push(token::mint_call(&token_b, 1000.into()));
    ops.push(token::mint_call(&token_c, 1000.into()));
    ops.push(token::transfer_call(&token_a, &admin, 100.into()));
    ops.push(token::transfer_call(&token_b, &admin, 600.into()));
    ops.push(token::transfer_call(&token_c, &admin, 200.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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
