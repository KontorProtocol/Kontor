use testlib::*;

import!(
    name = "token-a",
    height = 0,
    tx_index = 0,
    path = "../contracts/token/wit",
);

import!(
    name = "token-b",
    height = 0,
    tx_index = 0,
    path = "../contracts/token/wit",
);

import!(
    name = "pool",
    height = 0,
    tx_index = 0,
    path = "../contracts/pool/wit",
);

interface!(name = "token-dyn", path = "../contracts/token/wit");

#[tokio::test]
async fn test_amm_swaps() -> Result<()> {
    let mut runtime = Runtime::new(RuntimeConfig::default()).await?;

    let token_a = ContractAddress {
        name: "token-a".to_string(),
        height: 0,
        tx_index: 0,
    };

    let token_b = ContractAddress {
        name: "token-b".to_string(),
        height: 0,
        tx_index: 0,
    };

    let pool_address = ContractAddress {
        name: "pool".to_string(),
        height: 0,
        tx_index: 0,
    };

    let admin = "test_admin";
    let minter = "test_minter";
    token_a::mint(&mut runtime, minter, 1000.into()).await?;
    token_b::mint(&mut runtime, minter, 1000.into()).await?;

    token_a::transfer(&mut runtime, minter, admin, 100.into()).await??;
    token_b::transfer(&mut runtime, minter, admin, 500.into()).await??;

    let res = pool::re_init(
        &mut runtime,
        admin,
        token_a.clone(),
        100.into(),
        token_b.clone(),
        500.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(223.into()));

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    assert_eq!(bal_a, Ok(100.into()));
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    assert_eq!(bal_b, Ok(500.into()));
    let k1 = bal_a.unwrap() * bal_b.unwrap();

    let res = pool::quote_swap(&mut runtime, token_a.clone(), 10.into()).await?;
    assert_eq!(res, Ok(45.into()));

    let res = pool::quote_swap(&mut runtime, token_a.clone(), 100.into()).await?;
    assert_eq!(res, Ok(250.into()));

    let res = pool::quote_swap(&mut runtime, token_a.clone(), 1000.into()).await?;
    assert_eq!(res, Ok(454.into()));

    let res = pool::swap(&mut runtime, minter, token_a.clone(), 10.into(), 46.into()).await?;
    assert!(res.is_err()); // below minimum

    let res = pool::swap(&mut runtime, minter, token_a.clone(), 10.into(), 45.into()).await?;
    assert_eq!(res, Ok(45.into()));

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    let k2 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k2 >= k1);

    let res = pool::quote_swap(&mut runtime, token_b.clone(), 45.into()).await?;
    assert_eq!(res, Ok(9.into()));
    let res = pool::swap(&mut runtime, minter, token_b.clone(), 45.into(), 0.into()).await?;
    assert_eq!(res, Ok(9.into()));

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    let k3 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k3 >= k2);

    // use token interface to transfer shares
    let res = token_dyn::balance(&mut runtime, &pool_address, admin).await?;
    assert_eq!(res, Some(223.into()));
    let res = token_dyn::balance(&mut runtime, &pool_address, minter).await?;
    assert_eq!(res, None);

    token_dyn::transfer(&mut runtime, &pool_address, admin, minter, 23.into()).await??;

    let res = token_dyn::balance(&mut runtime, &pool_address, admin).await?;
    assert_eq!(res, Some(200.into()));
    let res = token_dyn::balance(&mut runtime, &pool_address, minter).await?;
    assert_eq!(res, Some(23.into()));

    Ok(())
}

#[tokio::test]
async fn test_amm_swap_fee() -> Result<()> {
    let mut runtime = Runtime::new(RuntimeConfig::default()).await?;

    let pool_address = ContractAddress {
        name: "pool".to_string(),
        height: 0,
        tx_index: 0,
    };

    let token_a = ContractAddress {
        name: "token-a".to_string(),
        height: 0,
        tx_index: 0,
    };

    let token_b = ContractAddress {
        name: "token-b".to_string(),
        height: 0,
        tx_index: 0,
    };

    let admin = "test_admin";
    let minter = "test_minter";
    token_a::mint(&mut runtime, minter, 1000.into()).await?;
    token_b::mint(&mut runtime, minter, 1000.into()).await?;

    token_a::transfer(&mut runtime, minter, admin, 100.into()).await??;
    token_b::transfer(&mut runtime, minter, admin, 500.into()).await??;

    pool::re_init(
        &mut runtime,
        admin,
        token_a.clone(),
        100.into(),
        token_b.clone(),
        500.into(),
        30.into(),
    )
    .await??;

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    let k1 = bal_a.unwrap() * bal_b.unwrap();

    let res = pool::quote_swap(&mut runtime, token_a.clone(), 10.into()).await?;
    assert_eq!(res, Ok(41.into()));

    let res = pool::quote_swap(&mut runtime, token_a.clone(), 100.into()).await?;
    assert_eq!(res, Ok(248.into()));

    let res = pool::quote_swap(&mut runtime, token_a.clone(), 1000.into()).await?;
    assert_eq!(res, Ok(454.into())); // fee dominated by rounding effect

    let res = pool::swap(&mut runtime, minter, token_a.clone(), 10.into(), 40.into()).await?;
    assert_eq!(res, Ok(41.into()));

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    let k2 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k2 >= k1);

    let res = pool::quote_swap(&mut runtime, token_b.clone(), 45.into()).await?;
    assert_eq!(res, Ok(9.into()));
    let res = pool::swap(&mut runtime, minter, token_b.clone(), 45.into(), 0.into()).await?;
    assert_eq!(res, Ok(9.into()));

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    let k3 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k3 >= k2);

    // use token interface to transfer shares
    let res = token_dyn::balance(&mut runtime, &pool_address, admin).await?;
    assert_eq!(res, Some(223.into()));
    let res = token_dyn::balance(&mut runtime, &pool_address, minter).await?;
    assert_eq!(res, None);

    token_dyn::transfer(&mut runtime, &pool_address, admin, minter, 23.into()).await??;

    let res = token_dyn::balance(&mut runtime, &pool_address, admin).await?;
    assert_eq!(res, Some(200.into()));
    let res = token_dyn::balance(&mut runtime, &pool_address, minter).await?;
    assert_eq!(res, Some(23.into()));

    Ok(())
}

#[tokio::test]
async fn test_amm_shares_token_interface() -> Result<()> {
    let mut runtime = Runtime::new(RuntimeConfig::default()).await?;

    let token_a = ContractAddress {
        name: "token-a".to_string(),
        height: 0,
        tx_index: 0,
    };

    let token_b = ContractAddress {
        name: "token-b".to_string(),
        height: 0,
        tx_index: 0,
    };

    let admin = "test_admin";
    let minter = "test_minter";
    let holder = "test_holder";
    token_a::mint(&mut runtime, minter, 1000.into()).await?;
    token_b::mint(&mut runtime, minter, 1000.into()).await?;

    token_a::transfer(&mut runtime, minter, admin, 100.into()).await??;
    token_b::transfer(&mut runtime, minter, admin, 500.into()).await??;

    let res = pool::re_init(
        &mut runtime,
        admin,
        token_a.clone(),
        100.into(),
        token_b.clone(),
        500.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(223.into()));

    let shares = pool::balance(&mut runtime, admin).await?;
    assert_eq!(shares, Some(223.into()));

    pool::transfer(&mut runtime, admin, holder, 40.into()).await??;

    let shares = pool::balance(&mut runtime, admin).await?;
    assert_eq!(shares, Some(183.into()));
    let shares = pool::balance(&mut runtime, holder).await?;
    assert_eq!(shares, Some(40.into()));

    // holder withdraws the tokens of the pair using the transferred shares
    let res = pool::withdraw(&mut runtime, holder, 10.into()).await?;
    assert_eq!(
        res,
        Ok(pool::WithdrawResult {
            amount_a: 4.into(),
            amount_b: 22.into(),
        })
    );

    let bal_a = token_a::balance(&mut runtime, holder).await?;
    assert_eq!(bal_a, Some(4.into()));
    let bal_b = token_b::balance(&mut runtime, holder).await?;
    assert_eq!(bal_b, Some(22.into()));

    Ok(())
}

#[tokio::test]
async fn test_amm_swap_low_slippage() -> Result<()> {
    let mut runtime = Runtime::new(RuntimeConfig::default()).await?;

    let token_a = ContractAddress {
        name: "token-a".to_string(),
        height: 0,
        tx_index: 0,
    };

    let token_b = ContractAddress {
        name: "token-b".to_string(),
        height: 0,
        tx_index: 0,
    };

    let admin = "test_admin";
    let minter = "test_minter";
    token_a::mint(&mut runtime, minter, 110000.into()).await?;
    token_b::mint(&mut runtime, minter, 510000.into()).await?;

    token_a::transfer(&mut runtime, minter, admin, 100000.into()).await??;
    token_b::transfer(&mut runtime, minter, admin, 500000.into()).await??;

    pool::re_init(
        &mut runtime,
        admin,
        token_a.clone(),
        100000.into(),
        token_b.clone(),
        500000.into(),
        30.into(),
    )
    .await??;

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    let k1 = bal_a.unwrap() * bal_b.unwrap();

    let res = pool::quote_swap(&mut runtime, token_a.clone(), 10.into()).await?;
    assert_eq!(res, Ok(44.into()));

    let res = pool::quote_swap(&mut runtime, token_a.clone(), 100.into()).await?;
    assert_eq!(res, Ok(494.into()));

    let res = pool::quote_swap(&mut runtime, token_a.clone(), 1000.into()).await?;
    assert_eq!(res, Ok(4935.into()));

    let res = pool::quote_swap(&mut runtime, token_a.clone(), 10000.into()).await?;
    assert_eq!(res, Ok(45330.into()));

    let res = pool::swap(
        &mut runtime,
        minter,
        token_a.clone(),
        10000.into(),
        45000.into(),
    )
    .await?;
    assert_eq!(res, Ok(45330.into()));

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    let k2 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k2 >= k1 + (30 * 450000).into()); // grows with fee amount

    let res = pool::quote_swap(&mut runtime, token_b.clone(), 45.into()).await?;
    assert_eq!(res, Ok(10.into()));
    let res = pool::swap(&mut runtime, minter, token_b.clone(), 45.into(), 0.into()).await?;
    assert_eq!(res, Ok(10.into()));

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    let k3 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k3 >= k2);

    Ok(())
}

#[tokio::test]
async fn test_amm_deposit_withdraw() -> Result<()> {
    let mut runtime = Runtime::new(RuntimeConfig::default()).await?;

    let token_a = ContractAddress {
        name: "token-a".to_string(),
        height: 0,
        tx_index: 0,
    };

    let token_b = ContractAddress {
        name: "token-b".to_string(),
        height: 0,
        tx_index: 0,
    };

    let admin = "test_admin";
    let minter = "test_minter";
    let holder = "test_holder";
    token_a::mint(&mut runtime, minter, 1000.into()).await?;
    token_b::mint(&mut runtime, minter, 1000.into()).await?;

    token_a::transfer(&mut runtime, minter, admin, 100.into()).await??;
    token_b::transfer(&mut runtime, minter, admin, 500.into()).await??;

    let res = pool::re_init(
        &mut runtime,
        admin,
        token_a.clone(),
        100.into(),
        token_b.clone(),
        500.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(223.into()));

    token_a::transfer(&mut runtime, minter, holder, 200.into()).await??;
    token_b::transfer(&mut runtime, minter, holder, 200.into()).await??;

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    assert_eq!(bal_a, Ok(100.into()));
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    assert_eq!(bal_b, Ok(500.into()));

    let res = pool::quote_withdraw(&mut runtime, 10.into()).await?;
    assert_eq!(
        res,
        Ok(pool::WithdrawResult {
            amount_a: 4.into(),
            amount_b: 22.into(),
        })
    );

    let res = pool::quote_deposit(&mut runtime, 10.into(), 100.into()).await?;
    assert_eq!(
        res,
        Ok(pool::DepositResult {
            lp_shares: 22.into(),
            deposit_a: 10.into(),
            deposit_b: 50.into(),
        })
    );

    let res = pool::deposit(&mut runtime, holder, 50.into(), 100.into()).await?;
    assert_eq!(
        res,
        Ok(pool::DepositResult {
            lp_shares: 44.into(),
            deposit_a: 20.into(),
            deposit_b: 99.into(),
        })
    );

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    assert_eq!(bal_a, Ok(120.into()));
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    assert_eq!(bal_b, Ok(599.into()));

    let bal = pool::balance(&mut runtime, admin).await?;
    assert_eq!(bal, Some(223.into()));
    let bal = pool::balance(&mut runtime, holder).await?;
    assert_eq!(bal, Some(44.into()));

    let res = pool::quote_withdraw(&mut runtime, 10.into()).await?;
    assert_eq!(
        res,
        Ok(pool::WithdrawResult {
            amount_a: 4.into(),
            amount_b: 22.into(),
        })
    );

    let res = pool::withdraw(&mut runtime, holder, 44.into()).await?;
    assert_eq!(
        res,
        Ok(pool::WithdrawResult {
            amount_a: 19.into(),
            amount_b: 98.into(),
        })
    );

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    assert_eq!(bal_a, Ok(101.into()));
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    assert_eq!(bal_b, Ok(501.into()));

    let bal = pool::balance(&mut runtime, admin).await?;
    assert_eq!(bal, Some(223.into()));
    let bal = pool::balance(&mut runtime, holder).await?;
    assert_eq!(bal, Some(0.into()));

    Ok(())
}

#[tokio::test]
async fn test_amm_limits() -> Result<()> {
    let mut runtime = Runtime::new(RuntimeConfig::default()).await?;

    let max_int = "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457";
    let large_value: Integer = "340_282_366_920_938_463_463_374_606_431".into(); // sqrt(MAX_INT) - 1000
    let oversized_value = large_value + 1.into();

    let token_a = ContractAddress {
        name: "token-a".to_string(),
        height: 0,
        tx_index: 0,
    };

    let token_b = ContractAddress {
        name: "token-b".to_string(),
        height: 0,
        tx_index: 0,
    };

    let admin = "test_admin";
    let minter = "test_minter";
    token_a::mint(&mut runtime, minter, max_int.into()).await?;
    token_b::mint(&mut runtime, minter, max_int.into()).await?;

    token_a::transfer(&mut runtime, minter, admin, 1000.into()).await??;
    token_b::transfer(&mut runtime, minter, admin, 1000.into()).await??;

    let res = pool::re_init(
        &mut runtime,
        admin,
        token_a.clone(),
        1000.into(),
        token_b.clone(),
        1000.into(),
        0.into(),
    )
    .await?;
    assert_eq!(res, Ok(1000.into()));

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    let k1 = bal_a.unwrap() * bal_b.unwrap();

    let res = pool::quote_swap(&mut runtime, token_a.clone(), large_value).await?;
    assert_eq!(res, Ok(999.into()));
    let res = pool::quote_swap(&mut runtime, token_a.clone(), oversized_value).await?;
    assert!(res.is_err());

    let res = pool::swap(
        &mut runtime,
        minter,
        token_a.clone(),
        large_value,
        900.into(),
    )
    .await?;
    assert_eq!(res, Ok(999.into()));

    let res = pool::quote_swap(&mut runtime, token_a.clone(), 1.into()).await?;
    assert!(res.is_err());
    let res = pool::swap(&mut runtime, minter, token_a.clone(), 1.into(), 0.into()).await?;
    assert!(res.is_err());

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    let k2 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k2 >= k1);

    let res = pool::quote_swap(&mut runtime, token_b.clone(), large_value).await?;
    assert_eq!(res, Ok("340_282_366_920_938_463_463_374_607_429".into()));
    let res = pool::swap(&mut runtime, minter, token_b.clone(), large_value, 0.into()).await?;
    assert_eq!(res, Ok("340_282_366_920_938_463_463_374_607_429".into()));

    let res = pool::quote_swap(&mut runtime, token_b.clone(), 1000.into()).await?;
    assert!(res.is_err());
    let res = pool::swap(&mut runtime, minter, token_b.clone(), 1000.into(), 0.into()).await?;
    assert!(res.is_err());

    let bal_a = pool::token_balance(&mut runtime, token_a.clone()).await?;
    let bal_b = pool::token_balance(&mut runtime, token_b.clone()).await?;
    let k3 = bal_a.unwrap() * bal_b.unwrap();
    assert!(k3 >= k2);

    Ok(())
}
