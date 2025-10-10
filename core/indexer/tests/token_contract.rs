use testlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../contracts/token/wit",
);

#[runtime(contracts_dir = "../../contracts")]
async fn test_token_contract() -> Result<()> {
    runtime.publish("token").await?;

    let minter = "test_minter";
    let holder = "test_holder";
    token::mint(&mut runtime, minter, 900.into()).await?;
    token::mint(&mut runtime, minter, 100.into()).await?;

    let result = token::balance(&mut runtime, minter).await?;
    assert_eq!(result, Some(1000.into()));

    let result = token::transfer(&mut runtime, holder, minter, 123.into()).await?;
    assert_eq!(
        result,
        Err(Error::Message("insufficient funds".to_string()))
    );

    token::transfer(&mut runtime, minter, holder, 40.into()).await??;
    token::transfer(&mut runtime, minter, holder, 2.into()).await??;

    let result = token::balance(&mut runtime, holder).await?;
    assert_eq!(result, Some(42.into()));

    let result = token::balance(&mut runtime, minter).await?;
    assert_eq!(result, Some(958.into()));

    let result = token::balance(&mut runtime, "foo").await?;
    assert_eq!(result, None);

    let result = token::balance_log10(&mut runtime, minter).await??;
    assert_eq!(result, Some("2.981_365_509_078_544_415".into()));

    Ok(())
}

#[runtime(contracts_dir = "../../contracts")]
async fn test_token_contract_large_numbers() -> Result<()> {
    runtime.publish("token").await?;

    let minter = "test_minter";
    let holder = "test_holder";
    token::mint(
        &mut runtime,
        minter,
        "100_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000".into(),
    )
    .await?;

    token::mint_checked(&mut runtime, minter, 100.into()).await??;

    let result = token::balance(&mut runtime, minter).await?;
    assert_eq!(
        result,
        Some(
            "100_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_100"
                .into()
        )
    );

    let max_int = "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457";
    assert!(
        token::mint_checked(&mut runtime, minter, max_int.into())
            .await?
            .is_err()
    );

    token::transfer(
        &mut runtime,
        minter,
        holder,
        "1_000_000_000_000_000_000_000_000_000_000".into(),
    )
    .await??;

    let result = token::balance(&mut runtime, holder).await?;
    assert_eq!(
        result,
        Some("1_000_000_000_000_000_000_000_000_000_000".into())
    );

    let result = token::balance(&mut runtime, minter).await?;
    assert_eq!(
        result,
        Some(
            "99_999_999_999_999_999_999_999_999_999_000_000_000_000_000_000_000_000_000_100".into()
        )
    );

    let result = token::balance_log10(&mut runtime, minter).await??;
    assert_eq!(result, Some("59.000_000_000_000_000_000".into()));

    let result = token::balance_log10(&mut runtime, holder).await??;
    assert_eq!(result, Some("30.000_000_000_000_000_000".into()));

    Ok(())
}
