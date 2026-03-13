use testlib::*;

interface!(name = "counter", path = "../../test-contracts/counter/wit");

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_counter_init_is_zero() -> Result<()> {
    let admin = runtime.identity().await?;
    let contract = runtime.publish(&admin, "counter").await?;

    let value = counter::get(runtime, &contract).await?;
    assert_eq!(value, 0);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_counter_increment() -> Result<()> {
    let admin = runtime.identity().await?;
    let contract = runtime.publish(&admin, "counter").await?;

    counter::increment(runtime, &contract, &admin).await?;
    let value = counter::get(runtime, &contract).await?;
    assert_eq!(value, 1);

    counter::increment(runtime, &contract, &admin).await?;
    counter::increment(runtime, &contract, &admin).await?;
    let value = counter::get(runtime, &contract).await?;
    assert_eq!(value, 3);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_counter_multiple_signers() -> Result<()> {
    let admin = runtime.identity().await?;
    let user = runtime.identity().await?;
    let contract = runtime.publish(&admin, "counter").await?;

    counter::increment(runtime, &contract, &admin).await?;
    counter::increment(runtime, &contract, &user).await?;
    counter::increment(runtime, &contract, &admin).await?;

    let value = counter::get(runtime, &contract).await?;
    assert_eq!(value, 3);

    Ok(())
}
