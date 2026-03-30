use testlib::*;

interface!(name = "counter", path = "../../test-contracts/counter/wit");

#[testlib::test(contracts_dir = "../../test-contracts", shared)]
async fn test_counter_increment() -> Result<()> {
    let admin = runtime.identity().await?;
    let contract = runtime.publish(&admin, "counter").await?;

    let before = counter::get(runtime, &contract).await?;

    let mut batch = runtime.batch();
    batch.push(&admin, counter::increment_call(&contract));
    batch.push(&admin, counter::increment_call(&contract));
    batch.push(&admin, counter::increment_call(&contract));
    batch.execute().await?;

    let value = counter::get(runtime, &contract).await?;
    assert_eq!(value, before + 3);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", shared)]
async fn test_counter_multiple_signers() -> Result<()> {
    let admin = runtime.identity().await?;
    let user = runtime.identity().await?;
    let contract = runtime.publish(&admin, "counter").await?;

    let before = counter::get(runtime, &contract).await?;

    let mut batch = runtime.batch();
    batch.push(&admin, counter::increment_call(&contract));
    batch.push(&user, counter::increment_call(&contract));
    batch.push(&admin, counter::increment_call(&contract));
    batch.execute().await?;

    let value = counter::get(runtime, &contract).await?;
    assert_eq!(value, before + 3);

    Ok(())
}
