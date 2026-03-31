use testlib::*;

interface!(name = "counter", path = "../../test-contracts/counter/wit");

#[testlib::test(contracts_dir = "../../test-contracts", shared)]
async fn test_counter_batching() -> Result<()> {
    let admin = runtime.identity().await?;
    let user = runtime.identity().await?;
    let contract = runtime.publish(&admin, "counter").await?;

    let before = counter::get(runtime, &contract).await?;

    // Unordered batch: separate transactions, one consensus round
    let mut batch = runtime.batch();
    batch.push(&admin, counter::increment_call(&contract));
    batch.push(&admin, counter::increment_call(&contract));
    batch.push(&admin, counter::increment_call(&contract));
    batch.execute().await?;

    let value = counter::get(runtime, &contract).await?;
    assert_eq!(value, before + 3);

    // Unordered batch with multiple signers
    let before = value;
    let mut batch = runtime.batch();
    batch.push(&admin, counter::increment_call(&contract));
    batch.push(&user, counter::increment_call(&contract));
    batch.push(&admin, counter::increment_call(&contract));
    batch.execute().await?;

    let value = counter::get(runtime, &contract).await?;
    assert_eq!(value, before + 3);

    // Ordered batch: single transaction, guaranteed execution order
    let before = value;
    let mut batch = runtime.batch();
    batch.push(&admin, counter::increment_call(&contract));
    batch.push(&admin, counter::increment_call(&contract));
    batch.push(&admin, counter::increment_call(&contract));
    let results = batch.execute_ordered().await?;
    assert_eq!(results.raw.len(), 3);

    let value = counter::get(runtime, &contract).await?;
    assert_eq!(value, before + 3);

    // Ordered batch with BLS aggregate: multiple signers in one transaction
    let before = value;
    let mut batch = runtime.batch();
    batch.push(&admin, counter::increment_call(&contract));
    batch.push(&user, counter::increment_call(&contract));
    batch.push(&admin, counter::increment_call(&contract));
    let results = batch.execute_ordered().await?;
    assert_eq!(results.raw.len(), 3);

    let value = counter::get(runtime, &contract).await?;
    assert_eq!(value, before + 3);

    Ok(())
}
