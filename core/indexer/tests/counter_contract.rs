use testlib::*;

interface!(name = "counter", path = "../../test-contracts/counter/wit");

#[testlib::test(contracts_dir = "../../test-contracts", shared)]
async fn test_counter_batching() -> Result<()> {
    let admin = runtime.identity().await?;
    let user = runtime.identity().await?;
    let contract = runtime.publish(&admin, "counter").await?;

    let before = counter::get(runtime, &contract).await?;

    // Unordered: separate transactions, one consensus round
    let mut submit = runtime.submit();
    submit.push(&admin, counter::increment_call(&contract));
    submit.push(&admin, counter::increment_call(&contract));
    submit.push(&admin, counter::increment_call(&contract));
    submit.execute().await?;

    let value = counter::get(runtime, &contract).await?;
    assert_eq!(value, before + 3);

    // Unordered with multiple signers
    let before = value;
    let mut submit = runtime.submit();
    submit.push(&admin, counter::increment_call(&contract));
    submit.push(&user, counter::increment_call(&contract));
    submit.push(&admin, counter::increment_call(&contract));
    submit.execute().await?;

    let value = counter::get(runtime, &contract).await?;
    assert_eq!(value, before + 3);

    // Ordered: single transaction, guaranteed execution order
    let before = value;
    let mut ops = Ops::new(&admin);
    ops.push(counter::increment_call(&contract));
    ops.push(counter::increment_call(&contract));
    ops.push(counter::increment_call(&contract));
    let mut submit = runtime.submit();
    submit.add(ops);
    let results = submit.execute().await?;
    assert_eq!(results.groups.len(), 1);
    assert_eq!(results.groups[0].len(), 3);

    let value = counter::get(runtime, &contract).await?;
    assert_eq!(value, before + 3);

    // Ordered with BLS aggregate: multiple signers in one transaction
    let before = value;
    let mut ops = AggregateOps::new();
    ops.push(&admin, counter::increment_call(&contract));
    ops.push(&user, counter::increment_call(&contract));
    ops.push(&admin, counter::increment_call(&contract));
    let mut submit = runtime.submit();
    submit.add(ops);
    let results = submit.execute().await?;
    assert_eq!(results.groups.len(), 1);
    assert_eq!(results.groups[0].len(), 3);

    let value = counter::get(runtime, &contract).await?;
    assert_eq!(value, before + 3);

    Ok(())
}
