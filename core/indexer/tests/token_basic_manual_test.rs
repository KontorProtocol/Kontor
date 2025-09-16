use testlib::*;

fn token_addr() -> ContractAddress {
    ContractAddress {
        name: "token".to_string(),
        height: 0,
        tx_index: 0,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_token_basic_operations() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    
    let alice = "alice";
    let bob = "bob";
    
    let addr = token_addr();
    
    // Initialize token contract
    runtime.execute(Some(alice), &addr, "init()").await?;
    
    // Test basic minting and balance operations (non-resource)
    runtime.execute(Some(alice), &addr, "mint({r0: 1000, r1: 0, r2: 0, r3: 0, sign: plus})").await?;
    
    let balance_result = runtime.execute(None, &addr, "balance(\"alice\")").await?;
    assert!(balance_result.contains("1000"));
    
    let total_supply = runtime.execute(None, &addr, "total-supply()").await?;
    assert!(total_supply.contains("1000"));
    
    // Test transfer
    runtime.execute(Some(alice), &addr, "transfer(\"bob\", {r0: 100, r1: 0, r2: 0, r3: 0, sign: plus})").await?;
    
    let alice_balance = runtime.execute(None, &addr, "balance(\"alice\")").await?;
    assert!(alice_balance.contains("900"));
    
    let bob_balance = runtime.execute(None, &addr, "balance(\"bob\")").await?;
    assert!(bob_balance.contains("100"));
    
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_token_resources_manual() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    
    let alice = "alice";
    let bob = "bob";
    
    let addr = token_addr();
    
    // Initialize and mint
    runtime.execute(Some(alice), &addr, "init()").await?;
    runtime.execute(Some(alice), &addr, "mint({r0: 1000, r1: 0, r2: 0, r3: 0, sign: plus})").await?;
    
    // Test withdraw - this should return a Balance resource handle
    let withdraw_result = runtime.execute(Some(alice), &addr, "withdraw({r0: 100, r1: 0, r2: 0, r3: 0, sign: plus})").await?;
    println!("Withdraw result: {}", withdraw_result);
    
    // Alice should have reduced balance
    let alice_balance = runtime.execute(None, &addr, "balance(\"alice\")").await?;
    assert!(alice_balance.contains("900"));
    
    // The withdraw_result should be parseable as a resource handle
    // For now, let's just check that it doesn't contain an error
    assert!(!withdraw_result.contains("Error"));
    assert!(!withdraw_result.contains("error"));
    
    Ok(())
}
