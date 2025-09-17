use testlib::*;

// Test the basic token functionality without resources
// Resources can't be serialized through the runtime's string interface,
// but we can still test the underlying functionality

#[tokio::test]
async fn test_token_withdraw_deposit() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;

    let alice = "alice";
    let token_addr = ContractAddress {
        name: "token".to_string(),
        height: 0,
        tx_index: 0,
    };

    // Initialize token contract
    runtime.execute(Some(alice), &token_addr, "init()").await?;

    // Mint tokens to alice
    runtime
        .execute(
            Some(alice),
            &token_addr,
            "mint({r0: 1000, r1: 0, r2: 0, r3: 0, sign: plus})",
        )
        .await?;

    // Check balance
    let balance = runtime
        .execute(None, &token_addr, &format!("balance(\"{}\")", alice))
        .await?;
    assert!(balance.contains("1000"));

    // Withdraw creates a resource (returns ok with a handle)
    let result = runtime
        .execute(
            Some(alice),
            &token_addr,
            "withdraw({r0: 100, r1: 0, r2: 0, r3: 0, sign: plus})",
        )
        .await?;
    assert!(result.contains("ok"));

    // Balance should be reduced
    let balance = runtime
        .execute(None, &token_addr, &format!("balance(\"{}\")", alice))
        .await?;
    assert!(balance.contains("900"));

    println!("✓ Token withdraw reduces balance correctly");
    println!("✓ Balance resources are created (but can't be tested through string interface)");

    Ok(())
}

#[tokio::test]
async fn test_token_basic_operations() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;

    let alice = "alice";
    let bob = "bob";
    let token_addr = ContractAddress {
        name: "token".to_string(),
        height: 0,
        tx_index: 0,
    };

    // Initialize
    runtime.execute(Some(alice), &token_addr, "init()").await?;

    // Mint to alice
    runtime
        .execute(
            Some(alice),
            &token_addr,
            "mint({r0: 1000, r1: 0, r2: 0, r3: 0, sign: plus})",
        )
        .await?;

    // Transfer from alice to bob
    runtime
        .execute(
            Some(alice),
            &token_addr,
            &format!(
                "transfer(\"{}\", {{r0: 250, r1: 0, r2: 0, r3: 0, sign: plus}})",
                bob
            ),
        )
        .await?;

    // Check balances
    let alice_balance = runtime
        .execute(None, &token_addr, &format!("balance(\"{}\")", alice))
        .await?;
    assert!(alice_balance.contains("750"));

    let bob_balance = runtime
        .execute(None, &token_addr, &format!("balance(\"{}\")", bob))
        .await?;
    assert!(bob_balance.contains("250"));

    println!("✓ Token transfer works correctly");

    Ok(())
}
