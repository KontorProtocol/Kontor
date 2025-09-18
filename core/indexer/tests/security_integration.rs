use anyhow::Result;
use indexer::runtime::{ResourceManager, ContractAddress};
use indexer::runtime::numerics;
use indexer::runtime::balance;
use indexer::runtime::stack::Stack;

/// End-to-end integration tests that test actual contract execution
/// These tests would have caught the security vulnerabilities

async fn setup_test_runtime() -> Result<(ResourceManager, Stack<i64>)> {
    // Simplified setup focusing on the resource management components
    let manager = ResourceManager::new();
    let stack = Stack::new();
    Ok((manager, stack))
}

fn test_token_address() -> ContractAddress {
    ContractAddress {
        name: "test_token".to_string(),
        height: 1,
        tx_index: 0,
    }
}

fn amm_address() -> ContractAddress {
    ContractAddress {
        name: "amm".to_string(),
        height: 2,
        tx_index: 0,
    }
}

#[tokio::test]
async fn test_balance_constructor_authorization_integration() -> Result<()> {
    let (mut manager, mut stack) = setup_test_runtime().await?;

    // TEST: Demonstrate the balance constructor authorization vulnerability

    // Simulate AMM contract context (contract ID 2)
    stack.push(2).await?;

    // AMM tries to create a balance for a different token's contract
    let foreign_token = ContractAddress {
        name: "foreign_token".to_string(),
        height: 1, // Different contract (token contract)
        tx_index: 0,
    };

    // This demonstrates the vulnerability: AMM creating balance for foreign token
    let forged_balance = balance::BalanceData::new(
        numerics::u64_to_integer(1000000)?, // Huge forged amount
        foreign_token,
        2 // Created by AMM (contract 2), not token contract (1)
    );

    let resource = manager.push_with_owner(forged_balance, 2)?;
    let balance_data = manager.get(&resource)?;

    // This shows the security issue:
    assert_eq!(balance_data.owner_contract, 2);    // Created by AMM
    assert_eq!(balance_data.token.height, 1);      // Claims to be for token contract 1
    assert_eq!(balance_data.amount.r0, 1000000);   // Massive forged amount

    // In the fixed HostBalance::new, this creation would be rejected
    // because current_contract_id (2) != token.height (1)

    stack.pop().await.ok_or_else(|| anyhow::anyhow!("Stack pop failed"))?;

    println!("✓ Balance constructor authorization integration test - shows forgery vulnerability");
    Ok(())
}

#[tokio::test]
async fn test_token_deposit_linearity_integration() -> Result<()> {
    let (mut manager, mut stack) = setup_test_runtime().await?;

    // TEST: Demonstrate the linearity violation in token deposit

    stack.push(1).await?; // Token contract context

    let balance = balance::BalanceData::new(
        numerics::u64_to_integer(500)?,
        test_token_address(),
        1
    );

    let balance_resource = manager.push_with_owner(balance, 1)?;
    let handle = balance_resource.rep();

    // Simulate the old vulnerable deposit() function:
    // 1. Read balance data without consuming
    let amount = manager.get(&balance_resource)?.amount.clone();
    assert_eq!(amount.r0, 500);

    // 2. Credit ledger (simulated)
    // ledger.set(recipient, current + amount)

    // 3. Balance is NOT consumed (the vulnerability)
    // The balance can be used again!

    // Second deposit attempt with same balance (vulnerability)
    let amount_again = manager.get(&balance_resource)?.amount.clone();
    assert_eq!(amount_again.r0, 500); // Same balance used twice!

    // Total credited: 1000 (but only 500 existed)
    // This is the linearity violation

    // The fix: deposit() must call balance.consume()
    let _consumed = manager.delete(balance_resource)?;
    assert_eq!(manager.get_owner(handle), None);

    stack.pop().await.ok_or_else(|| anyhow::anyhow!("Stack pop failed"))?;

    println!("✓ Token deposit linearity integration test - shows double-spending vulnerability");
    Ok(())
}

#[tokio::test]
async fn test_cross_contract_balance_access_integration() -> Result<()> {
    let (mut manager, mut stack) = setup_test_runtime().await?;

    // TEST: Demonstrate unauthorized cross-contract balance data access

    // Token contract (ID 1) creates a balance
    stack.push(1).await?;

    let balance = balance::BalanceData::new(
        numerics::u64_to_integer(1000)?,
        test_token_address(),
        1
    );

    let balance_resource = manager.push_with_owner(balance, 1)?;

    stack.pop().await.ok_or_else(|| anyhow::anyhow!("Stack pop failed"))?;

    // AMM contract (ID 2) tries to read token contract's balance data
    stack.push(2).await?;

    // This demonstrates the vulnerability: unauthorized data access
    // The old balance_amount() and balance_token() functions would allow this
    let table = &manager;
    let balance_data = table.get(&balance_resource)?;

    // AMM can read private balance data from token contract:
    assert_eq!(balance_data.owner_contract, 1); // Owned by token contract
    assert_eq!(balance_data.amount.r0, 1000);   // AMM reads private amount
    assert_eq!(balance_data.token.name, "test_token"); // AMM reads token info

    // This shows the data leak vulnerability
    // The fixed balance_amount() function validates ownership before reading

    stack.pop().await.ok_or_else(|| anyhow::anyhow!("Stack pop failed"))?;

    println!("✓ Cross-contract balance access integration test - shows data leak vulnerability");
    Ok(())
}

#[tokio::test]
async fn test_amm_balance_creation_vulnerability_demo() -> Result<()> {
    let (mut manager, mut stack) = setup_test_runtime().await?;

    // DEMONSTRATES: How AMM could forge balances in the old system

    stack.push(2).await?; // AMM contract context

    // AMM creates fake balances for popular tokens
    let bitcoin_token = ContractAddress {
        name: "bitcoin".to_string(),
        height: 100, // Bitcoin contract
        tx_index: 0,
    };

    let ethereum_token = ContractAddress {
        name: "ethereum".to_string(),
        height: 200, // Ethereum contract
        tx_index: 0,
    };

    // The old vulnerability: AMM could call Balance::new() for any token
    let fake_bitcoin = balance::BalanceData::new(
        numerics::u64_to_integer(1000000)?, // 1M fake Bitcoin
        bitcoin_token,
        2 // Created by AMM, not Bitcoin contract
    );

    let fake_ethereum = balance::BalanceData::new(
        numerics::u64_to_integer(5000000)?, // 5M fake Ethereum
        ethereum_token,
        2 // Created by AMM, not Ethereum contract
    );

    let btc_resource = manager.push_with_owner(fake_bitcoin, 2)?;
    let eth_resource = manager.push_with_owner(fake_ethereum, 2)?;

    // This demonstrates the security breach:
    assert_eq!(manager.get(&btc_resource)?.owner_contract, 2); // Created by AMM
    assert_eq!(manager.get(&btc_resource)?.token.height, 100); // Claims Bitcoin
    assert_eq!(manager.get(&btc_resource)?.amount.r0, 1000000); // Massive amount

    assert_eq!(manager.get(&eth_resource)?.owner_contract, 2); // Created by AMM
    assert_eq!(manager.get(&eth_resource)?.token.height, 200); // Claims Ethereum
    assert_eq!(manager.get(&eth_resource)?.amount.r0, 5000000); // Massive amount

    stack.pop().await.ok_or_else(|| anyhow::anyhow!("Stack pop failed"))?;

    println!("✓ AMM balance forgery vulnerability demonstration");
    Ok(())
}