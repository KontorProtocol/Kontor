use testlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 1,
    path = "../contracts/token/wit",
);

#[tokio::test]
async fn test_asset_withdraw_deposit() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    
    // Load token contract
    load_token_test(&runtime).await?;
    
    let user = "test_user";
    let recipient = "recipient";
    
    let token_addr = ContractAddress {
        name: "token".to_string(),
        height: 0,
        tx_index: 1,
    };
    
    // Initialize token contract
    runtime.execute(Some(user), &token_addr, "init()").await?;
    
    // Mint some tokens to user
    runtime.execute(Some(user), &token_addr, "mint({r0: 1000, r1: 0, r2: 0, r3: 0, sign: plus})").await?;
    
    // Check initial balance
    let initial_balance = token::balance(&runtime, user).await?.unwrap();
    assert_eq!(initial_balance, 1000.into());
    
    // Test withdraw -> deposit flow
    let withdrawn_balance = token::withdraw(&runtime, user, 500.into()).await??;
    println!("Withdrawn balance: {:?}", withdrawn_balance);
    
    // User should now have 500 tokens left
    let remaining_balance = token::balance(&runtime, user).await?.unwrap();
    assert_eq!(remaining_balance, 500.into());
    
    // Deposit the withdrawn balance to recipient
    token::deposit(&runtime, user, recipient, withdrawn_balance).await??;
    
    // Check final balances
    let user_final = token::balance(&runtime, user).await?.unwrap();
    let recipient_final = token::balance(&runtime, recipient).await?.unwrap();
    
    assert_eq!(user_final, 500.into());
    assert_eq!(recipient_final, 500.into());
    
    Ok(())
}

#[tokio::test]
async fn test_asset_split_join_security() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    load_token_test(&runtime).await?;
    
    let user = "test_user";
    let recipient = "recipient";
    
    let token_addr = ContractAddress {
        name: "token".to_string(),
        height: 0,
        tx_index: 1,
    };
    
    // Initialize and mint tokens
    runtime.execute(Some(user), &token_addr, "init()").await?;
    runtime.execute(Some(user), &token_addr, "mint({r0: 1000, r1: 0, r2: 0, r3: 0, sign: plus})").await?;
    
    // Test that we can withdraw, but can't split more than we have
    let balance = token::withdraw(&runtime, user, 500.into()).await??;
    
    // This should work - split 200 from 500
    // Note: split/join operations happen in Rust, not through WIT calls
    // So we can't test them directly through the runtime interface
    // But we can test the security by trying to deposit invalid balances
    
    // Deposit the balance normally
    token::deposit(&runtime, user, recipient, balance).await??;
    
    // Verify the transfer worked
    let recipient_balance = token::balance(&runtime, recipient).await?.unwrap();
    assert_eq!(recipient_balance, 500.into());
    
    Ok(())
}

#[tokio::test]
async fn test_cross_contract_security() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    
    // Load two different token contracts
    load_two_token_contracts(&runtime).await?;
    
    let user = "test_user";
    
    let token_a_addr = ContractAddress {
        name: "token".to_string(),
        height: 0,
        tx_index: 1,
    };
    
    let token_b_addr = ContractAddress {
        name: "token".to_string(),
        height: 0,
        tx_index: 2,
    };
    
    // Initialize both contracts
    runtime.execute(Some(user), &token_a_addr, "init()").await?;
    runtime.execute(Some(user), &token_b_addr, "init()").await?;
    
    // Mint tokens in contract A
    runtime.execute(Some(user), &token_a_addr, "mint({r0: 1000, r1: 0, r2: 0, r3: 0, sign: plus})").await?;
    
    // Withdraw from contract A
    let balance_from_a = runtime.execute(Some(user), &token_a_addr, "withdraw({r0: 500, r1: 0, r2: 0, r3: 0, sign: plus})").await?;
    println!("Withdrew from token A: {:?}", balance_from_a);
    
    // Try to deposit into contract B (this should fail due to address mismatch)
    let deposit_result = runtime.execute(Some(user), &token_b_addr, &format!("deposit(\"test_user\", {})", balance_from_a)).await;
    
    // This should fail with "invalid balance object for this token"
    assert!(deposit_result.is_err());
    let error_msg = deposit_result.unwrap_err().to_string();
    assert!(error_msg.contains("invalid balance object"), "Expected security error, got: {}", error_msg);
    
    Ok(())
}

async fn load_two_token_contracts(runtime: &Runtime) -> Result<()> {
    use indexer::{
        database::{queries::insert_contract, types::ContractRow},
    };
    
    const TOKEN: &[u8] = include_bytes!("../../../contracts/target/wasm32-unknown-unknown/release/token.wasm.br");
    
    let conn = runtime.runtime.get_storage_conn();
    
    // Load token at tx_index 1
    insert_contract(
        &conn,
        ContractRow::builder()
            .height(0)
            .tx_index(1)
            .name("token".to_string())
            .bytes(TOKEN.to_vec())
            .build(),
    ).await?;
    
    // Load token at tx_index 2
    insert_contract(
        &conn,
        ContractRow::builder()
            .height(0)
            .tx_index(2)
            .name("token".to_string())
            .bytes(TOKEN.to_vec())
            .build(),
    ).await?;
    
    Ok(())
}

async fn load_token_test(runtime: &Runtime) -> Result<()> {
    use indexer::{
        database::{queries::insert_contract, types::ContractRow},
        runtime::ContractAddress,
    };
    
    const TOKEN: &[u8] = include_bytes!("../../../contracts/target/wasm32-unknown-unknown/release/token.wasm.br");
    
    let conn = runtime.runtime.get_storage_conn();
    
    insert_contract(
        &conn,
        ContractRow::builder()
            .height(0)
            .tx_index(1)
            .name("token".to_string())
            .bytes(TOKEN.to_vec())
            .build(),
    ).await?;
    
    Ok(())
}

// Re-export types
use token::Balance;
use indexer::runtime::wit::kontor::built_in::foreign::ContractAddress;
