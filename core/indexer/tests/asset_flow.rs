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
