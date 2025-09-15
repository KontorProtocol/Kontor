use testlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../contracts/token/wit",
);

#[tokio::test]
async fn test_withdraw_deposit_flow() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    
    let alice = "alice";
    let bob = "bob";
    
    // Initialize token contract
    token::init(&runtime, alice).await?;
    
    // Mint tokens to alice
    token::mint(&runtime, alice, 1000.into()).await?;
    
    // Withdraw creates a balance resource
    let balance = token::withdraw(&runtime, alice, 100.into()).await??;
    
    // Alice's ledger balance is reduced
    let alice_balance = token::balance(&runtime, alice).await?;
    assert_eq!(alice_balance, Some(900.into()));
    
    // Deposit the balance to bob
    token::deposit(&runtime, alice, bob.to_string(), balance).await??;
    
    // Bob now has the tokens
    let bob_balance = token::balance(&runtime, bob).await?;
    assert_eq!(bob_balance, Some(100.into()));
    
    Ok(())
}

#[tokio::test]
async fn test_split_balance() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    
    let alice = "alice";
    let bob = "bob";
    let charlie = "charlie";
    
    // Initialize and mint
    token::init(&runtime, alice).await?;
    token::mint(&runtime, alice, 1000.into()).await?;
    
    // Withdraw a balance
    let balance = token::withdraw(&runtime, alice, 100.into()).await??;
    
    // Split the balance 60/40
    let (balance1, balance2_opt) = token::split(&runtime, alice, balance, 60.into()).await??;
    
    let balance2 = balance2_opt.expect("Should have remainder");
    
    // Deposit the split balances to different recipients
    token::deposit(&runtime, alice, bob.to_string(), balance1).await??;
    token::deposit(&runtime, alice, charlie.to_string(), balance2).await??;
    
    // Verify the split worked correctly
    assert_eq!(token::balance(&runtime, bob).await?, Some(60.into()));
    assert_eq!(token::balance(&runtime, charlie).await?, Some(40.into()));
    assert_eq!(token::balance(&runtime, alice).await?, Some(900.into()));
    
    Ok(())
}

#[tokio::test]
async fn test_merge_balances() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    
    let alice = "alice";
    let bob = "bob";
    
    // Initialize and mint
    token::init(&runtime, alice).await?;
    token::mint(&runtime, alice, 1000.into()).await?;
    
    // Withdraw two balances
    let balance1 = token::withdraw(&runtime, alice, 60.into()).await??;
    let balance2 = token::withdraw(&runtime, alice, 40.into()).await??;
    
    // Merge them
    let merged = token::merge(&runtime, alice, balance1, balance2).await??;
    
    // Deposit the merged balance
    token::deposit(&runtime, alice, bob.to_string(), merged).await??;
    
    assert_eq!(token::balance(&runtime, bob).await?, Some(100.into()));
    assert_eq!(token::balance(&runtime, alice).await?, Some(900.into()));
    
    Ok(())
}

#[tokio::test]
async fn test_withdraw_insufficient_funds() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    
    let alice = "alice";
    
    // Initialize and mint
    token::init(&runtime, alice).await?;
    token::mint(&runtime, alice, 100.into()).await?;
    
    // Try to withdraw more than available
    let err = token::withdraw(&runtime, alice, 200.into()).await?;
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("insufficient funds"));
    
    // Balance unchanged
    assert_eq!(token::balance(&runtime, alice).await?, Some(100.into()));
    
    Ok(())
}

// This test demonstrates the compile-time linearity guarantee.
// If Balance implemented Copy or Clone, this wouldn't compile.
#[tokio::test]
async fn test_balance_moves_not_copies() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    
    let alice = "alice";
    let bob = "bob";
    
    // Initialize and mint
    token::init(&runtime, alice).await?;
    token::mint(&runtime, alice, 1000.into()).await?;
    
    // Withdraw a balance
    let balance = token::withdraw(&runtime, alice, 100.into()).await??;
    
    // This moves balance, it cannot be used again
    token::deposit(&runtime, alice, bob.to_string(), balance).await??;
    
    // If you uncommented the next line, it would be a compile error because
    // balance was moved in the previous line:
    // token::deposit(&runtime, alice, "charlie", balance).await??; // COMPILE ERROR: use of moved value
    
    assert_eq!(token::balance(&runtime, bob).await?, Some(100.into()));
    
    Ok(())
}