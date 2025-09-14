use testlib::*;

import!(
    name = "amm",
    height = 0,
    tx_index = 0,
    path = "../contracts/amm/wit",
);

// For testing, we'll simulate two tokens by using the same token contract
// In a real scenario, these would be separate token contracts
import!(
    name = "token",
    height = 0,
    tx_index = 1,
    path = "../contracts/token/wit",
);

#[tokio::test]
async fn test_amm_basic_flow() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    
    let user = "test_user";
    let admin = "test_admin";
    
    // Create token pair - in real scenario these would be different contracts
    // For testing, we use different height/index to differentiate them
    let token_pair = TokenPair { 
        token_a: ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 1,
        },
        token_b: ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 2,  // Different index to simulate second token
        }
    };
    
    // Mint tokens to user (using same token contract for simplicity)
    token::mint(&runtime, user, 100_000.into()).await?;
    
    // Since we're using the same token contract for both A and B in testing,
    // we need to be careful with approvals and balances
    let amm_address_str = "amm_0_0";
    token::approve(&runtime, user, amm_address_str, 100_000.into()).await??;
    
    // Test pool creation
    let lp_tokens = amm::create(&runtime, user, token_pair.clone(), 1_000.into(), 2_000.into(), 30.into(), 50.into()).await??;
    assert!(lp_tokens > 0.into());
    
    // Check pool values
    let vals = amm::values(&runtime, token_pair.clone()).await?.unwrap();
    assert_eq!(vals.a, 1_000.into());
    assert_eq!(vals.b, 2_000.into());
    assert_eq!(vals.lp, lp_tokens);
    
    // Check fees
    let fees = amm::fees(&runtime, token_pair.clone()).await?.unwrap();
    assert_eq!(fees.lp_fee_bps, 30.into());
    assert_eq!(fees.admin_fee_pct, 50.into());
    
    // Test deposit
    let additional_lp = amm::deposit(&runtime, user, token_pair.clone(), 500.into(), 1_000.into(), 0.into()).await??;
    assert!(additional_lp > 0.into());
    
    // Test withdrawal
    let withdraw_amount = additional_lp / 2.into();
    let withdraw_result = amm::withdraw(&runtime, user, token_pair.clone(), withdraw_amount, 0.into(), 0.into()).await??;
    assert!(withdraw_result.a_out > 0.into());
    assert!(withdraw_result.b_out > 0.into());
    
    // Test swaps
    let swap_out = amm::swap_a(&runtime, user, token_pair.clone(), 100.into(), 1.into()).await??;
    assert!(swap_out > 0.into());
    
    let swap_out = amm::swap_b(&runtime, user, token_pair.clone(), 100.into(), 1.into()).await??;
    assert!(swap_out > 0.into());
    
    Ok(())
}

#[tokio::test] 
async fn test_amm_validation() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    
    let user = "test_user";
    
    // Test with same token (should fail)
    let same_token_pair = TokenPair { 
        token_a: ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 1,
        },
        token_b: ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 1,  // Same as token_a
        }
    };
    
    token::mint(&runtime, user, 10_000.into()).await?;
    token::approve(&runtime, user, "amm_0_0", 10_000.into()).await??;
    
    let err = amm::create(&runtime, user, same_token_pair, 1_000.into(), 1_000.into(), 30.into(), 50.into()).await?;
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("must not be equal"));
    
    // Test with reversed pair (should fail)
    let reversed_pair = TokenPair { 
        token_a: ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 2,  // Higher index first
        },
        token_b: ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 1,  // Lower index second
        }
    };
    
    let err = amm::create(&runtime, user, reversed_pair, 1_000.into(), 1_000.into(), 30.into(), 50.into()).await?;
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("must be ordered"));
    
    Ok(())
}

#[tokio::test]
async fn test_amm_admin_functions() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    
    let admin = "test_admin";  // First signer becomes admin
    let user = "test_user";
    
    let token_pair = TokenPair { 
        token_a: ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 1,
        },
        token_b: ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 2,
        }
    };
    
    // Admin creates pool
    token::mint(&runtime, admin, 50_000.into()).await?;
    token::approve(&runtime, admin, "amm_0_0", 50_000.into()).await??;
    
    let _ = amm::create(&runtime, admin, token_pair.clone(), 10_000.into(), 10_000.into(), 30.into(), 50.into()).await??;
    
    // Generate some fees through swaps
    let _ = amm::swap_a(&runtime, admin, token_pair.clone(), 1_000.into(), 1.into()).await??;
    
    // Check admin
    let stored_admin = amm::admin(&runtime).await?;
    assert_eq!(stored_admin, admin);
    
    // Check admin fees accumulated
    let admin_fees = amm::admin_fee_value(&runtime, token_pair.clone()).await?.unwrap();
    assert!(admin_fees > 0.into());
    
    // Admin can withdraw fees
    let withdrawn = amm::admin_withdraw_fees(&runtime, admin, token_pair.clone(), 0.into()).await??;
    assert!(withdrawn > 0.into());
    
    // Admin can set fees
    amm::admin_set_fees(&runtime, admin, token_pair.clone(), 10.into(), 25.into()).await??;
    let fees = amm::fees(&runtime, token_pair.clone()).await?.unwrap();
    assert_eq!(fees.lp_fee_bps, 10.into());
    assert_eq!(fees.admin_fee_pct, 25.into());
    
    // Non-admin cannot withdraw fees
    token::mint(&runtime, user, 1_000.into()).await?;
    let err = amm::admin_withdraw_fees(&runtime, user, token_pair.clone(), 0.into()).await?;
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("Not authorized"));
    
    Ok(())
}

#[tokio::test]
async fn test_amm_lp_tokens() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    
    let alice = "alice";
    let bob = "bob";
    
    let token_pair = TokenPair { 
        token_a: ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 1,
        },
        token_b: ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 2,
        }
    };
    
    // Alice creates pool
    token::mint(&runtime, alice, 20_000.into()).await?;
    token::approve(&runtime, alice, "amm_0_0", 20_000.into()).await??;
    
    let lp_tokens = amm::create(&runtime, alice, token_pair.clone(), 5_000.into(), 5_000.into(), 30.into(), 50.into()).await??;
    
    // Check Alice's LP balance
    let alice_lp = amm::lp_balance(&runtime, token_pair.clone(), alice).await?.unwrap();
    assert_eq!(alice_lp, lp_tokens);
    
    // Transfer half to Bob
    let transfer_amount = lp_tokens / 2.into();
    amm::transfer_lp(&runtime, alice, token_pair.clone(), bob, transfer_amount).await??;
    
    // Check balances after transfer
    let alice_lp_after = amm::lp_balance(&runtime, token_pair.clone(), alice).await?.unwrap();
    let bob_lp = amm::lp_balance(&runtime, token_pair.clone(), bob).await?.unwrap();
    
    assert_eq!(alice_lp_after, lp_tokens - transfer_amount);
    assert_eq!(bob_lp, transfer_amount);
    
    // Check total supply remains the same
    let total_supply = amm::lp_total_supply(&runtime, token_pair).await?.unwrap();
    assert_eq!(total_supply, lp_tokens);
    
    Ok(())
}

// Re-export types that the import macro generates
use amm::TokenPair;
use indexer::runtime::wit::kontor::built_in::foreign::ContractAddress;