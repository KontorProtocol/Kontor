//! Load tests for Kontor
//!
//! These tests are designed to stress-test the system.
//! Run with `--release` for meaningful performance data.
//!
//! The CI configuration ensures these always run optimized.

use testlib::*;
use tracing::info;

interface!(name = "token", path = "../../../test-contracts/token/wit");

/// Simple load test: process many blocks with many contract calls
/// Each contract call creates a transaction and mines a block automatically in regtest
#[testlib::test(contracts_dir = "../../../test-contracts", mode = "regtest", logging)]
#[ignore = "Load tests run in CI"]
async fn test_token_contract_load() -> Result<()> {
    let num_operations = 500; // Total contract calls to execute

    info!("Starting load test: {} contract operations", num_operations);

    // Setup: create a token contract and some users
    let minter = runtime.identity().await?;
    let token = runtime.publish(&minter, "token").await?;

    // Mint a large supply
    token::mint(runtime, &token, &minter, "1000000000".into()).await??;

    // Create a pool of users
    let mut users = vec![];
    for _ in 0..10 {
        users.push(runtime.identity().await?);
    }

    info!("Setup complete. Starting contract operations...");
    let start = std::time::Instant::now();

    // Execute many contract operations
    // Each operation will create a transaction and mine a block
    for i in 0..num_operations {
        if i % 50 == 0 {
            info!("Progress: {}/{} operations", i, num_operations);
        }

        // Mix of operations: transfers and balance checks
        let user_idx = i % users.len();
        let user = &users[user_idx];

        if i % 3 == 0 {
            // Transfer operation (creates a transaction and block)
            let amount = (i % 100 + 1) as u64;
            let _ = token::transfer(runtime, &token, &minter, user, amount.into()).await;
        } else {
            // Balance check operation (read-only, no block)
            let _ = token::balance(runtime, &token, user).await;
        }
    }

    let elapsed = start.elapsed();

    info!("Load test completed!");
    info!("  Total operations: {}", num_operations);
    info!("  Total time: {:?}", elapsed);
    info!(
        "  Operations/sec: {:.2}",
        num_operations as f64 / elapsed.as_secs_f64()
    );

    // Estimate blocks created (transfers create blocks, balance checks don't)
    let num_transfers = num_operations / 3;
    info!("  Estimated blocks: {}", num_transfers);
    info!(
        "  Blocks/sec: {:.2}",
        num_transfers as f64 / elapsed.as_secs_f64()
    );

    // Verify final state
    let minter_balance = token::balance(runtime, &token, &minter).await?;
    info!("  Final minter balance: {:?}", minter_balance);

    Ok(())
}
