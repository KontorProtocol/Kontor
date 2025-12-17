//! API load tests for Kontor
//!
//! These tests stress-test the API layer with many requests.
//! Run with `--release` for meaningful performance data.
//!
//! The CI configuration ensures these always run optimized.

use testlib::*;
use tracing::info;

interface!(name = "token", path = "../../test-contracts/token/wit");

/// API load test: make many view calls to measure API throughput
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest", logging)]
#[ignore = "Load tests run in CI"]
async fn test_api_view_calls_load() -> Result<()> {
    let num_requests = 10_000; // Total API requests

    info!("Starting API load test: {} view requests", num_requests);

    // Setup: create some data to query
    let minter = runtime.identity().await?;
    let token = runtime.publish(&minter, "token").await?;

    // Create some state
    token::mint(runtime, &token, &minter, "1000000".into()).await??;

    let holder = runtime.identity().await?;
    for i in 0..10 {
        token::transfer(runtime, &token, &minter, &holder, ((i + 1) * 100).into()).await??;
    }

    info!("Setup complete. Starting view requests...");
    let start = std::time::Instant::now();

    // Make many view calls (read-only operations)
    let mut successful_requests = 0;
    for req_num in 0..num_requests {
        if req_num % 50 == 0 {
            info!("Progress: {}/{} view requests", req_num, num_requests);
        }

        // Alternate between querying different accounts
        let result = if req_num % 2 == 0 {
            token::balance(runtime, &token, &minter).await
        } else {
            token::balance(runtime, &token, &holder).await
        };

        if result.is_ok() {
            successful_requests += 1;
        }
    }

    let elapsed = start.elapsed();

    info!("API load test completed!");
    info!("  Total requests: {}", num_requests);
    info!("  Successful requests: {}", successful_requests);
    info!("  Total time: {:?}", elapsed);
    info!(
        "  Requests/sec: {:.2}",
        num_requests as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}
