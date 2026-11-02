//! Lite tests for the token contract's network-conditioned dev mint: on for
//! test networks, off at mainnet genesis. Also validates the rebuilt
//! `token.wasm.br` (the indexer deploys the committed binary, not source).

use anyhow::Result;
use indexer::test_utils::OwnedTestRuntime;

#[tokio::test]
async fn dev_mint_on_for_test_networks() -> Result<()> {
    // Default test runtime is regtest → faucet on.
    let (rt, _dir, _name) = OwnedTestRuntime::new(100_000).await?;
    assert!(
        rt.dev_mint_enabled().await?,
        "public dev mint is on for signet/testnet/regtest"
    );
    Ok(())
}

#[tokio::test]
async fn dev_mint_disabled_on_mainnet() -> Result<()> {
    // `init` runs under mainnet, so the public dev mint self-disables via the
    // `network()` built-in — no genesis wiring needed.
    let (rt, _dir, _name) =
        OwnedTestRuntime::new_with_network(100_000, bitcoin::Network::Bitcoin).await?;
    assert!(
        !rt.dev_mint_enabled().await?,
        "public mint is off at mainnet genesis"
    );
    Ok(())
}
