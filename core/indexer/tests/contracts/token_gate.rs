//! Lite tests for the token contract's network-conditioned dev mint: on for
//! test networks, off at mainnet genesis. Also validates the rebuilt
//! `token.wasm.br` (the indexer deploys the committed binary, not source).

use anyhow::Result;
use indexer::runtime::token::api as token;
use indexer::test_utils::{test_runtime, test_runtime_with_network};

#[tokio::test]
async fn dev_mint_on_for_test_networks() -> Result<()> {
    // Default test runtime is regtest → faucet on.
    let (mut rt, _dir, _name) = test_runtime().await?;
    assert!(
        token::dev_mint_enabled(&mut rt).await?,
        "public dev mint is on for signet/testnet/regtest"
    );
    Ok(())
}

#[tokio::test]
async fn dev_mint_disabled_on_mainnet() -> Result<()> {
    // `init` runs under mainnet, so the public dev mint self-disables via the
    // `network()` built-in — no genesis wiring needed.
    let (mut rt, _dir, _name) = test_runtime_with_network(bitcoin::Network::Bitcoin).await?;
    assert!(
        !token::dev_mint_enabled(&mut rt).await?,
        "public mint is off at mainnet genesis"
    );
    Ok(())
}
