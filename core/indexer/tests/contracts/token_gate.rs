//! Lite test for the token contract's dev-mint network gate: the flag defaults
//! on and the core-context `set_dev_mint` toggles it. Also validates that the
//! rebuilt `token.wasm.br` actually carries the new methods (the indexer
//! deploys the committed binary, not source).

use anyhow::{Result, anyhow};
use indexer::runtime::token::api as token;
use indexer::test_utils::test_runtime;
use testlib::Signer;

fn core() -> Signer {
    Signer::Core(Box::new(Signer::Nobody))
}

#[tokio::test]
async fn dev_mint_defaults_on_and_core_can_disable() -> Result<()> {
    let (mut rt, _dir, _name) = test_runtime().await?;

    assert!(
        token::dev_mint_enabled(&mut rt).await?,
        "public dev mint is on by default (signet/testnet/regtest)"
    );

    token::set_dev_mint(&mut rt, &core(), false)
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;
    assert!(
        !token::dev_mint_enabled(&mut rt).await?,
        "set_dev_mint(false) disables the public mint (mainnet genesis path)"
    );

    token::set_dev_mint(&mut rt, &core(), true)
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;
    assert!(
        token::dev_mint_enabled(&mut rt).await?,
        "re-enabling works"
    );
    Ok(())
}
