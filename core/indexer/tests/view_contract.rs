use futures_util::future::join_all;
use indexer::{api, runtime};
use indexer_types::ViewResult;
use testlib::*;
use tokio::time::Instant;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../../../native-contracts/token/wit",
);

#[testlib::test(contracts_dir = "../../../test-contracts", mode = "regtest", logging)]
async fn test_view_contract() -> Result<()> {
    let minter = runtime.identity().await?;

    token::mint(runtime, &minter, 900.into()).await??;

    let calls = (0..100).map(|i| {
        let minter = minter.clone();
        async move {
            let result = api::client::Client::new("http://localhost:9333/api")?
                .view(
                    &runtime::token::address(),
                    &format!("balance(\"{}\")", &*minter),
                )
                .await?;
            tracing::info!("{}: Balance: {:?}", i, result);
            Ok::<ViewResult, anyhow::Error>(result)
        }
    });

    let start = Instant::now();
    let results = join_all(calls).await;
    let duration = start.elapsed();
    for result in results {
        let result = result?;
        assert!(matches!(result, ViewResult::Ok { value } if value.starts_with("some")));
    }
    tracing::info!("Duration: {:?}", duration);
    Ok(())
}
