use anyhow::Result;
use clap::Parser;
use kontor::api::Context;
use kontor::{api, reactor};
use kontor::{bitcoin_client, bitcoin_follower, config::Config, database, logging, stopper};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    logging::setup();
    info!("Kontor");
    let config = Config::try_parse()?;
    info!("{:#?}", config);
    let bitcoin = bitcoin_client::Client::new_from_config(config.clone())?;
    let cancel_token = CancellationToken::new();
    let mut handles = vec![];
    handles.push(stopper::run(cancel_token.clone()));
    let db_path = config.database_dir.join("state.db");
    let reader = database::Reader::new(&db_path).await?;
    let writer = database::Writer::new(&db_path).await?;
    handles.push(
        api::run(Context {
            config: config.clone(),
            cancel_token: cancel_token.clone(),
            reader: reader.clone(),
        })
        .await?,
    );
    let (reactor_tx, reactor_rx) = mpsc::channel(10);
    handles.push(
        bitcoin_follower::run(
            config,
            cancel_token.clone(),
            reader.clone(),
            bitcoin,
            |t| t,
            reactor_tx,
        )
        .await?,
    );
    handles.push(reactor::run(cancel_token, reader, writer, reactor_rx));
    for handle in handles {
        let _ = handle.await;
    }
    info!("Exited");
    Ok(())
}
