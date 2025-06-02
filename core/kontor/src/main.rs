use anyhow::Result;
use clap::Parser;
use kontor::api::Env;
use kontor::reactor::events::EventSubscriber;
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
    let bitcoin = bitcoin_client::Client::new_from_config(&config)?;
    let cancel_token = CancellationToken::new();
    let mut handles = vec![];
    handles.push(stopper::run(cancel_token.clone())?);
    let filename = "state.db";
    let reader = database::Reader::new(config.clone(), filename).await?;
    let writer = database::Writer::new(&config, filename).await?;
    let (_, event_rx) = mpsc::channel(10);
    let event_subscriber = EventSubscriber::new();
    handles.push(event_subscriber.run(cancel_token.clone(), event_rx));
    handles.push(
        api::run(Env {
            config: config.clone(),
            cancel_token: cancel_token.clone(),
            reader: reader.clone(),
            event_subscriber,
            bitcoin: bitcoin.clone(),
        })
        .await?,
    );
    let (reactor_tx, reactor_rx) = mpsc::channel(10);
    handles.push(
        bitcoin_follower::run(
            config.starting_block_height,
            Some(config.zmq_address),
            cancel_token.clone(),
            reader.clone(),
            bitcoin,
            Some,
            reactor_tx,
        )
        .await?,
    );
    handles.push(reactor::run(
        config.starting_block_height - 1,
        cancel_token,
        reader,
        writer,
        reactor_rx,
    ));
    for handle in handles {
        let _ = handle.await;
    }
    info!("Exited");
    Ok(())
}
