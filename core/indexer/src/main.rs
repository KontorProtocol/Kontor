use std::panic;

use crate::api::Env;
use anyhow::Result;
use bitcoin::Network;
use clap::Parser;
use indexer::config::RegtestConfig;
use indexer::database::queries::delete_unprocessed_blocks;
use indexer::reactor::results::ResultSubscriber;
use indexer::runtime::Runtime;
use indexer::{api, block, reactor};
use indexer::{bitcoin_client, bitcoin_follower, config::Config, database, logging, stopper};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    logging::setup();
    info!("Kontor");
    let mut config = Config::try_parse()?;
    if config.network == Network::Regtest && config.use_local_regtest {
        let regtest_config = RegtestConfig::default();
        config.bitcoin_rpc_url = regtest_config.bitcoin_rpc_url;
        config.bitcoin_rpc_user = regtest_config.bitcoin_rpc_user;
        config.bitcoin_rpc_password = regtest_config.bitcoin_rpc_password;
    }
    info!("{:#?}", config);
    let bitcoin = bitcoin_client::Client::new_from_config(&config)?;
    let cancel_token = CancellationToken::new();
    let panic_token = cancel_token.clone();
    panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("Unknown panic");
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".to_string());
        error!(target: "panic", "Panic at {}: {}", location, message);
        panic_token.cancel();
    }));
    let mut handles = vec![];
    handles.push(stopper::run(cancel_token.clone())?);
    let filename = "state.db";
    let reader = database::Reader::new(config.clone(), filename).await?;
    let writer = database::Writer::new(&config, filename).await?;
    delete_unprocessed_blocks(&writer.connection()).await?;

    let (event_tx, event_rx) = mpsc::channel(10);
    let (ctrl, ctrl_rx) = bitcoin_follower::ctrl::CtrlChannel::create();
    let (init_tx, init_rx) = oneshot::channel();
    handles.push(reactor::run(
        config.starting_block_height,
        cancel_token.clone(),
        reader.clone(),
        writer,
        ctrl,
        Some(init_tx),
        Some(event_tx),
    ));
    init_rx.await?;
    let (init_tx, init_rx) = oneshot::channel();
    handles.push(
        bitcoin_follower::run(
            config.zmq_address.clone(),
            cancel_token.clone(),
            bitcoin.clone(),
            block::filter_map,
            ctrl_rx,
            Some(init_tx),
        )
        .await?,
    );
    init_rx.await?;

    let result_subscriber = ResultSubscriber::default();
    handles.push(result_subscriber.run(cancel_token.clone(), event_rx));
    handles.push(
        api::run(Env {
            config: config.clone(),
            cancel_token: cancel_token.clone(),
            reader: reader.clone(),
            result_subscriber,
            bitcoin: bitcoin.clone(),
            runtime: Runtime::new_read_only(&reader).await?,
        })
        .await?,
    );

    for handle in handles {
        let _ = handle.await;
    }
    info!("Exited");
    Ok(())
}
