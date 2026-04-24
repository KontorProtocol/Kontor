use std::panic;
use std::sync::Arc;
use std::thread::available_parallelism;

use crate::api::Env;
use anyhow::Result;
use clap::Parser;
use indexer::database::queries::select_recent_blocks;
use indexer::event::EventSubscriber;
use indexer::{api, block, built_info, reactor, runtime};
use indexer::{bitcoin_client, bitcoin_follower, config::Config, database, logging, stopper};
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    logging::setup();
    info!("Kontor");
    info!(
        version = built_info::PKG_VERSION,
        target = built_info::TARGET
    );
    let config = Config::try_parse()?;
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
    let reader = database::Reader::new(&config.data_dir, filename).await?;
    let writer = database::Writer::new(&config.data_dir, filename).await?;
    let available = Arc::new(RwLock::new(false));
    let (event_tx, event_rx) = mpsc::channel(10);
    let event_subscriber = EventSubscriber::new();
    let (simulate_tx, simulate_rx) = mpsc::channel(available_parallelism()?.into());
    let (fees_tx, fees_rx) = tokio::sync::watch::channel(indexer_types::Fees::floor(1));
    handles.push(event_subscriber.run(cancel_token.clone(), event_rx));
    handles.push(
        api::run(Env {
            config: config.clone(),
            cancel_token: cancel_token.clone(),
            available: available.clone(),
            reader: reader.clone(),
            event_subscriber: event_subscriber.clone(),
            bitcoin: bitcoin.clone(),
            runtime_pool: runtime::pool::new(config.data_dir.clone(), filename.to_string()).await?,
            simulate_tx,
            fees_rx,
        })
        .await?,
    );

    let known_hashes = {
        let conn = reader.connection().await?;
        let recent_blocks = select_recent_blocks(&conn, 50).await?;
        recent_blocks
            .iter()
            .map(|b| (b.height as u64, b.hash))
            .collect::<Vec<_>>()
    };

    let (block_rx, mempool_rx, replay_tx, follower_handle) = bitcoin_follower::run(
        bitcoin.clone(),
        block::filter_map,
        cancel_token.clone(),
        config.starting_block_height,
        known_hashes,
        config.zmq_address.clone(),
    )
    .await;
    handles.push(follower_handle);

    let (private_key, consensus_enabled) = if let Some(key_hex) = &config.consensus_private_key {
        (
            indexer::consensus::signing::private_key_from_hex(key_hex)?,
            true,
        )
    } else {
        info!("No consensus private key provided, running as sync-only follower");
        (
            indexer::consensus::signing::generate_random_private_key(),
            false,
        )
    };
    let engine_config = reactor::engine::EngineConfig {
        private_key,
        listen_addr: config.consensus_listen_addr.clone(),
        persistent_peers: config.consensus_peers.clone(),
        data_dir: config.data_dir.clone(),
        consensus_enabled,
    };

    let (ready_tx, ready_rx) = oneshot::channel();
    handles.push(reactor::run(
        config.starting_block_height,
        cancel_token.clone(),
        writer,
        block_rx,
        mempool_rx,
        Some(ready_tx),
        Some(event_tx),
        Some(simulate_rx),
        engine_config,
        bitcoin.clone(),
        Some(replay_tx),
        load_genesis_validators(&config)?,
        None,
        config.consensus_propose_timeout_ms,
        Some(fees_tx),
    ));
    ready_rx.await?;
    {
        let mut available = available.write().await;
        *available = true;
    }

    info!("Initialized");
    for handle in handles {
        let _ = handle.await;
    }
    info!("Exited");
    Ok(())
}

fn load_genesis_validators(config: &Config) -> Result<Vec<runtime::GenesisValidator>> {
    let genesis = indexer::config::GenesisConfig::load(&config.genesis_file)?;
    genesis
        .validators
        .into_iter()
        .map(|v| {
            let ed25519_bytes = hex::decode(&v.ed25519_pubkey)
                .map_err(|e| anyhow::anyhow!("invalid ed25519 hex: {e}"))?;
            let stake = runtime::Decimal::from(v.stake.as_str());
            Ok(runtime::GenesisValidator {
                x_only_pubkey: v.x_only_pubkey,
                stake,
                ed25519_pubkey: ed25519_bytes,
            })
        })
        .collect()
}
