use std::panic;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread::available_parallelism;

use crate::api::Env;
use anyhow::Result;
use clap::{Parser, Subcommand};
use indexer::database::queries::select_recent_blocks;
use indexer::event::EventSubscriber;
use indexer::info::{compute_info_core, run_info_publisher};
use indexer::keygen::{self, KeygenArgs};
use indexer::{api, block, built_info, reactor, reg_tester, runtime};
use indexer::{bitcoin_client, bitcoin_follower, config::Config, database, logging, stopper};
use indexer_types::{Inst, InstKind};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[derive(Parser)]
#[command(
    name = "kontor",
    author = "Unspendable Labs",
    version = "0.1.0",
    about = "Kontor is a Bitcoin Layer 2"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the indexer daemon.
    Run(Box<Config>),
    /// Generate validator keys deterministically from a master seed.
    Keygen(KeygenArgs),
    /// Stand up a single-node regtest devnet (bitcoind + one validator,
    /// auto-miner, pre-funded dev account). Intended for local SDK
    /// development and CI; prints `KONTOR_REGTEST_*` markers on stdout.
    Regtest,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run(config) => run_daemon(*config).await,
        Command::Keygen(args) => keygen::run(args),
        Command::Regtest => run_regtest().await,
    }
}

/// Deterministic dev-account seed for `kontor regtest`. Pinning it gives
/// the devnet a stable, pre-funded key that SDKs and CI can rely on
/// without parsing it out of the markers — though it's printed anyway.
const REGTEST_DEV_SEED: [u8; 64] = [0x42u8; 64];

/// Stand up a single-node regtest devnet and run it until Ctrl-C. Reuses
/// the test harness's `RegTesterCluster` bringup so the binary and the
/// Rust test suite share one code path. Spawns the running binary
/// (`current_exe`) as the validator node.
async fn run_regtest() -> Result<()> {
    logging::setup_with_format(logging::Format::Plain);

    /// Pre-created identity pool size. Each identity is independently
    /// funded (1M sats) and pre-issued native tokens, so SDK tests can
    /// pay gas + transfer/sell without further setup. Bump this when
    /// adding a regtest file that needs its own slot.
    const IDENTITY_COUNT: usize = 8;

    let kontor_bin = std::env::current_exe()?;
    let mut cluster = reg_tester::RegTesterCluster::setup_with(
        1,
        1,
        1,
        IDENTITY_COUNT,
        0,
        Some(REGTEST_DEV_SEED),
        &kontor_bin,
    )
    .await?;

    // Issue native tokens to the dev (admin) account too — the dev key
    // remains useful for ad-hoc admin ops (e.g. `fundAddress` from SDK
    // tests), so giving it issuance keeps that path working. The N
    // pre-created identities already received Issuance + BLS
    // registration inside `setup_with`.
    let mut reg_tester = cluster.reg_tester();
    reg_tester
        .instruction(
            &mut cluster.identity,
            Inst {
                gas_limit: 10_000,
                kind: InstKind::Issuance,
            },
        )
        .await?;

    // Drain the registered identity pool. Each identity holds 1M sats
    // (one funding UTXO) plus a fresh chunk of native tokens — ready
    // for SDK tests to claim one per test slot.
    let mut identities = Vec::with_capacity(IDENTITY_COUNT);
    for _ in 0..IDENTITY_COUNT {
        identities.push(cluster.pool.pop_registered().await?);
    }

    let api_port = cluster.node_configs[0].api_port;
    let dev = &cluster.identity;
    // One JSON line, consumed by `@kontor/sdk/regtest`'s `startRegtest()`.
    // A single line is parsed atomically — it can't be matched while still
    // half-streamed the way five independent marker lines could.
    let info = serde_json::json!({
        "apiUrl": format!("http://localhost:{api_port}/api"),
        "bitcoinRpc": cluster.bitcoin_rpc_endpoint(),
        "devPrivateKey": hex::encode(dev.keypair.secret_bytes()),
        "devPublicKey": dev.x_only_public_key().to_string(),
        "devAddress": dev.address.to_string(),
        "identities": identities
            .iter()
            .map(|id| {
                let (outpoint, txout) = &id.next_funding_utxo;
                serde_json::json!({
                    "privateKey": hex::encode(id.keypair.secret_bytes()),
                    "publicKey": id.x_only_public_key().to_string(),
                    "address": id.address.to_string(),
                    "fundingUtxo": {
                        "txid": outpoint.txid.to_string(),
                        "vout": outpoint.vout,
                        "value": txout.value.to_sat(),
                        "scriptPubKey": hex::encode(txout.script_pubkey.as_bytes()),
                    },
                })
            })
            .collect::<Vec<_>>(),
    });
    println!("KONTOR_REGTEST_INFO {info}");
    println!("kontor regtest devnet running — Ctrl-C to stop");

    // Catch SIGTERM as well as SIGINT: the SDK's `startRegtest()` wrapper
    // stops the devnet with a plain `kill` (SIGTERM). Either signal must
    // reach `teardown` so bitcoind and the node child aren't orphaned.
    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        r = tokio::signal::ctrl_c() => r?,
        _ = sigterm.recv() => {}
    }
    info!("Shutting down regtest devnet");
    cluster.teardown().await?;
    Ok(())
}

async fn run_daemon(config: Config) -> Result<()> {
    logging::setup_with_format(config.log_format);

    // Install the Prometheus recorder before any worker spawns. `metrics::*`
    // macro calls before this silently no-op. Spawn the upkeep tick so
    // histogram buckets don't accumulate stale data.
    let prom_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("install Prometheus recorder");
    {
        let h = prom_handle.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tick.tick().await;
                h.run_upkeep();
            }
        });
    }

    info!("Kontor");
    info!(
        version = built_info::PKG_VERSION,
        target = built_info::TARGET
    );
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
    let reactor_ready = Arc::new(AtomicBool::new(false));
    let (consensus_listen_addr_tx, consensus_listen_addr_rx) = tokio::sync::watch::channel(None);
    let (event_tx, event_rx) = mpsc::channel(10);
    let event_subscriber = EventSubscriber::new();
    // Seed the info snapshot from current DB state; the reactor republishes
    // it on every block/batch/rollback. Shared with Env for long-polling.
    let initial_info = {
        let conn = reader.connection().await?;
        compute_info_core(&conn).await?
    };
    let (info_tx, info_rx) = tokio::sync::watch::channel(initial_info);
    // Recomputes `InfoCore` off the `Event` broadcast and republishes it
    // for long-poll `GET /api/` readers — no reactor involvement.
    handles.push(run_info_publisher(
        cancel_token.clone(),
        event_subscriber.subscribe(),
        reader.clone(),
        info_tx,
    ));
    let (simulate_tx, simulate_rx) = mpsc::channel(available_parallelism()?.into());
    let (fees_tx, fees_rx) = tokio::sync::watch::channel(indexer_types::Fees::floor(1));
    handles.push(event_subscriber.run(cancel_token.clone(), event_rx));
    handles.push(
        api::run(
            Env {
                config: config.clone(),
                cancel_token: cancel_token.clone(),
                reactor_ready: reactor_ready.clone(),
                consensus_listen_addr: consensus_listen_addr_rx.clone(),
                reader: reader.clone(),
                event_subscriber: event_subscriber.clone(),
                bitcoin: bitcoin.clone(),
                runtime_pool: runtime::pool::new(
                    config.data_dir.clone(),
                    filename.to_string(),
                    config.network,
                    config.view_gas_limit,
                )
                .await?,
                simulate_tx,
                fees_rx,
                info_rx,
            },
            prom_handle.clone(),
        )
        .await?,
    );

    let known_hashes = {
        let conn = reader.connection().await?;
        let recent_blocks = select_recent_blocks(&conn, 50).await?;
        recent_blocks
            .iter()
            .map(|b| (b.height, b.hash))
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

    let private_key = indexer::consensus::signing::resolve_consensus_private_key(
        config.consensus_mode,
        config.consensus_private_key.as_deref(),
        config.consensus_private_key_file.as_deref(),
    )?;
    let consensus_enabled =
        config.consensus_mode == indexer::consensus::signing::ConsensusMode::Validator;
    if !consensus_enabled {
        info!("Consensus mode: follower — sync-only, will not sign");
    }
    let engine_config = reactor::engine::EngineConfig {
        private_key,
        listen_addr: config.consensus_listen_addr.clone(),
        persistent_peers: config.consensus_peers.clone(),
        data_dir: config.data_dir.clone(),
        consensus_enabled,
        discovery_enabled: true,
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
        consensus_listen_addr_tx,
        config.network,
        reactor::PruneConfig {
            enabled: config.prune,
            retain_blocks: config.prune_retain_blocks,
        },
    ));
    ready_rx.await?;
    reactor_ready.store(true, std::sync::atomic::Ordering::Relaxed);
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
