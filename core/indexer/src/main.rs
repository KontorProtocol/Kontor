use std::panic;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread::available_parallelism;

use crate::api::Env;
use anyhow::Result;
use clap::{Parser, Subcommand};
use futures_util::future;
use indexer::database::queries::select_recent_blocks;
use indexer::event::EventSubscriber;
use indexer::info::{compute_info_core, run_info_publisher};
use indexer::keygen::{self, KeygenArgs};
use indexer::{api, block, built_info, reactor, reg_tester, runtime};
use indexer::{bitcoin_client, bitcoin_follower, config::Config, database, logging, stopper};
use indexer_types::{Inst, InstKind};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

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
    // Log the resolved config. On mainnet, redact the inline consensus key
    // (`CONSENSUS_PRIVATE_KEY`) so it never hits the logs; on dev networks
    // (regtest/signet/testnet) it's left in for debugging convenience.
    if config.network == bitcoin::Network::Bitcoin && config.consensus_private_key.is_some() {
        let mut redacted = config.clone();
        redacted.consensus_private_key = Some("<redacted>".to_string());
        info!("{:#?}", redacted);
    } else {
        info!("{:#?}", config);
    }
    let bitcoin = bitcoin_client::Client::new_from_config(&config)?;
    let cancel_token = CancellationToken::new();
    // A panic anywhere is fatal, including in tasks nobody joins, so the
    // supervisor below has to hear about it. The hook can't be async and can't
    // return a value, so it reports down a channel; the first message is the
    // cause. It deliberately does *not* cancel — cancelling behind the
    // supervisor's back is what made a crash indistinguishable from a stop.
    let (panic_tx, mut panic_rx) = mpsc::unbounded_channel();
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
        let _ = panic_tx.send(format!("panic at {location}: {message}"));
    }));
    // The long-lived subsystems, named for the exit message. None of them is
    // optional: the first one to exit takes the node with it.
    let mut subsystems: Vec<(&'static str, JoinHandle<Result<()>>)> = Vec::new();
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
    subsystems.push((
        "info publisher",
        run_info_publisher(
            cancel_token.clone(),
            event_subscriber.subscribe(),
            reader.clone(),
            info_tx,
        ),
    ));
    let (simulate_tx, simulate_rx) = mpsc::channel(available_parallelism()?.into());
    let (fees_tx, fees_rx) = tokio::sync::watch::channel(indexer_types::Fees::floor(1));
    subsystems.push((
        "event subscriber",
        event_subscriber.run(cancel_token.clone(), event_rx),
    ));
    subsystems.push((
        "api",
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
    ));

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
    subsystems.push(("bitcoin follower", follower_handle));

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
    subsystems.push((
        "reactor",
        reactor::run(
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
        ),
    ));

    // Arm readiness off the critical path. Waiting on `ready_rx` here instead
    // would mean a reactor that dies during startup reports "channel closed" —
    // the sender dropping — while its actual error sits unread in a task nobody
    // joined. Left to the supervisor, the reactor's own error is what surfaces.
    tokio::spawn({
        let reactor_ready = reactor_ready.clone();
        async move {
            if ready_rx.await.is_ok() {
                reactor_ready.store(true, std::sync::atomic::Ordering::Relaxed);
                info!("Initialized");
            }
        }
    });

    // Why we stopped is decided by which of these arrives first — nothing else
    // in the process cancels, so the first subsystem to exit before a stop was
    // asked for is, by construction, the cause.
    let stop = tokio::select! {
        () = stopper::signal_received() => Stop::Signal,
        Some(cause) = panic_rx.recv() => Stop::Fatal(anyhow::anyhow!("{cause}")),
        fatal = first_exit(&mut subsystems) => fatal,
    };

    info!("Initiating shutdown");
    cancel_token.cancel();
    drain(subsystems).await;
    exit_status(stop)
}

/// Wait out the remaining subsystems after the stop decision has been made.
///
/// Whatever they report here is the wake of that decision, not its cause — one
/// real failure closes channels and unwinds tasks behind it, and a cancelled
/// `retry` hands back the error it was retrying. Worth logging, never worth
/// reporting as the reason the process stopped.
async fn drain(subsystems: Vec<(&'static str, JoinHandle<Result<()>>)>) {
    for (name, handle) in subsystems {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!("{name} failed while shutting down: {e:#}"),
            Err(e) => warn!("{name} did not shut down cleanly: {e}"),
        }
    }
}

/// Turn "why we stopped" into a process exit status.
///
/// A signal exits 0; a subsystem that died exits non-zero, so an orchestrator
/// sees a failure instead of `Completed` and backs off rather than restarting
/// into the same fault forever.
fn exit_status(stop: Stop) -> Result<()> {
    match stop {
        Stop::Signal => {
            info!("Exited");
            Ok(())
        }
        Stop::Fatal(cause) => {
            error!("Exited: {cause:#}");
            Err(cause)
        }
    }
}

/// Why the node stopped. `Signal` exits 0 and `Fatal` exits non-zero, which is
/// the only thing a deployment has to tell "asked to stop" from "died".
enum Stop {
    Signal,
    Fatal(anyhow::Error),
}

/// Resolves when the first subsystem exits, removing it from `subsystems` so
/// the caller can still drain the rest.
///
/// Every exit here is fatal, clean or not: this only runs before anything has
/// asked the node to stop, and a subsystem that returns `Ok(())` unbidden has
/// stopped doing its job just as surely as one that returned an error.
async fn first_exit(subsystems: &mut Vec<(&'static str, JoinHandle<Result<()>>)>) -> Stop {
    let (result, index, _) = future::select_all(subsystems.iter_mut().map(|(_, h)| h)).await;
    let (name, _) = subsystems.remove(index);
    Stop::Fatal(match result {
        Ok(Err(e)) => e.context(format!("{name} failed")),
        Err(e) => anyhow::anyhow!("{name} task panicked: {e}"),
        Ok(Ok(())) => anyhow::anyhow!("{name} exited without a shutdown request"),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn subsystem(result: Result<()>) -> JoinHandle<Result<()>> {
        tokio::spawn(async move { result })
    }

    /// A signal-driven stop has nothing to report, so the daemon exits 0 and the
    /// orchestrator treats it as intentional. Reporting failure on every
    /// shutdown would make the signal as useless as reporting success on every
    /// one.
    #[test]
    fn signal_exits_zero() {
        assert!(exit_status(Stop::Signal).is_ok());
    }

    /// A dead subsystem exits non-zero, with its own error intact — an exit
    /// status alone tells an operator to look, the cause tells them where.
    #[tokio::test]
    async fn subsystem_failure_carries_the_cause() {
        let mut subsystems = vec![(
            "reactor",
            subsystem(Err(anyhow::anyhow!(
                "Unexpected block height 316333, expected 316206"
            ))),
        )];
        let err = exit_status(first_exit(&mut subsystems).await)
            .expect_err("a dead subsystem must fail the process");
        let msg = format!("{err:#}");
        assert!(msg.contains("reactor failed"), "{msg}");
        assert!(msg.contains("316333"), "the cause must reach the operator");
    }

    /// A subsystem that returns `Ok(())` unbidden has stopped doing its job just
    /// as surely as one that errored. Discarding task results is what let this
    /// pass for a clean shutdown.
    #[tokio::test]
    async fn clean_exit_without_a_stop_request_is_fatal() {
        let mut subsystems = vec![("bitcoin follower", subsystem(Ok(())))];
        let err = exit_status(first_exit(&mut subsystems).await)
            .expect_err("an unbidden exit must fail the process");
        assert!(
            format!("{err:#}").contains("bitcoin follower exited without a shutdown request"),
            "{err:#}"
        );
    }

    /// A panicking subsystem arrives as a `JoinError`, so the supervisor sees it
    /// without the panic hook having to double as an error channel.
    #[tokio::test]
    async fn panicking_subsystem_is_fatal() {
        let handle: JoinHandle<Result<()>> = tokio::spawn(async { panic!("boom") });
        let mut subsystems = vec![("api", handle)];
        let err = exit_status(first_exit(&mut subsystems).await)
            .expect_err("a panicking subsystem must fail the process");
        assert!(format!("{err:#}").contains("api task panicked"), "{err:#}");
    }

    /// A failure that surfaces *after* the stop decision must not become the
    /// reason we stopped. This is the SIGTERM-during-a-reorg case: cancelling
    /// makes `retry` give up and hand back the error it was retrying, so the
    /// poller reports a failure on a perfectly ordinary shutdown. Reporting that
    /// would fail the process on every rollout.
    #[tokio::test]
    async fn a_failure_while_shutting_down_is_not_the_cause() {
        let stop = Stop::Signal;
        drain(vec![(
            "bitcoin poller",
            subsystem(Err(anyhow::anyhow!("get block hash for reorg: cancelled"))),
        )])
        .await;
        assert!(
            exit_status(stop).is_ok(),
            "a subsystem erroring on the way out must not turn a clean stop into a crash"
        );
    }

    /// Only the subsystem that exited is removed, so the drain that follows can
    /// await the survivors — polling an already-finished handle panics.
    #[tokio::test]
    async fn only_the_exited_subsystem_is_removed() {
        let (tx, rx) = oneshot::channel::<()>();
        let mut subsystems = vec![
            ("reactor", subsystem(Err(anyhow::anyhow!("boom")))),
            (
                "api",
                tokio::spawn(async move {
                    let _ = rx.await;
                    Ok(())
                }),
            ),
        ];
        let _ = first_exit(&mut subsystems).await;
        assert_eq!(subsystems.len(), 1);
        assert_eq!(subsystems[0].0, "api");

        tx.send(()).expect("the survivor is still listening");
        subsystems
            .remove(0)
            .1
            .await
            .expect("joins")
            .expect("exits cleanly");
    }
}
