use std::panic;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread::available_parallelism;
use std::time::Duration;

use crate::api::Env;
use anyhow::Result;
use clap::{Parser, Subcommand};
use futures_util::{FutureExt, future};
use indexer::database::queries::select_recent_blocks;
use indexer::event::EventSubscriber;
use indexer::info::{compute_info_core, run_info_publisher};
use indexer::keygen::{self, KeygenArgs};
use indexer::stopper::{self, Shutdown};
use indexer::{api, block, built_info, reactor, reg_tester, runtime};
use indexer::{bitcoin_client, bitcoin_follower, config::Config, database, logging};
use indexer_types::{Inst, InstKind};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
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

    // First, before any startup work: `signal_received()` REGISTERS the
    // handlers, and until they exist a SIGTERM kills the process with the
    // default disposition (exit 143) — so a rollout catching a node during a
    // slow DB open would page as a crash. Polled at the root select below.
    let signal_received = stopper::signal_received();
    tokio::pin!(signal_received);

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
    let shutdown = Shutdown::new();
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
    let filename = "state.db";
    let reader = database::Reader::new(&config.data_dir, filename).await?;
    let writer = database::Writer::new(&config.data_dir, filename).await?;
    let reactor_ready = Arc::new(AtomicBool::new(false));
    // Whether we are stopping because something died — see `Env::failed`.
    let failed = Arc::new(AtomicBool::new(false));
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
    let info_publisher_handle = run_info_publisher(
        shutdown.signal(),
        event_subscriber.subscribe(),
        reader.clone(),
        info_tx,
    );
    let (simulate_tx, simulate_rx) = mpsc::channel(available_parallelism()?.into());
    let (fees_tx, fees_rx) = tokio::sync::watch::channel(indexer_types::Fees::floor(1));
    let event_subscriber_handle = event_subscriber.run(shutdown.signal(), event_rx);
    let api_handle = api::run(
        Env {
            config: config.clone(),
            shutdown: shutdown.signal(),
            reactor_ready: reactor_ready.clone(),
            failed: failed.clone(),
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
    .await?;

    let known_hashes = {
        let conn = reader.connection().await?;
        let recent_blocks = select_recent_blocks(&conn, 50).await?;
        recent_blocks
            .iter()
            .map(|b| (b.height, b.hash))
            .collect::<Vec<_>>()
    };

    // Relay channel: the reactor hands accepted batch txs to the broadcaster
    // instead of gating votes on `send_raw_transaction`.
    let (relay_tx, relay_rx) = mpsc::channel(indexer::broadcaster::CHANNEL_CAPACITY);
    let broadcaster_handle = indexer::broadcaster::run(bitcoin.clone(), relay_rx, shutdown.signal());

    let (block_rx, mempool_rx, replay_tx, follower_handle) = bitcoin_follower::run(
        bitcoin.clone(),
        block::filter_map,
        shutdown.signal(),
        config.starting_block_height,
        known_hashes,
        config.zmq_address.clone(),
    )
    .await;

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
    let reactor_handle = reactor::run(
        config.starting_block_height,
        shutdown.signal(),
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
        Some(relay_tx),
    );

    // The long-lived subsystems, named for the exit message. None of them is
    // optional: the first one to exit takes the node with it.
    //
    // The ORDER is attribution policy, not bookkeeping: when one failure
    // cascades, its victims can finish in the same poll, and `select_all`
    // breaks same-poll ties by lowest index — so cascade SOURCES go first.
    // The reactor feeds on everything and everything feeds on the follower's
    // bitcoind view; the api and the two broadcast consumers only ever die
    // downstream of those.
    let mut subsystems: Vec<(&'static str, JoinHandle<Result<()>>)> = vec![
        ("reactor", reactor_handle),
        ("bitcoin follower", follower_handle),
        // Behind the reactor on purpose: its channel sender lives there, so
        // its clean death is only ever a cascade of the reactor's.
        ("broadcaster", broadcaster_handle),
        ("api", api_handle),
        ("event subscriber", event_subscriber_handle),
        ("info publisher", info_publisher_handle),
    ];

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

    // Why we stopped is decided by which of these arms wins — nothing else in
    // the process cancels, so an arm that fires before a stop was asked for is
    // the cause (modulo scheduler tie-breaks, which `biased` pins down).
    //
    // The order is a policy, not a style choice. Before anything has asked the
    // node to stop, a panic or a subsystem exit is never a CONSEQUENCE of
    // shutdown — so when one is ready in the same poll as a signal, preferring
    // it can only upgrade a would-be-silent failure into a named one, never
    // turn a clean rollout into a false page. Panics outrank handle exits so a
    // panic that also unwound its task is attributed to its file:line, not to
    // a generic "task panicked".
    let stop = tokio::select! {
        biased;
        Some(cause) = panic_rx.recv() => Stop::Fatal(anyhow::anyhow!("{cause}")),
        fatal = first_exit(&mut subsystems) => match fatal {
            // A panicking subsystem races its hook's report against its
            // `JoinError`: the send happens first, so `biased` normally routes
            // it to the arm above — but if the message landed after this poll
            // began, fold it in rather than reporting the bare join error.
            Stop::Fatal(e) => match panic_rx.try_recv() {
                Ok(cause) => Stop::Fatal(e.context(cause)),
                Err(_) => Stop::Fatal(e),
            },
            stop => stop,
        },
        () = &mut signal_received => Stop::Signal,
    };

    // Ordered before the cancel so no request can observe a shutdown in progress
    // without also being able to see why: the API keeps serving through a drain,
    // and must not do that for a node whose reactor is gone. `Relaxed` is
    // enough BECAUSE of that ordering — `cancel()` is a release store and every
    // reader that acts on the token's cancellation acquires it, so this store
    // is visible to anything that saw the cancel. Not a coincidence to tidy.
    if matches!(stop, Stop::Fatal(_)) {
        failed.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    info!("Initiating shutdown");
    shutdown.cancel();
    let wedged = drain(subsystems, SHUTDOWN_BUDGET).await;
    if !wedged.is_empty() {
        // A subsystem that ignored its budget may be wedged SYNCHRONOUSLY, and
        // a synchronously-wedged task can hang the runtime's own teardown —
        // returning through `#[tokio::main]` would then spin forever with the
        // budget already spent, liveness green, and nothing left to log. Exit
        // here instead: abrupt, but the alternative is the hung green-probed
        // process this whole change exists to kill.
        if let Err(e) = exit_status(stop, &wedged) {
            error!("Exited: {e:#}");
        }
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        std::process::exit(1);
    }
    exit_status(stop, &wedged)
}

/// How long the subsystems get to stop once cancelled. Comfortably covers the
/// API's 10s graceful window and a reactor finishing an in-flight block; a
/// correct shutdown takes a fraction of it. Exceeding it means something is not
/// listening to cancellation, and waiting longer has never once fixed that —
/// without a bound the process hangs instead of exiting, which tells an
/// orchestrator even less than exiting 0 did.
///
/// Deliberately UNDER Kubernetes' default `terminationGracePeriodSeconds` (30s):
/// the wedged-drain exit must beat the orchestrator's SIGKILL or the diagnostic
/// is lost as a bare 137. The kontor-network helm charts should set the grace
/// period above this with margin (45s) — see the infra repo.
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(25);

/// Wait out the remaining subsystems after the stop decision has been made, and
/// report any that were still running when the budget ran out.
///
/// Whatever they report here is the wake of that decision, not its cause — one
/// real failure closes channels and unwinds tasks behind it, and a cancelled
/// `retry` hands back the error it was retrying. Worth logging, never worth
/// reporting as the reason the process stopped.
///
/// Abandoning a wedged subsystem is safe for the same reason a crash is: every
/// state write on the reactor's paths commits transactionally (the #518
/// hardening), so whatever the abandoned task was mid-way through is a
/// savepoint the restart rolls back or a transaction it never sees half of.
///
/// The budget is a deadline shared across the whole drain, so once it passes
/// every subsystem still running is named, not just the first one to hold us up.
async fn drain(
    subsystems: Vec<(&'static str, JoinHandle<Result<()>>)>,
    budget: Duration,
) -> Vec<&'static str> {
    let deadline = tokio::time::Instant::now() + budget;
    let mut wedged = Vec::new();
    for (name, handle) in subsystems {
        match tokio::time::timeout_at(deadline, handle).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => warn!("{name} failed while shutting down: {e:#}"),
            Ok(Err(e)) => warn!("{name} did not shut down cleanly: {e}"),
            Err(_) => {
                error!("{name} ignored cancellation for {budget:?}, abandoning it");
                wedged.push(name);
            }
        }
    }
    wedged
}

/// Turn "why we stopped" into a process exit status.
///
/// A signal exits 0; a subsystem that died exits non-zero, so an orchestrator
/// sees a failure instead of `Completed` and backs off rather than restarting
/// into the same fault forever. A stop that had to abandon a subsystem is not a
/// clean stop either, however it started — a node that cannot shut down is a bug
/// worth paging for, and reporting 0 would bury it.
fn exit_status(stop: Stop, wedged: &[&str]) -> Result<()> {
    match stop {
        Stop::Signal if !wedged.is_empty() => {
            anyhow::bail!("stopped on signal, but {} never stopped", wedged.join(", "))
        }
        Stop::Signal => {
            info!("Exited");
            Ok(())
        }
        // The wedged names ride ON the cause rather than replacing it — the
        // operator needs both what killed the node and what then refused to die.
        Stop::Fatal(cause) if !wedged.is_empty() => Err(cause.context(format!(
            "additionally, {} never stopped within the shutdown budget",
            wedged.join(", ")
        ))),
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

/// Resolves when the first subsystem exits, removing every already-finished
/// subsystem from `subsystems` so the caller can still drain the rest.
///
/// Every exit here is fatal, clean or not: this only runs before anything has
/// asked the node to stop, and a subsystem that returns `Ok(())` unbidden has
/// stopped doing its job just as surely as one that returned an error.
///
/// One real failure cascades: channels close behind the dying subsystem, and
/// its dependents can finish in the same poll — some of them CLEANLY, since a
/// task whose input channel closed has, from its own point of view, simply run
/// out of work. Two layers keep the cause honest: the vec is ordered with
/// cascade sources first (`select_all` breaks same-poll ties by lowest index),
/// and when the winner is only a clean-exit sentinel, a sweep of the other
/// already-finished handles prefers any real error or panic over it.
async fn first_exit(subsystems: &mut Vec<(&'static str, JoinHandle<Result<()>>)>) -> Stop {
    // `select_all` panics on an empty iterator, and a panic in the shutdown path
    // is the last thing this code should contribute. Unreachable while `main`
    // pushes all five, but "nothing is running" is a fatal answer either way.
    if subsystems.is_empty() {
        return Stop::Fatal(anyhow::anyhow!("no subsystems left running"));
    }
    let (result, index, _) = future::select_all(subsystems.iter_mut().map(|(_, h)| h)).await;
    let (name, _) = subsystems.remove(index);
    let mut cause = exit_error(name, result);

    if cause.downcast_ref::<stopper::UnexpectedExit>().is_some() {
        // Every handle that is ALREADY finished must leave the vec here — the
        // drain will await the survivors, and polling a completed JoinHandle
        // again panics — so the sweep collects them all, keeping the first
        // real error it finds as the cause and logging the rest as cascade.
        let mut i = 0;
        while i < subsystems.len() {
            match (&mut subsystems[i].1).now_or_never() {
                Some(result) => {
                    let (name, _) = subsystems.remove(i);
                    let e = exit_error(name, result);
                    if cause.downcast_ref::<stopper::UnexpectedExit>().is_some()
                        && e.downcast_ref::<stopper::UnexpectedExit>().is_none()
                    {
                        warn!("{cause:#} (a cascade of the failure reported instead)");
                        cause = e;
                    } else {
                        warn!("{e:#} (finished in the same poll as the reported failure)");
                    }
                }
                None => i += 1,
            }
        }
    }
    Stop::Fatal(cause)
}

/// One finished subsystem handle, as the error the supervisor would report. A
/// clean-but-unbidden exit becomes a typed [`stopper::UnexpectedExit`] so cause
/// attribution can rank real errors above manufactured ones.
fn exit_error(
    name: &'static str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> anyhow::Error {
    match result {
        Ok(Err(e)) => e.context(format!("{name} failed")),
        Err(e) => anyhow::anyhow!("{name} task panicked: {e}"),
        Ok(Ok(())) => anyhow::Error::new(stopper::UnexpectedExit(name)),
    }
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
        assert!(exit_status(Stop::Signal, &[]).is_ok());
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
        let err = exit_status(first_exit(&mut subsystems).await, &[])
            .expect_err("a dead subsystem must fail the process");
        let msg = format!("{err:#}");
        assert!(msg.contains("reactor failed"), "{msg}");
        assert!(msg.contains("316333"), "the cause must reach the operator");
    }

    /// A dying subsystem often takes an innocent neighbour with it IN THE SAME
    /// POLL: the neighbour's input channel closes and it exits cleanly — from
    /// its own point of view it just ran out of work. Whatever the vec order
    /// says, the clean exit must never outrank the real error as the cause.
    #[tokio::test]
    async fn a_real_error_outranks_a_simultaneous_clean_exit() {
        // Sentinel FIRST, so `select_all`'s index tie-break alone would pick
        // it; the sweep must still surface the real error behind it.
        let clean = subsystem(Ok(()));
        let failed = subsystem(Err(anyhow::anyhow!("database disk image is malformed")));
        while !(clean.is_finished() && failed.is_finished()) {
            tokio::task::yield_now().await;
        }
        let mut subsystems = vec![("event subscriber", clean), ("reactor", failed)];

        let err = exit_status(first_exit(&mut subsystems).await, &[])
            .expect_err("a real error was present and must fail the process");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("reactor failed") && msg.contains("malformed"),
            "the real error must be the cause, not the clean-exit sentinel: {msg}"
        );
        assert!(
            subsystems.is_empty(),
            "every finished handle must leave the vec — the drain polls the rest"
        );
    }

    /// A subsystem that returns `Ok(())` unbidden has stopped doing its job just
    /// as surely as one that errored. Discarding task results is what let this
    /// pass for a clean shutdown.
    #[tokio::test]
    async fn clean_exit_without_a_stop_request_is_fatal() {
        let mut subsystems = vec![("bitcoin follower", subsystem(Ok(())))];
        let err = exit_status(first_exit(&mut subsystems).await, &[])
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
        let err = exit_status(first_exit(&mut subsystems).await, &[])
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
        let wedged = drain(
            vec![(
                "bitcoin poller",
                subsystem(Err(anyhow::anyhow!("get block hash for reorg: cancelled"))),
            )],
            SHUTDOWN_BUDGET,
        )
        .await;
        assert!(wedged.is_empty(), "it stopped, it just stopped badly");
        assert!(
            exit_status(stop, &wedged).is_ok(),
            "a subsystem erroring on the way out must not turn a clean stop into a crash"
        );
    }

    /// A subsystem that ignores cancellation is abandoned rather than waited on
    /// forever, and the process says so. Hanging here is strictly worse than the
    /// bug this whole change is about: a stuck process exits with nothing at all,
    /// and an orchestrator can only wait out its grace period and SIGKILL it.
    #[tokio::test]
    async fn a_subsystem_that_never_stops_is_abandoned_and_reported() {
        let deaf: JoinHandle<Result<()>> = tokio::spawn(async {
            std::future::pending::<()>().await;
            Ok(())
        });
        let wedged = drain(
            vec![("reactor", deaf), ("api", subsystem(Ok(())))],
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(wedged, vec!["reactor"]);

        let err = exit_status(Stop::Signal, &wedged)
            .expect_err("a node that cannot shut down must not report success");
        assert!(format!("{err:#}").contains("reactor"), "{err:#}");
    }

    /// A fatal stop that ALSO had to abandon a subsystem reports both: the
    /// cause is what the operator pages on, the wedged name is what they then
    /// go find in the drain log.
    #[test]
    fn wedged_names_ride_on_the_fatal_cause() {
        let err = exit_status(
            Stop::Fatal(anyhow::anyhow!("reactor failed: db corrupt")),
            &["api"],
        )
        .expect_err("fatal remains fatal with a wedged drain");
        let msg = format!("{err:#}");
        assert!(msg.contains("db corrupt"), "{msg}");
        assert!(
            msg.contains("api") && msg.contains("never stopped"),
            "{msg}"
        );
    }

    /// Defensive: `select_all` panics on an empty iterator, and the shutdown path
    /// is the worst place to learn that.
    #[tokio::test]
    async fn no_subsystems_is_fatal_not_a_panic() {
        let mut subsystems = Vec::new();
        let err = exit_status(first_exit(&mut subsystems).await, &[])
            .expect_err("nothing running is not a healthy node");
        assert!(format!("{err:#}").contains("no subsystems"), "{err:#}");
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
