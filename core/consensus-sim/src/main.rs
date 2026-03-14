use std::time::Duration;

use clap::Parser;
use eyre::Result;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info};

use consensus_sim::{allocate_ports, make_engine_config, mock_bitcoin, run_node};
use indexer::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use indexer::consensus::signing::PrivateKey;
use indexer::consensus::{Genesis, Validator, ValidatorSet};
use malachitebft_app_channel::app::types::core::VotingPower;

#[derive(Parser)]
#[command(name = "consensus-sim")]
struct Args {
    /// Number of validators to run
    #[arg(long, default_value_t = 1)]
    validators: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();
    let n = args.validators;

    let mut rng = rand::thread_rng();
    let private_keys: Vec<PrivateKey> = (0..n).map(|_| PrivateKey::generate(&mut rng)).collect();

    let validators: Vec<Validator> = private_keys
        .iter()
        .map(|pk| Validator::new(pk.public_key(), 1 as VotingPower))
        .collect();

    let validator_set = ValidatorSet::new(validators);
    let genesis = Genesis { validator_set };

    info!(validators = n, "Starting consensus simulator");

    let cancel_token = CancellationToken::new();

    // Spawn mock bitcoin source with shared broadcast senders
    let (block_broadcast_tx, _) = tokio::sync::broadcast::channel::<BlockEvent>(256);
    let (mempool_broadcast_tx, _) = tokio::sync::broadcast::channel::<MempoolEvent>(256);
    let (mock_block_tx, mock_mempool_tx) = {
        let (btx, brx) = mpsc::channel(256);
        let (mtx, mrx) = mpsc::channel(256);
        let bbtx = block_broadcast_tx.clone();
        let mbtx = mempool_broadcast_tx.clone();
        tokio::spawn(async move {
            let mut brx = brx;
            while let Some(event) = brx.recv().await {
                let _ = bbtx.send(event);
            }
        });
        tokio::spawn(async move {
            let mut mrx = mrx;
            while let Some(event) = mrx.recv().await {
                let _ = mbtx.send(event);
            }
        });
        (btx, mtx)
    };

    tokio::spawn({
        let cancel = cancel_token.clone();
        async move {
            mock_bitcoin::run(
                mock_block_tx,
                mock_mempool_tx,
                cancel,
                Duration::from_secs(10),
                3,
            )
            .await;
        }
    });

    let ports = allocate_ports(n)?;
    let mut join_set = tokio::task::JoinSet::new();

    for (i, private_key) in private_keys.into_iter().enumerate() {
        let genesis = genesis.clone();
        let engine_config = make_engine_config(i, &ports, private_key);

        // Per-node: bridge broadcast → mpsc
        let node_block_rx = {
            let (tx, rx) = mpsc::channel(256);
            let mut brx = block_broadcast_tx.subscribe();
            tokio::spawn(async move {
                while let Ok(event) = brx.recv().await {
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
            });
            rx
        };
        let node_mempool_rx = {
            let (tx, rx) = mpsc::channel(256);
            let mut brx = mempool_broadcast_tx.subscribe();
            tokio::spawn(async move {
                while let Ok(event) = brx.recv().await {
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
            });
            rx
        };

        let cancel = cancel_token.clone();
        join_set.spawn(
            async move {
                if let Err(e) = run_node(
                    i,
                    engine_config,
                    genesis,
                    node_block_rx,
                    node_mempool_rx,
                    None,
                    None,
                    None,
                    None,
                    cancel,
                )
                .await
                {
                    tracing::error!(node = i, error = %e, "Node exited with error");
                }
            }
            .instrument(tracing::info_span!("validator", id = i)),
        );
    }

    while let Some(result) = join_set.join_next().await {
        if let Err(e) = result {
            tracing::error!(error = %e, "Node task panicked");
        }
    }

    cancel_token.cancel();
    Ok(())
}
