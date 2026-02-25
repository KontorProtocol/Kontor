use std::time::Duration;

use clap::Parser;
use eyre::Result;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info};

use consensus_sim::{make_config, mock_bitcoin, run_node};
use indexer::bitcoin_follower::event::BitcoinEvent;
use indexer::consensus::signing::PrivateKey;
use indexer::consensus::{Genesis, Validator, ValidatorSet};
use malachitebft_app_channel::app::types::core::VotingPower;

const CONSENSUS_BASE_PORT: usize = 27000;

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

    // Spawn mock bitcoin source with a shared broadcast sender
    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<BitcoinEvent>(256);
    let mock_bitcoin_tx = {
        let (tx, rx) = mpsc::channel(256);
        let btx = broadcast_tx.clone();
        tokio::spawn(async move {
            let mut rx = rx;
            while let Some(event) = rx.recv().await {
                let _ = btx.send(event);
            }
        });
        tx
    };

    tokio::spawn({
        let cancel = cancel_token.clone();
        async move {
            mock_bitcoin::run(mock_bitcoin_tx, cancel, Duration::from_secs(10), 3).await;
        }
    });

    let mut join_set = tokio::task::JoinSet::new();

    for (i, private_key) in private_keys.into_iter().enumerate() {
        let genesis = genesis.clone();
        let config = make_config(i, n, CONSENSUS_BASE_PORT);

        // Per-node: bridge broadcast → mpsc
        let bitcoin_rx = {
            let (tx, rx) = mpsc::channel(256);
            let mut brx = broadcast_tx.subscribe();
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
                if let Err(e) =
                    run_node(i, private_key, genesis, config, bitcoin_rx, None, cancel).await
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
