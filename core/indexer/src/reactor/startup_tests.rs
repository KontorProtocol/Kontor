use std::time::Duration;

use anyhow::{Result, anyhow};
use malachitebft_app_channel::AppMsg;
use malachitebft_core_types::Round;
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, sleep, timeout};

use super::engine::EngineConfig;
use super::executor::NoopExecutor;
use super::mempool_fee_index::MempoolFeeIndex;
use super::{PruneConfig, Reactor, start_consensus};
use crate::consensus::signing::PrivateKey;
use crate::logging;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::{Decimal, GenesisValidator};
use crate::stopper::Shutdown;
use crate::test_utils::{new_mock_block_hash, test_runtime_with_genesis};

#[tokio::test]
async fn delayed_get_value_preserves_the_round_proposal_deadline() -> Result<()> {
    logging::setup();
    let key = PrivateKey::from([19; 32]);
    let (mut runtime, dir, _name) = test_runtime_with_genesis(&[GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }])
    .await?;
    let mut consensus = start_consensus(
        EngineConfig {
            private_key: key,
            listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
            persistent_peers: Vec::new(),
            data_dir: dir.path().to_path_buf(),
            consensus_enabled: true,
            discovery_enabled: false,
        },
        &mut runtime,
        None,
        None,
        1,
        MempoolFeeIndex::new(None),
    )
    .await?;
    consensus.timeouts.propose = Duration::from_secs(10);
    let shutdown = Shutdown::new();
    let (_block_tx, block_rx) = mpsc::channel(1);
    let (_mempool_tx, mempool_rx) = mpsc::channel(1);
    let (addr_tx, _addr_rx) = watch::channel(None);
    let mut reactor = Reactor::new(
        NoopExecutor,
        runtime,
        block_rx,
        mempool_rx,
        shutdown.signal(),
        None,
        None,
        None,
        consensus,
        PruneConfig {
            enabled: false,
            retain_blocks: 144,
        },
        1,
        Some(new_mock_block_hash(1)),
        addr_tx,
    );
    let result = timeout(Duration::from_secs(30), async {
        let mut tick = interval(Duration::from_millis(10));
        loop {
            tokio::select! {
                msg = reactor.consensus.channels.consensus.recv() => {
                    let msg = msg.ok_or_else(|| anyhow!("consensus channel closed"))?;
                    match &msg {
                        AppMsg::GetValue { round, .. } if *round == Round::new(0) => {
                            // The engine's propose timer keeps running while the
                            // application is busy and has not handled this request.
                            sleep(Duration::from_secs(5)).await;
                        }
                        AppMsg::StartedRound { round, .. } if *round != Round::new(0) => {
                            return Err(anyhow!("delayed proposal missed round zero"));
                        }
                        AppMsg::Decided { certificate, .. } => {
                            assert_eq!(certificate.round, Round::new(0));
                            reactor.handle_consensus_msg(msg).await?;
                            return Ok(());
                        }
                        _ => {}
                    }
                    reactor.handle_consensus_msg(msg).await?;
                }
                _ = tick.tick() => {
                    reactor.try_fulfill_pending_proposal().await?;
                }
            }
        }
    })
    .await;
    reactor
        .consensus
        .engine_handle
        .actor
        .get_cell()
        .stop_and_wait(None, Some(Duration::from_secs(5)))
        .await?;
    result?
}
