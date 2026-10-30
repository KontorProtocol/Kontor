use std::future::pending;
use std::slice;
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::{Network, Transaction as BitcoinTransaction, Witness};
use indexer_types::Transaction;
use malachitebft_core_types::Round;
use malachitebft_engine::node::NodeRef;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

use super::aggregate_error_tests::reactor;
use super::batches::IoApply;
use super::consensus_state::PendingProposal;
use super::executor::{RecognizedTransaction, TxPolicy};
use crate::bitcoin_follower::block::BlockInput;
use crate::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use crate::consensus::Height;
use crate::consensus::signing::PrivateKey;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::{Decimal, GenesisValidator};
use crate::stopper::Shutdown;
use crate::test_utils::{new_mock_block_hash, test_runtime_with_genesis};

struct StopEngine(NodeRef);

impl Drop for StopEngine {
    fn drop(&mut self) {
        self.0.stop(None);
    }
}

fn recognized(raw: BitcoinTransaction) -> RecognizedTransaction {
    RecognizedTransaction {
        parsed: Some(Transaction {
            txid: raw.compute_txid(),
            index: 0,
            inputs: Vec::new(),
            op_return_raw: None,
        }),
        raw,
    }
}

#[tokio::test]
async fn pending_recognition_keeps_blocks_and_requests_live_with_channel_backpressure() -> Result<()>
{
    let (runtime, dir, _) = test_runtime_with_genesis(&[GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: PrivateKey::from([17; 32]).public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }])
    .await?;
    let mut trial = reactor(runtime, &dir).await?;
    let _engine = StopEngine(trial.consensus.engine_handle.actor.clone());
    let raw = genesis_block(Network::Regtest).txdata.remove(0);
    let shutdown = Shutdown::new();
    trial.shutdown = shutdown.signal();
    let (block_tx, block_rx) = mpsc::channel(1);
    let (mempool_tx, mempool_rx) = mpsc::channel(1);
    let (simulate_tx, simulate_rx) = mpsc::channel(1);
    trial.block_rx = block_rx;
    trial.mempool_rx = mempool_rx;
    trial.simulate_rx = Some(simulate_rx);
    trial
        .consensus
        .mempool
        .stage_snapshot(slice::from_ref(&raw));
    let (entered_tx, entered_rx) = oneshot::channel();
    trial.mempool_preparation = Some(Box::pin(async move {
        let _ = entered_tx.send(());
        pending().await
    }));
    let drive = async {
        let result: Result<()> = async {
            timeout(Duration::from_secs(5), entered_rx).await??;
            block_tx
                .send(BlockEvent::BlockInsert {
                    target_height: 2,
                    block: BlockInput::new(
                        2,
                        new_mock_block_hash(2),
                        new_mock_block_hash(1),
                        vec![raw.clone()],
                    ),
                })
                .await?;
            let (reply, receive) = oneshot::channel();
            simulate_tx.send((raw.clone(), reply)).await?;
            ensure!(timeout(Duration::from_secs(5), receive).await???.is_none());
            mempool_tx
                .send(MempoolEvent::Remove(raw.compute_txid()))
                .await?;
            ensure!(
                timeout(
                    Duration::from_millis(50),
                    mempool_tx.send(MempoolEvent::Remove(raw.compute_txid()))
                )
                .await
                .is_err()
            );
            Ok(())
        }
        .await;
        shutdown.cancel();
        result
    };
    let (running, driven) = tokio::join!(trial.run_event_loop(), drive);
    driven?;
    running?;
    ensure!(trial.consensus.pending_blocks.contains_key(&2));
    ensure!(!trial.consensus.mempool.finish(recognized(raw)));
    Ok(())
}

#[tokio::test]
async fn delayed_verdicts_cannot_accept_or_remove_a_replacement_witness() -> Result<()> {
    let (runtime, dir, _) = test_runtime_with_genesis(&[GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: PrivateKey::from([17; 32]).public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }])
    .await?;
    let mut trial = reactor(runtime, &dir).await?;
    let _engine = StopEngine(trial.consensus.engine_handle.actor.clone());
    let old = genesis_block(Network::Regtest).txdata.remove(0);
    let mut current = old.clone();
    current.input[0].witness = Witness::from_slice(&[b"replacement".as_slice()]);
    trial.consensus.mempool.insert(recognized(current.clone()));
    for verdict in [TxPolicy::Accepted, TxPolicy::Rejected("old witness".into())] {
        trial
            .apply_io_verdicts(
                IoApply::BuildProposal {
                    anchor_height: 1,
                    anchor_hash: new_mock_block_hash(1),
                },
                Ok(vec![(old.clone(), verdict)]),
            )
            .await?;
        ensure!(trial.validated_candidates.is_none());
        ensure!(trial.consensus.mempool.contains_candidate(&current));
    }
    trial
        .apply_io_verdicts(
            IoApply::BuildProposal {
                anchor_height: 1,
                anchor_hash: new_mock_block_hash(1),
            },
            Ok(vec![(current.clone(), TxPolicy::Accepted)]),
        )
        .await?;
    ensure!(trial.validated_candidates.is_some());
    // Change the witness after banking, before the next proposal consumes it.
    trial.consensus.mempool.insert(recognized(old.clone()));
    let (reply, mut receive) = oneshot::channel();
    trial.consensus.pending_proposal = Some(PendingProposal {
        height: Height::new(1),
        round: Round::new(0),
        reply,
        hard_deadline: Instant::now() + Duration::from_secs(60),
    });
    ensure!(!trial.try_fulfill_pending_proposal().await?);
    ensure!(
        receive.try_recv().is_err(),
        "stale banked witness was proposed"
    );
    ensure!(trial.validated_candidates.is_none());
    ensure!(
        trial.io_jobs.len() == 1,
        "replacement needs fresh validation"
    );
    Ok(())
}
