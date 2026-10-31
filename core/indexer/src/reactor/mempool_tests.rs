use std::future::pending;
use std::slice;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::{Network, Transaction as BitcoinTransaction, Witness};
use indexer_types::Transaction;
use malachitebft_core_types::Round;
use malachitebft_engine::node::NodeRef;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

use super::aggregate_error_tests::reactor;
use super::batches::IoApply;
use super::consensus_state::PendingProposal;
use super::executor::{Executor, RecognizedTransaction, TxPolicy};
use super::mempool::MempoolPreparation;
use crate::bitcoin_follower::block::BlockInput;
use crate::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Address, Height, ProposalData};
use crate::database::queries::rollback_to_height;
use crate::protocol::coordinator::linked::{PreparedTransaction, TransactionRecognizer};
use crate::protocol::coordinator::selection::{
    ApplicationPosition, ExecutorVersion, select_legacy_p1,
};
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
        parsed: Some(PreparedTransaction::fixture(Transaction {
            txid: raw.compute_txid(),
            index: 0,
            inputs: Vec::new(),
            op_return_raw: None,
        })),
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
    trial.mempool_preparation = Some(MempoolPreparation {
        selection: trial.preparation_selection().await?,
        result: Box::pin(async move {
            let _ = entered_tx.send(());
            pending().await
        }),
    });
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
            simulate_tx.send((vec![0], reply)).await?;
            let malformed = timeout(Duration::from_secs(5), receive).await???;
            ensure!(malformed.is_err());
            let (reply, receive) = oneshot::channel();
            simulate_tx.send((serialize(&raw), reply)).await?;
            ensure!(timeout(Duration::from_secs(5), receive).await???.is_err());
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
                    selection: trial.preparation_selection().await?,
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
                selection: trial.preparation_selection().await?,
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

#[tokio::test]
async fn rollback_invalidates_delayed_verdicts_even_at_the_same_anchor() -> Result<()> {
    let (runtime, dir, _) = test_runtime_with_genesis(&[GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: PrivateKey::from([17; 32]).public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }])
    .await?;
    let mut trial = reactor(runtime, &dir).await?;
    let _engine = StopEngine(trial.consensus.engine_handle.actor.clone());
    let raw = genesis_block(Network::Regtest).txdata.remove(0);
    trial.consensus.mempool.insert(recognized(raw.clone()));
    let before = trial.preparation_selection().await?;
    rollback_to_height(&trial.db_conn(), 1).await?;
    for verdict in [
        TxPolicy::Accepted,
        TxPolicy::Rejected("before rollback".into()),
    ] {
        trial
            .apply_io_verdicts(
                IoApply::BuildProposal {
                    selection: before.clone(),
                    anchor_height: 1,
                    anchor_hash: new_mock_block_hash(1),
                },
                Ok(vec![(raw.clone(), verdict)]),
            )
            .await?;
        ensure!(trial.validated_candidates.is_none());
        ensure!(trial.consensus.mempool.contains_candidate(&raw));
    }
    // An identical proposal is accepted with a fresh selection. This makes a
    // stale rejection distinguishable from unrelated anchor or fixture failures.
    for (selection, accepted) in [
        (before, false),
        (trial.preparation_selection().await?, true),
    ] {
        let (reply, receive) = oneshot::channel();
        trial
            .apply_io_verdicts(
                IoApply::ValidateProposal {
                    selection,
                    height: Height::new(1),
                    round: Round::new(0),
                    proposer: Address::from_public_key(&PrivateKey::from([17; 32]).public_key()),
                    anchor_height: 1,
                    anchor_hash: new_mock_block_hash(1),
                    parsed: vec![recognized(raw.clone()).parsed.unwrap()],
                    reply,
                },
                Ok(vec![(raw.clone(), TxPolicy::Accepted)]),
            )
            .await?;
        ensure!(receive.await?.is_some() == accepted);
        ensure!(trial.consensus.undecided.contains_key(&Height::new(1)) == accepted);
    }
    Ok(())
}

#[tokio::test]
async fn rollback_invalidates_banked_verdicts_before_proposal_use() -> Result<()> {
    let (runtime, dir, _) = test_runtime_with_genesis(&[GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: PrivateKey::from([17; 32]).public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }])
    .await?;
    let mut trial = reactor(runtime, &dir).await?;
    let _engine = StopEngine(trial.consensus.engine_handle.actor.clone());
    let raw = genesis_block(Network::Regtest).txdata.remove(0);
    trial.consensus.mempool.insert(recognized(raw.clone()));
    trial
        .apply_io_verdicts(
            IoApply::BuildProposal {
                selection: trial.preparation_selection().await?,
                anchor_height: 1,
                anchor_hash: new_mock_block_hash(1),
            },
            Ok(vec![(raw.clone(), TxPolicy::Accepted)]),
        )
        .await?;
    ensure!(trial.validated_candidates.is_some());
    rollback_to_height(&trial.db_conn(), 1).await?;
    let (reply, mut receive) = oneshot::channel();
    trial.consensus.pending_proposal = Some(PendingProposal {
        height: Height::new(1),
        round: Round::new(0),
        reply,
        hard_deadline: Instant::now() + Duration::from_secs(60),
    });
    ensure!(!trial.try_fulfill_pending_proposal().await?);
    ensure!(receive.try_recv().is_err());
    ensure!(trial.validated_candidates.is_none());
    ensure!(
        trial.io_jobs.len() == 1,
        "rollback requires fresh validation"
    );
    ensure!(trial.consensus.mempool.contains_candidate(&raw));
    Ok(())
}

#[tokio::test]
async fn production_preparation_uses_retained_recognition_and_proposal_bytes() -> Result<()> {
    let (runtime, dir, _) = test_runtime_with_genesis(&[GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: PrivateKey::from([17; 32]).public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }])
    .await?;
    let mut trial = reactor(runtime, &dir).await?;
    let _engine = StopEngine(trial.consensus.engine_handle.actor.clone());
    let raw = genesis_block(Network::Regtest).txdata.remove(0);
    let mut replacement = raw.clone();
    replacement.input[0].witness = Witness::from_slice(&[b"not batchable".as_slice()]);
    ensure!(raw.compute_txid() == replacement.compute_txid());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    // This deliberately recognizes bytes that P1 rejects, so a node-side P1
    // fallback cannot pass the dispatch assertions below.
    trial.recognizer = TransactionRecognizer::new(
        ExecutorVersion::LegacyP1,
        Network::Regtest,
        Arc::new(move |_, bytes| {
            let raw: BitcoinTransaction = deserialize(&bytes).unwrap();
            record.lock().unwrap().push(bytes);
            Ok(Ok(Some((
                Arc::new(()),
                raw.compute_txid().to_byte_array(),
                raw.input[0].witness.is_empty(),
                Vec::new(),
            ))))
        }),
    );
    let selection = trial.preparation_selection().await?;
    let prepared = trial
        .executor
        .parse_mempool(
            &trial.recognizer,
            &selection,
            vec![raw.clone(), replacement.clone()],
        )
        .await?;
    ensure!(prepared.len() == 2);
    ensure!(
        prepared[0]
            .parsed
            .as_ref()
            .unwrap()
            .eligible_for(&selection)
    );
    ensure!(
        !prepared[1]
            .parsed
            .as_ref()
            .unwrap()
            .eligible_for(&selection)
    );
    let foreign = select_legacy_p1(
        &trial.db_conn(),
        Network::Bitcoin,
        ApplicationPosition::Preparation {
            anchor_height: 1,
            anchor_hash: Some(new_mock_block_hash(1)),
        },
    )
    .await?;
    ensure!(!prepared[0].parsed.as_ref().unwrap().eligible_for(&foreign));
    ensure!(
        trial
            .executor
            .parse_mempool(&trial.recognizer, &foreign, vec![raw.clone()])
            .await
            .is_err()
    );
    ensure!(
        seen.lock().unwrap().len() == 2,
        "foreign selection entered the recognizer"
    );
    trial
        .consensus
        .mempool
        .replace(prepared.into_iter().take(1).collect());
    let (reply, receive) = oneshot::channel();
    trial
        .validate_and_accept_proposal(
            &ProposalData::new_batch(1, new_mock_block_hash(1), vec![replacement.clone()]),
            trial.consensus.address,
            Height::new(2),
            Round::new(0),
            reply,
        )
        .await?;
    ensure!(
        receive.await?.is_none(),
        "proposal used cached batch eligibility for another witness"
    );
    ensure!(
        trial.io_jobs.is_empty(),
        "ineligible proposal reached Bitcoin RPC validation"
    );
    ensure!(trial.consensus.mempool.contains_candidate(&raw));
    ensure!(seen.lock().unwrap().last() == Some(&serialize(&replacement)));

    // Infrastructure failures must not become successful empty preparations.
    trial.recognizer = TransactionRecognizer::new(
        ExecutorVersion::LegacyP1,
        Network::Regtest,
        Arc::new(|_, _| Err((0, "recognizer unavailable".into()))),
    );
    ensure!(
        trial
            .executor
            .parse_mempool(&trial.recognizer, &selection, vec![raw])
            .await
            .is_err()
    );
    Ok(())
}
