use std::future::pending;
use std::slice;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, ensure};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::{Network, OutPoint, Transaction as BitcoinTransaction, Witness};
use futures_util::{future::BoxFuture, poll};
use indexer_types::Transaction;
use malachitebft_core_types::Round;
use malachitebft_engine::host::Next;
use malachitebft_engine::node::NodeRef;
use tempfile::TempDir;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

use super::Reactor;
use super::batches::{IncomingProposal, ValidationJob};
use super::certified_fixture;
use super::executor::{Executor, RecognizedTransaction, RuntimeExecutor, TxPolicy};
use super::mempool::MempoolPreparation;
use super::proposal_builder::PendingProposal;
use super::proposal_builder::{BuildContext, Verdicts};
use crate::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Address, Height, ProposalData, Value};
use crate::database::certified_history::proposals;
use crate::database::queries::rollback_to_height;
use crate::protocol::coordinator::linked::{PreparedTransaction, TransactionRecognizer};
use crate::protocol::coordinator::selection::{
    ApplicationPosition, ExecutorVersion, select_legacy_p1,
};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::{Decimal, GenesisValidator};
use crate::stopper::Shutdown;
use crate::test_utils::test_genesis;

struct StopEngine(NodeRef);

impl Drop for StopEngine {
    fn drop(&mut self) {
        self.0.stop(None);
    }
}

async fn fixture() -> Result<(Reactor<RuntimeExecutor>, TempDir)> {
    let key = PrivateKey::from([17; 32]);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let directory = TempDir::new()?;
    let mut trial = certified_fixture::reactor(directory.path(), &genesis, key.clone(), 1).await?;
    let block = certified_fixture::empty_block(1);
    let value = Value::from_input(block.exact_input(trial.consensus.protocol_context)?)?;
    let height = Height::new(1);
    let round = Round::new(0);
    let proof = certified_fixture::certificate(&key, &value, height, round);
    certified_fixture::proposal(&mut trial, value, height, round).await?;
    let (reply, persisted) = oneshot::channel();
    trial
        .consensus
        .receive_decision(&trial.db_conn(), proof.clone(), reply)
        .await?;
    persisted.await?;
    let (reply, next) = oneshot::channel();
    trial.handle_finalized(proof, reply).await?;
    trial.advance().await?;
    ensure!(matches!(next.await?, Next::Start(height, _) if height == Height::new(2)));
    Ok((trial, directory))
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
    let (mut trial, _directory) = fixture().await?;
    let anchor_hash = trial.execution.last_hash.unwrap();
    trial.consensus.current_round = Round::new(0);
    trial.consensus.current_proposer = Some(trial.consensus.address);
    let _engine = StopEngine(trial.consensus.engine.legacy_handle().actor.clone());
    let mut raw = genesis_block(Network::Regtest).txdata.remove(0);
    raw.input[0].previous_output = OutPoint::new(raw.compute_txid(), 0);
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
                    block: certified_fixture::block(2, anchor_hash, 0, vec![raw.clone()]),
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
    let (mut trial, _directory) = fixture().await?;
    let anchor_hash = trial.execution.last_hash.unwrap();
    trial.consensus.current_round = Round::new(0);
    trial.consensus.current_proposer = Some(trial.consensus.address);
    let _engine = StopEngine(trial.consensus.engine.legacy_handle().actor.clone());
    let old = genesis_block(Network::Regtest).txdata.remove(0);
    let mut current = old.clone();
    current.input[0].witness = Witness::from_slice(&[b"replacement".as_slice()]);
    trial.consensus.mempool.insert(recognized(current.clone()));
    for verdict in [TxPolicy::Accepted, TxPolicy::Rejected("old witness".into())] {
        trial
            .apply_build_verdicts(
                BuildContext {
                    selection: trial.preparation_selection().await?,
                    anchor_height: 1,
                    anchor_hash,
                },
                Ok(vec![(old.clone(), verdict)]),
            )
            .await?;
        ensure!(!trial.proposal_builder.has_banked());
        ensure!(trial.consensus.mempool.contains_candidate(&current));
    }
    trial
        .apply_build_verdicts(
            BuildContext {
                selection: trial.preparation_selection().await?,
                anchor_height: 1,
                anchor_hash,
            },
            Ok(vec![(current.clone(), TxPolicy::Accepted)]),
        )
        .await?;
    ensure!(trial.proposal_builder.has_banked());
    // Change the witness after banking, before the next proposal consumes it.
    trial.consensus.mempool.insert(recognized(old.clone()));
    let (reply, mut receive) = oneshot::channel();
    trial.proposal_builder.start_request(PendingProposal {
        height: Height::new(2),
        round: Round::new(0),
        reply,
        hard_deadline: Instant::now() + Duration::from_secs(60),
    });
    ensure!(!trial.try_fulfill_pending_proposal().await?);
    ensure!(
        receive.try_recv().is_err(),
        "stale banked witness was proposed"
    );
    ensure!(!trial.proposal_builder.has_banked());
    ensure!(
        trial.proposal_builder.build_in_flight(),
        "replacement needs fresh validation"
    );
    Ok(())
}

#[tokio::test]
async fn rollback_invalidates_delayed_verdicts_even_at_the_same_anchor() -> Result<()> {
    let (mut trial, _directory) = fixture().await?;
    let anchor_hash = trial.execution.last_hash.unwrap();
    trial.consensus.current_round = Round::new(0);
    trial.consensus.current_proposer = Some(trial.consensus.address);
    let _engine = StopEngine(trial.consensus.engine.legacy_handle().actor.clone());
    let raw = genesis_block(Network::Regtest).txdata.remove(0);
    trial.consensus.mempool.insert(recognized(raw.clone()));
    let before = trial.preparation_selection().await?;
    rollback_to_height(&trial.db_conn(), 1).await?;
    for verdict in [
        TxPolicy::Accepted,
        TxPolicy::Rejected("before rollback".into()),
    ] {
        trial
            .apply_build_verdicts(
                BuildContext {
                    selection: before.clone(),
                    anchor_height: 1,
                    anchor_hash,
                },
                Ok(vec![(raw.clone(), verdict)]),
            )
            .await?;
        ensure!(!trial.proposal_builder.has_banked());
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
            .apply_validation_verdicts(
                IncomingProposal {
                    value: Value::new_batch_raw(
                        trial.consensus.protocol_context,
                        1,
                        anchor_hash,
                        vec![raw.clone()],
                    )?,
                    selection,
                    height: Height::new(2),
                    round: Round::new(0),
                    proposer: Address::from_public_key(&PrivateKey::from([17; 32]).public_key()),
                    anchor_height: 1,
                    anchor_hash,
                    parsed: vec![recognized(raw.clone()).parsed.unwrap()],
                    reply,
                },
                Ok(vec![(raw.clone(), TxPolicy::Accepted)]),
            )
            .await?;
        ensure!(receive.await?.is_some() == accepted);
        ensure!(
            proposals::normal(
                &trial.db_conn(),
                Height::new(2),
                Round::new(0),
                trial.consensus.protocol_context
            )
            .await?
            .is_some()
                == accepted
        );
    }
    Ok(())
}

#[tokio::test]
async fn rollback_invalidates_banked_verdicts_before_proposal_use() -> Result<()> {
    let (mut trial, _directory) = fixture().await?;
    let anchor_hash = trial.execution.last_hash.unwrap();
    trial.consensus.current_round = Round::new(0);
    trial.consensus.current_proposer = Some(trial.consensus.address);
    let _engine = StopEngine(trial.consensus.engine.legacy_handle().actor.clone());
    let raw = genesis_block(Network::Regtest).txdata.remove(0);
    trial.consensus.mempool.insert(recognized(raw.clone()));
    trial
        .apply_build_verdicts(
            BuildContext {
                selection: trial.preparation_selection().await?,
                anchor_height: 1,
                anchor_hash,
            },
            Ok(vec![(raw.clone(), TxPolicy::Accepted)]),
        )
        .await?;
    ensure!(trial.proposal_builder.has_banked());
    rollback_to_height(&trial.db_conn(), 1).await?;
    let (reply, mut receive) = oneshot::channel();
    trial.proposal_builder.start_request(PendingProposal {
        height: Height::new(2),
        round: Round::new(0),
        reply,
        hard_deadline: Instant::now() + Duration::from_secs(60),
    });
    ensure!(!trial.try_fulfill_pending_proposal().await?);
    ensure!(receive.try_recv().is_err());
    ensure!(!trial.proposal_builder.has_banked());
    ensure!(
        trial.proposal_builder.build_in_flight(),
        "rollback requires fresh validation"
    );
    ensure!(trial.consensus.mempool.contains_candidate(&raw));
    Ok(())
}

#[tokio::test]
async fn production_preparation_uses_retained_recognition_and_proposal_bytes() -> Result<()> {
    let (mut trial, _directory) = fixture().await?;
    let anchor_hash = trial.execution.last_hash.unwrap();
    trial.consensus.current_round = Round::new(0);
    trial.consensus.current_proposer = Some(trial.consensus.address);
    let _engine = StopEngine(trial.consensus.engine.legacy_handle().actor.clone());
    let raw = genesis_block(Network::Regtest).txdata.remove(0);
    let mut replacement = raw.clone();
    replacement.input[0].witness = Witness::from_slice(&[b"not batchable".as_slice()]);
    ensure!(raw.compute_txid() == replacement.compute_txid());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    // This deliberately recognizes bytes that P1 rejects, so a node-side P1
    // fallback cannot pass the dispatch assertions below.
    trial.execution.recognizer = TransactionRecognizer::new(
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
        .execution
        .executor
        .parse_mempool(
            &trial.execution.recognizer,
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
            anchor_hash: Some(anchor_hash),
        },
    )
    .await?;
    ensure!(!prepared[0].parsed.as_ref().unwrap().eligible_for(&foreign));
    ensure!(
        trial
            .execution
            .executor
            .parse_mempool(&trial.execution.recognizer, &foreign, vec![raw.clone()])
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
            &ProposalData::new(Value::new_batch_raw(
                trial.consensus.protocol_context,
                1,
                anchor_hash,
                vec![replacement.clone()],
            )?),
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
        trial.validation_jobs.is_empty() && !trial.proposal_builder.build_in_flight(),
        "ineligible proposal reached Bitcoin RPC validation"
    );
    ensure!(trial.consensus.mempool.contains_candidate(&raw));
    ensure!(seen.lock().unwrap().last() == Some(&serialize(&replacement)));

    // Infrastructure failures must not become successful empty preparations.
    trial.execution.recognizer = TransactionRecognizer::new(
        ExecutorVersion::LegacyP1,
        Network::Regtest,
        Arc::new(|_, _| Err((0, "recognizer unavailable".into()))),
    );
    ensure!(
        trial
            .execution
            .executor
            .parse_mempool(&trial.execution.recognizer, &selection, vec![raw])
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn competing_validation_completions_preserve_first_accepted_slot() -> Result<()> {
    let (mut trial, _directory) = fixture().await?;
    let _engine = StopEngine(trial.consensus.engine.legacy_handle().actor.clone());
    let anchor_hash = trial.execution.last_hash.unwrap();
    trial.consensus.current_round = Round::new(0);
    trial.consensus.current_proposer = Some(trial.consensus.address);
    let selection = trial.preparation_selection().await?;
    let mut first_id = None;
    for attempt in 0..2 {
        let mut raw = genesis_block(Network::Regtest).txdata.remove(0);
        raw.output[0].script_pubkey = if attempt == 0 {
            raw.output[0].script_pubkey.clone()
        } else {
            Default::default()
        };
        let value = Value::new_batch_raw(
            trial.consensus.protocol_context,
            1,
            anchor_hash,
            vec![raw.clone()],
        )?;
        let id = value.id();
        let (reply, received) = oneshot::channel();
        trial
            .apply_validation_verdicts(
                IncomingProposal {
                    value,
                    selection: selection.clone(),
                    height: Height::new(2),
                    round: Round::new(0),
                    proposer: trial.consensus.address,
                    anchor_height: 1,
                    anchor_hash,
                    parsed: vec![recognized(raw.clone()).parsed.unwrap()],
                    reply,
                },
                Ok(vec![(raw, TxPolicy::Accepted)]),
            )
            .await?;
        assert_eq!(received.await?.is_some(), attempt == 0);
        if attempt == 0 {
            first_id = Some(id);
        }
        let retained = proposals::normal(
            &trial.db_conn(),
            Height::new(2),
            Round::new(0),
            trial.consensus.protocol_context,
        )
        .await?
        .unwrap();
        assert_eq!(Some(retained.value.id()), first_id);
        if attempt == 1 {
            assert_ne!(Some(id), first_id);
            assert!(
                proposals::exact(
                    &trial.db_conn(),
                    Height::new(2),
                    id,
                    trial.consensus.protocol_context
                )
                .await?
                .is_none()
            );
        }
    }
    Ok(())
}

struct CountDrop(Arc<AtomicUsize>);

impl Drop for CountDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn gated_verdicts(
    verdicts: Verdicts,
    entered: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
    drops: Arc<AtomicUsize>,
) -> BoxFuture<'static, Verdicts> {
    let guard = CountDrop(drops);
    Box::pin(async move {
        let _guard = guard;
        let _ = entered.send(());
        release.await?;
        verdicts
    })
}

#[tokio::test]
async fn proposal_build_polling_cancellation_and_reset_preserve_ownership() -> Result<()> {
    let (mut trial, _directory) = fixture().await?;
    let _engine = StopEngine(trial.consensus.engine.legacy_handle().actor.clone());
    let selection = trial.preparation_selection().await?;
    let anchor_hash = trial.execution.last_hash.unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let (entered, mut started) = oneshot::channel();
    let (release, waiting) = oneshot::channel();
    trial.proposal_builder.start_build(
        BuildContext {
            selection: selection.clone(),
            anchor_height: 1,
            anchor_hash,
        },
        gated_verdicts(Ok(vec![]), entered, waiting, drops.clone()),
    )?;
    {
        let mut polling = Box::pin(trial.proposal_builder.next_build());
        assert!(poll!(&mut polling).is_pending());
    }
    started.try_recv()?;
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert!(trial.proposal_builder.build_in_flight());
    assert!(
        trial
            .proposal_builder
            .start_build(
                BuildContext {
                    selection: selection.clone(),
                    anchor_height: 2,
                    anchor_hash
                },
                Box::pin(async { Ok(vec![]) }),
            )
            .is_err()
    );
    release.send(()).unwrap();
    let completed = trial.proposal_builder.next_build().await;
    completed.verdicts?;
    assert_eq!(completed.context.anchor_height, 1);
    assert_eq!(completed.context.anchor_hash, anchor_hash);
    assert!(
        completed
            .context
            .selection
            .can_reuse_preparation(&selection)
    );
    assert!(!trial.proposal_builder.build_in_flight());
    assert_eq!(drops.load(Ordering::SeqCst), 1);

    for polled in [false, true] {
        let (entered, _started) = oneshot::channel();
        let (_release, waiting) = oneshot::channel();
        let drops = Arc::new(AtomicUsize::new(0));
        let (reply, mut receive) = oneshot::channel();
        trial.proposal_builder.start_request(PendingProposal {
            height: Height::new(2),
            round: Round::new(0),
            reply,
            hard_deadline: Instant::now() + Duration::from_secs(60),
        });
        trial.proposal_builder.start_build(
            BuildContext {
                selection: selection.clone(),
                anchor_height: 1,
                anchor_hash,
            },
            gated_verdicts(Ok(vec![]), entered, waiting, drops.clone()),
        )?;
        if polled {
            let mut polling = Box::pin(trial.proposal_builder.next_build());
            assert!(poll!(&mut polling).is_pending());
        }
        trial.proposal_builder.reset();
        assert!(!trial.proposal_builder.build_in_flight());
        assert!(trial.proposal_builder.request().is_none());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(matches!(
            receive.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
    }
    let (entered, _started) = oneshot::channel();
    let (_release, waiting) = oneshot::channel();
    let drops = Arc::new(AtomicUsize::new(0));
    trial.proposal_builder.start_build(
        BuildContext {
            selection,
            anchor_height: 1,
            anchor_hash,
        },
        gated_verdicts(Ok(vec![]), entered, waiting, drops.clone()),
    )?;
    drop(trial);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn expired_proposal_banks_its_build_for_the_next_round() -> Result<()> {
    let (mut trial, _directory) = fixture().await?;
    let _engine = StopEngine(trial.consensus.engine.legacy_handle().actor.clone());
    trial.consensus.current_round = Round::new(0);
    trial.consensus.current_proposer = Some(trial.consensus.address);
    let raw = genesis_block(Network::Regtest).txdata.remove(0);
    trial.consensus.mempool.insert(recognized(raw.clone()));
    let selection = trial.preparation_selection().await?;
    let (entered, _started) = oneshot::channel();
    let (release, waiting) = oneshot::channel();
    let drops = Arc::new(AtomicUsize::new(0));
    trial.proposal_builder.start_build(
        BuildContext {
            selection,
            anchor_height: 1,
            anchor_hash: trial.execution.last_hash.unwrap(),
        },
        gated_verdicts(
            Ok(vec![(raw.clone(), TxPolicy::Accepted)]),
            entered,
            waiting,
            drops.clone(),
        ),
    )?;
    let (reply, receive) = oneshot::channel();
    trial.proposal_builder.start_request(PendingProposal {
        height: Height::new(2),
        round: Round::new(0),
        reply,
        hard_deadline: Instant::now(),
    });
    assert!(trial.try_fulfill_pending_proposal().await?);
    assert!(receive.await?.value.batch_raw_txs().is_empty());
    assert!(trial.proposal_builder.build_in_flight());
    release.send(()).unwrap();
    let completed = trial.proposal_builder.next_build().await;
    trial
        .apply_build_verdicts(completed.context, completed.verdicts)
        .await?;
    assert!(trial.proposal_builder.has_banked());
    trial.consensus.current_round = Round::new(1);
    let (reply, receive) = oneshot::channel();
    trial
        .handle_get_value(
            Height::new(2),
            Round::new(1),
            Duration::from_secs(60),
            reply,
        )
        .await?;
    assert_eq!(receive.await?.value.batch_raw_txs(), vec![raw]);
    assert!(!trial.proposal_builder.has_banked());
    assert!(!trial.proposal_builder.build_in_flight());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn stale_build_releases_its_slot_before_resnapshot_and_errors_stay_fatal() -> Result<()> {
    let (mut trial, _directory) = fixture().await?;
    let _engine = StopEngine(trial.consensus.engine.legacy_handle().actor.clone());
    let raw = genesis_block(Network::Regtest).txdata.remove(0);
    trial.consensus.mempool.insert(recognized(raw.clone()));
    let selection = trial.preparation_selection().await?;
    let anchor_hash = trial.execution.last_hash.unwrap();
    trial.proposal_builder.start_build(
        BuildContext {
            selection: selection.clone(),
            anchor_height: 1,
            anchor_hash,
        },
        Box::pin(async move { Ok(vec![(raw, TxPolicy::Accepted)]) }),
    )?;
    rollback_to_height(&trial.db_conn(), 1).await?;
    let (reply, mut receive) = oneshot::channel();
    trial.proposal_builder.start_request(PendingProposal {
        height: Height::new(2),
        round: Round::new(0),
        reply,
        hard_deadline: Instant::now() + Duration::from_secs(60),
    });
    let completed = trial.proposal_builder.next_build().await;
    assert!(!trial.proposal_builder.build_in_flight());
    trial
        .apply_build_verdicts(completed.context, completed.verdicts)
        .await?;
    assert!(trial.proposal_builder.build_in_flight());
    assert!(!trial.try_fulfill_pending_proposal().await?);
    assert!(trial.proposal_builder.build_in_flight());
    assert!(receive.try_recv().is_err());
    // Even an obsolete selection cannot turn infrastructure failure into a retry.
    assert!(
        trial
            .apply_build_verdicts(
                BuildContext {
                    selection,
                    anchor_height: 1,
                    anchor_hash
                },
                Err(anyhow!("validation infrastructure failed")),
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("validation infrastructure failed")
    );
    Ok(())
}

#[tokio::test]
async fn stalled_local_build_does_not_delay_an_incoming_validation_reply() -> Result<()> {
    let (mut trial, _directory) = fixture().await?;
    let _engine = StopEngine(trial.consensus.engine.legacy_handle().actor.clone());
    trial.consensus.current_round = Round::new(0);
    trial.consensus.current_proposer = Some(trial.consensus.address);
    let anchor_hash = trial.execution.last_hash.unwrap();
    let selection = trial.preparation_selection().await?;
    let drops = Arc::new(AtomicUsize::new(0));
    let (entered, started) = oneshot::channel();
    let (_release, waiting) = oneshot::channel();
    trial.proposal_builder.start_build(
        BuildContext {
            selection: selection.clone(),
            anchor_height: 1,
            anchor_hash,
        },
        gated_verdicts(Ok(vec![]), entered, waiting, drops.clone()),
    )?;
    let raw = genesis_block(Network::Regtest).txdata.remove(0);
    let (reply, receive) = oneshot::channel();
    let (release_incoming, waiting) = oneshot::channel();
    let transaction = raw.clone();
    trial.validation_jobs.push_back(ValidationJob {
        verdicts: Box::pin(async move {
            waiting.await?;
            Ok(vec![(transaction, TxPolicy::Accepted)])
        }),
        proposal: IncomingProposal {
            value: Value::new_batch_raw(
                trial.consensus.protocol_context,
                1,
                anchor_hash,
                vec![raw.clone()],
            )?,
            selection,
            height: Height::new(2),
            round: Round::new(0),
            proposer: trial.consensus.address,
            anchor_height: 1,
            anchor_hash,
            parsed: vec![recognized(raw).parsed.unwrap()],
            reply,
        },
    });
    let shutdown = Shutdown::new();
    trial.shutdown = shutdown.signal();
    let drive = async {
        let result: Result<()> = async {
            timeout(Duration::from_secs(5), started).await??;
            release_incoming.send(()).unwrap();
            assert!(timeout(Duration::from_secs(5), receive).await??.is_some());
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            Ok(())
        }
        .await;
        shutdown.cancel();
        result
    };
    let (running, driven) = tokio::join!(trial.run_event_loop(), drive);
    driven?;
    running?;
    assert!(trial.proposal_builder.build_in_flight());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    trial.proposal_builder.reset();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn local_build_banks_while_an_incoming_validation_is_stalled() -> Result<()> {
    let (mut trial, _directory) = fixture().await?;
    let _engine = StopEngine(trial.consensus.engine.legacy_handle().actor.clone());
    trial.consensus.current_round = Round::new(0);
    trial.consensus.current_proposer = Some(trial.consensus.address);
    let anchor_hash = trial.execution.last_hash.unwrap();
    let selection = trial.preparation_selection().await?;
    let raw = genesis_block(Network::Regtest).txdata.remove(0);
    trial.consensus.mempool.insert(recognized(raw.clone()));
    let drops = Arc::new(AtomicUsize::new(0));
    let (entered, started) = oneshot::channel();
    let (_release, waiting) = oneshot::channel();
    let (reply, mut receive) = oneshot::channel();
    trial.validation_jobs.push_back(ValidationJob {
        verdicts: gated_verdicts(Ok(vec![]), entered, waiting, drops.clone()),
        proposal: IncomingProposal {
            value: Value::new_batch_raw(
                trial.consensus.protocol_context,
                1,
                anchor_hash,
                vec![raw.clone()],
            )?,
            selection: selection.clone(),
            height: Height::new(2),
            round: Round::new(0),
            proposer: trial.consensus.address,
            anchor_height: 1,
            anchor_hash,
            parsed: vec![recognized(raw.clone()).parsed.unwrap()],
            reply,
        },
    });
    let (release_local, waiting) = oneshot::channel();
    let (completed, observed) = oneshot::channel();
    trial.proposal_builder.start_build(
        BuildContext {
            selection,
            anchor_height: 1,
            anchor_hash,
        },
        Box::pin(async move {
            waiting.await?;
            let _ = completed.send(());
            Ok(vec![(raw, TxPolicy::Accepted)])
        }),
    )?;
    let (simulate, incoming) = mpsc::channel(1);
    trial.simulate_rx = Some(incoming);
    let shutdown = Shutdown::new();
    trial.shutdown = shutdown.signal();
    let drive = async {
        let result: Result<()> = async {
            timeout(Duration::from_secs(5), started).await??;
            release_local.send(()).unwrap();
            timeout(Duration::from_secs(5), observed).await??;
            // This request is a barrier through the next reactor iteration.
            let (reply, receive) = oneshot::channel();
            simulate.send((vec![0], reply)).await?;
            assert!(timeout(Duration::from_secs(5), receive).await???.is_err());
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            Ok(())
        }
        .await;
        shutdown.cancel();
        result
    };
    let (running, driven) = tokio::join!(trial.run_event_loop(), drive);
    driven?;
    running?;
    assert!(trial.proposal_builder.has_banked());
    assert!(!trial.proposal_builder.build_in_flight());
    assert_eq!(trial.validation_jobs.len(), 1);
    assert!(matches!(
        receive.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    trial.validation_jobs.clear();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    Ok(())
}
