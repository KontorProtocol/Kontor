use std::time::Duration;

use anyhow::{Context, Result, ensure};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;
use bitcoin::{BlockHash, Network, hashes::Hash};
use indexer_types::{BlockRow, Event};
use libsql::{Connection, params};
use malachitebft_app_channel::app::types::ProposedValue;
use malachitebft_core_types::{CommitSignature, NilOrVal, Round, Validity};
use malachitebft_engine::host::Next;
use serde_json::{Value as Json, json};
use tempfile::TempDir;
use tokio::sync::oneshot::error::TryRecvError;
use tokio::sync::{mpsc, oneshot, watch};

use crate::bitcoin_client::Client;
use crate::bitcoin_follower::block::BlockInput;
use crate::bitcoin_follower::event::BlockEvent;
use crate::consensus::codec::encode_commit_certificate;
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Address, CommitCertificate, Ctx, Height, Value, Vote};
use crate::database::certified_history::{self, closure, completion, finality, replay_input, work};
use crate::database::connection::new_connection;
use crate::database::queries::{insert_batch, insert_block, select_block_at_height};
use crate::protocol::canonical_application::{ApplicationSource, DecisionExclusions};
use crate::protocol::coordinator::application_closure::{StageOutcome, WorkItem};
use crate::protocol::coordinator::bootstrap;
use crate::protocol::coordinator::certified_decision::{AuthenticatedDecision, Decision};
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::coordinator::closure_execution::begin_stage;
use crate::protocol::coordinator::closure_record::ClosureRecord;
use crate::protocol::coordinator::decision::DeferredDecision;
use crate::protocol::coordinator::linked::initialize;
use crate::protocol::coordinator::replay_input::ReplayInput;
use crate::protocol::operations::GenesisEnvelope;
use crate::protocol_qualification::fixture::issuance_transaction;
use crate::reactor::batches::BatchOutcome;
use crate::reactor::consensus_state::certified_startup;
use crate::reactor::engine::EngineConfig;
use crate::reactor::executor::RuntimeExecutor;
use crate::reactor::mempool_fee_index::MempoolFeeIndex;
use crate::reactor::{PruneConfig, Reactor, start_linked_consensus};
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::SessionFactory;
use crate::runtime::pool::LinkedSession;
use crate::stopper::Shutdown;
use prost::Message;

fn certificate(value: &Value, round: u32) -> CommitCertificate<Ctx> {
    certificate_at(value, 1, round)
}

fn certificate_at(value: &Value, height: u64, round: u32) -> CommitCertificate<Ctx> {
    let key = PrivateKey::from([7; 32]);
    let address = Address::from_public_key(&key.public_key());
    let height = Height::new(height);
    let round = Round::new(round);
    let vote = Vote::new_precommit(height, round, NilOrVal::Val(value.id()), address);
    CommitCertificate {
        height,
        round,
        value_id: value.id(),
        commit_signatures: vec![CommitSignature {
            address,
            signature: key.sign(&vote.to_sign_bytes()),
        }],
    }
}

pub(crate) async fn run(
    factory: SessionFactory,
    service: &OwnerService,
    genesis: GenesisEnvelope,
) -> Result<Json> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "callbacks.db").await?;
    let network = Network::Regtest;
    let (baseline, fresh) = bootstrap::prepare(&conn, network, 100, &genesis).await?;
    ensure!(fresh);
    insert_block(
        &conn,
        BlockRow::builder()
            .height(0)
            .hash(BlockHash::all_zeros())
            .build(),
    )
    .await?;
    let session = LinkedSession::new(conn.clone(), factory(conn.clone()).await?);
    initialize(service, &session, network, 100, genesis).await?;
    bootstrap::complete(service, &session, network, &baseline).await?;
    // An unrelated legacy batch row must not select or erase certified history.
    insert_batch(
        &conn,
        99,
        50,
        &BlockHash::all_zeros().to_string(),
        &[],
        false,
    )
    .await?;
    let mut state = start_linked_consensus(
        EngineConfig {
            private_key: PrivateKey::from([7; 32]),
            listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
            persistent_peers: Vec::new(),
            data_dir: dir.path().to_path_buf(),
            consensus_enabled: false,
            discovery: Default::default(),
        },
        &session,
        service,
        network,
        None,
        None,
        0,
        MempoolFeeIndex::new(None),
    )
    .await?;
    let engine = state.engine_handle.actor.clone();
    let result = async {
        ensure!(state.current_height == Height::new(1));
        ensure!(conn.query("SELECT 1 FROM batches WHERE consensus_height = 99", ()).await?.next().await?.is_some());
        let unanchored = Value::new_batch_raw(state.protocol_context, 99, BlockHash::all_zeros(), vec![])?;
        let authority = certified_history::committee(&conn, 1).await?;
        let invalid = Decision { height: 1, predecessor: authority.decision, committee: authority.id()?, descriptor: unanchored.descriptor().clone() };
        let certified = AuthenticatedDecision::verify(invalid, unanchored.input().clone(), encode_commit_certificate(&certificate(&unanchored, 0))?.encode_to_vec(), &authority)?;
        ensure!(certified_history::append(&conn, &certified).await.is_err());
        ensure!(certified_history::frontier(&conn).await?.authenticated_height == 0);
        ensure!(certified_history::branch::tip(&conn).await?.is_none());
        let value = Value::from_input(ExactInput::block(state.protocol_context, 100, serialize(&genesis_block(network)))?)?;
        let proof = certificate(&value, 0);
        let (reply, mut ack) = oneshot::channel();
        state.receive_decision(&conn, proof.clone(), reply).await?;
        ensure!(matches!(ack.try_recv(), Err(TryRecvError::Empty)));
        ensure!(certified_history::frontier(&conn).await?.authenticated_height == 0);
        state.undecided.entry(Height::new(1)).or_default().insert(Round::new(0), ProposedValue {
            height: Height::new(1), round: Round::new(0), valid_round: Round::Nil,
            proposer: state.address, value: value.clone(), validity: Validity::Valid,
        });
        conn.execute_batch("CREATE TRIGGER interrupt_decision BEFORE INSERT ON certified_decisions BEGIN SELECT RAISE(ABORT, 'injected persistence failure'); END").await?;
        ensure!(state.try_acknowledge_decision(&conn).await.is_err());
        ensure!(matches!(ack.try_recv(), Err(TryRecvError::Empty)));
        ensure!(certified_history::frontier(&conn).await?.authenticated_height == 0);
        ensure!(conn.is_autocommit());
        ensure!(conn.query("SELECT 1 FROM certified_inputs", ()).await?.next().await?.is_none());
        conn.execute_batch("DROP TRIGGER interrupt_decision").await?;
        state.try_acknowledge_decision(&conn).await?;
        ack.await?;
        let original = certified_history::load(&conn, 1).await?;
        conn.execute_batch("BEGIN IMMEDIATE").await?;
        conn.execute("UPDATE certified_decisions SET bitcoin_height = ?1 WHERE height = ?2",
            params![101u64.to_be_bytes().to_vec(), 1u64.to_be_bytes().to_vec()]).await?;
        ensure!(certified_history::load(&conn, 1).await.is_err());
        conn.execute_batch("ROLLBACK").await?;
        ensure!(original.input() == value.input());
        ensure!(certified_history::branch::tip(&conn).await? == Some((100, genesis_block(network).block_hash())));
        ensure!(state.closed_next_height(&conn, Height::new(1)).await?.is_none());
        ensure!(state.current_height == Height::new(1));
        let original_proof = encode_commit_certificate(&proof)?.encode_to_vec();
        ensure!(original.proof() == original_proof);
        state.undecided.clear();
        let later = certificate(&value, 1);
        ensure!(state.finalized_value(&conn, &later).await? == value);
        let augmentation = conn.query("SELECT proof_augmentation FROM certified_decisions", ()).await?.next().await?.context("augmentation row")?.get::<Vec<u8>>(0)?;
        ensure!(augmentation == encode_commit_certificate(&later)?.encode_to_vec());
        state.finalized_value(&conn, &certificate(&value, 2)).await?;
        ensure!(conn.query("SELECT proof_augmentation FROM certified_decisions", ()).await?.next().await?.unwrap().get::<Vec<u8>>(0)? == augmentation);
        ensure!(certified_history::load(&conn, 1).await?.proof() == original_proof);
        let other = Value::new_batch_raw(state.protocol_context, 1, BlockHash::all_zeros(), vec![])?;
        ensure!(state.finalized_value(&conn, &certificate(&other, 0)).await.is_err());
        let (reply, ack) = oneshot::channel();
        state.receive_decision(&conn, certificate(&value, 3), reply).await?;
        ack.await?;
        let reopened = new_connection(dir.path(), "callbacks.db").await?;
        ensure!(certified_history::load(&reopened, 1).await?.input() == value.input());
        ensure!(certified_startup(&reopened).await.is_err());
        let frontier = certified_history::frontier(&reopened).await?;
        ensure!(frontier.authenticated_height == 1 && frontier.closed_height == 0);
        ensure!(service.active_roots().await == 0);
        let (_block_tx, block_rx) = mpsc::channel(1);
        let (_mempool_tx, mempool_rx) = mpsc::channel(1);
        let (addr_tx, _addr_rx) = watch::channel(None);
        let shutdown = Shutdown::new();
        let client = Client::new("http://127.0.0.1:1".into(), String::new(), String::new())?;
        let mut reactor = Reactor::from_session(RuntimeExecutor::new(client), session,
            network, service.clone(), block_rx, mempool_rx, shutdown.signal(), None, None,
            None, state, PruneConfig { enabled: false, retain_blocks: 144 }, 99, None, addr_tx);
        let decision = DeferredDecision { consensus_height: Height::new(1), value: value.clone(),
            certificate: original_proof, execution_txs: None };
        let block = BlockInput::from_exact(value.input())?;
        let initial = closure::canonical_position(&conn, baseline.context.chain).await?;
        closure::begin(&conn, 1).await?;
        ensure!(completion::publish(&conn, 1).await.is_err());
        conn.execute_batch("CREATE TRIGGER interrupt_stage BEFORE INSERT ON closure_stages BEGIN SELECT RAISE(ABORT, 'injected stage persistence failure'); END").await?;
        ensure!(reactor.handle_block(block.clone(), &decision).await.is_err());
        ensure!(closure::canonical_position(&conn, baseline.context.chain).await? == initial);
        ensure!(select_block_at_height(&conn, 100).await?.is_none());
        ensure!(closure::progress(&conn, 1).await?.stage == 0);
        ensure!(conn.is_autocommit() && service.active_roots().await == 0);
        conn.execute_batch("DROP TRIGGER interrupt_stage").await?;
        reactor.handle_block(block, &decision).await?;
        let applied = closure::recover(&reopened, 1).await?;
        ensure!(applied.stage == 1 && applied.next.map(|next| next.0) == Some(WorkItem::Finality));
        ensure!(applied.position.ordinal == initial.ordinal + 2);
        let foreign_cursor = work::qualify(&conn, &reopened, applied.work_origin()?).await?;
        let foreign_stage = begin_stage(service, &reactor.session, network, 1).await?.context("missing finality stage")?;
        ensure!(foreign_stage.finish(Ok(((), StageOutcome::FinalityEvaluated, foreign_cursor))).await.is_err());
        ensure!(closure::recover(&reopened, 1).await? == applied);

        // Inject a replay plan to test the stage/cursor mechanism independently
        // of the automatic finality policy.
        for interrupt in [true, false] {
            if interrupt {
                conn.execute_batch("CREATE TRIGGER interrupt_replay_plan BEFORE INSERT ON closure_stages BEGIN SELECT RAISE(ABORT, 'injected replay plan publication failure'); END").await?;
            }
            let stage = begin_stage(service, &reactor.session, network, 1).await?.context("missing finality plan stage")?;
            let result = async {
                let draft = work::begin(&conn, applied.work_origin()?).await?;
                let draft = work::append(&conn, draft, &[
                    WorkItem::Rollback { height: 99 }, WorkItem::Execute { decision: 1 }, WorkItem::Finality,
                ]).await?;
                let cursor = work::publish(&conn, draft).await?;
                Ok(((), StageOutcome::FinalityEvaluated, cursor))
            }.await;
            let finished = stage.finish(result).await;
            if interrupt {
                ensure!(finished.is_err());
                ensure!(work::for_origin(&reopened, applied.work_origin()?).await.is_err());
                ensure!(closure::recover(&reopened, 1).await? == applied);
                conn.execute_batch("DROP TRIGGER interrupt_replay_plan").await?;
            } else {
                finished?;
            }
        }
        let planned = closure::recover(&reopened, 1).await?;
        ensure!(planned.stage == 2 && planned.next.map(|next| next.0) == Some(WorkItem::Rollback { height: 99 }));
        reactor.rollback(99).await?;
        ensure!(closure::recover(&reopened, 1).await?.next.map(|next| next.0) == Some(WorkItem::Execute { decision: 1 }));
        reactor.handle_block(BlockInput::from_exact(value.input())?, &decision).await?;
        ensure!(closure::canonical_position(&conn, baseline.context.chain).await? == applied.position);

        ensure!(completion::publish(&conn, 1).await.is_err());
        ensure!(reactor.consensus.closed_next_height(&conn, Height::new(1)).await?.is_none());
        // The first block has no batch obligations. Exercise the owned finality
        // stage directly; full reactor finality/replay integration is separate.
        let stage = begin_stage(service, &reactor.session, network, 1).await?.context("missing finality stage")?;
        ensure!(stage.action() == WorkItem::Finality);
        let result = async {
            let (_, rollback) = reactor.consensus.run_finality_checks(&conn, 100).await?;
            ensure!(rollback.is_none());
            Ok(((), StageOutcome::FinalityEvaluated, stage.remaining_after()))
        }.await;
        stage.finish(result).await?;
        conn.execute_batch("CREATE TRIGGER interrupt_closure BEFORE INSERT ON decision_closures BEGIN SELECT RAISE(ABORT, 'injected closure publication failure'); END").await?;
        ensure!(completion::publish(&conn, 1).await.is_err());
        ensure!(certified_history::frontier(&conn).await?.closed_height == 0);
        ensure!(certified_history::committee(&conn, 2).await.is_err());
        ensure!(closure::progress(&conn, 1).await?.remaining.is_empty());
        conn.execute_batch("DROP TRIGGER interrupt_closure").await?;
        let completed = completion::publish(&conn, 1).await?;
        ensure!(completed.stages == 5 && completed.output == applied.position);
        ensure!(completion::publish(&conn, 1).await? == completed);
        ensure!(completion::completed(&reopened, 1).await? == completed);
        ensure!(certified_startup(&reopened).await?.1 == Height::new(2));
        ensure!(reactor.consensus.closed_next_height(&conn, Height::new(1)).await?.is_some());
        ensure!(reactor.consensus.current_height == Height::new(2));
        ensure!(select_block_at_height(&conn, 0).await?.is_some());
        ensure!(service.active_roots().await == 0);
        Ok::<_, anyhow::Error>((reactor, reopened, decision, completed))
    }.await;
    let result = match result {
        Ok((mut reactor, reopened, decision, completed)) => async {
            qualify_batches(&mut reactor, &reopened, service, &decision, &completed).await?;
            qualify_replacement(&mut reactor, &reopened, service, &decision, &completed).await?;
            qualify_finality(&mut reactor, &reopened, service).await?;
            qualify_live_closure(&mut reactor).await?;
            Ok(json!({"authenticated": 14, "closed": 14, "live_closure_driver": true, "automatic_finality_replay": true, "owned_replacement_rollback": true, "bounded_work_plan": true, "replay_plan_publication_atomic": true, "local_reorg_is_not_authority": true, "owned_batch_stages": true, "owned_block_stage": true,
            "closure_publication_atomic": true, "next_height_after_closure": true, "ack_after_durable_input": true,
            "interrupted_append_rolled_back": true, "finalization_without_volatile_cache": true,
            "original_and_one_augmentation": true, "reopen_verified": true}))
        }.await,
        Err(error) => Err(error),
    };
    let stopped = engine
        .stop_and_wait(None, Some(Duration::from_secs(5)))
        .await;
    stopped.context("qualification engine shutdown")?;
    result
}

async fn accept_for_closure(
    reactor: &mut Reactor<RuntimeExecutor>,
    value: Value,
    height: u64,
) -> Result<()> {
    let proof = certificate_at(&value, height, 0);
    reactor
        .consensus
        .undecided
        .entry(Height::new(height))
        .or_default()
        .insert(
            Round::new(0),
            ProposedValue {
                height: Height::new(height),
                round: Round::new(0),
                valid_round: Round::Nil,
                proposer: reactor.consensus.address,
                value,
                validity: Validity::Valid,
            },
        );
    let (reply, ack) = oneshot::channel();
    reactor
        .consensus
        .receive_decision(&reactor.db_conn(), proof, reply)
        .await?;
    ack.await?;
    Ok(())
}

async fn qualify_finality(
    reactor: &mut Reactor<RuntimeExecutor>,
    reopened: &Connection,
    service: &OwnerService,
) -> Result<()> {
    let conn = reactor.db_conn();
    let network = reactor.network;
    let parent = issuance_transaction()?;
    let parent_id = parent.compute_txid();
    let mut child = parent.clone();
    child.input[0].previous_output.txid = parent_id;
    child.input[0].previous_output.vout = 0;
    let child_id = child.compute_txid();
    let mut next_height = 5;
    let mut tip = reactor.last_hash.context("missing finality starting tip")?;
    for bitcoin_height in 100..=106 {
        if bitcoin_height > 100 {
            let mut block = genesis_block(network);
            block.header.prev_blockhash = tip;
            block.header.nonce = bitcoin_height as u32;
            tip = block.block_hash();
            let value = Value::from_input(ExactInput::block(
                reactor.consensus.protocol_context,
                bitcoin_height,
                serialize(&block),
            )?)?;
            accept_for_closure(reactor, value, next_height).await?;
            if bitcoin_height == 106 {
                // Commit the block first, then interrupt the planner before
                // publication. The failed parent is due; its child is not.
                let retained = certified_history::load(&conn, next_height).await?;
                let value = Value::from_input(retained.input().clone())?;
                let decision = DeferredDecision {
                    consensus_height: Height::new(next_height),
                    value: value.clone(),
                    certificate: retained.proof().to_vec(),
                    execution_txs: None,
                };
                reactor
                    .handle_block(BlockInput::from_exact(value.input())?, &decision)
                    .await?;
                let before = closure::progress(&conn, next_height).await?;
                let origin = before.work_origin()?;
                conn.execute_batch("CREATE TRIGGER interrupt_finality_seed BEFORE INSERT ON closure_finality_seeds BEGIN SELECT RAISE(ABORT, 'injected planner write failure'); END").await?;
                ensure!(finality::step(&conn, next_height).await.is_err());
                ensure!(conn.is_autocommit());
                ensure!(closure::progress(&reopened, next_height).await? == before);
                ensure!(work::for_origin(&reopened, origin).await.is_err());
                conn.execute_batch("DROP TRIGGER interrupt_finality_seed")
                    .await?;
                ensure!(!finality::step(&conn, next_height).await?);
                ensure!(closure::progress(&reopened, next_height).await? == before);
                ensure!(
                    conn.query(
                        "SELECT 1 FROM excluded_batch_txids WHERE batch_height = 5",
                        ()
                    )
                    .await?
                    .next()
                    .await?
                    .is_none()
                );
                let mut steps = 1;
                while !finality::step(&reopened, next_height).await? {
                    steps += 1;
                    ensure!(steps < 30, "bounded fixture planner failed to finish");
                }
                let draft = work::for_origin(&conn, origin).await?;
                ensure!(draft.cursor().is_err());
                let snapshot = conn.query("SELECT input_id FROM closure_replay_inputs WHERE plan_key = ?1 AND decision = ?2", params![origin.key()?.to_vec(), 7u64.to_be_bytes().to_vec()]).await?.next().await?.context("child replay input missing")?;
                let id: [u8; 32] = snapshot
                    .get::<Vec<u8>>(0)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("bad snapshot id"))?;
                let child_input = replay_input::get(&conn, id, origin, 7).await?;
                ensure!(
                    child_input.exclusions.direct.is_empty()
                        && child_input.exclusions.effective == vec![child_id.to_byte_array()]
                        && child_input.dropped_positions == vec![0]
                );
                conn.execute_batch("CREATE TRIGGER interrupt_finality_publish BEFORE INSERT ON closure_stages BEGIN SELECT RAISE(ABORT, 'injected finality publication failure'); END").await?;
                ensure!(reactor.apply_certified_closure(next_height).await.is_err());
                ensure!(work::for_origin(&reopened, origin).await?.cursor().is_err());
                ensure!(closure::progress(&reopened, next_height).await? == before);
                ensure!(
                    conn.query(
                        "SELECT 1 FROM excluded_batch_txids WHERE batch_height = 5",
                        ()
                    )
                    .await?
                    .next()
                    .await?
                    .is_none()
                );
                conn.execute_batch("DROP TRIGGER interrupt_finality_publish")
                    .await?;
            }
            reactor.apply_certified_closure(next_height).await?;
            ensure!(
                reactor
                    .consensus
                    .closed_next_height(&conn, Height::new(next_height))
                    .await?
                    .is_some()
            );
            next_height += 1;
        }
        if bitcoin_height <= 101 {
            let raw = if bitcoin_height == 100 {
                parent.clone()
            } else {
                child.clone()
            };
            let value = Value::new_batch_raw(
                reactor.consensus.protocol_context,
                bitcoin_height,
                tip,
                vec![raw],
            )?;
            accept_for_closure(reactor, value, next_height).await?;
            reactor.apply_certified_closure(next_height).await?;
            ensure!(
                reactor
                    .consensus
                    .closed_next_height(&conn, Height::new(next_height))
                    .await?
                    .is_some()
            );
            next_height += 1;
        }
    }
    ensure!(next_height == 13 && reactor.last_height == 106);
    ensure!(certified_startup(&reopened).await?.1 == Height::new(13));
    ensure!(
        conn.query(
            "SELECT 1 FROM transactions WHERE txid IN (?1, ?2)",
            params![parent_id.to_string(), child_id.to_string()]
        )
        .await?
        .next()
        .await?
        .is_none()
    );
    ensure!(
        conn.query(
            "SELECT 1 FROM excluded_batch_txids WHERE batch_height = 5 AND txid = ?1",
            [parent_id.to_string()]
        )
        .await?
        .next()
        .await?
        .is_some()
    );
    ensure!(
        conn.query(
            "SELECT 1 FROM excluded_batch_txids WHERE txid = ?1",
            [child_id.to_string()]
        )
        .await?
        .next()
        .await?
        .is_none()
    );
    ensure!(service.active_roots().await == 0);

    Ok(())
}

async fn qualify_batches(
    reactor: &mut Reactor<RuntimeExecutor>,
    reopened: &Connection,
    service: &OwnerService,
    decision: &DeferredDecision,
    completed: &ClosureRecord,
) -> Result<()> {
    let conn = reactor.db_conn();
    let network = reactor.network;
    for height in 2..=3 {
        let raw = if height == 2 {
            vec![]
        } else {
            genesis_block(network).txdata
        };
        let value = Value::new_batch_raw(
            reactor.consensus.protocol_context,
            100,
            genesis_block(network).block_hash(),
            raw.clone(),
        )?;
        let proof = certificate_at(&value, height, 0);
        let proof_bytes = encode_commit_certificate(&proof)?.encode_to_vec();
        reactor
            .consensus
            .undecided
            .entry(Height::new(height))
            .or_default()
            .insert(
                Round::new(0),
                ProposedValue {
                    height: Height::new(height),
                    round: Round::new(0),
                    valid_round: Round::Nil,
                    proposer: reactor.consensus.address,
                    value,
                    validity: Validity::Valid,
                },
            );
        let (reply, ack) = oneshot::channel();
        reactor
            .consensus
            .receive_decision(&conn, proof, reply)
            .await?;
        ack.await?;
        if height == 2 {
            conn.execute_batch("CREATE TRIGGER interrupt_batch_stage BEFORE INSERT ON closure_stages BEGIN SELECT RAISE(ABORT, 'injected batch stage failure'); END").await?;
            ensure!(
                reactor
                    .process_decided_batch(
                        100,
                        genesis_block(network).block_hash(),
                        Height::new(height),
                        &proof_bytes,
                        &raw,
                        None
                    )
                    .await
                    .is_err()
            );
            ensure!(
                closure::canonical_position(&conn, reactor.consensus.protocol_context.chain)
                    .await?
                    == completed.output
            );
            ensure!(closure::progress(&conn, height).await?.stage == 0);
            ensure!(
                conn.query("SELECT 1 FROM batches WHERE consensus_height = 2", ())
                    .await?
                    .next()
                    .await?
                    .is_none()
            );
            ensure!(reactor.consensus.unfinalized_batches.is_empty());
            conn.execute_batch("DROP TRIGGER interrupt_batch_stage")
                .await?;
        }
        let outcome = reactor
            .process_decided_batch(
                100,
                genesis_block(network).block_hash(),
                Height::new(height),
                &proof_bytes,
                &raw,
                None,
            )
            .await?;
        ensure!(
            outcome
                == if height == 2 {
                    BatchOutcome::Executed
                } else {
                    BatchOutcome::RecordedOnly
                }
        );
        let record = closure::stage(&conn, height, 1).await?;
        ensure!(
            record.outcome
                == if height == 2 {
                    StageOutcome::Applied
                } else {
                    StageOutcome::UnrecognizedBatch
                }
        );
        ensure!(record.applications.len() == if height == 2 { 1 } else { 0 });
        if height == 3 {
            let before = closure::progress(&conn, height).await?;
            let origin = before.work_origin()?;
            let retained = certified_history::load(&conn, height).await?;
            let txid = raw[0].compute_txid().to_byte_array();
            let frozen = ReplayInput {
                origin,
                decision: retained.decision().id()?,
                interval_since: 1,
                dropped_positions: vec![0],
                exclusions: DecisionExclusions {
                    consensus_height: height,
                    direct: vec![txid],
                    effective: vec![txid],
                },
            };
            let mut trailing = frozen.encode()?;
            trailing.push(0);
            ensure!(ReplayInput::decode(&trailing).is_err());
            let mut invalid = frozen.clone();
            invalid.exclusions.direct.push(txid);
            ensure!(invalid.encode().is_err());
            invalid = frozen.clone();
            invalid.exclusions.effective.clear();
            ensure!(invalid.encode().is_err());
            invalid = frozen.clone();
            invalid.dropped_positions = vec![raw.len() as u64];
            ensure!(invalid.transactions(&raw).is_err());
            invalid = frozen.clone();
            invalid.dropped_positions = vec![0, 0];
            ensure!(invalid.encode().is_err());
            // Effective txid sets alone cannot distinguish two occurrences.
            let repeated = vec![raw[0].clone(), raw[0].clone()];
            let mut occurrence = frozen.clone();
            occurrence.exclusions.direct.clear();
            ensure!(occurrence.transactions(&repeated)? == raw);
            let old_batch = certified_history::load(&conn, 2).await?;
            let empty = ReplayInput {
                origin,
                decision: old_batch.decision().id()?,
                interval_since: 1,
                dropped_positions: vec![],
                exclusions: DecisionExclusions {
                    consensus_height: 2,
                    direct: vec![],
                    effective: vec![],
                },
            };
            // The planner is not wired yet. Supply an explicit attempt to
            // exercise frozen subsets through actual rollback and execution.
            for interrupt in [true, false] {
                if interrupt {
                    conn.execute_batch("CREATE TRIGGER interrupt_frozen_plan BEFORE INSERT ON closure_stages BEGIN SELECT RAISE(ABORT, 'injected frozen plan failure'); END").await?;
                }
                let stage = begin_stage(service, &reactor.session, network, height)
                    .await?
                    .context("missing freeze stage")?;
                let result = async {
                    let draft = work::begin(&conn, origin).await?;
                    let mut bad = frozen.clone();
                    bad.interval_since = 2;
                    ensure!(replay_input::insert(&conn, &bad).await.is_err());
                    bad = frozen.clone();
                    bad.exclusions.direct = vec![[44; 32]];
                    bad.exclusions.effective = bad.exclusions.direct.clone();
                    ensure!(replay_input::insert(&conn, &bad).await.is_err());
                    let input = replay_input::insert(&conn, &frozen).await?;
                    ensure!(replay_input::insert(&conn, &frozen).await? == input);
                    let mut wrong_origin = origin;
                    wrong_origin.previous = [71; 32];
                    ensure!(
                        replay_input::get(&conn, input, wrong_origin, height)
                            .await
                            .is_err()
                    );
                    ensure!(replay_input::get(&conn, input, origin, 2).await.is_err());
                    let empty_input = replay_input::insert(&conn, &empty).await?;
                    let draft = work::append(
                        &conn,
                        draft,
                        &[
                            WorkItem::Rollback { height: 99 },
                            WorkItem::Execute { decision: 1 },
                            WorkItem::Replay {
                                decision: 2,
                                input: empty_input,
                            },
                            WorkItem::Replay {
                                decision: height,
                                input,
                            },
                            WorkItem::Finality,
                        ],
                    )
                    .await?;
                    conn.execute_batch("SAVEPOINT corrupt_replay_input").await?;
                    conn.execute(
                        "UPDATE closure_replay_inputs SET record = ?2 WHERE input_id = ?1",
                        params![input.to_vec(), empty.encode()?],
                    )
                    .await?;
                    ensure!(work::publish(&conn, draft).await.is_err());
                    conn.execute_batch(
                        "ROLLBACK TO corrupt_replay_input; RELEASE corrupt_replay_input",
                    )
                    .await?;
                    let cursor = work::publish(&conn, draft).await?;
                    ensure!(replay_input::insert(&conn, &frozen).await.is_err());
                    Ok(((), StageOutcome::FinalityEvaluated, cursor))
                }
                .await;
                let finished = stage.finish(result).await;
                if interrupt {
                    ensure!(finished.is_err());
                    ensure!(
                        replay_input::get(&reopened, frozen.id()?, origin, height)
                            .await
                            .is_err()
                    );
                    ensure!(closure::recover(&reopened, height).await? == before);
                    conn.execute_batch("DROP TRIGGER interrupt_frozen_plan")
                        .await?;
                } else {
                    finished?;
                }
            }
            ensure!(replay_input::get(&reopened, frozen.id()?, origin, height).await? == frozen);
            reactor.rollback(99).await?;
            reactor
                .handle_block(BlockInput::from_exact(decision.value.input())?, &decision)
                .await?;
            reactor
                .process_decided_batch(
                    100,
                    genesis_block(network).block_hash(),
                    Height::new(2),
                    old_batch.proof(),
                    &[],
                    None,
                )
                .await?;
            // No live direct-exclusion rows exist. Re-derivation would lose
            // the saved direct receipt; trying the original subset must fail.
            ensure!(
                conn.query("SELECT 1 FROM excluded_batch_txids", ())
                    .await?
                    .next()
                    .await?
                    .is_none()
            );
            let pending = closure::recover(&reopened, height).await?;
            ensure!(
                reactor
                    .process_decided_batch(
                        100,
                        genesis_block(network).block_hash(),
                        Height::new(height),
                        &proof_bytes,
                        &raw,
                        None
                    )
                    .await
                    .is_err()
            );
            ensure!(closure::recover(&reopened, height).await? == pending);
            conn.execute_batch("CREATE TRIGGER interrupt_frozen_batch BEFORE INSERT ON closure_stages BEGIN SELECT RAISE(ABORT, 'injected frozen batch failure'); END").await?;
            ensure!(
                reactor
                    .process_decided_batch(
                        100,
                        genesis_block(network).block_hash(),
                        Height::new(height),
                        &proof_bytes,
                        &[],
                        Some(&raw)
                    )
                    .await
                    .is_err()
            );
            ensure!(closure::recover(&reopened, height).await? == pending);
            conn.execute_batch("DROP TRIGGER interrupt_frozen_batch")
                .await?;
            ensure!(
                reactor
                    .process_decided_batch(
                        100,
                        genesis_block(network).block_hash(),
                        Height::new(height),
                        &proof_bytes,
                        &[],
                        Some(&raw)
                    )
                    .await?
                    == BatchOutcome::Executed
            );
            let replayed = closure::stage(&conn, height, pending.stage + 1).await?;
            let ApplicationSource::Batch { exclusions, .. } = &replayed.applications[0].source
            else {
                anyhow::bail!("missing replay batch application");
            };
            ensure!(*exclusions == frozen.exclusions);
            ensure!(replay_input::get(&reopened, frozen.id()?, origin, height).await? == frozen);
        }
        let stage = begin_stage(service, &reactor.session, network, height)
            .await?
            .context("missing batch finality stage")?;
        let result = async {
            let (_, rollback) = reactor.consensus.run_finality_checks(&conn, 100).await?;
            ensure!(rollback.is_none());
            Ok(((), StageOutcome::FinalityEvaluated, stage.remaining_after()))
        }
        .await;
        stage.finish(result).await?;
        completion::publish(&conn, height).await?;
        ensure!(
            reactor
                .consensus
                .closed_next_height(&conn, Height::new(height))
                .await?
                .is_some()
        );
    }

    Ok(())
}

async fn qualify_replacement(
    reactor: &mut Reactor<RuntimeExecutor>,
    reopened: &Connection,
    service: &OwnerService,
    decision: &DeferredDecision,
    completed: &ClosureRecord,
) -> Result<()> {
    let conn = reactor.db_conn();
    let network = reactor.network;
    ensure!(certified_startup(&reopened).await?.1 == Height::new(4));
    let before_replacement =
        closure::canonical_position(&conn, reactor.consensus.protocol_context.chain).await?;
    let old_hash = genesis_block(network).block_hash();
    let mut replacement = genesis_block(network);
    replacement.header.nonce = replacement.header.nonce.wrapping_add(1);
    let replacement_hash = replacement.block_hash();
    let replacement_value = Value::from_input(ExactInput::block(
        reactor.consensus.protocol_context,
        100,
        serialize(&replacement),
    )?)?;
    let replacement_block = BlockInput::from_exact(replacement_value.input())?;
    reactor
        .consensus
        .pending_blocks
        .insert(100, replacement_block.clone());
    reactor
        .process_block_event(BlockEvent::Rollback { to_height: 99 })
        .await?;
    ensure!(reactor.consensus.pending_blocks.is_empty());
    ensure!(reactor.last_height == 100 && reactor.last_hash == Some(old_hash));
    ensure!(
        closure::canonical_position(&conn, reactor.consensus.protocol_context.chain).await?
            == before_replacement
    );
    ensure!(certified_history::branch::tip(&conn).await? == Some((100, old_hash)));
    reactor
        .consensus
        .pending_blocks
        .insert(100, BlockInput::from_exact(decision.value.input())?);
    ensure!(reactor.pending_block_value().await?.is_none());
    reactor
        .consensus
        .pending_blocks
        .insert(100, replacement_block.clone());
    ensure!(reactor.pending_block_value().await? == Some(replacement_value.clone()));

    let proof = certificate_at(&replacement_value, 4, 0);
    let replacement_decision = DeferredDecision {
        consensus_height: Height::new(4),
        value: replacement_value.clone(),
        certificate: encode_commit_certificate(&proof)?.encode_to_vec(),
        execution_txs: None,
    };
    reactor
        .consensus
        .undecided
        .entry(Height::new(4))
        .or_default()
        .insert(
            Round::new(0),
            ProposedValue {
                height: Height::new(4),
                round: Round::new(0),
                valid_round: Round::Nil,
                proposer: reactor.consensus.address,
                value: replacement_value,
                validity: Validity::Valid,
            },
        );
    let (reply, ack) = oneshot::channel();
    reactor
        .consensus
        .receive_decision(&conn, proof, reply)
        .await?;
    ack.await?;
    let plan = closure::begin(&conn, 4).await?;
    ensure!(
        plan.next.map(|next| next.0) == Some(WorkItem::Rollback { height: 99 })
            && plan.remaining.count == 3
    );
    ensure!(reactor.rollback(98).await.is_err());
    conn.execute_batch("CREATE TRIGGER interrupt_rollback_stage BEFORE INSERT ON closure_stages BEGIN SELECT RAISE(ABORT, 'injected rollback stage failure'); END").await?;
    ensure!(reactor.rollback(99).await.is_err());
    ensure!(reactor.last_height == 100 && reactor.last_hash == Some(old_hash));
    ensure!(
        closure::canonical_position(&conn, reactor.consensus.protocol_context.chain).await?
            == before_replacement
    );
    ensure!(
        select_block_at_height(&conn, 100)
            .await?
            .context("old block lost after interrupted rollback")?
            .hash
            == old_hash
    );
    ensure!(closure::recover(&reopened, 4).await?.stage == 0);
    ensure!(conn.is_autocommit() && service.active_roots().await == 0);
    conn.execute_batch("DROP TRIGGER interrupt_rollback_stage")
        .await?;
    reactor.rollback(99).await?;
    let rolled_back = closure::recover(&reopened, 4).await?;
    ensure!(
        rolled_back.stage == 1
            && rolled_back.next.map(|next| next.0) == Some(WorkItem::Execute { decision: 4 })
            && rolled_back.remaining.count - rolled_back.remaining.index == 2
    );
    ensure!(reactor.last_height == 99 && reactor.last_hash.is_none());
    ensure!(select_block_at_height(&conn, 100).await?.is_none());
    ensure!(select_block_at_height(&conn, 0).await?.is_some());
    ensure!(certified_history::branch::at(&conn, 100, 1).await? == Some(old_hash));
    ensure!(certified_history::branch::tip(&conn).await? == Some((100, replacement_hash)));
    ensure!(completion::completed(&reopened, 1).await? == *completed);
    ensure!(certified_history::load(&conn, 2).await?.decision().height == 2);
    ensure!(certified_history::committee(&conn, 4).await?.height == 4);
    ensure!(certified_startup(&reopened).await.is_err());
    reactor
        .handle_block(replacement_block, &replacement_decision)
        .await?;
    reactor.apply_certified_closure(4).await?;
    let replacement_closure = completion::publish(&conn, 4).await?;
    ensure!(
        replacement_closure.stages == 3
            && replacement_closure.bitcoin_hash == replacement_hash.to_byte_array()
    );
    ensure!(
        reactor
            .consensus
            .closed_next_height(&conn, Height::new(4))
            .await?
            .is_some()
    );
    ensure!(certified_startup(&reopened).await?.1 == Height::new(5));
    ensure!(completion::completed(&reopened, 1).await? == *completed);
    ensure!(service.active_roots().await == 0);

    Ok(())
}

async fn qualify_live_closure(reactor: &mut Reactor<RuntimeExecutor>) -> Result<()> {
    let conn = reactor.db_conn();
    let (event_tx, mut events) = mpsc::channel(8);
    reactor.event_tx = Some(event_tx);
    let mut block = genesis_block(reactor.network);
    block.header.prev_blockhash = reactor.last_hash.context("missing live fixture tip")?;
    block.header.nonce = 107;
    let hash = block.block_hash();
    let value = Value::from_input(ExactInput::block(
        reactor.consensus.protocol_context,
        107,
        serialize(&block),
    )?)?;
    let proof = certificate_at(&value, 13, 0);
    accept_for_closure(reactor, value, 13).await?;
    reactor.consensus.undecided.clear();
    let mut competing = block;
    competing.header.nonce += 1;
    let competing_value = Value::from_input(ExactInput::block(
        reactor.consensus.protocol_context,
        107,
        serialize(&competing),
    )?)?;
    reactor
        .consensus
        .pending_blocks
        .insert(107, BlockInput::from_exact(competing_value.input())?);
    let (reply, mut next) = oneshot::channel();
    reactor.handle_finalized(proof.clone(), reply).await?;
    ensure!(matches!(next.try_recv(), Err(TryRecvError::Empty)));
    conn.execute_batch("CREATE TRIGGER interrupt_live_stage BEFORE INSERT ON closure_stages BEGIN SELECT RAISE(ABORT, 'injected live execution failure'); END").await?;
    ensure!(reactor.advance().await.is_err());
    ensure!(matches!(next.try_recv(), Err(TryRecvError::Empty)));
    ensure!(reactor.last_height == 106);
    ensure!(certified_history::frontier(&conn).await?.closed_height == 12);
    conn.execute_batch("DROP TRIGGER interrupt_live_stage")
        .await?;
    reactor.advance().await?;
    ensure!(matches!(next.await?, Next::Start(height, _) if height == Height::new(14)));
    ensure!(reactor.last_height == 107 && reactor.last_hash == Some(hash));
    ensure!(
        select_block_at_height(&conn, 107)
            .await?
            .context("certified block was not executed")?
            .hash
            == hash
    );
    ensure!(reactor.pending_block_value().await? == Some(competing_value));
    let completed = completion::completed(&conn, 13).await?;
    let (reply, next) = oneshot::channel();
    reactor.handle_finalized(proof, reply).await?;
    reactor.advance().await?;
    ensure!(matches!(next.await?, Next::Start(height, _) if height == Height::new(14)));
    ensure!(completion::completed(&conn, 13).await? == completed);

    let value = Value::new_batch_raw(reactor.consensus.protocol_context, 107, hash, vec![])?;
    let proof = certificate_at(&value, 14, 0);
    accept_for_closure(reactor, value, 14).await?;
    // Decided can finish execution before Finalized arrives. The later callback
    // must release Next without replaying the already committed empty batch.
    reactor.advance().await?;
    let completed = completion::completed(&conn, 14).await?;
    ensure!(reactor.consensus.current_height == Height::new(14));
    let (reply, next) = oneshot::channel();
    reactor.handle_finalized(proof, reply).await?;
    reactor.advance().await?;
    ensure!(matches!(next.await?, Next::Start(height, _) if height == Height::new(15)));
    ensure!(completion::completed(&conn, 14).await? == completed);
    let mut heartbeats = 0;
    while let Ok(event) = events.try_recv() {
        if let Event::BatchProcessed { txids } = event {
            ensure!(txids.is_empty());
            heartbeats += 1;
        }
    }
    ensure!(
        heartbeats == 1,
        "empty batch notification missing or duplicated"
    );
    Ok(())
}
