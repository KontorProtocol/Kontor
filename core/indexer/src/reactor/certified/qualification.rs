use std::time::Duration;

use anyhow::{Context, Result, ensure};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;
use bitcoin::{BlockHash, Network, hashes::Hash};
use indexer_types::BlockRow;
use malachitebft_app_channel::app::types::ProposedValue;
use malachitebft_core_types::{CommitSignature, NilOrVal, Round, Validity};
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
use crate::database::certified_history::{self, closure, completion, work};
use crate::database::connection::new_connection;
use crate::database::queries::{insert_batch, insert_block, select_block_at_height};
use crate::protocol::coordinator::application_closure::{StageOutcome, WorkItem};
use crate::protocol::coordinator::bootstrap;
use crate::protocol::coordinator::certified_decision::{AuthenticatedDecision, Decision};
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::coordinator::closure_execution::begin_stage;
use crate::protocol::coordinator::decision::DeferredDecision;
use crate::protocol::coordinator::linked::initialize;
use crate::protocol::operations::GenesisEnvelope;
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
        // of the unfinished finality policy that will produce these plans.
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
        for height in 2..=3 {
            let raw = if height == 2 { vec![] } else { genesis_block(network).txdata };
            let value = Value::new_batch_raw(reactor.consensus.protocol_context, 100, genesis_block(network).block_hash(), raw.clone())?;
            let proof = certificate_at(&value, height, 0);
            let proof_bytes = encode_commit_certificate(&proof)?.encode_to_vec();
            reactor.consensus.undecided.entry(Height::new(height)).or_default().insert(Round::new(0), ProposedValue {
                height: Height::new(height), round: Round::new(0), valid_round: Round::Nil,
                proposer: reactor.consensus.address, value, validity: Validity::Valid,
            });
            let (reply, ack) = oneshot::channel();
            reactor.consensus.receive_decision(&conn, proof, reply).await?;
            ack.await?;
            if height == 2 {
                conn.execute_batch("CREATE TRIGGER interrupt_batch_stage BEFORE INSERT ON closure_stages BEGIN SELECT RAISE(ABORT, 'injected batch stage failure'); END").await?;
                ensure!(reactor.process_decided_batch(100, genesis_block(network).block_hash(), Height::new(height), &proof_bytes, &raw, None).await.is_err());
                ensure!(closure::canonical_position(&conn, baseline.context.chain).await? == completed.output);
                ensure!(closure::progress(&conn, height).await?.stage == 0);
                ensure!(conn.query("SELECT 1 FROM batches WHERE consensus_height = 2", ()).await?.next().await?.is_none());
                ensure!(reactor.consensus.unfinalized_batches.is_empty());
                conn.execute_batch("DROP TRIGGER interrupt_batch_stage").await?;
            }
            let outcome = reactor.process_decided_batch(100, genesis_block(network).block_hash(), Height::new(height), &proof_bytes, &raw, None).await?;
            ensure!(outcome == if height == 2 { BatchOutcome::Executed } else { BatchOutcome::RecordedOnly });
            let record = closure::stage(&conn, height, 1).await?;
            ensure!(record.outcome == if height == 2 { StageOutcome::Applied } else { StageOutcome::UnrecognizedBatch });
            ensure!(record.applications.len() == if height == 2 { 1 } else { 0 });
            let stage = begin_stage(service, &reactor.session, network, height).await?.context("missing batch finality stage")?;
            let result = async {
                let (_, rollback) = reactor.consensus.run_finality_checks(&conn, 100).await?;
                ensure!(rollback.is_none());
                Ok(((), StageOutcome::FinalityEvaluated, stage.remaining_after()))
            }.await;
            stage.finish(result).await?;
            completion::publish(&conn, height).await?;
            ensure!(reactor.consensus.closed_next_height(&conn, Height::new(height)).await?.is_some());
        }
        ensure!(certified_startup(&reopened).await?.1 == Height::new(4));
        let before_replacement = closure::canonical_position(&conn, baseline.context.chain).await?;
        let old_hash = genesis_block(network).block_hash();
        let mut replacement = genesis_block(network);
        replacement.header.nonce = replacement.header.nonce.wrapping_add(1);
        let replacement_hash = replacement.block_hash();
        let replacement_value = Value::from_input(ExactInput::block(baseline.context, 100, serialize(&replacement))?)?;
        let replacement_block = BlockInput::from_exact(replacement_value.input())?;
        reactor.consensus.pending_blocks.insert(100, replacement_block.clone());
        reactor.process_block_event(BlockEvent::Rollback { to_height: 99 }).await?;
        ensure!(reactor.consensus.pending_blocks.is_empty());
        ensure!(reactor.last_height == 100 && reactor.last_hash == Some(old_hash));
        ensure!(closure::canonical_position(&conn, baseline.context.chain).await? == before_replacement);
        ensure!(certified_history::branch::tip(&conn).await? == Some((100, old_hash)));
        reactor.consensus.pending_blocks.insert(100, BlockInput::from_exact(value.input())?);
        ensure!(reactor.pending_block_value().await?.is_none());
        reactor.consensus.pending_blocks.insert(100, replacement_block.clone());
        ensure!(reactor.pending_block_value().await? == Some(replacement_value.clone()));

        let proof = certificate_at(&replacement_value, 4, 0);
        let replacement_decision = DeferredDecision {
            consensus_height: Height::new(4), value: replacement_value.clone(),
            certificate: encode_commit_certificate(&proof)?.encode_to_vec(), execution_txs: None,
        };
        reactor.consensus.undecided.entry(Height::new(4)).or_default().insert(Round::new(0), ProposedValue {
            height: Height::new(4), round: Round::new(0), valid_round: Round::Nil,
            proposer: reactor.consensus.address, value: replacement_value, validity: Validity::Valid,
        });
        let (reply, ack) = oneshot::channel();
        reactor.consensus.receive_decision(&conn, proof, reply).await?;
        ack.await?;
        let plan = closure::begin(&conn, 4).await?;
        ensure!(plan.next.map(|next| next.0) == Some(WorkItem::Rollback { height: 99 }) && plan.remaining.count == 3);
        ensure!(reactor.rollback(98).await.is_err());
        conn.execute_batch("CREATE TRIGGER interrupt_rollback_stage BEFORE INSERT ON closure_stages BEGIN SELECT RAISE(ABORT, 'injected rollback stage failure'); END").await?;
        ensure!(reactor.rollback(99).await.is_err());
        ensure!(reactor.last_height == 100 && reactor.last_hash == Some(old_hash));
        ensure!(closure::canonical_position(&conn, baseline.context.chain).await? == before_replacement);
        ensure!(select_block_at_height(&conn, 100).await?.context("old block lost after interrupted rollback")?.hash == old_hash);
        ensure!(closure::recover(&reopened, 4).await?.stage == 0);
        ensure!(conn.is_autocommit() && service.active_roots().await == 0);
        conn.execute_batch("DROP TRIGGER interrupt_rollback_stage").await?;
        reactor.rollback(99).await?;
        let rolled_back = closure::recover(&reopened, 4).await?;
        ensure!(rolled_back.stage == 1 && rolled_back.next.map(|next| next.0) == Some(WorkItem::Execute { decision: 4 }) && rolled_back.remaining.count - rolled_back.remaining.index == 2);
        ensure!(reactor.last_height == 99 && reactor.last_hash.is_none());
        ensure!(select_block_at_height(&conn, 100).await?.is_none());
        ensure!(select_block_at_height(&conn, 0).await?.is_some());
        ensure!(certified_history::branch::at(&conn, 100, 1).await? == Some(old_hash));
        ensure!(certified_history::branch::tip(&conn).await? == Some((100, replacement_hash)));
        ensure!(completion::completed(&reopened, 1).await? == completed);
        ensure!(certified_history::load(&conn, 2).await?.decision().height == 2);
        ensure!(certified_history::committee(&conn, 4).await?.height == 4);
        ensure!(certified_startup(&reopened).await.is_err());
        reactor.handle_block(replacement_block, &replacement_decision).await?;
        let stage = begin_stage(service, &reactor.session, network, 4).await?.context("replacement finality stage absent")?;
        let result = async {
            let (_, rollback) = reactor.consensus.run_finality_checks(&conn, 100).await?;
            ensure!(rollback.is_none());
            Ok(((), StageOutcome::FinalityEvaluated, stage.remaining_after()))
        }.await;
        stage.finish(result).await?;
        let replacement_closure = completion::publish(&conn, 4).await?;
        ensure!(replacement_closure.stages == 3 && replacement_closure.bitcoin_hash == replacement_hash.to_byte_array());
        ensure!(reactor.consensus.closed_next_height(&conn, Height::new(4)).await?.is_some());
        ensure!(certified_startup(&reopened).await?.1 == Height::new(5));
        ensure!(completion::completed(&reopened, 1).await? == completed);
        ensure!(service.active_roots().await == 0);
        Ok(json!({"authenticated": 4, "closed": 4, "owned_replacement_rollback": true, "bounded_work_plan": true, "replay_plan_publication_atomic": true, "local_reorg_is_not_authority": true, "owned_batch_stages": true, "owned_block_stage": true,
            "closure_publication_atomic": true, "next_height_after_closure": true, "ack_after_durable_input": true,
            "interrupted_append_rolled_back": true, "finalization_without_volatile_cache": true,
            "original_and_one_augmentation": true, "reopen_verified": true}))
    }.await;
    let stopped = engine
        .stop_and_wait(None, Some(Duration::from_secs(5)))
        .await;
    stopped.context("qualification engine shutdown")?;
    result
}
