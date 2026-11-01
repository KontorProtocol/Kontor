use std::time::Duration;

use anyhow::Result;
use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, ScriptBuf, Transaction, TxIn, TxOut};
use indexer_types::{Inst, InstKind, Insts};
use malachitebft_app_channel::AppMsg;
use malachitebft_app_channel::app::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_app_channel::app::types::PeerId;
use malachitebft_core_consensus::Role;
use malachitebft_core_types::{Round, Validity};
use malachitebft_engine::host::Next;
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio::time::timeout;

use super::certified_fixture;
use super::consensus_state::proposal_sign_hash;
use super::execution::ExecutionContext;
use super::executor::RuntimeExecutor;
use super::{PruneConfig, Reactor, create_executor_session};
use crate::bitcoin_client::Client;
use crate::bitcoin_follower::event::BlockEvent;
use crate::consensus::signing::PrivateKey;
use crate::consensus::{
    Height, ProposalData, ProposalFin, ProposalInit, ProposalPart, ProposalParts, Validator,
    ValidatorSet, Value,
};
use crate::database::certified_history::{closure, completion, registrations};
use crate::database::queries::select_block_latest;
use crate::database::{Writer, canonical_history, certified_history};
use crate::protocol::coordinator::certified_input::EraContext;
use crate::runtime::ownership::OwnerService;
use crate::runtime::staking::{self, api as staking_api};
use crate::runtime::token::api as token_api;
use crate::runtime::{Decimal, GenesisParameters, GenesisValidator};
use crate::stopper::Shutdown;
use crate::test_utils::test_genesis;

#[tokio::test]
async fn next_height_uses_executed_stake_and_preserves_early_proposals() -> Result<()> {
    for deferred in [false, true] {
        for before_finalized in [false, true] {
            check_handoff(deferred, false, before_finalized).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn last_validator_exit_halts_before_releasing_the_next_height() -> Result<()> {
    for deferred in [false, true] {
        check_handoff(deferred, true, false).await?;
    }
    Ok(())
}

#[tokio::test]
async fn certified_a_b_a_replacement_preserves_history_and_restores_execution() -> Result<()> {
    let key = PrivateKey::from([17; 32]);
    let owner = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[31; 32])?);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: owner.x_only_public_key().0.to_string(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100.9999999"),
    }]);
    let dir = TempDir::new()?;
    let mut reactor = certified_fixture::reactor(dir.path(), &genesis, key.clone(), 1).await?;
    let a = certified_fixture::empty_block(1);
    let b = certified_fixture::block(1, a.prev_hash, 1, Vec::new());
    let mut saved = Vec::new();
    let mut first_state = None;
    let mut first_supply = None;
    for (index, block) in [a.clone(), b.clone(), a.clone()].into_iter().enumerate() {
        let height = Height::new(index as u64 + 1);
        let value = Value::from_input(block.exact_input(reactor.consensus.protocol_context)?)?;
        let proof = certified_fixture::certificate(&key, &value, height, Round::new(0));
        certified_fixture::proposal(&mut reactor, value, height, Round::new(0));
        let (reply, received) = oneshot::channel();
        reactor
            .consensus
            .receive_decision(&reactor.db_conn(), proof.clone(), reply)
            .await?;
        received.await?;
        let (reply, next) = oneshot::channel();
        reactor.handle_finalized(proof, reply).await?;
        reactor.advance().await?;
        let Next::Start(next_height, _) = next.await? else {
            panic!("missing successor")
        };
        assert_eq!(next_height, Height::new(index as u64 + 2));
        let conn = reactor.db_conn();
        let state = canonical_history::state(&conn).await?;
        let supply = token_api::total_supply(&mut *reactor.execution.test_runtime().await).await?;
        if index == 0 {
            first_state = Some(state);
            first_supply = Some(supply);
        } else if index == 2 {
            assert_eq!(Some(state), first_state);
            assert_eq!(
                Some(supply),
                first_supply,
                "replacement must not duplicate emission"
            );
        }
        assert_eq!(reactor.execution.last_hash, Some(block.hash));
        saved.push(completion::completed(&conn, height.as_u64()).await?);
    }
    reactor
        .consensus
        .engine_handle
        .actor
        .get_cell()
        .stop_and_wait(None, Some(Duration::from_secs(5)))
        .await?;
    drop(reactor);
    let reactor = certified_fixture::reactor(dir.path(), &genesis, key, 1).await?;
    let conn = reactor.db_conn();
    let frontier = certified_history::frontier(&conn).await?;
    assert_eq!(
        (frontier.authenticated_height, frontier.closed_height),
        (3, 3)
    );
    assert_eq!(canonical_history::state(&conn).await?, first_state.unwrap());
    assert_eq!(reactor.execution.last_hash, Some(a.hash));
    for (index, expected) in [a.hash, b.hash, a.hash].into_iter().enumerate() {
        let height = index as u64 + 1;
        assert_eq!(
            certified_history::branch::at(&conn, 1, height).await?,
            Some(expected)
        );
        assert_eq!(completion::completed(&conn, height).await?, saved[index]);
        assert_eq!(
            certified_history::load(&conn, height)
                .await?
                .decision()
                .height,
            height
        );
    }
    assert_ne!(saved[0].id()?, saved[2].id()?);
    assert_eq!(saved[0].output, saved[2].output);
    reactor
        .consensus
        .engine_handle
        .actor
        .get_cell()
        .stop_and_wait(None, Some(Duration::from_secs(5)))
        .await?;
    Ok(())
}

async fn check_handoff(deferred: bool, exiting: bool, before_finalized: bool) -> Result<()> {
    let key = PrivateKey::from([17; 32]);
    let owner = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[31; 32])?);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: owner.x_only_public_key().0.to_string(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100.9999999"),
    }]);
    let dir = TempDir::new()?;
    let mut reactor = certified_fixture::reactor(dir.path(), &genesis, key.clone(), 2).await?;
    let mut parent = certified_fixture::empty_block(1).hash;
    for block_height in 2..=if exiting { 14 } else { 2 } {
        let transactions = if exiting && block_height == 2 {
            vec![certified_fixture::transaction(
                &owner,
                Insts::direct(vec![
                    Inst {
                        gas_limit: 100_000,
                        kind: InstKind::Issuance,
                    },
                    Inst {
                        gas_limit: 100_000,
                        kind: InstKind::Call {
                            contract: staking::address(),
                            expr: "leave-validation()".into(),
                        },
                    },
                ]),
                1,
            )?]
        } else {
            Vec::new()
        };
        let block = certified_fixture::block(block_height, parent, 0, transactions);
        parent = block.hash;
        let height = Height::new(block_height - 1);
        let round = Round::new(0);
        let value = Value::from_input(block.exact_input(reactor.consensus.protocol_context)?)?;
        let certificate = certified_fixture::certificate(&key, &value, height, round);
        let (acknowledge, mut ack) = oneshot::channel();
        if !deferred {
            certified_fixture::proposal(&mut reactor, value.clone(), height, round);
        }
        reactor
            .consensus
            .receive_decision(&reactor.db_conn(), certificate.clone(), acknowledge)
            .await?;
        if deferred {
            assert!(matches!(
                ack.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert_eq!(
                certified_history::frontier(&reactor.db_conn())
                    .await?
                    .authenticated_height,
                height.as_u64() - 1
            );
            certified_fixture::proposal(&mut reactor, value, height, round);
            reactor
                .consensus
                .try_acknowledge_decision(&reactor.db_conn())
                .await?;
        }
        ack.await?;
        if before_finalized {
            reactor.consensus.current_round = round;
            reactor.consensus.current_proposer = Some(reactor.consensus.address);
            let parts = signed_block_proposal(reactor.consensus.protocol_context, &key, 2, 0, 3);
            let (reply, received) = oneshot::channel();
            reactor.accept_proposal_parts(parts, reply).await?;
            assert!(received.await?.is_none());
            assert_eq!(reactor.consensus.early_proposals.len(), 1);
        }
        let (reply, mut next) = oneshot::channel();
        reactor.handle_finalized(certificate, reply).await?;
        assert!(matches!(
            next.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        if exiting && deferred && block_height == 14 {
            let conn = reactor.db_conn();
            let before = canonical_history::state(&conn).await?;
            conn.execute_batch("CREATE TRIGGER fail_exit_observation BEFORE INSERT ON registration_observations BEGIN SELECT RAISE(ABORT, 'injected observation persistence failure'); END").await?;
            assert!(reactor.advance().await.is_err());
            assert_eq!(canonical_history::state(&conn).await?, before);
            assert_eq!(select_block_latest(&conn).await?.unwrap().height, 13);
            assert_eq!(
                staking_api::get_active_set(&mut *reactor.execution.test_runtime().await)
                    .await?
                    .len(),
                1
            );
            assert!(matches!(
                next.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(conn.is_autocommit());
            conn.execute_batch("DROP TRIGGER fail_exit_observation")
                .await?;
        }
        // No pending Bitcoin block or RPC is supplied after the durable acknowledgement.
        let execution = reactor.advance().await;
        if exiting && execution.is_err() {
            assert_eq!(
                block_height, 14,
                "validator exited before its scheduled epoch"
            );
            let error = execution.unwrap_err();
            assert!(
                error
                    .downcast_ref::<completion::InvalidNextAuthority>()
                    .is_some(),
                "{error:#}"
            );
            assert!(
                next.try_recv().is_err(),
                "must not authorize a new consensus height"
            );
            assert!(
                staking_api::get_active_set(&mut *reactor.execution.test_runtime().await)
                    .await?
                    .is_empty()
            );
            assert_eq!(reactor.execution.last_height, block_height);
            return check_exit_recovery(reactor, &dir, &genesis).await;
        }
        execution?;
        let Next::Start(next_height, params) = timeout(Duration::from_secs(5), next).await?? else {
            panic!("expected the next consensus height");
        };
        assert_eq!(next_height, Height::new(block_height));
        assert_eq!(
            params.validator_set.total_voting_power(),
            if exiting { 100 } else { 101 }
        );
        assert_eq!(reactor.execution.last_height, block_height);
        assert_eq!(
            select_block_latest(&reactor.db_conn())
                .await?
                .unwrap()
                .height,
            block_height
        );
        assert!(!exiting || block_height < 14, "last validator never exited");
    }
    if !exiting {
        check_early_proposal(&mut reactor, 0).await?;
        check_early_proposal(&mut reactor, 1).await?;
        check_buffer_authentication_and_limits(&mut reactor).await?;
    }
    reactor
        .consensus
        .engine_handle
        .actor
        .get_cell()
        .stop_and_wait(None, Some(Duration::from_secs(5)))
        .await?;
    Ok(())
}

async fn check_exit_recovery(
    reactor: Reactor<RuntimeExecutor>,
    directory: &TempDir,
    genesis: &GenesisParameters,
) -> Result<()> {
    let conn = reactor.db_conn();
    let frontier = certified_history::frontier(&conn).await?;
    let height = frontier.authenticated_height;
    assert_eq!(height, 13);
    assert_eq!(frontier.closed_height, 12);
    let progress = closure::recover(&conn, height).await?;
    assert!(progress.remaining.is_empty());
    let observation = registrations::latest(&conn).await?.unwrap();
    assert!(observation.committee.is_empty());
    assert_eq!(observation.entries.len(), 1);
    assert_eq!(observation.entries[0].value.as_ref().unwrap().1, 0);
    assert!(observation.entries[0].generation.is_none());
    assert!(
        certified_history::committee(&conn, height + 1)
            .await
            .is_err()
    );
    assert!(completion::completed(&conn, height).await.is_err());
    let canonical = canonical_history::state(&conn).await?;
    let context = reactor.execution.protocol_context;
    reactor
        .consensus
        .engine_handle
        .actor
        .get_cell()
        .stop_and_wait(None, Some(Duration::from_secs(5)))
        .await?;
    drop(conn);
    drop(reactor);

    // Recovery must encounter the authority gate without replaying the committed exit.
    let writer = Writer::new(directory.path(), "certified-fixture.db").await?;
    let service = OwnerService::new();
    let (executor, session, tip, hash) = create_executor_session(
        2,
        &writer,
        &service,
        Client::new("http://127.0.0.1:1".into(), String::new(), String::new())?,
        None,
        genesis,
        Network::Regtest,
    )
    .await?;
    let mut execution = ExecutionContext::new(
        executor,
        session,
        Network::Regtest,
        service,
        context,
        PruneConfig {
            enabled: false,
            retain_blocks: 144,
        },
        tip,
        hash,
    );
    let error = execution
        .recover(&Shutdown::new().signal())
        .await
        .unwrap_err();
    assert!(
        error
            .downcast_ref::<completion::InvalidNextAuthority>()
            .is_some(),
        "{error:#}"
    );
    let conn = execution.db_conn();
    assert!(conn.is_autocommit());
    assert_eq!(execution.owner_service.active_roots().await, 0);
    assert_eq!(canonical_history::state(&conn).await?, canonical);
    assert_eq!(closure::recover(&conn, height).await?, progress);
    assert_eq!(registrations::latest(&conn).await?, Some(observation));
    let reopened = certified_history::frontier(&conn).await?;
    assert_eq!(reopened.authenticated_height, height);
    assert_eq!(reopened.closed_height, frontier.closed_height);
    assert_eq!(reopened.closure_id, frontier.closure_id);
    assert!(
        certified_history::committee(&conn, height + 1)
            .await
            .is_err()
    );
    assert!(completion::completed(&conn, height).await.is_err());
    assert_eq!(select_block_latest(&conn).await?.unwrap().height, 14);
    assert!(
        staking_api::get_active_set(&mut *execution.test_runtime().await)
            .await?
            .is_empty()
    );
    Ok(())
}

async fn check_early_proposal(
    reactor: &mut Reactor<RuntimeExecutor>,
    target_round: u32,
) -> Result<()> {
    let height = Height::new(2);
    let round = Round::new(target_round);
    let proposer = reactor.consensus.address;
    let context = reactor.consensus.protocol_context;
    let block = certified_fixture::empty_block(3);
    let parts = signed_block_proposal(context, &PrivateKey::from([17; 32]), 2, target_round, 3);
    reactor.consensus.pending_blocks.insert(3, block.clone());
    assert_eq!(
        reactor.consensus.current_round,
        if target_round == 0 {
            Round::Nil
        } else {
            Round::new(target_round - 1)
        }
    );
    let already_buffered = reactor.consensus.early_proposals.len();
    let mut forged = parts.clone();
    forged.parts[2] =
        ProposalPart::Fin(ProposalFin::new(PrivateKey::from([99; 32]).sign(b"forged")));
    let (reply, received) = oneshot::channel();
    reactor.accept_proposal_parts(forged, reply).await?;
    assert!(received.await?.is_none());
    assert_eq!(reactor.consensus.early_proposals.len(), already_buffered);
    let publisher = proposal_peer(1);
    let stream_id = StreamId::new(vec![target_round as u8].into());
    for (sequence, content) in parts
        .parts
        .iter()
        .cloned()
        .map(StreamContent::Data)
        .chain([StreamContent::Fin])
        .enumerate()
    {
        let (reply, received) = oneshot::channel();
        // Exercise both relayed parts and transports without publisher metadata.
        let (from, published_by) = if target_round == 0 {
            (proposal_peer(sequence as u8 + 2), Some(publisher))
        } else {
            (publisher, None)
        };
        reactor
            .handle_consensus_msg(AppMsg::ReceivedProposalPart {
                from,
                published_by,
                part: StreamMessage::new(stream_id.clone(), sequence as u64, content),
                reply,
            })
            .await?;
        assert!(received.await?.is_none());
    }
    assert_eq!(reactor.consensus.early_proposals.len(), 1);
    for _ in 0..32 {
        let (reply, received) = oneshot::channel();
        reactor.accept_proposal_parts(parts.clone(), reply).await?;
        assert!(received.await?.is_none());
    }
    assert_eq!(reactor.consensus.early_proposals.len(), 1);
    assert!(
        !reactor
            .consensus
            .undecided
            .get(&height)
            .is_some_and(|rounds| rounds.contains_key(&round))
    );
    let (reply_value, received) = oneshot::channel();
    reactor
        .handle_consensus_msg(AppMsg::StartedRound {
            height,
            round,
            proposer,
            role: Role::Validator,
            reply_value,
        })
        .await?;
    let proposals = timeout(Duration::from_secs(5), received).await??;
    assert_eq!(proposals.len(), 1);
    assert_eq!(
        proposals[0].value,
        Value::from_input(block.exact_input(context)?)?
    );
    assert_eq!(proposals[0].validity, Validity::Valid);
    assert!(reactor.consensus.early_proposals.is_empty());
    Ok(())
}

fn proposal_peer(seed: u8) -> PeerId {
    let mut bytes = vec![0x12, 0x20];
    bytes.extend_from_slice(&[seed; 32]);
    PeerId::from_bytes(&bytes).expect("valid sha256 multihash peer id")
}

fn signed_block_proposal(
    context: EraContext,
    key: &PrivateKey,
    height: u64,
    round: u32,
    block: u64,
) -> ProposalParts {
    let height = Height::new(height);
    let round = Round::new(round);
    let proposer = Validator::new(key.public_key(), 1).address;
    let data = ProposalData::new(
        Value::from_input(
            certified_fixture::empty_block(block)
                .exact_input(context)
                .unwrap(),
        )
        .unwrap(),
    );
    let signature = key.sign(&proposal_sign_hash(height, round, &data));
    ProposalParts {
        height,
        round,
        proposer,
        parts: vec![
            ProposalPart::Init(ProposalInit::new(height, round, Round::Nil, proposer)),
            ProposalPart::Data(data),
            ProposalPart::Fin(ProposalFin::new(signature)),
        ],
    }
}

async fn check_buffer_authentication_and_limits(
    reactor: &mut Reactor<RuntimeExecutor>,
) -> Result<()> {
    let context = reactor.consensus.protocol_context;
    let state = &mut reactor.consensus;
    let key = PrivateKey::from([17; 32]);
    let newcomer = PrivateKey::from([18; 32]);
    let proposer = state.address;
    let height = Height::new(2);
    let next_height = Height::new(3);
    let round = Round::new(0);
    let old_set = state.current_validator_set.clone();
    state.current_round = round;

    // A forged copy arriving first cannot hide a later valid newcomer proposal.
    let genuine = signed_block_proposal(context, &newcomer, 3, 0, 4);
    let mut forged = genuine.clone();
    forged.parts[2] = ProposalPart::Fin(ProposalFin::new(key.sign(b"forged")));
    state.buffer_early_proposal(forged);
    state.buffer_early_proposal(genuine.clone());
    state.buffer_early_proposal(signed_block_proposal(context, &key, 2, 1, 3));
    assert_eq!(state.early_proposals.len(), 3);
    assert!(state.take_early_proposal(height, round, proposer).is_none());
    assert_eq!(state.early_proposals.len(), 3);
    assert!(
        state
            .take_early_proposal(height, Round::new(1), proposer)
            .is_some()
    );
    assert_eq!(state.early_proposals.len(), 2);
    state.current_validator_set = ValidatorSet::new([Validator::new(newcomer.public_key(), 1)]);
    let accepted = state
        .take_early_proposal(next_height, round, genuine.proposer)
        .unwrap();
    assert_eq!(accepted.parts, genuine.parts);
    assert!(state.early_proposals.is_empty());

    // Recheck membership after a set change, even for previously verified entries.
    state.current_validator_set = old_set.clone();
    state.buffer_early_proposal(signed_block_proposal(context, &key, 3, 0, 4));
    state.current_validator_set = ValidatorSet::new([Validator::new(newcomer.public_key(), 1)]);
    assert!(
        state
            .take_early_proposal(next_height, round, proposer)
            .is_none()
    );
    state.current_validator_set = old_set;
    state.buffer_early_proposal(signed_block_proposal(context, &key, 2, 1, 3));
    assert!(
        state
            .take_early_proposal(height, Round::new(1), genuine.proposer)
            .is_none()
    );
    assert!(state.early_proposals.is_empty());

    for (h, r) in [(1, 0), (2, 0), (2, 2), (3, 1), (4, 0)] {
        state.buffer_early_proposal(signed_block_proposal(context, &key, h, r, 4));
    }
    let mut nil = genuine.clone();
    nil.round = Round::Nil;
    state.buffer_early_proposal(nil);
    assert!(state.early_proposals.is_empty());
    state.current_height = Height::new(u64::MAX);
    state.current_round = Round::new(u32::MAX);
    state.buffer_early_proposal(signed_block_proposal(context, &key, 0, 0, 4));
    state.buffer_early_proposal(signed_block_proposal(context, &key, u64::MAX, 0, 4));
    assert!(state.early_proposals.is_empty());
    state.current_height = height;
    state.current_round = round;
    for block in 4..24 {
        state.buffer_early_proposal(signed_block_proposal(context, &newcomer, 3, 0, block));
    }
    assert_eq!(state.early_proposals.len(), 4);
    for block in 4..24 {
        state.buffer_early_proposal(signed_block_proposal(context, &key, 3, 0, block));
    }
    assert_eq!(state.early_proposals.len(), 16);
    assert!(
        state
            .take_early_proposal(Height::new(4), round, proposer)
            .is_none()
    );
    assert!(state.early_proposals.is_empty());

    let oversized_unknown = signed_large_proposal(context, &newcomer, 1024 * 1024, 4)?;
    state.buffer_early_proposal(oversized_unknown);
    assert!(state.early_proposals.is_empty());
    assert!(signed_large_proposal(context, &key, 8 * 1024 * 1024, 4).is_err());
    assert!(state.early_proposals.is_empty());
    for block in 4..7 {
        state.buffer_early_proposal(signed_large_proposal(context, &key, 3_000_000, block)?);
    }
    assert_eq!(state.early_proposals.len(), 2);
    assert!(
        state
            .early_proposals
            .iter()
            .map(|(_, bytes)| bytes)
            .sum::<usize>()
            <= 8 * 1024 * 1024
    );

    state.buffer_early_proposal(genuine);
    let before = certified_history::frontier(&reactor.db_conn()).await?;
    reactor
        .process_block_event(BlockEvent::Rollback { to_height: 2 })
        .await?;
    assert_eq!(
        certified_history::frontier(&reactor.db_conn()).await?,
        before
    );
    assert!(
        reactor
            .consensus
            .pending_blocks
            .keys()
            .all(|height| *height <= 2)
    );
    Ok(())
}

fn signed_large_proposal(
    context: EraContext,
    key: &PrivateKey,
    bytes: usize,
    block: u64,
) -> Result<ProposalParts> {
    let mut parts = signed_block_proposal(context, key, 3, 0, block);
    let data = ProposalData::new(Value::new_batch_raw(
        context,
        block,
        certified_fixture::empty_block(block).hash,
        vec![Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(vec![0; bytes]),
            }],
        }],
    )?);
    let signature = key.sign(&proposal_sign_hash(parts.height, parts.round, &data));
    parts.parts[1] = ProposalPart::Data(data);
    parts.parts[2] = ProposalPart::Fin(ProposalFin::new(signature));
    Ok(parts)
}
