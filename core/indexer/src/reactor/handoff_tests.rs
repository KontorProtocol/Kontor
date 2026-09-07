use std::time::Duration;

use anyhow::Result;
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use indexer_types::Block;
use malachitebft_app_channel::AppMsg;
use malachitebft_app_channel::app::types::ProposedValue;
use malachitebft_core_consensus::Role;
use malachitebft_core_types::{Round, Validity};
use malachitebft_engine::host::Next;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;

use super::consensus_state::proposal_sign_hash;
use super::engine::EngineConfig;
use super::executor::NoopExecutor;
use super::mempool_fee_index::MempoolFeeIndex;
use super::{PruneConfig, Reactor, start_consensus};
use crate::bitcoin_follower::event::BlockEvent;
use crate::consensus::signing::PrivateKey;
use crate::consensus::{
    CommitCertificate, Height, ProposalData, ProposalFin, ProposalInit, ProposalPart,
    ProposalParts, Validator, ValidatorSet, Value,
};
use crate::database::queries::select_block_latest;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::staking::api as staking;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, GenesisValidator};
use crate::stopper::Shutdown;
use crate::test_utils::{new_mock_block_hash, test_runtime_with_genesis};

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

async fn check_handoff(deferred: bool, exiting: bool, before_finalized: bool) -> Result<()> {
    let key = PrivateKey::from([17; 32]);
    let pubkey = random_x_only_pubkey();
    let (mut runtime, dir, _name) = test_runtime_with_genesis(&[GenesisValidator {
        x_only_pubkey: pubkey.clone(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100.9999999"),
    }])
    .await?;
    if exiting {
        runtime.set_context(1, None, None, None).await;
        let signer = Signer::Id(runtime.get_or_create_identity(&pubkey).await?);
        token::issue_to(
            &mut runtime,
            &Signer::Core(Box::new(Signer::Nobody)),
            HolderRef::from(&signer),
            Decimal::from("1000"),
        )
        .await??;
        staking::leave_validation(&mut runtime, &signer).await??;
    }
    let consensus = start_consensus(
        EngineConfig {
            private_key: key,
            listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
            persistent_peers: Vec::new(),
            data_dir: dir.path().to_path_buf(),
            consensus_enabled: false,
            discovery_enabled: false,
        },
        &mut runtime,
        None,
        None,
        1,
        MempoolFeeIndex::new(None),
    )
    .await?;
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
    for block_height in 2..=if exiting { 13 } else { 2 } {
        let block = Block {
            height: block_height,
            hash: new_mock_block_hash(block_height as u32),
            prev_hash: new_mock_block_hash((block_height - 1) as u32),
            transactions: Vec::new(),
        };
        let height = Height::new(block_height - 1);
        let round = Round::new(0);
        let value = Value::new_block(block.height, block.hash);
        let certificate = CommitCertificate::new(height, round, value.id(), Vec::new());
        reactor
            .consensus
            .undecided
            .entry(height)
            .or_default()
            .insert(
                round,
                ProposedValue {
                    height,
                    round,
                    valid_round: Round::Nil,
                    proposer: reactor.consensus.address,
                    value,
                    validity: Validity::Valid,
                },
            );
        if !deferred {
            reactor
                .consensus
                .pending_blocks
                .insert(block.height, block.clone());
        }
        if before_finalized {
            reactor.consensus.current_round = round;
            reactor.consensus.current_proposer = Some(reactor.consensus.address);
            let parts = signed_block_proposal(&PrivateKey::from([17; 32]), 2, 0, 3);
            let (reply, received) = oneshot::channel();
            reactor.accept_proposal_parts(parts, reply).await?;
            assert!(received.await?.is_none());
            assert_eq!(reactor.consensus.early_proposals.len(), 1);
        }
        let (reply, mut next) = oneshot::channel();
        // Certificate verification precedes this callback; this fixture exercises
        // native lifecycle execution and the reply that authorizes the next height.
        let finalized = reactor.handle_finalized(certificate, reply).await;
        let execution = if deferred {
            finalized?;
            reactor.advance().await?;
            assert!(matches!(
                next.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert_eq!(reactor.last_height, block_height - 1);
            reactor
                .process_block_event(BlockEvent::BlockInsert {
                    target_height: block_height,
                    block,
                })
                .await
        } else {
            match finalized {
                Ok(_) => reactor.advance().await,
                Err(error) => Err(error),
            }
        };
        if exiting && block_height == 13 {
            let error = execution.expect_err("removing the last validator must halt");
            assert!(format!("{error:#}").contains("validator set is empty"));
            assert!(
                next.try_recv().is_err(),
                "must not authorize a new consensus height"
            );
            assert!(
                staking::get_active_set(&mut reactor.runtime)
                    .await?
                    .is_empty()
            );
        } else {
            execution?;
            let Next::Start(next_height, params) = timeout(Duration::from_secs(5), next).await??
            else {
                panic!("expected the next consensus height");
            };
            assert_eq!(next_height, Height::new(block_height));
            assert_eq!(
                params.validator_set.total_voting_power(),
                if exiting { 100 } else { 101 }
            );
        }
        assert_eq!(reactor.last_height, block_height);
        assert_eq!(
            select_block_latest(&reactor.db_conn())
                .await?
                .unwrap()
                .height,
            block_height
        );
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

async fn check_early_proposal(
    reactor: &mut Reactor<NoopExecutor>,
    target_round: u32,
) -> Result<()> {
    let height = Height::new(2);
    let round = Round::new(target_round);
    let proposer = reactor.consensus.address;
    let hash = new_mock_block_hash(3);
    let parts = signed_block_proposal(&PrivateKey::from([17; 32]), 2, target_round, 3);
    reactor.consensus.pending_blocks.insert(
        3,
        Block {
            height: 3,
            hash,
            prev_hash: new_mock_block_hash(2),
            transactions: Vec::new(),
        },
    );
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
    assert_eq!(proposals[0].value, Value::new_block(3, hash));
    assert_eq!(proposals[0].validity, Validity::Valid);
    assert!(reactor.consensus.early_proposals.is_empty());
    Ok(())
}

fn signed_block_proposal(key: &PrivateKey, height: u64, round: u32, block: u64) -> ProposalParts {
    let height = Height::new(height);
    let round = Round::new(round);
    let proposer = Validator::new(key.public_key(), 1).address;
    let data = ProposalData::new_block(block, new_mock_block_hash(block as u32));
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

async fn check_buffer_authentication_and_limits(reactor: &mut Reactor<NoopExecutor>) -> Result<()> {
    let conn = reactor.db_conn();
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
    let genuine = signed_block_proposal(&newcomer, 3, 0, 4);
    let mut forged = genuine.clone();
    forged.parts[2] = ProposalPart::Fin(ProposalFin::new(key.sign(b"forged")));
    state.buffer_early_proposal(forged);
    state.buffer_early_proposal(genuine.clone());
    state.buffer_early_proposal(signed_block_proposal(&key, 2, 1, 3));
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
    state.buffer_early_proposal(signed_block_proposal(&key, 3, 0, 4));
    state.current_validator_set = ValidatorSet::new([Validator::new(newcomer.public_key(), 1)]);
    assert!(
        state
            .take_early_proposal(next_height, round, proposer)
            .is_none()
    );
    state.current_validator_set = old_set;
    state.buffer_early_proposal(signed_block_proposal(&key, 2, 1, 3));
    assert!(
        state
            .take_early_proposal(height, Round::new(1), genuine.proposer)
            .is_none()
    );
    assert!(state.early_proposals.is_empty());

    for (h, r) in [(1, 0), (2, 0), (2, 2), (3, 1), (4, 0)] {
        state.buffer_early_proposal(signed_block_proposal(&key, h, r, 4));
    }
    let mut nil = genuine.clone();
    nil.round = Round::Nil;
    state.buffer_early_proposal(nil);
    assert!(state.early_proposals.is_empty());
    state.current_height = Height::new(u64::MAX);
    state.current_round = Round::new(u32::MAX);
    state.buffer_early_proposal(signed_block_proposal(&key, 0, 0, 4));
    state.buffer_early_proposal(signed_block_proposal(&key, u64::MAX, 0, 4));
    assert!(state.early_proposals.is_empty());
    state.current_height = height;
    state.current_round = round;
    for block in 4..24 {
        state.buffer_early_proposal(signed_block_proposal(&newcomer, 3, 0, block));
    }
    assert_eq!(state.early_proposals.len(), 4);
    for block in 4..24 {
        state.buffer_early_proposal(signed_block_proposal(&key, 3, 0, block));
    }
    assert_eq!(state.early_proposals.len(), 16);
    assert!(
        state
            .take_early_proposal(Height::new(4), round, proposer)
            .is_none()
    );
    assert!(state.early_proposals.is_empty());

    let oversized_unknown = signed_large_proposal(&newcomer, 1024 * 1024, 4);
    state.buffer_early_proposal(oversized_unknown);
    assert!(state.early_proposals.is_empty());
    state.buffer_early_proposal(signed_large_proposal(&key, 8 * 1024 * 1024, 4));
    assert!(state.early_proposals.is_empty());
    for block in 4..7 {
        state.buffer_early_proposal(signed_large_proposal(&key, 4 * 1024 * 1024 - 1024, block));
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
    state.clear_on_rollback(&conn, 2).await?;
    assert!(state.early_proposals.is_empty());
    Ok(())
}

fn signed_large_proposal(key: &PrivateKey, bytes: usize, block: u64) -> ProposalParts {
    let mut parts = signed_block_proposal(key, 3, 0, block);
    let data = ProposalData::new_batch(
        block,
        new_mock_block_hash(block as u32),
        vec![Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(vec![0; bytes]),
            }],
        }],
    );
    let signature = key.sign(&proposal_sign_hash(parts.height, parts.round, &data));
    parts.parts[1] = ProposalPart::Data(data);
    parts.parts[2] = ProposalPart::Fin(ProposalFin::new(signature));
    parts
}
