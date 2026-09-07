use std::time::Duration;

use anyhow::Result;
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
    ProposalParts, Value,
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
        check_handoff(deferred, false).await?;
    }
    Ok(())
}

#[tokio::test]
async fn last_validator_exit_halts_before_releasing_the_next_height() -> Result<()> {
    for deferred in [false, true] {
        check_handoff(deferred, true).await?;
    }
    Ok(())
}

async fn check_handoff(deferred: bool, exiting: bool) -> Result<()> {
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
        staking::begin_unstake(&mut runtime, &signer).await??;
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
        check_early_proposal(&mut reactor).await?;
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

async fn check_early_proposal(reactor: &mut Reactor<NoopExecutor>) -> Result<()> {
    let height = Height::new(2);
    let round = Round::new(0);
    let proposer = reactor.consensus.address;
    let hash = new_mock_block_hash(3);
    let data = ProposalData::new_block(3, hash);
    let signature = reactor
        .consensus
        .signing_provider
        .sign(&proposal_sign_hash(height, round, &data));
    let parts = ProposalParts {
        height,
        round,
        proposer,
        parts: vec![
            ProposalPart::Init(ProposalInit::new(height, round, Round::Nil, proposer)),
            ProposalPart::Data(data),
            ProposalPart::Fin(ProposalFin::new(signature)),
        ],
    };
    reactor.consensus.pending_blocks.insert(
        3,
        Block {
            height: 3,
            hash,
            prev_hash: new_mock_block_hash(2),
            transactions: Vec::new(),
        },
    );
    assert_eq!(reactor.consensus.current_round, Round::Nil);
    let mut forged = parts.clone();
    forged.parts[2] =
        ProposalPart::Fin(ProposalFin::new(PrivateKey::from([99; 32]).sign(b"forged")));
    let (reply, received) = oneshot::channel();
    reactor.accept_proposal_parts(forged, reply).await?;
    assert!(received.await?.is_none());
    assert!(reactor.consensus.early_proposals.is_empty());
    for _ in 0..32 {
        let (reply, received) = oneshot::channel();
        reactor.accept_proposal_parts(parts.clone(), reply).await?;
        assert!(received.await?.is_none());
    }
    assert_eq!(reactor.consensus.early_proposals.len(), 16);
    assert!(!reactor.consensus.undecided.contains_key(&height));
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
