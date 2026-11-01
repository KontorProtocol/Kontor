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
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;

use crate::consensus::codec::encode_commit_certificate;
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Address, CommitCertificate, Ctx, Height, Value, Vote};
use crate::database::certified_history;
use crate::database::connection::new_connection;
use crate::database::queries::{insert_batch, insert_block};
use crate::protocol::coordinator::bootstrap;
use crate::protocol::coordinator::certified_decision::{AuthenticatedDecision, Decision};
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::coordinator::linked::initialize;
use crate::protocol::operations::GenesisEnvelope;
use crate::reactor::consensus_state::certified_startup;
use crate::reactor::engine::EngineConfig;
use crate::reactor::mempool_fee_index::MempoolFeeIndex;
use crate::reactor::start_linked_consensus;
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::SessionFactory;
use crate::runtime::pool::LinkedSession;
use prost::Message;

fn certificate(value: &Value, round: u32) -> CommitCertificate<Ctx> {
    let key = PrivateKey::from([7; 32]);
    let address = Address::from_public_key(&key.public_key());
    let height = Height::new(1);
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
        Ok(json!({"authenticated": 1, "closed": 0, "ack_after_durable_input": true,
            "interrupted_append_rolled_back": true, "finalization_without_volatile_cache": true,
            "original_and_one_augmentation": true, "reopen_verified": true}))
    }.await;
    let stopped = state
        .engine_handle
        .actor
        .stop_and_wait(None, Some(Duration::from_secs(5)))
        .await;
    stopped.context("qualification engine shutdown")?;
    result
}
