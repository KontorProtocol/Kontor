use bitcoin::{BlockHash, blockdata::constants::genesis_block, consensus::serialize, hashes::Hash};
use indexer_types::BlockRow;
use std::slice;
use tempfile::TempDir;

use super::*;
use crate::consensus::signing::PrivateKey;
use crate::database::canonical_history::{self, HistoryState};
use crate::database::certified_history::{self, completion, control, replay};
use crate::database::connection::new_connection;
use crate::database::queries::insert_block;
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::canonical_input::CanonicalInput;
use crate::protocol::coordinator::baseline::Baseline;
use crate::protocol::coordinator::certified_decision::tests::proof;
use crate::protocol::coordinator::certified_decision::{AuthenticatedDecision, Decision};
use crate::protocol::coordinator::certified_input::{CommandKind, ExactInput};
use crate::protocol::coordinator::control::{
    ApprovalSigner, ControlAction, ControlOperation, UpgradeControl,
};
use crate::protocol::coordinator::genesis::bind_identity;
use crate::protocol::coordinator::linked::{canonical_session, initialize};
use crate::protocol::coordinator::registration_history::ObservationPosition;
use crate::protocol::coordinator::selection::select_legacy_p1;
use crate::protocol::identity::ExecutionIdentity;
use crate::reg_tester::random_x_only_pubkey;

#[tokio::test]
async fn owned_closure_stage_records_real_observation_and_rolls_back_failed_effects() -> Result<()>
{
    let directory = TempDir::new()?;
    let conn = new_connection(directory.path(), "owned-closure.db").await?;
    certified_history::initialize(&conn).await?;
    let key = PrivateKey::from([7; 32]);
    let genesis = (
        "1".into(),
        vec![(
            random_x_only_pubkey(),
            "100".into(),
            key.public_key().as_bytes().to_vec(),
        )],
    );
    let chain = bind_identity(&conn, Network::Regtest, 1, &genesis).await?;
    let baseline = Baseline::for_node(chain)?;
    let context = baseline.context;
    certified_history::begin_baseline(&conn, &baseline, 1).await?;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(0)
            .hash(BlockHash::all_zeros())
            .build(),
    )
    .await?;
    let session = canonical_session(conn.clone(), Network::Regtest).await?;
    let service = OwnerService::new();
    initialize(&service, &session, Network::Regtest, 1, genesis).await?;
    let selection =
        select_legacy_p1(&conn, Network::Regtest, ApplicationPosition::Committee).await?;
    let lease =
        begin_canonical_unit(&service, &session, &selection, Network::Regtest, false).await?;
    let observed = observe_registrations(&session, &selection, Network::Regtest, vec![]).await;
    let observed = finish_canonical_unit(lease, observed, false).await?;
    let position = closure::canonical_position(&conn, chain).await?;
    let snapshot = RegistrationSnapshot::observe(
        None,
        ObservationPosition {
            context,
            height: 0,
            decision: certified_history::genesis_predecessor(context)?,
            stage: 0,
            lineage: position.lineage,
        },
        observed,
    )?;
    certified_history::finish_genesis(&conn, &snapshot).await?;
    let authority = snapshot.authority()?;
    let block = genesis_block(Network::Regtest);
    let input = ExactInput::block(context, 1, serialize(&block))?;
    let decision = Decision {
        height: 1,
        predecessor: authority.decision,
        committee: authority.id()?,
        descriptor: input.descriptor().clone(),
    };
    let certificate = proof(&decision, slice::from_ref(&key), &[0], 0);
    let certified =
        AuthenticatedDecision::verify(decision.clone(), input, certificate, &authority)?;
    certified_history::append(&conn, &certified).await?;
    conn.execute("CREATE TABLE owned_effect (value INTEGER)", ())
        .await?;

    let stage = begin_stage(&service, &session, Network::Regtest, 1)
        .await?
        .unwrap();
    assert_eq!(stage.action(), WorkItem::Execute { decision: 1 });
    assert_eq!(
        stage.selection().envelope().3,
        (3, 1, Some(block.block_hash().to_byte_array()), 1)
    );
    assert!(!conn.is_autocommit());
    conn.execute("INSERT INTO owned_effect VALUES (1)", ())
        .await?;
    assert!(
        stage
            .finish::<()>(Err(anyhow::anyhow!("injected application failure")))
            .await
            .is_err()
    );
    assert!(conn.is_autocommit());
    assert_eq!(service.active_roots().await, 0);
    assert_eq!(
        conn.query("SELECT COUNT(*) FROM owned_effect", ())
            .await?
            .next()
            .await?
            .unwrap()
            .get::<i64>(0)?,
        0
    );
    assert_eq!(closure::recover(&conn, 1).await?.stage, 0);

    let stage = begin_stage(&service, &session, Network::Regtest, 1)
        .await?
        .unwrap();
    let HistoryState::Ready(cursor) = canonical_history::state(&conn).await? else {
        panic!()
    };
    let application = CanonicalApplication {
        chain,
        ordinal: cursor.ordinal + 1,
        parent_lineage: cursor.lineage,
        execution: ExecutionIdentity::Baseline(session.executor.execution_definition?),
        storage_height: 1,
        source: ApplicationSource::BlockTransactions {
            height: 1,
            hash: block.block_hash().to_byte_array(),
            parent_hash: block.header.prev_blockhash.to_byte_array(),
        },
        input: Some(CanonicalInput::bitcoin(&block.txdata)?),
    };
    let lifecycle = CanonicalApplication {
        ordinal: application.ordinal + 1,
        parent_lineage: application.lineage()?,
        source: ApplicationSource::BlockLifecycle {
            height: 1,
            hash: block.block_hash().to_byte_array(),
        },
        input: None,
        ..application.clone()
    };
    conn.execute("INSERT INTO owned_effect VALUES (1)", ())
        .await?;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(1)
            .hash(block.block_hash())
            .build(),
    )
    .await?;
    canonical_history::append(&conn, &application).await?;
    canonical_history::append(&conn, &lifecycle).await?;
    let remaining = stage.remaining_after();
    let (_, record) = stage
        .finish(Ok(((), StageOutcome::Applied, remaining)))
        .await?;
    assert_eq!(record.applications, vec![application, lifecycle]);
    assert!(conn.is_autocommit());
    assert_eq!(service.active_roots().await, 0);
    let observed = registrations::at(&conn, 1, 1).await?;
    assert_eq!(observed.entries, snapshot.entries);
    let stage = begin_stage(&service, &session, Network::Regtest, 1)
        .await?
        .unwrap();
    assert_eq!(stage.action(), WorkItem::Finality);
    let remaining = stage.remaining_after();
    stage
        .finish(Ok(((), StageOutcome::FinalityEvaluated, remaining)))
        .await?;
    assert!(
        begin_stage(&service, &session, Network::Regtest, 1)
            .await?
            .is_none()
    );
    assert_eq!(closure::recover(&conn, 1).await?.stage, 2);
    assert_eq!(
        conn.query("SELECT COUNT(*) FROM owned_effect", ())
            .await?
            .next()
            .await?
            .unwrap()
            .get::<i64>(0)?,
        1
    );
    completion::publish(&conn, 1).await?;
    let authority = certified_history::committee(&conn, 2).await?;
    let state = control::admission::state(&conn, context).await?;
    let mut manifest = state.current_manifest.clone();
    manifest.protocol_number = 2;
    manifest.predecessor = context.protocol;
    let action = ControlAction {
        context,
        head: state.head,
        nonce: 1,
        expected_pending: None,
        reference_height: 1,
        reference_decision: decision.id()?,
        expires_at: 100,
        operation: ControlOperation::Schedule {
            manifest,
            activation: 1009,
        },
    };
    let envelope = UpgradeControl {
        approvals: vec![
            ApprovalSigner::new(key.clone()).sign(&action, authority.members[0].generation)?,
        ],
        action,
    };
    let input = ExactInput::control(context, 1, block.block_hash(), &envelope)?;
    let at = control::Position {
        decision: 2,
        stage: 0,
    };
    let accepted = control::admission::verify(&conn, &input, 2, at).await?;
    let mut invalid = envelope.clone();
    invalid.approvals[0].signature[0] ^= 1;
    let invalid = ExactInput::control(context, 1, block.block_hash(), &invalid)?;
    assert!(
        control::admission::verify(&conn, &invalid, 2, at)
            .await
            .is_err()
    );
    let wrong_anchor = ExactInput::control(context, 0, BlockHash::all_zeros(), &envelope)?;
    assert!(
        control::admission::verify(&conn, &wrong_anchor, 2, at)
            .await
            .is_err()
    );
    let decision = Decision {
        height: 2,
        predecessor: decision.id()?,
        committee: authority.id()?,
        descriptor: input.descriptor().clone(),
    };
    let certified = AuthenticatedDecision::verify(
        decision.clone(),
        input,
        proof(&decision, slice::from_ref(&key), &[0], 0),
        &authority,
    )?;
    certified_history::append(&conn, &certified).await?;
    let stage = begin_stage(&service, &session, Network::Regtest, 2)
        .await?
        .unwrap();
    assert_eq!(
        control::admission::apply(&conn, 2, 2).await?,
        StageOutcome::Applied
    );
    assert_eq!(control::current(&conn).await?, Some(accepted.next.clone()));
    assert!(
        stage
            .finish::<()>(Err(anyhow::anyhow!("control publication interrupted")))
            .await
            .is_err()
    );
    assert_eq!(control::current(&conn).await?, None);
    assert_eq!(closure::recover(&conn, 2).await?.stage, 0);
    let stage = begin_stage(&service, &session, Network::Regtest, 2)
        .await?
        .unwrap();
    let outcome = control::admission::apply(&conn, 2, 2).await?;
    let remaining = stage.remaining_after();
    let (_, record) = stage.finish(Ok(((), outcome, remaining))).await?;
    assert_eq!(record.applications.len(), 1);
    assert_eq!(control::current(&conn).await?, Some(accepted.next.clone()));
    assert!(
        control::admission::verify(&conn, certified.input(), 2, at)
            .await
            .is_err()
    );
    let selected = replay::eligible(&conn, 2, 2).await?.unwrap();
    assert_eq!(selected.kind, CommandKind::Control);
    assert_eq!(replay::page(&conn, 2, 1, None).await?.len(), 2);
    let reopened = new_connection(directory.path(), "owned-closure.db").await?;
    assert_eq!(control::current(&reopened).await?, Some(accepted.next));
    assert_eq!(closure::recover(&reopened, 2).await?.stage, 1);
    let stage = begin_stage(&service, &session, Network::Regtest, 2)
        .await?
        .unwrap();
    let remaining = stage.remaining_after();
    stage
        .finish(Ok(((), StageOutcome::FinalityEvaluated, remaining)))
        .await?;
    completion::publish(&conn, 2).await?;
    assert_eq!(certified_history::frontier(&conn).await?.closed_height, 2);
    let authority = certified_history::committee(&conn, 3).await?;
    let state = control::admission::state(&conn, context).await?;
    let pending = state.pending.as_ref().unwrap();
    let action = ControlAction {
        context,
        head: state.head,
        nonce: state.nonce + 1,
        expected_pending: Some(pending.id),
        reference_height: 2,
        reference_decision: decision.id()?,
        expires_at: 100,
        operation: ControlOperation::Cancel {
            target: pending.manifest.id()?,
            activation: pending.activation,
        },
    };
    let envelope = UpgradeControl {
        approvals: vec![
            ApprovalSigner::new(key.clone()).sign(&action, authority.members[0].generation)?,
        ],
        action,
    };
    let input = ExactInput::control(context, 1, block.block_hash(), &envelope)?;
    let decision = Decision {
        height: 3,
        predecessor: decision.id()?,
        committee: authority.id()?,
        descriptor: input.descriptor().clone(),
    };
    let certified = AuthenticatedDecision::verify(
        decision.clone(),
        input,
        proof(&decision, &[key], &[0], 0),
        &authority,
    )?;
    certified_history::append(&conn, &certified).await?;
    let stage = begin_stage(&service, &session, Network::Regtest, 3)
        .await?
        .unwrap();
    let remaining = stage.remaining_after();
    let outcome = control::admission::apply(&conn, 3, 3).await?;
    stage.finish(Ok(((), outcome, remaining))).await?;
    assert!(control::current(&conn).await?.unwrap().pending.is_none());
    // An old closure binds its original application, not the latest control snapshot.
    assert_eq!(closure::recover(&conn, 2).await?.stage, 2);
    assert_eq!(completion::completed(&conn, 2).await?.height, 2);
    service.shutdown();
    Ok(())
}
