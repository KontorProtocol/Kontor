use std::slice;

use bitcoin::{blockdata::constants::genesis_block, consensus::serialize, hashes::Hash};
use indexer_types::BlockRow;
use tempfile::TempDir;

use super::*;
use crate::consensus::signing::PrivateKey;
use crate::database::certified_history::{
    self, completion, control, eras, finality, registrations, work,
};
use crate::database::connection::new_connection;
use crate::database::queries::insert_block;
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::canonical_input::CanonicalInput;
use crate::protocol::coordinator::activation::TransitionDescriptor;
use crate::protocol::coordinator::baseline::Baseline;
use crate::protocol::coordinator::certified_decision::tests::proof;
use crate::protocol::coordinator::certified_decision::{AuthenticatedDecision, Decision};
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::coordinator::control::{ControlState, PendingPlan};
use crate::protocol::coordinator::genesis::bind_identity;
use crate::protocol::coordinator::linked::{
    begin_canonical_unit, canonical_session, finish_canonical_unit, initialize,
    observe_registrations,
};
use crate::protocol::coordinator::registration_history::{
    ObservationPosition, RegistrationSnapshot,
};
use crate::protocol::coordinator::selection::{select_canonical, select_legacy_p1};
use crate::protocol::identity::PlanId;
use crate::protocol::v1::migration_definition;
use crate::reg_tester::random_x_only_pubkey;

// This starts from an accepted schedule and completed block application. The
// test exercises the real migration/observer/closure transaction, not approval
// notice or block transaction execution, which have their own admission tests.
// Use the registered no-op with populated native state. State-rewriting migration
// rollback is covered separately; the actual P2 backfill will need this full path.
pub(crate) async fn fixture() -> Result<(TempDir, LinkedSession, OwnerService, MigrationDefinition)>
{
    let directory = TempDir::new()?;
    let conn = new_connection(directory.path(), "activation.db").await?;
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
    let definition = migration_definition::noop(session.executor.execution_definition?);
    let mut target = baseline.manifest.clone();
    target.protocol_number = 2;
    target.predecessor = context.protocol;
    target.migration = definition.id()?;
    let state = ControlState {
        context,
        current_manifest: baseline.manifest,
        head: [10; 32],
        nonce: 1,
        pending: Some(PendingPlan {
            id: PlanId([3; 32]),
            manifest: target,
            activation: 1,
            consumed: false,
        }),
    };
    conn.execute("BEGIN", ()).await?;
    let position = closure::canonical_position(&conn, chain).await?;
    let control_application = CanonicalApplication {
        chain,
        ordinal: position.ordinal + 1,
        parent_lineage: position.lineage,
        execution: ExecutionIdentity::Baseline(session.executor.execution_definition?),
        storage_height: 0,
        source: ApplicationSource::UpgradeControl {
            decision: 1,
            action: [9; 32],
            control: state.head,
        },
        input: None,
    };
    canonical_history::append(&conn, &control_application).await?;
    control::record(
        &conn,
        &control_application,
        &state,
        control::Position {
            decision: 1,
            stage: 1,
        },
    )
    .await?;
    conn.execute("COMMIT", ()).await?;

    let selected =
        select_legacy_p1(&conn, Network::Regtest, ApplicationPosition::Committee).await?;
    let lease =
        begin_canonical_unit(&service, &session, &selected, Network::Regtest, false).await?;
    let observed = observe_registrations(&session, &selected, Network::Regtest, vec![]).await;
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
    let descriptor =
        TransitionDescriptor::expected(&state, 1, block.block_hash().to_byte_array(), 1)?;
    let ordinary = ExactInput::block(context, 1, serialize(&block))?;
    assert!(
        control::check_transition(&conn, ordinary.descriptor(), 1)
            .await
            .unwrap_err()
            .is::<control::ActivationRequired>()
    );
    let mut wrong = descriptor.clone().unwrap();
    wrong.plan = PlanId([99; 32]);
    assert!(
        control::check_transition(
            &conn,
            ordinary.clone().with_transition(wrong)?.descriptor(),
            1
        )
        .await
        .unwrap_err()
        .is::<control::RejectedTransition>()
    );
    let input = ordinary.with_transition(descriptor.unwrap())?;
    assert!(
        control::check_transition(&conn, input.descriptor(), 1)
            .await?
            .is_some()
    );
    assert!(
        control::check_installed_transition(&conn, input.descriptor(), 1)
            .await
            .unwrap_err()
            .is::<registry::UnavailableProtocol>()
    );
    assert!(
        control::check_transition(&conn, input.descriptor(), 2)
            .await
            .unwrap_err()
            .is::<control::RejectedTransition>()
    );
    let decision = Decision {
        height: 1,
        predecessor: authority.decision,
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
    let stage = begin_stage(&service, &session, Network::Regtest, 1)
        .await?
        .unwrap();
    insert_block(
        &conn,
        BlockRow::builder()
            .height(1)
            .hash(block.block_hash())
            .build(),
    )
    .await?;
    let position = closure::canonical_position(&conn, chain).await?;
    let transactions = CanonicalApplication {
        chain,
        ordinal: position.ordinal + 1,
        parent_lineage: position.lineage,
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
        ordinal: transactions.ordinal + 1,
        parent_lineage: transactions.lineage()?,
        source: ApplicationSource::BlockLifecycle {
            height: 1,
            hash: block.block_hash().to_byte_array(),
        },
        input: None,
        ..transactions.clone()
    };
    canonical_history::append(&conn, &transactions).await?;
    canonical_history::append(&conn, &lifecycle).await?;
    let remaining = stage.remaining_after();
    stage
        .finish(Ok(((), StageOutcome::Applied, remaining)))
        .await?;
    while !finality::step(&conn, 1).await? {}
    let progress = closure::progress(&conn, 1).await?;
    let draft = work::for_origin(&conn, progress.work_origin()?).await?;
    let stage = begin_stage(&service, &session, Network::Regtest, 1)
        .await?
        .unwrap();
    let remaining = work::publish(&conn, draft).await?;
    stage
        .finish(Ok(((), StageOutcome::FinalityEvaluated, remaining)))
        .await?;
    assert_eq!(
        closure::recover(&conn, 1).await?.next.map(|next| next.0),
        Some(WorkItem::Activate { decision: 1 })
    );
    Ok((directory, session, service, definition))
}

#[tokio::test]
async fn activation_observation_and_stage_commit_share_migration_transaction() -> Result<()> {
    let (directory, session, service, definition) = Box::pin(fixture()).await?;
    let conn = &session.conn;
    let before = canonical_history::state(conn).await?;
    let pending = control::current(conn).await?;
    let observation = registrations::latest(conn).await?.unwrap();
    let skipped = begin_stage(&service, &session, Network::Regtest, 1)
        .await?
        .unwrap();
    let remaining = skipped.remaining_after();
    let error = skipped
        .finish(Ok(((), StageOutcome::NoActivation, remaining)))
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("pending activation cannot be skipped"));
    assert_eq!(closure::recover(conn, 1).await?.stage, 2);
    let (_, anchor_height, anchor_hash) = boundary(&session, 1).await?;
    let selected = select_legacy_p1(
        conn,
        Network::Regtest,
        ApplicationPosition::Migration {
            anchor_height,
            anchor_hash,
        },
    )
    .await?;
    conn.execute_batch("CREATE TRIGGER fail_activation_stage BEFORE INSERT ON closure_stages WHEN NEW.stage = X'0000000000000003' BEGIN SELECT RAISE(ABORT, 'activation stage interrupted'); END;").await?;
    let error = apply(
        &service,
        &session,
        &selected,
        Network::Regtest,
        1,
        definition.clone(),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("activation stage interrupted"),
        "{error:#}"
    );
    assert!(conn.is_autocommit());
    assert_eq!(canonical_history::state(conn).await?, before);
    assert_eq!(control::current(conn).await?, pending);
    assert!(activation::current(conn).await?.is_none());
    assert_eq!(
        registrations::latest(conn).await?,
        Some(observation.clone())
    );
    assert_eq!(closure::recover(conn, 1).await?.stage, 2);
    conn.execute_batch("DROP TRIGGER fail_activation_stage")
        .await?;
    let selected = select_legacy_p1(
        conn,
        Network::Regtest,
        ApplicationPosition::Migration {
            anchor_height,
            anchor_hash,
        },
    )
    .await?;
    let record = apply(
        &service,
        &session,
        &selected,
        Network::Regtest,
        1,
        definition,
    )
    .await?;
    assert_eq!(record.outcome, StageOutcome::Applied);
    assert_eq!(record.applications.len(), 1);
    assert_eq!(record.stage, 3);
    assert!(
        select_canonical(conn, Network::Regtest, ApplicationPosition::View)
            .await
            .is_err(),
        "an unregistered protocol cannot fall back to its familiar executor definition"
    );
    assert!(control::current(conn).await?.unwrap().pending.is_none());
    let observed = registrations::latest(conn).await?.unwrap();
    assert_eq!(observed.entries, observation.entries);
    assert_eq!(observed.position.lineage, record.output.lineage);
    let reopened = new_connection(directory.path(), "activation.db").await?;
    assert_eq!(closure::recover(&reopened, 1).await?.stage, 3);
    assert_eq!(
        activation::current(&reopened).await?,
        activation::current(conn).await?
    );
    assert!(conn.is_autocommit());
    assert_eq!(service.active_roots().await, 0);

    let before_completion = certified_history::frontier(conn).await?;
    assert_eq!(before_completion.closed_height, 0);
    conn.execute_batch("CREATE TRIGGER fail_era_publication BEFORE INSERT ON completed_protocol_eras BEGIN SELECT RAISE(ABORT, 'era publication interrupted'); END;").await?;
    let error = completion::publish(conn, 1).await.unwrap_err();
    assert!(format!("{error:#}").contains("era publication interrupted"));
    assert_eq!(certified_history::frontier(conn).await?, before_completion);
    assert!(eras::at(conn, 1).await?.is_none());
    assert!(certified_history::committee(conn, 2).await.is_err());
    assert!(completion::completed(conn, 1).await.is_err());
    conn.execute_batch("DROP TRIGGER fail_era_publication")
        .await?;
    let completed = completion::publish(conn, 1).await?;
    let transition = eras::at(conn, 1).await?.unwrap();
    let next = certified_history::committee(conn, 2).await?;
    assert_eq!(next.context, transition.next);
    assert_eq!(next.members, observed.authority()?.members);
    assert_eq!(next.lineage, observed.position.lineage);
    assert_eq!(transition.previous, observed.position.context);
    assert_eq!(transition.start_height()?, 2);
    assert_eq!(eras::genesis(conn).await?, transition.previous);
    let after = certified_history::frontier(&reopened).await?;
    assert_eq!(after.genesis, before_completion.genesis);
    assert_eq!(after.context, Some(transition.next));
    assert_eq!(after.closed_height, 1);
    let projected = control::admission::state(conn, transition.next).await?;
    let historical = control::current(conn).await?.unwrap();
    assert_eq!(projected.current_manifest.id()?, transition.next.protocol);
    assert_eq!(projected.context, transition.next);
    assert_eq!(projected.head, historical.head);
    assert_eq!(projected.nonce, historical.nonce);
    assert_eq!(projected.pending, historical.pending);
    assert_eq!(historical.context, transition.previous);
    assert!(
        control::admission::state(conn, transition.previous)
            .await
            .is_err()
    );
    assert_eq!(completion::completed(&reopened, 1).await?, completed);
    assert_eq!(completion::publish(conn, 1).await?, completed);
    let original = certified_history::load(conn, 1).await?;
    certified_history::append(conn, &original).await?;
    certified_history::begin_baseline(conn, &Baseline::for_node(transition.next.chain)?, 1).await?;
    let mut second_block = genesis_block(Network::Regtest);
    second_block.header.prev_blockhash = second_block.block_hash();
    second_block.header.nonce = second_block.header.nonce.wrapping_add(1);
    let second_input = ExactInput::block(transition.next, 2, serialize(&second_block))?;
    let second_decision = Decision {
        height: 2,
        predecessor: original.decision().id()?,
        committee: next.id()?,
        descriptor: second_input.descriptor().clone(),
    };
    let certified = AuthenticatedDecision::verify(
        second_decision.clone(),
        second_input,
        proof(&second_decision, &[PrivateKey::from([7; 32])], &[0], 0),
        &next,
    )?;
    certified_history::append(conn, &certified).await?;
    assert_eq!(
        certified_history::frontier(conn)
            .await?
            .authenticated_height,
        2
    );
    assert_eq!(completion::completed(conn, 1).await?, completed);
    // Losing the handoff record must not make the new committee look valid.
    conn.execute("BEGIN", ()).await?;
    conn.execute("DELETE FROM completed_protocol_eras", ())
        .await?;
    assert!(certified_history::frontier(conn).await.is_err());
    assert!(completion::completed(conn, 1).await.is_err());
    conn.execute("ROLLBACK", ()).await?;
    Ok(())
}

#[tokio::test]
async fn uninstalled_target_keeps_activation_unfinished_without_mutation() -> Result<()> {
    let (_directory, session, service, _definition) = Box::pin(fixture()).await?;
    let before = canonical_history::state(&session.conn).await?;
    let error = step(&service, &session, Network::Regtest, 1)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("is not installed"));
    assert!(completion::publish(&session.conn, 1).await.is_err());
    assert_eq!(canonical_history::state(&session.conn).await?, before);
    assert_eq!(closure::recover(&session.conn, 1).await?.stage, 2);
    assert!(
        control::current(&session.conn)
            .await?
            .unwrap()
            .pending
            .is_some()
    );
    assert!(session.conn.is_autocommit());
    Ok(())
}
