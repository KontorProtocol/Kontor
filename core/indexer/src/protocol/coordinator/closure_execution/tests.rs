use bitcoin::{BlockHash, blockdata::constants::genesis_block, consensus::serialize, hashes::Hash};
use indexer_types::BlockRow;
use tempfile::TempDir;

use super::*;
use crate::consensus::signing::PrivateKey;
use crate::database::canonical_history::{self, HistoryState};
use crate::database::certified_history;
use crate::database::connection::new_connection;
use crate::database::queries::insert_block;
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::canonical_input::CanonicalInput;
use crate::protocol::coordinator::certified_decision::tests::proof;
use crate::protocol::coordinator::certified_decision::{AuthenticatedDecision, Decision};
use crate::protocol::coordinator::certified_input::{EraContext, ExactInput};
use crate::protocol::coordinator::genesis::bind_identity;
use crate::protocol::coordinator::linked::{canonical_session, initialize};
use crate::protocol::coordinator::registration_history::ObservationPosition;
use crate::protocol::identity::{ExecutionIdentity, ProtocolId};
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
    let context = EraContext {
        chain,
        era: [2; 32],
        protocol: ProtocolId([3; 32]),
        codec: 1,
    };
    certified_history::begin_genesis(&conn, context).await?;
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
    let certificate = proof(&decision, &[key], &[0], 0);
    let certified = AuthenticatedDecision::verify(decision, input, certificate, &authority)?;
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
    service.shutdown();
    Ok(())
}
