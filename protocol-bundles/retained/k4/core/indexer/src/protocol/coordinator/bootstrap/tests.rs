use bitcoin::Network;
use indexer_types::BlockRow;

use super::*;
use crate::bitcoin_client::Client;
use crate::consensus::signing::PrivateKey;
use crate::database::Writer;
use crate::database::canonical_history;
use crate::database::queries::insert_block;
use crate::protocol::identity::ChainId;
use crate::reactor::create_executor_session;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::{Decimal, GenesisValidator};
use crate::test_utils::{new_mock_block_hash, new_test_db, test_genesis};

#[tokio::test]
async fn live_bootstrap_persists_genesis_and_reopens_without_reapplying_it() -> Result<()> {
    let (_reader, writer, (dir, name)) = new_test_db().await?;
    let service = OwnerService::new();
    let key = PrivateKey::from([37; 32]);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let (_, session, height, hash) = create_executor_session(
        1,
        &writer,
        &service,
        Client::new("".into(), "".into(), "".into())?,
        &genesis,
        Network::Regtest,
    )
    .await?;
    assert_eq!((height, hash), (0, None));
    let conn = writer.connection();
    let state = certified_history::frontier(&conn).await?;
    assert_eq!(state.status, Status::Ready);
    let context = state.context.context("genesis context")?;
    let baseline = Baseline::current(context.chain)?;
    assert_eq!(context, baseline.context);
    assert_eq!(
        certified_history::protocol(&conn, context.protocol).await?,
        baseline.manifest
    );
    let authority = certified_history::committee(&conn, 1).await?;
    assert_eq!(authority.members.len(), 1);
    assert_eq!(authority.members[0].key, *key.public_key().as_bytes());
    let canonical = canonical_history::state(&conn).await?;
    let observation = registrations::at(&conn, 0, 0).await?;
    drop(session);
    let writer = Writer::new(dir.path(), &name).await?;
    let conn = writer.connection();
    let (_, session, _, _) = create_executor_session(
        1,
        &writer,
        &service,
        Client::new("".into(), "".into(), "".into())?,
        &genesis,
        Network::Regtest,
    )
    .await?;
    assert_eq!(canonical_history::state(&conn).await?, canonical);
    assert_eq!(certified_history::frontier(&conn).await?, state);
    assert_eq!(registrations::at(&conn, 0, 0).await?, observation);
    assert_eq!(service.active_roots().await, 0);
    assert!(session.conn.is_autocommit());

    assert_eq!(
        conn.query("PRAGMA synchronous", ())
            .await?
            .next()
            .await?
            .unwrap()
            .get::<u64>(0)?,
        2
    );
    conn.execute(
        "UPDATE certified_history_state SET closure_id = ?1",
        [vec![99u8; 32]],
    )
    .await?;
    assert!(
        create_executor_session(
            1,
            &writer,
            &service,
            Client::new("".into(), "".into(), "".into())?,
            &genesis,
            Network::Regtest
        )
        .await
        .is_err()
    );
    conn.execute(
        "UPDATE certified_history_state SET closure_id = ?1",
        [state.closure_id.unwrap().to_vec()],
    )
    .await?;
    conn.execute(
        "UPDATE canonical_history_state SET lineage = ?1",
        [vec![98u8; 32]],
    )
    .await?;
    assert!(
        create_executor_session(
            1,
            &writer,
            &service,
            Client::new("".into(), "".into(), "".into())?,
            &genesis,
            Network::Regtest
        )
        .await
        .is_err()
    );
    conn.execute(
        "UPDATE canonical_history_state SET lineage = ?1",
        [observation.position.lineage.to_vec()],
    )
    .await?;
    conn.execute("UPDATE certified_protocols SET manifest = x'00'", ())
        .await?;
    assert!(
        create_executor_session(
            1,
            &writer,
            &service,
            Client::new("".into(), "".into(), "".into())?,
            &genesis,
            Network::Regtest
        )
        .await
        .is_err()
    );
    assert_eq!(canonical_history::state(&conn).await?, canonical);
    assert_eq!(certified_history::frontier(&conn).await?, state);
    assert_eq!(service.active_roots().await, 0);
    service.shutdown();
    Ok(())
}

#[tokio::test]
async fn populated_untracked_database_is_preserved_and_refused() -> Result<()> {
    let (_reader, writer, (_dir, _name)) = new_test_db().await?;
    let conn = writer.connection();
    insert_block(
        &conn,
        BlockRow::builder()
            .height(7)
            .hash(new_mock_block_hash(7))
            .relevant(true)
            .build(),
    )
    .await?;
    let service = OwnerService::new();
    let error = create_executor_session(
        1,
        &writer,
        &service,
        Client::new("".into(), "".into(), "".into())?,
        &test_genesis(&[]),
        Network::Regtest,
    )
    .await
    .err()
    .context("populated database was accepted")?;
    assert!(error.downcast_ref::<HistoryUnavailable>().is_some());
    assert_eq!(
        certified_history::frontier(&conn).await?.status,
        Status::Unavailable
    );
    let row = conn
        .query("SELECT COUNT(*), MIN(height), MAX(height) FROM blocks", ())
        .await?
        .next()
        .await?
        .unwrap();
    assert_eq!(
        (row.get::<u64>(0)?, row.get::<u64>(1)?, row.get::<u64>(2)?),
        (1, 7, 7)
    );
    assert_eq!(
        conn.query("SELECT COUNT(*) FROM certified_protocols", ())
            .await?
            .next()
            .await?
            .unwrap()
            .get::<u64>(0)?,
        0
    );
    assert_eq!(service.active_roots().await, 0);
    service.shutdown();
    Ok(())
}

#[tokio::test]
async fn baseline_manifest_and_genesis_reservation_commit_atomically() -> Result<()> {
    let (_reader, writer, (_dir, _name)) = new_test_db().await?;
    let conn = writer.connection();
    certified_history::initialize(&conn).await?;
    let baseline = Baseline::current(ChainId([3; 32]))?;
    conn.execute_batch("CREATE TRIGGER reject_manifest BEFORE INSERT ON certified_protocols BEGIN SELECT RAISE(ABORT, 'injected manifest interruption'); END;").await?;
    assert!(
        certified_history::begin_baseline(&conn, &baseline, 1)
            .await
            .is_err()
    );
    assert_eq!(
        certified_history::frontier(&conn).await?.status,
        Status::Pending
    );
    assert!(conn.is_autocommit());
    conn.execute_batch("DROP TRIGGER reject_manifest;").await?;
    certified_history::begin_baseline(&conn, &baseline, 1).await?;
    let reserved = certified_history::frontier(&conn).await?;
    certified_history::begin_baseline(&conn, &baseline, 1).await?;
    assert_eq!(certified_history::frontier(&conn).await?, reserved);
    assert_eq!(
        certified_history::protocol(&conn, baseline.context.protocol).await?,
        baseline.manifest
    );
    let different = Baseline::current(ChainId([4; 32]))?;
    assert!(
        certified_history::begin_baseline(&conn, &different, 1)
            .await
            .is_err()
    );
    assert_eq!(certified_history::frontier(&conn).await?, reserved);
    Ok(())
}
