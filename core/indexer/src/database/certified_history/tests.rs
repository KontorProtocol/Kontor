use bitcoin::{BlockHash, hashes::Hash};
use indexer_types::BlockRow;
use tempfile::TempDir;

use super::*;
use crate::consensus::signing::PrivateKey;
use crate::database::connection::new_connection;
use crate::database::queries::insert_block;
use crate::protocol::coordinator::certified_decision::tests::{fixture, proof};

async fn prepared() -> Result<(
    TempDir,
    Connection,
    CommitteeRecord,
    ExactInput,
    Decision,
    Vec<PrivateKey>,
)> {
    let directory = TempDir::new()?;
    let conn = new_connection(directory.path(), "certified.db").await?;
    initialize(&conn).await?;
    let (mut authority, input, mut decision, keys) = fixture();
    begin_genesis(&conn, authority.context).await?;
    conn.execute_batch("BEGIN IMMEDIATE").await?;
    canonical_history::bind_genesis(&conn, authority.context.chain).await?;
    conn.execute_batch("COMMIT").await?;
    authority.decision = genesis_predecessor(authority.context)?;
    authority.lineage = authority.context.chain.0;
    decision.predecessor = authority.decision;
    decision.committee = authority.id()?;
    finish_genesis(&conn, &authority).await?;
    Ok((directory, conn, authority, input, decision, keys))
}

#[tokio::test]
async fn append_is_atomic_reopened_and_exactly_retryable() -> Result<()> {
    let (directory, conn, authority, input, decision, keys) = prepared().await?;
    let certified = AuthenticatedDecision::verify(
        decision.clone(),
        input,
        proof(&decision, &keys, &[0, 1, 2], 0),
        &authority,
    )?;
    conn.execute_batch(
        "CREATE TRIGGER interrupt_append BEFORE INSERT ON certified_decisions
        BEGIN SELECT RAISE(ABORT, 'injected failure after input insertion'); END;",
    )
    .await?;
    assert!(append(&conn, &certified).await.is_err());
    let count: i64 = conn
        .query("SELECT COUNT(*) FROM certified_inputs", ())
        .await?
        .next()
        .await?
        .unwrap()
        .get(0)?;
    assert_eq!(count, 0);
    assert_eq!(frontier(&conn).await?.authenticated_height, 0);
    assert!(conn.is_autocommit());
    conn.execute_batch("DROP TRIGGER interrupt_append").await?;
    append(&conn, &certified).await?;
    let state = frontier(&conn).await?;
    assert_eq!(state.authenticated_height, 1);
    assert_eq!(state.closed_height, 0);
    assert_eq!(state.authenticated_id, Some(decision.id()?));
    drop(conn);
    let reopened = new_connection(directory.path(), "certified.db").await?;
    initialize(&reopened).await?;
    append(&reopened, &certified).await?;
    assert_eq!(frontier(&reopened).await?, state);
    let loaded = load(&reopened, 1).await?;
    assert_eq!(loaded.decision(), certified.decision());
    assert_eq!(loaded.input(), certified.input());
    assert_eq!(loaded.proof(), certified.proof());
    let synchronous: i64 = reopened
        .query("PRAGMA synchronous", ())
        .await?
        .next()
        .await?
        .unwrap()
        .get(0)?;
    assert_eq!(synchronous, 2);
    Ok(())
}

#[tokio::test]
async fn original_and_one_augmentation_survive_equivalent_certificates() -> Result<()> {
    let (_directory, conn, authority, input, decision, keys) = prepared().await?;
    let first = AuthenticatedDecision::verify(
        decision.clone(),
        input.clone(),
        proof(&decision, &keys, &[0, 1, 2], 0),
        &authority,
    )?;
    append(&conn, &first).await?;
    let second = AuthenticatedDecision::verify(
        decision.clone(),
        input.clone(),
        proof(&decision, &keys, &[1, 2, 3], 0),
        &authority,
    )?;
    assert!(append(&conn, &second).await.is_err());
    augment(&conn, &second).await?;
    augment(&conn, &second).await?;
    let third = AuthenticatedDecision::verify(
        decision.clone(),
        input,
        proof(&decision, &keys, &[3, 2, 0], 1),
        &authority,
    )?;
    augment(&conn, &third).await?;
    let row = conn
        .query(
            "SELECT original_proof, proof_augmentation FROM certified_decisions",
            (),
        )
        .await?
        .next()
        .await?
        .unwrap();
    assert_eq!(row.get::<Vec<u8>>(0)?, first.proof());
    assert_eq!(row.get::<Vec<u8>>(1)?, second.proof());
    assert_eq!(load(&conn, 1).await?.decision().id()?, decision.id()?);
    Ok(())
}

#[tokio::test]
async fn append_rejects_wrong_predecessor_authority_and_conflicting_input() -> Result<()> {
    let (_directory, conn, authority, input, decision, keys) = prepared().await?;
    let mut wrong = decision.clone();
    wrong.predecessor[0] ^= 1;
    let certified = AuthenticatedDecision::verify(
        wrong.clone(),
        input.clone(),
        proof(&wrong, &keys, &[0, 1, 2], 0),
        &authority,
    )?;
    assert!(append(&conn, &certified).await.is_err());
    let mut wrong_authority = authority.clone();
    wrong_authority.members[0].generation[0] ^= 1;
    wrong = decision.clone();
    wrong.committee = wrong_authority.id()?;
    let certified = AuthenticatedDecision::verify(
        wrong.clone(),
        input.clone(),
        proof(&wrong, &keys, &[0, 1, 2], 0),
        &wrong_authority,
    )?;
    assert!(append(&conn, &certified).await.is_err());
    let certified = AuthenticatedDecision::verify(
        decision.clone(),
        input.clone(),
        proof(&decision, &keys, &[0, 1, 2], 0),
        &authority,
    )?;
    append(&conn, &certified).await?;
    let different = ExactInput::batch(
        authority.context,
        10,
        BlockHash::from_byte_array([9; 32]),
        &[],
    )?;
    wrong = decision.clone();
    wrong.descriptor = different.descriptor().clone();
    let certified = AuthenticatedDecision::verify(
        wrong.clone(),
        different,
        proof(&wrong, &keys, &[0, 1, 2], 0),
        &authority,
    )?;
    assert!(append(&conn, &certified).await.is_err());
    assert_eq!(load(&conn, 1).await?.input(), &input);
    conn.execute("UPDATE certified_inputs SET body = x'00000001'", ())
        .await?;
    assert!(load(&conn, 1).await.is_err());
    Ok(())
}

#[tokio::test]
async fn old_populated_database_is_preserved_without_invented_authority() -> Result<()> {
    let directory = TempDir::new()?;
    let conn = new_connection(directory.path(), "legacy.db").await?;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(1)
            .hash(BlockHash::all_zeros())
            .build(),
    )
    .await?;
    initialize(&conn).await?;
    assert_eq!(frontier(&conn).await?.status, Status::Unavailable);
    let (authority, _, _, _) = fixture();
    assert!(begin_genesis(&conn, authority.context).await.is_err());
    assert!(finish_genesis(&conn, &authority).await.is_err());
    let count: i64 = conn
        .query("SELECT COUNT(*) FROM blocks", ())
        .await?
        .next()
        .await?
        .unwrap()
        .get(0)?;
    assert_eq!(count, 1);
    Ok(())
}

#[tokio::test]
async fn reserved_genesis_resumes_but_cannot_substitute_context() -> Result<()> {
    let directory = TempDir::new()?;
    let conn = new_connection(directory.path(), "genesis.db").await?;
    initialize(&conn).await?;
    let (authority, _, _, _) = fixture();
    begin_genesis(&conn, authority.context).await?;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(1)
            .hash(BlockHash::all_zeros())
            .build(),
    )
    .await?;
    drop(conn);
    let reopened = new_connection(directory.path(), "genesis.db").await?;
    initialize(&reopened).await?;
    assert_eq!(frontier(&reopened).await?.status, Status::Initializing);
    begin_genesis(&reopened, authority.context).await?;
    let mut different = authority.context;
    different.era[0] ^= 1;
    assert!(begin_genesis(&reopened, different).await.is_err());
    assert_eq!(frontier(&reopened).await?.context, Some(authority.context));
    Ok(())
}
