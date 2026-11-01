use bitcoin::absolute::LockTime;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, BlockHash, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
    Witness, hashes::Hash,
};
use indexer_types::BlockRow;
use tempfile::TempDir;

use super::*;
use crate::consensus::signing::PrivateKey;
use crate::database::connection::new_connection;
use crate::database::queries::insert_block;
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::coordinator::certified_decision::tests::{fixture, proof};
use crate::protocol::coordinator::registration_history::{
    ObservationPosition, RegistrationSnapshot,
};
use crate::protocol::identity::{ExecutionDefinitionId, ExecutionIdentity};
use crate::protocol::registration::RegistrationObservation;

pub(super) fn observed(snapshot: &RegistrationSnapshot) -> RegistrationObservation {
    (
        snapshot.committee.clone(),
        snapshot
            .entries
            .iter()
            .map(|entry| (entry.holder.clone(), entry.value.clone()))
            .collect(),
    )
}

fn genesis_observation(authority: &CommitteeRecord) -> Result<RegistrationSnapshot> {
    let mut observed: Vec<_> = authority
        .members
        .iter()
        .map(|member| (member.holder.clone(), Some((member.key.to_vec(), 1, 0, 0))))
        .collect();
    observed.sort();
    RegistrationSnapshot::observe(
        None,
        ObservationPosition {
            context: authority.context,
            height: 0,
            decision: genesis_predecessor(authority.context)?,
            stage: 0,
            lineage: authority.context.chain.0,
        },
        (
            authority
                .members
                .iter()
                .map(|member| (member.address, member.key, member.power))
                .collect(),
            observed,
        ),
    )
}

pub(super) async fn prepared() -> Result<(
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
    let (mut authority, _, mut decision, keys) = fixture();
    let input = ExactInput::block(
        authority.context,
        1,
        serialize(&genesis_block(Network::Regtest)),
    )?;
    decision.descriptor = input.descriptor().clone();
    begin_genesis(&conn, authority.context).await?;
    conn.execute_batch("BEGIN IMMEDIATE").await?;
    canonical_history::bind_genesis(&conn, authority.context.chain).await?;
    conn.execute_batch("COMMIT").await?;
    let observation = genesis_observation(&authority)?;
    authority = observation.authority()?;
    decision.predecessor = authority.decision;
    decision.committee = authority.id()?;
    finish_genesis(&conn, &observation).await?;
    Ok((directory, conn, authority, input, decision, keys))
}

fn witnessed_block(transaction: Transaction) -> Block {
    let mut block = genesis_block(Network::Regtest);
    block.txdata.push(transaction);
    block.txdata[0].input[0].witness = Witness::from_slice(&[[0; 32]]);
    let commitment = Block::compute_witness_commitment(&block.witness_root().unwrap(), &[0; 32]);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(&commitment.to_byte_array());
    block.txdata[0].output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    block
}

#[tokio::test]
async fn unexecuted_decision_retains_exact_witnesses_across_restart() -> Result<()> {
    let (directory, conn, authority, _, mut decision, keys) = prepared().await?;
    let mut transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([4; 32]),
                vout: 0,
            },
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    transaction.input[0].witness = Witness::from_slice(&[b"decided witness"]);
    let block = witnessed_block(transaction.clone());
    let input = ExactInput::block(authority.context, 1, serialize(&block))?;
    decision.descriptor = input.descriptor().clone();
    let certified = AuthenticatedDecision::verify(
        decision.clone(),
        input,
        proof(&decision, &keys, &[0, 1, 2], 0),
        &authority,
    )?;
    append(&conn, &certified).await?;
    let saved = frontier(&conn).await?;
    assert_eq!(saved.authenticated_height, 1);
    assert_eq!(saved.closed_height, 0);
    drop(conn);

    let reopened = new_connection(directory.path(), "certified.db").await?;
    initialize(&reopened).await?;
    let loaded = load(&reopened, 1).await?;
    assert_eq!(loaded.input().transactions()?, block.txdata);
    assert_eq!(loaded.input(), certified.input());
    // No canonical batch has run. Durable input retention must not depend on its rows.
    let count: i64 = reopened
        .query("SELECT COUNT(*) FROM batches", ())
        .await?
        .next()
        .await?
        .unwrap()
        .get(0)?;
    assert_eq!(count, 0);

    let mut alternative = transaction.clone();
    alternative.input[0].witness = Witness::from_slice(&[b"different witness"]);
    assert_eq!(alternative.compute_txid(), transaction.compute_txid());
    assert_ne!(alternative.compute_wtxid(), transaction.compute_wtxid());
    let alternative_input = ExactInput::block(
        authority.context,
        1,
        serialize(&witnessed_block(alternative)),
    )?;
    let mut alternative_decision = decision;
    alternative_decision.descriptor = alternative_input.descriptor().clone();
    let conflicting = AuthenticatedDecision::verify(
        alternative_decision.clone(),
        alternative_input,
        proof(&alternative_decision, &keys, &[0, 1, 2], 0),
        &authority,
    )?;
    assert!(append(&reopened, &conflicting).await.is_err());
    assert_eq!(frontier(&reopened).await?, saved);
    assert_eq!(
        load(&reopened, 1).await?.input().transactions()?,
        block.txdata
    );
    Ok(())
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
    assert!(
        finish_genesis(&conn, &genesis_observation(&authority)?)
            .await
            .is_err()
    );
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

#[tokio::test]
async fn registration_stages_commit_with_effects_and_survive_canonical_rollback() -> Result<()> {
    let (directory, conn, authority, input, decision, keys) = prepared().await?;
    let certified = AuthenticatedDecision::verify(
        decision.clone(),
        input,
        proof(&decision, &keys, &[0, 1, 2], 0),
        &authority,
    )?;
    append(&conn, &certified).await?;
    let genesis = registrations::at(&conn, 0, 0).await?;
    let application = CanonicalApplication {
        chain: authority.context.chain,
        ordinal: 1,
        parent_lineage: genesis.position.lineage,
        execution: ExecutionIdentity::Baseline(ExecutionDefinitionId([17; 32])),
        storage_height: 1,
        source: ApplicationSource::BlockLifecycle {
            height: 1,
            hash: [8; 32],
        },
        input: None,
    };
    let position = ObservationPosition {
        context: authority.context,
        height: 1,
        decision: decision.id()?,
        stage: 1,
        lineage: application.lineage()?,
    };
    let first = RegistrationSnapshot::observe(Some(&genesis), position, observed(&genesis))?;
    conn.execute_batch("CREATE TABLE stage_effect (value INTEGER); CREATE TRIGGER fail_observation BEFORE INSERT ON registration_observations BEGIN SELECT RAISE(ABORT, 'stage observation failure'); END;").await?;
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    unit.execute("INSERT INTO stage_effect VALUES (1)", ())
        .await?;
    canonical_history::append(&unit, &application).await?;
    assert!(registrations::record(&unit, &first).await.is_err());
    unit.rollback().await?;
    assert_eq!(registrations::latest(&conn).await?, Some(genesis.clone()));
    assert_eq!(
        conn.query("SELECT COUNT(*) FROM stage_effect", ())
            .await?
            .next()
            .await?
            .unwrap()
            .get::<i64>(0)?,
        0
    );
    let HistoryState::Ready(cursor) = canonical_history::state(&conn).await? else {
        panic!()
    };
    assert_eq!(cursor.ordinal, 0);
    conn.execute_batch("DROP TRIGGER fail_observation").await?;
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    unit.execute("INSERT INTO stage_effect VALUES (1)", ())
        .await?;
    canonical_history::append(&unit, &application).await?;
    registrations::record(&unit, &first).await?;
    unit.commit().await?;
    drop(conn);
    let conn = new_connection(directory.path(), "certified.db").await?;
    initialize(&conn).await?;
    assert_eq!(registrations::at(&conn, 1, 1).await?, first);
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    registrations::record(&unit, &first).await?;
    unit.commit().await?;
    assert_eq!(
        conn.query("SELECT COUNT(*) FROM stage_effect", ())
            .await?
            .next()
            .await?
            .unwrap()
            .get::<i64>(0)?,
        1
    );

    let mut after_exit = observed(&first);
    let key = after_exit.1[0].1.as_ref().unwrap().0.clone();
    after_exit.1[0].1 = None;
    after_exit.0.retain(|member| member.1.as_slice() != key);
    let second = RegistrationSnapshot::observe(
        Some(&first),
        ObservationPosition {
            stage: 2,
            lineage: genesis.position.lineage,
            ..position
        },
        after_exit,
    )?;
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    canonical_history::rollback(&unit, 0).await?;
    registrations::record(&unit, &second).await?;
    unit.commit().await?;
    assert_eq!(registrations::at(&conn, 1, 1).await?, first);
    assert_eq!(load(&conn, 1).await?.decision(), &decision);
    assert_eq!(committee(&conn, 1).await?, authority);
    let third = RegistrationSnapshot::observe(
        Some(&second),
        ObservationPosition {
            stage: 3,
            ..position
        },
        observed(&genesis),
    )?;
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    canonical_history::append(&unit, &application).await?;
    registrations::record(&unit, &third).await?;
    unit.commit().await?;
    assert_eq!(third.position.lineage, first.position.lineage);
    assert_ne!(third.entries[0].generation, first.entries[0].generation);
    assert_eq!(third.entries[1..], first.entries[1..]);
    Ok(())
}

#[tokio::test]
async fn registration_stage_rejects_wrong_decision_lineage_generation_and_writer() -> Result<()> {
    let (_directory, conn, authority, input, decision, keys) = prepared().await?;
    let genesis = registrations::at(&conn, 0, 0).await?;
    let certified = AuthenticatedDecision::verify(
        decision.clone(),
        input,
        proof(&decision, &keys, &[0, 1, 2], 0),
        &authority,
    )?;
    let next = RegistrationSnapshot::observe(
        Some(&genesis),
        ObservationPosition {
            height: 1,
            decision: decision.id()?,
            stage: 1,
            ..genesis.position
        },
        observed(&genesis),
    )?;
    assert!(registrations::record(&conn, &next).await.is_err());
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    assert!(registrations::record(&unit, &next).await.is_err());
    unit.rollback().await?;
    append(&conn, &certified).await?;
    for variant in 0..4 {
        let mut wrong = next.clone();
        match variant {
            0 => wrong.position.decision[0] ^= 1,
            1 => wrong.position.lineage[0] ^= 1,
            2 => wrong.entries[0].generation = Some([99; 32]),
            _ => wrong.position.stage = 2,
        }
        let unit = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        assert!(registrations::record(&unit, &wrong).await.is_err());
        unit.rollback().await?;
    }
    conn.execute_batch("PRAGMA synchronous = NORMAL").await?;
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    assert!(registrations::record(&unit, &next).await.is_err());
    unit.rollback().await?;
    assert_eq!(registrations::latest(&conn).await?, Some(genesis));
    Ok(())
}
