use std::any::Any;
use std::future::pending;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures_util::FutureExt;
use indexer_types::BlockRow;
use libsql::{AuthAction, AuthContext, Authorization, Connection, Value, params};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use super::storage_identity::{
    CORE_SIGNER_ID as VERSIONED_CORE_SIGNER_ID, IdentityError, advance_nonce,
    ensure_identity as ensure_versioned,
};
use crate::database::queries::{
    Error as QueryError, create_core_signer, ensure_identity, get_checkpoint_latest,
    get_signer_entry_by_id, identity_callbacks, insert_block, insert_contract_state,
    nonce_callbacks,
};
use crate::database::types::{CORE_SIGNER_ID, ContractStateRow, Identity};
use crate::runtime::wit::Signer;
use crate::runtime::{ExecutionError, Storage};
use crate::test_utils::{new_mock_block_hash, new_test_db, test_runtime};

async fn initialize(conn: &Connection) -> Result<()> {
    for height in 0..=2 {
        insert_block(
            conn,
            BlockRow::builder()
                .height(height)
                .hash(new_mock_block_hash(height as u32))
                .build(),
        )
        .await?;
    }
    insert_contract_state(
        conn,
        ContractStateRow::builder()
            .contract_id(1)
            .height(1)
            .path(b"identity-baseline".to_vec())
            .value(vec![42])
            .build(),
    )
    .await?;
    Ok(())
}

async fn snapshot(conn: &Connection) -> Result<(Vec<Vec<Vec<Value>>>, String)> {
    let mut tables = Vec::new();
    for table in ["signers", "x_only_pubkeys", "nonces", "bls_keys"] {
        let mut rows = conn
            .query(&format!("SELECT * FROM {table} ORDER BY rowid"), ())
            .await?;
        let count = rows.column_count();
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(
                (0..count)
                    .map(|index| row.get_value(index))
                    .collect::<libsql::Result<Vec<_>>>()?,
            );
        }
        tables.push(values);
    }
    Ok((tables, get_checkpoint_latest(conn).await?.unwrap().hash))
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else {
        panic!("unexpected panic payload")
    }
}

#[tokio::test]
async fn identity_adapter_preserves_allocation_keys_versions_and_core_checks() -> Result<()> {
    let (_r1, w1, _t1) = new_test_db().await?;
    let (_r2, w2, _t2) = new_test_db().await?;
    let before = w1.connection();
    let after = w2.connection();
    initialize(&before).await?;
    initialize(&after).await?;
    let mut storage = Storage::builder().conn(after.clone()).build();
    for _ in 0..2 {
        assert_eq!(
            create_core_signer(&before).await?,
            storage.create_core_signer().await?
        );
        assert_eq!(snapshot(&after).await?, snapshot(&before).await?);
    }
    assert_eq!(storage.create_core_signer().await?, CORE_SIGNER_ID);
    for (height, pubkey) in [(1, "first"), (2, "second"), (2, "first")] {
        storage.height = height;
        let old = ensure_identity(&before, pubkey, height).await?;
        let id = storage.ensure_identity(pubkey).await?;
        assert_eq!(id, old.signer_id());
        assert_eq!(storage.lookup_identity(pubkey).await?, Some(id));
        assert_eq!(
            storage.identity_pubkey(id).await?,
            old.x_only_pubkey(&before).await?
        );
        for bytes in [vec![1; 96], vec![2; 96]] {
            old.register_bls_key(&before, &bytes, height).await?;
            storage.write_identity_bls_key(id, &bytes).await?;
            assert_eq!(
                storage.identity_bls_key(id).await?,
                old.bls_pubkey(&before).await?
            );
            assert_eq!(snapshot(&after).await?, snapshot(&before).await?);
            let entry = get_signer_entry_by_id(&before, id).await?.unwrap();
            assert_eq!(
                storage.signer_entry(id).await?,
                Some((
                    entry.signer_id,
                    entry.x_only_pubkey,
                    entry.bls_pubkey,
                    entry.next_nonce
                ))
            );
        }
    }
    assert_eq!(storage.lookup_identity("absent").await?, None);
    assert_eq!(storage.signer_entry(999).await?, None);
    let old = Identity::new(999).x_only_pubkey(&before).await.unwrap_err();
    assert_eq!(
        storage.identity_pubkey(999).await.unwrap_err().to_string(),
        old.to_string()
    );
    for conn in [&before, &after] {
        conn.execute("DELETE FROM bls_keys", ()).await?;
        conn.execute("DELETE FROM nonces", ()).await?;
        conn.execute("DELETE FROM x_only_pubkeys", ()).await?;
        conn.execute("DELETE FROM signers", ()).await?;
        conn.execute("INSERT INTO signers (id, height) VALUES (7, 0)", ())
            .await?;
    }
    assert_eq!(
        storage.create_core_signer().await.unwrap_err().to_string(),
        create_core_signer(&before).await.unwrap_err().to_string()
    );
    Ok(())
}

#[tokio::test]
async fn identity_adapter_late_creation_failure_preserves_partial_rows_and_rollback() -> Result<()>
{
    let (_r1, w1, _t1) = new_test_db().await?;
    let (_r2, w2, _t2) = new_test_db().await?;
    let before = w1.connection();
    let after = w2.connection();
    initialize(&before).await?;
    initialize(&after).await?;
    let storage = Storage::builder().conn(after.clone()).build();
    let saved = snapshot(&after).await?;
    before.execute("BEGIN", ()).await?;
    storage.savepoint().await?;
    for conn in [&before, &after] {
        conn.authorizer(Some(Arc::new(|context: &AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Insert {
                    table_name: "nonces"
                }
            ) {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        })))?;
    }
    let old = ensure_identity(&before, "partial", 1).await.unwrap_err();
    let new = storage.ensure_identity("partial").await.unwrap_err();
    assert!(matches!(new, IdentityError::Infrastructure(_)));
    assert_eq!(new.to_string(), old.to_string());
    for conn in [&before, &after] {
        conn.authorizer(None)?;
    }
    assert_ne!(snapshot(&after).await?, saved);
    assert_eq!(snapshot(&after).await?, snapshot(&before).await?);
    before.execute("ROLLBACK", ()).await?;
    storage.rollback().await?;
    assert_eq!(snapshot(&after).await?, saved);
    assert_eq!(storage.ensure_identity("fresh").await?, 1);
    Ok(())
}

#[tokio::test]
async fn identity_adapter_nonce_boundaries_errors_and_versions_match_original() -> Result<()> {
    let (_r1, w1, _t1) = new_test_db().await?;
    let (_r2, w2, _t2) = new_test_db().await?;
    let before = w1.connection();
    let after = w2.connection();
    initialize(&before).await?;
    initialize(&after).await?;
    let old = ensure_identity(&before, "nonce", 1).await?;
    let storage = Storage::builder().conn(after.clone()).build();
    let id = storage.ensure_identity("nonce").await?;
    for (stored, caller) in [
        (None, 0),
        (Some(0i64), 0),
        (Some(0), 10_000),
        (Some(0), 10_001),
        (Some(4), 3),
        (Some(i64::MAX), i64::MAX as u64),
        (Some(-1), u64::MAX),
        (Some(-2), u64::MAX - 1),
        (Some(-10002), u64::MAX),
    ] {
        for conn in [&before, &after] {
            conn.execute("DELETE FROM nonces", ()).await?;
            if let Some(value) = stored {
                conn.execute(
                    "INSERT INTO nonces (signer_id, next_nonce, height) VALUES (?, ?, 1)",
                    params![id, value],
                )
                .await?;
            }
        }
        let original = old
            .advance_nonce(&before, caller, 2)
            .await
            .map_err(|e| (matches!(e, QueryError::InvalidData(_)), e.to_string()));
        let extracted = storage
            .advance_nonce(id, caller, 2)
            .await
            .map_err(|e| (matches!(e, IdentityError::InvalidData(_)), e.to_string()));
        assert_eq!(extracted, original, "stored={stored:?} caller={caller}");
        assert_eq!(snapshot(&after).await?, snapshot(&before).await?);
        after.execute_batch("VACUUM").await?;
    }
    for conn in [&before, &after] {
        conn.execute("UPDATE nonces SET next_nonce = 'bad'", ())
            .await?;
    }
    let original = AssertUnwindSafe(old.advance_nonce(&before, 0, 2))
        .catch_unwind()
        .await
        .unwrap_err();
    let extracted = AssertUnwindSafe(storage.advance_nonce(id, 0, 2))
        .catch_unwind()
        .await
        .unwrap_err();
    assert_eq!(panic_message(extracted), panic_message(original));
    after.execute_batch("VACUUM").await?;
    Ok(())
}

#[tokio::test]
async fn identity_adapter_nonce_owner_survives_validation_until_cancelled_write() -> Result<()> {
    let (_r, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    initialize(&conn).await?;
    let id = ensure_identity(&conn, "cursor", 1).await?.signer_id();
    let saved = snapshot(&conn).await?;
    let mut callbacks = nonce_callbacks(&conn);
    let write = callbacks.1.clone();
    let entered = Arc::new(Semaphore::new(0));
    let notify = entered.clone();
    callbacks.1 = Arc::new(move |owner, nonce, height| {
        let write = write.clone();
        let notify = notify.clone();
        Box::pin(async move {
            notify.add_permits(1);
            pending::<()>().await;
            write(owner, nonce, height).await
        })
    });
    let mut advance = Box::pin(advance_nonce(callbacks, id, 0, 2));
    timeout(Duration::from_secs(10), async {
        tokio::select! {
            result = &mut advance => panic!("nonce advance finished before cancellation: {result:?}"),
            permit = entered.acquire() => permit.unwrap().forget(),
        }
    }).await?;
    assert!(conn.execute_batch("VACUUM").await.is_err());
    drop(advance);
    conn.execute_batch("VACUUM").await?;
    assert_eq!(snapshot(&conn).await?, saved);
    assert_eq!(advance_nonce(nonce_callbacks(&conn), id, 0, 2).await?, 1);
    conn.execute_batch("VACUUM").await?;
    Ok(())
}

#[tokio::test]
async fn identity_adapter_cancellation_after_pubkey_write_rolls_back() -> Result<()> {
    let (_r, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    initialize(&conn).await?;
    let storage = Storage::builder().conn(conn.clone()).build();
    let saved = snapshot(&conn).await?;
    storage.savepoint().await?;
    let mut callbacks = identity_callbacks(&conn);
    let write = callbacks.2.clone();
    let entered = Arc::new(Semaphore::new(0));
    let notify = entered.clone();
    callbacks.2 = Arc::new(move |id, key, height| {
        let write = write.clone();
        let notify = notify.clone();
        Box::pin(async move {
            write(id, key, height).await?;
            notify.add_permits(1);
            pending::<()>().await;
            Ok(())
        })
    });
    let mut create = Box::pin(ensure_versioned(callbacks, "cancelled", 1));
    timeout(Duration::from_secs(10), async {
        tokio::select! {
            result = &mut create => panic!("identity finished before cancellation: {result:?}"),
            permit = entered.acquire() => permit.unwrap().forget(),
        }
    })
    .await?;
    assert_ne!(snapshot(&conn).await?, saved);
    drop(create);
    storage.rollback().await?;
    assert_eq!(snapshot(&conn).await?, saved);
    Ok(())
}

#[tokio::test]
async fn identity_adapter_bls_reregistration_short_circuits_before_proof_parsing() -> Result<()> {
    let (mut runtime, _temp, _name) = test_runtime().await?;
    let conn = runtime.get_storage_conn();
    let identity = ensure_identity(&conn, "deliberately-invalid-x-only-key", 1).await?;
    let signer = Signer::Id(identity.clone());
    identity.register_bls_key(&conn, &[7; 96], 1).await?;
    runtime
        .register_bls_key(&signer, &[7; 96], &[], &[])
        .await?;
    let error = runtime
        .register_bls_key(&signer, &[8; 96], &[], &[])
        .await
        .unwrap_err();
    assert!(matches!(&error, ExecutionError::Deterministic(_)));
    assert_eq!(
        error.to_string(),
        "deterministic error: BLS pubkey already registered for signer"
    );
    conn.authorizer(Some(Arc::new(|context: &AuthContext<'_>| {
        if matches!(
            context.action,
            AuthAction::Read {
                table_name: "bls_keys",
                ..
            }
        ) {
            Authorization::Deny
        } else {
            Authorization::Allow
        }
    })))?;
    let error = runtime
        .register_bls_key(&signer, &[7; 96], &[], &[])
        .await
        .unwrap_err();
    conn.authorizer(None)?;
    assert!(matches!(error, ExecutionError::NonDeterministic(_)));
    Ok(())
}

#[test]
fn core_signer_id_is_reserved_one() {
    assert_eq!(VERSIONED_CORE_SIGNER_ID, 1);
    assert_eq!(CORE_SIGNER_ID, VERSIONED_CORE_SIGNER_ID);
}
