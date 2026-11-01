use std::future::pending;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use indexer_types::BlockRow;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use super::storage_session::savepoint;
use crate::database::queries::{get_checkpoint_latest, insert_block};
use crate::database::storage_session_v1::session_callbacks;
use crate::runtime::Storage;
use crate::test_utils::{new_mock_block_hash, new_test_db};

#[tokio::test]
async fn session_adapter_preserves_nested_rollback_and_clone_bookkeeping() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    insert_block(
        &conn,
        BlockRow::builder()
            .height(1)
            .hash(new_mock_block_hash(1))
            .build(),
    )
    .await?;
    let storage = Storage::builder().conn(conn.clone()).build();
    let clone = storage.clone();
    storage.savepoint().await?;
    storage.set(1, b"outer", &[1], None, None).await?;
    let outer_checkpoint = get_checkpoint_latest(&conn).await?.unwrap();
    clone.savepoint().await?;
    assert_eq!(storage.savepoint_stack.peek().await, Some(1));
    clone.set(1, b"nested", &[2], None, None).await?;
    clone.rollback().await?;
    assert_eq!(storage.savepoint_stack.peek().await, Some(0));
    assert_eq!(storage.get(10, 1, b"nested").await?, None);
    assert_eq!(
        get_checkpoint_latest(&conn).await?.unwrap().hash,
        outer_checkpoint.hash
    );
    // ROLLBACK TO retains the SQLite savepoint even after the P1 stack pops it.
    conn.execute("RELEASE S1", ()).await?;
    clone.savepoint().await?;
    assert_eq!(storage.savepoint_stack.peek().await, Some(2));
    clone.set(1, b"committed", &[3], None, None).await?;
    clone.commit().await?;
    storage.commit().await?;
    assert!(conn.is_autocommit());
    assert_eq!(storage.get(10, 1, b"outer").await?, Some(vec![1]));
    assert_eq!(storage.get(10, 1, b"committed").await?, Some(vec![3]));
    storage.savepoint().await?;
    assert_eq!(storage.savepoint_counter.get().await, 1);
    storage.rollback().await?;
    assert!(clone.savepoint_stack.is_empty().await);
    Ok(())
}

#[tokio::test]
async fn session_adapter_keeps_pop_before_error_and_failed_begin_bookkeeping() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    let storage = Storage::builder().conn(conn.clone()).build();
    for rollback in [false, true] {
        storage.savepoint_stack.push(7).await?;
        let sql = if rollback {
            "ROLLBACK TO S7"
        } else {
            "RELEASE S7"
        };
        let original = conn.execute(sql, ()).await.unwrap_err().to_string();
        let extracted = if rollback {
            storage.rollback().await
        } else {
            storage.commit().await
        };
        assert_eq!(extracted.unwrap_err().to_string(), original);
        assert!(storage.savepoint_stack.is_empty().await);
    }
    conn.execute("BEGIN TRANSACTION", ()).await?;
    storage.savepoint_counter.increment().await;
    let original = conn
        .execute("BEGIN TRANSACTION", ())
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(storage.savepoint().await.unwrap_err().to_string(), original);
    assert!(storage.savepoint_stack.is_empty().await);
    assert_eq!(storage.savepoint_counter.get().await, 1);
    storage.rollback_transaction().await?;
    storage.savepoint_stack.push(9).await?;
    let original = conn.execute("ROLLBACK", ()).await.unwrap_err().to_string();
    assert_eq!(
        storage
            .rollback_transaction()
            .await
            .unwrap_err()
            .to_string(),
        original
    );
    assert!(storage.savepoint_stack.is_empty().await);
    // An empty stack is a no-op for ordinary commit and rollback.
    storage.commit().await?;
    storage.rollback().await?;
    Ok(())
}

#[tokio::test]
async fn session_adapter_cancelled_begin_can_be_reset_before_reuse() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    let storage = Storage::builder().conn(conn.clone()).build();
    let mut callbacks = session_callbacks(&conn);
    let begin = callbacks.0.clone();
    let entered = Arc::new(Semaphore::new(0));
    let notify = entered.clone();
    callbacks.0 = Arc::new(move || {
        let begin = begin.clone();
        let notify = notify.clone();
        Box::pin(async move {
            begin().await?;
            notify.add_permits(1);
            pending::<()>().await;
            Ok(())
        })
    });
    let mut begin = Box::pin(savepoint(
        callbacks,
        &storage.savepoint_stack,
        &storage.savepoint_counter,
    ));
    timeout(Duration::from_secs(10), async {
        tokio::select! {
            result = &mut begin => panic!("begin finished before cancellation: {result:?}"),
            permit = entered.acquire() => permit.unwrap().forget(),
        }
    })
    .await?;
    assert!(!conn.is_autocommit());
    assert!(storage.savepoint_stack.is_empty().await);
    drop(begin);
    storage.rollback_transaction().await?;
    assert!(conn.is_autocommit());
    storage.savepoint().await?;
    storage.commit().await?;
    assert!(conn.is_autocommit());
    Ok(())
}
