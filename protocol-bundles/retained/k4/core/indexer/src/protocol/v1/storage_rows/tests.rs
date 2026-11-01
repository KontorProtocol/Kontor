use std::any::Any;
use std::future::pending;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures_util::{FutureExt, TryStreamExt};
use indexer_types::BlockRow;
use libsql::{Connection, params};
use stdlib::KeyElement;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use super::{ReadError, StorageRowCursor};
use crate::database::queries::{StorageRowCursor as OriginalCursor, insert_block, row_callbacks};
use crate::protocol::storage_rows::ReadColumn;
use crate::runtime::Storage;
use crate::test_utils::{new_mock_block_hash, new_test_db};

async fn insert_heights(conn: &Connection) -> Result<()> {
    for height in [1, 2] {
        insert_block(
            conn,
            BlockRow::builder()
                .height(height)
                .hash(new_mock_block_hash(height as u32))
                .build(),
        )
        .await?;
    }
    Ok(())
}

async fn compare(
    conn: &Connection,
    root: &[u8],
    lo: Option<Vec<u8>>,
    hi: Option<Vec<u8>>,
    descending: bool,
    budget: u64,
) -> Result<usize> {
    let mut original =
        OriginalCursor::new(conn, 1, root.to_vec(), lo.clone(), hi.clone(), descending);
    let mut versioned =
        StorageRowCursor::new(row_callbacks(conn), 1, root.to_vec(), lo, hi, descending);
    let mut count = 0;
    loop {
        let before = AssertUnwindSafe(original.next(budget)).catch_unwind().await;
        let after = AssertUnwindSafe(versioned.next(budget))
            .catch_unwind()
            .await;
        let (before, after) = match (before, after) {
            (Ok(before), Ok(after)) => (before, after),
            (Err(before), Err(after)) => {
                assert_eq!(panic_text(before.as_ref()), panic_text(after.as_ref()));
                assert!(versioned.next(u64::MAX).await?.is_none());
                return Ok(count);
            }
            _ => panic!("original and extracted cursor disagree on driver panic"),
        };
        let before = before.map_err(|error| error.to_string());
        let after = after.map_err(|error| error.to_string());
        assert_eq!(after, before);
        match after {
            Ok(Some(_)) => count += 1,
            _ => break,
        }
    }
    assert!(original.next(u64::MAX).await?.is_none());
    assert!(versioned.next(u64::MAX).await?.is_none());
    Ok(count)
}

fn panic_text(payload: &(dyn Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<String>() {
        message
    } else {
        payload.downcast_ref::<&str>().expect("expected text panic")
    }
}

#[tokio::test]
async fn row_adapter_matches_original_bounds_versions_and_budgets() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    insert_heights(&conn).await?;
    let mut storage = Storage::builder().conn(conn.clone()).build();
    let root = "parity\0root".to_owned().encode();
    storage.set(1, &root, &[99], None, None).await?;
    for member in 0..6u64 {
        let path = [root.clone(), member.encode()].concat();
        storage.set(1, &path, &[0; 128], None, None).await?;
        storage
            .set(1, &path, &vec![member as u8; member as usize], None, None)
            .await?;
        storage.set(2, &path, &[255], None, None).await?;
    }
    storage.height = 2;
    storage
        .set(
            1,
            &[root.clone(), 4u64.encode()].concat(),
            &[42],
            None,
            None,
        )
        .await?;
    let removed = storage
        .find_live_subtree(1, &[root.clone(), 5u64.encode()].concat())
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    storage.tombstone_rows(1, &removed).await?;
    for descending in [false, true] {
        for lo in [None, Some(vec![]), Some(2u64.encode()), Some(7u64.encode())] {
            for hi in [None, Some(vec![]), Some(4u64.encode()), Some(1u64.encode())] {
                for budget in [0, 1, 3, 6, u64::MAX] {
                    compare(&conn, &root, lo.clone(), hi.clone(), descending, budget).await?;
                }
            }
        }
    }
    assert_eq!(compare(&conn, &root, None, None, false, u64::MAX).await?, 5);
    Ok(())
}

#[tokio::test]
async fn row_adapter_retains_corrupt_row_error_precedence() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    insert_heights(&conn).await?;
    let storage = Storage::builder().conn(conn.clone()).build();
    // SQL accepts malformed codec bytes. Invalid sizes must be observed before
    // decoding these keys, but only after the key-byte budget has been checked.
    for suffix in [
        vec![254],
        [1u64.encode(), 2u64.encode()].concat(),
        1u64.encode(),
    ] {
        conn.execute("DELETE FROM current_contract_state", ())
            .await?;
        let root = "precedence".to_owned().encode();
        let path = [root.clone(), suffix.clone()].concat();
        storage.set(1, &path, &[7; 8], None, None).await?;
        for corrupt_size in [false, true] {
            if corrupt_size {
                conn.execute("UPDATE current_contract_state SET size = 'bad'", ())
                    .await?;
            }
            for budget in [0, suffix.len() as u64, u64::MAX] {
                compare(&conn, &root, None, None, false, budget).await?;
                let mut cursor =
                    StorageRowCursor::new(row_callbacks(&conn), 1, root.clone(), None, None, false);
                let result = AssertUnwindSafe(cursor.next(budget)).catch_unwind().await;
                // The frozen driver's integer conversion panics on TEXT. It
                // must still happen after the key budget and before decoding.
                if corrupt_size && budget != 0 {
                    let panic = result.expect_err("TEXT size must retain the driver panic");
                    assert_eq!(
                        panic_text(panic.as_ref()),
                        "internal error: entered unreachable code: invalid value type"
                    );
                    continue;
                }
                let result = result.expect("this stage must not panic");
                if budget == 0 || budget == suffix.len() as u64 {
                    assert!(matches!(result, Err(ReadError::ValueTooLarge)));
                }
            }
        }
        conn.execute("UPDATE current_contract_state SET size = 0", ())
            .await?;
        // An admitted key with a missing historical value must remain an
        // infrastructure failure, rather than an absent row or guest rejection.
        conn.execute("DELETE FROM contract_state WHERE path = ?", params![path])
            .await?;
        compare(&conn, &root, None, None, false, u64::MAX).await?;
        let mut cursor = StorageRowCursor::new(row_callbacks(&conn), 1, root, None, None, false);
        let error = cursor.next(u64::MAX).await.unwrap_err();
        if suffix == vec![254] {
            assert!(matches!(error, ReadError::KeyCodec(_)));
        } else if suffix == 1u64.encode() {
            assert!(matches!(error, ReadError::Infrastructure(_)));
        } else {
            assert!(matches!(error, ReadError::NonScalarRow));
        }
    }
    Ok(())
}

fn suspend_column<T: Send + 'static>(
    callback: ReadColumn<T>,
    entered: Arc<Semaphore>,
) -> ReadColumn<T> {
    Arc::new(move |owner| {
        let callback = callback.clone();
        let entered = entered.clone();
        Box::pin(async move {
            let result = callback(owner).await?;
            entered.add_permits(1);
            pending::<()>().await;
            Ok(result)
        })
    })
}

#[tokio::test]
async fn row_adapter_cancellation_releases_each_live_stage() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    insert_heights(&conn).await?;
    let storage = Storage::builder().conn(conn.clone()).build();
    let root = "cancel-row".to_owned().encode();
    for member in 0..2u64 {
        storage
            .set(
                1,
                &[root.clone(), member.encode()].concat(),
                &[7],
                None,
                None,
            )
            .await?;
    }
    for stage in 1..=5 {
        let entered = Arc::new(Semaphore::new(0));
        let mut callbacks = row_callbacks(&conn);
        match stage {
            1 => {
                let advance = callbacks.1.clone();
                let entered = entered.clone();
                callbacks.1 = Arc::new(move |owner| {
                    let advance = advance.clone();
                    let entered = entered.clone();
                    Box::pin(async move {
                        let result = advance(owner).await?;
                        entered.add_permits(1);
                        pending::<()>().await;
                        Ok(result)
                    })
                });
            }
            2 => callbacks.2 = suspend_column(callbacks.2, entered.clone()),
            3 => callbacks.3 = suspend_column(callbacks.3, entered.clone()),
            4 => callbacks.4 = suspend_column(callbacks.4, entered.clone()),
            5 => {
                let read = callbacks.5.clone();
                let entered = entered.clone();
                callbacks.5 = Arc::new(move |owner, height, path| {
                    let read = read.clone();
                    let entered = entered.clone();
                    Box::pin(async move {
                        let result = read(owner, height, path).await?;
                        entered.add_permits(1);
                        pending::<()>().await;
                        Ok(result)
                    })
                });
            }
            _ => unreachable!(),
        }
        let mut cursor = StorageRowCursor::new(callbacks, 1, root.clone(), None, None, false);
        let mut call = Box::pin(cursor.next(u64::MAX));
        timeout(Duration::from_secs(10), async {
            tokio::select! {
                result = &mut call => panic!("stage {stage} completed before cancellation: {result:?}"),
                permit = entered.acquire() => permit.unwrap().forget(),
            }
        }).await?;
        assert!(
            conn.execute("VACUUM", ()).await.is_err(),
            "stage {stage} must hold a live SQL snapshot"
        );
        drop(call);
        conn.execute("VACUUM", ()).await?;
        assert!(cursor.next(u64::MAX).await?.is_none());
    }
    Ok(())
}
