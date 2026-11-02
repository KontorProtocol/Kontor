use std::any::Any;
use std::future::pending;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use futures_util::{FutureExt, StreamExt, TryStreamExt};
use indexer_types::BlockRow;
use libsql::Connection;
use stdlib::KeyElement;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use super::storage_error::ReadError;
use super::storage_keys::keys;
use super::storage_point::read_value;
use crate::database::connection::new_connection;
use crate::database::queries::{
    get_latest_contract_state_value, insert_block, insert_contract_state, key_callbacks,
    path_prefix_filter_contract_state, point_callbacks, rollback_to_height, traversal_probe,
};
use crate::database::types::ContractStateRow;
use crate::test_utils::{new_mock_block_hash, new_test_db};

async fn heights(conn: &Connection) -> Result<()> {
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

fn row(
    contract_id: u64,
    height: u64,
    path: Vec<u8>,
    value: Vec<u8>,
    deleted: bool,
) -> ContractStateRow {
    ContractStateRow::builder()
        .contract_id(contract_id)
        .height(height)
        .path(path)
        .value(value)
        .deleted(deleted)
        .build()
}

async fn point_parity(conn: &Connection, contract_id: u64, path: &[u8]) -> Result<()> {
    for budget in [0, 1, 7, 8, 9, u64::MAX] {
        let before = get_latest_contract_state_value(conn, budget, contract_id, path)
            .await
            .map_err(|e| e.to_string());
        let after = read_value(point_callbacks(conn), budget, contract_id, path)
            .await
            .map_err(|e| e.to_string());
        assert_eq!(after, before);
    }
    Ok(())
}

#[tokio::test]
async fn point_adapter_matches_versions_empty_values_tombstones_and_rollback() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    heights(&conn).await?;
    let path = "point-parity".to_owned().encode();
    point_parity(&conn, 1, &path).await?;
    for (height, value, deleted) in [
        (1, vec![1; 8], false),
        (2, vec![], false),
        (2, vec![2; 8], false),
        (2, vec![], true),
    ] {
        insert_contract_state(&conn, row(1, height, path.clone(), value, deleted)).await?;
        insert_contract_state(&conn, row(2, height, path.clone(), vec![9], false)).await?;
        point_parity(&conn, 1, &path).await?;
        point_parity(&conn, 2, &path).await?;
        point_parity(&conn, 3, &path).await?;
    }
    rollback_to_height(&conn, 1).await?;
    point_parity(&conn, 1, &path).await?;
    assert_eq!(
        read_value(point_callbacks(&conn), 8, 1, &path).await?,
        Some(vec![1; 8])
    );
    Ok(())
}

#[tokio::test]
async fn point_adapter_pins_snapshot_across_staged_callbacks() -> Result<()> {
    let (_reader, writer, (temp, name)) = new_test_db().await?;
    let conn = writer.connection();
    heights(&conn).await?;
    let path = "point-snapshot".to_owned().encode();
    insert_contract_state(&conn, row(1, 1, path.clone(), vec![1; 8], false)).await?;
    let view = new_connection(temp.path(), &name).await?;
    let replacement = row(1, 1, path.clone(), vec![2; 16], false);
    let mut callbacks = point_callbacks(&view);
    let open = callbacks.0.clone();
    callbacks.0 = Arc::new(move |id, path| {
        let open = open.clone();
        let conn = conn.clone();
        let replacement = replacement.clone();
        Box::pin(async move {
            let selected = open(id, path).await?;
            assert!(selected.is_some());
            insert_contract_state(&conn, replacement)
                .await
                .map_err(|e| e.to_string())?;
            Ok(selected)
        })
    });
    assert_eq!(read_value(callbacks, 8, 1, &path).await?, Some(vec![1; 8]));
    assert!(matches!(
        read_value(point_callbacks(&view), 8, 1, &path).await,
        Err(ReadError::ValueTooLarge)
    ));
    assert_eq!(
        read_value(point_callbacks(&view), 16, 1, &path).await?,
        Some(vec![2; 16])
    );
    view.execute("VACUUM", ()).await?;
    Ok(())
}

fn panic_text(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .expect("text panic")
}

#[tokio::test]
async fn point_adapter_retains_conversion_panic_before_budget_check() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    heights(&conn).await?;
    let path = "bad-point".to_owned().encode();
    insert_contract_state(&conn, row(1, 1, path.clone(), vec![1; 8], false)).await?;
    conn.execute("PRAGMA foreign_keys = OFF", ()).await?;
    for sql in [
        "UPDATE current_contract_state SET size = 'bad'",
        "UPDATE current_contract_state SET height = 'bad', size = 8",
    ] {
        conn.execute(sql, ()).await?;
        for budget in [0, u64::MAX] {
            let before = AssertUnwindSafe(get_latest_contract_state_value(&conn, budget, 1, &path))
                .catch_unwind()
                .await
                .unwrap_err();
            let after = AssertUnwindSafe(read_value(point_callbacks(&conn), budget, 1, &path))
                .catch_unwind()
                .await
                .unwrap_err();
            assert_eq!(panic_text(before.as_ref()), panic_text(after.as_ref()));
            conn.execute("VACUUM", ()).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn point_adapter_cancellation_drops_metadata_before_connection_reuse() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    heights(&conn).await?;
    let path = "cancel-point".to_owned().encode();
    insert_contract_state(&conn, row(1, 1, path.clone(), vec![1; 8], false)).await?;
    for stage in 0..3 {
        let entered = Arc::new(Semaphore::new(0));
        let mut callbacks = point_callbacks(&conn);
        match stage {
            0 => {
                let open = callbacks.0.clone();
                let entered = entered.clone();
                callbacks.0 = Arc::new(move |id, path| {
                    let open = open.clone();
                    let entered = entered.clone();
                    Box::pin(async move {
                        let result = open(id, path).await?;
                        entered.add_permits(1);
                        pending::<()>().await;
                        Ok(result)
                    })
                });
            }
            1 => {
                let size = callbacks.1.clone();
                let entered = entered.clone();
                callbacks.1 = Arc::new(move |owner| {
                    let size = size.clone();
                    let entered = entered.clone();
                    Box::pin(async move {
                        let result = size(owner).await?;
                        entered.add_permits(1);
                        pending::<()>().await;
                        Ok(result)
                    })
                });
            }
            2 => {
                let value = callbacks.2.clone();
                let entered = entered.clone();
                callbacks.2 = Arc::new(move |owner, height, path| {
                    let value = value.clone();
                    let entered = entered.clone();
                    Box::pin(async move {
                        entered.add_permits(1);
                        pending::<()>().await;
                        value(owner, height, path).await
                    })
                });
            }
            _ => unreachable!(),
        }
        let mut call = Box::pin(read_value(callbacks, 8, 1, &path));
        timeout(Duration::from_secs(10), async {
            tokio::select! {
                result = &mut call => panic!("point stage {stage} completed early: {result:?}"),
                permit = entered.acquire() => permit.unwrap().forget(),
            }
        })
        .await?;
        assert!(conn.execute("VACUUM", ()).await.is_err());
        drop(call);
        conn.execute("VACUUM", ()).await?;
        assert_eq!(
            read_value(point_callbacks(&conn), 8, 1, &path).await?,
            Some(vec![1; 8])
        );
    }
    Ok(())
}

#[tokio::test]
async fn key_adapter_matches_bounded_duplicate_seeks_and_order() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    heights(&conn).await?;
    let root = "key\0parity".to_owned().encode();
    insert_contract_state(&conn, row(1, 1, root.clone(), vec![], false)).await?;
    for child in 0..4u64 {
        for field in 0..80u64 {
            insert_contract_state(
                &conn,
                row(
                    1,
                    1,
                    [root.clone(), child.encode(), field.encode()].concat(),
                    vec![1],
                    false,
                ),
            )
            .await?;
        }
    }
    for descending in [false, true] {
        for lo in [None, Some(vec![]), Some(1u64.encode()), Some(5u64.encode())] {
            for hi in [None, Some(vec![]), Some(3u64.encode()), Some(0u64.encode())] {
                let before = path_prefix_filter_contract_state(
                    &conn,
                    1,
                    root.clone(),
                    lo.clone(),
                    hi.clone(),
                    descending,
                )
                .await?;
                let after = keys(
                    key_callbacks(&conn),
                    1,
                    root.clone(),
                    lo.clone(),
                    hi.clone(),
                    descending,
                );
                let (before, visited_before) =
                    traversal_probe::measure(before.try_collect::<Vec<_>>()).await;
                let (after, visited_after) =
                    traversal_probe::measure(after.try_collect::<Vec<_>>()).await;
                assert_eq!(after?, before?);
                assert_eq!(visited_after, visited_before);
                assert!(visited_after <= 132);
                conn.execute("VACUUM", ()).await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn key_adapter_drop_releases_initial_and_reseek_cursors() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    heights(&conn).await?;
    let root = "cancel-keys".to_owned().encode();
    for child in 0..2u64 {
        for field in 0..80u64 {
            insert_contract_state(
                &conn,
                row(
                    1,
                    1,
                    [root.clone(), child.encode(), field.encode()].concat(),
                    vec![1],
                    false,
                ),
            )
            .await?;
        }
    }
    for descending in [false, true] {
        for suspend_at in [1, 34] {
            let entered = Arc::new(Semaphore::new(0));
            let mut callbacks = key_callbacks(&conn);
            let advance = callbacks.1.clone();
            let seen = Arc::new(AtomicUsize::new(0));
            let notify = entered.clone();
            callbacks.1 = Arc::new(move |owner| {
                let advance = advance.clone();
                let seen = seen.clone();
                let notify = notify.clone();
                Box::pin(async move {
                    let result = advance(owner).await?;
                    if seen.fetch_add(1, Ordering::SeqCst) + 1 == suspend_at {
                        assert!(result.is_some());
                        notify.add_permits(1);
                        pending::<()>().await;
                    }
                    Ok(result)
                })
            });
            let mut stream = Box::pin(keys(callbacks, 1, root.clone(), None, None, descending));
            if suspend_at == 34 {
                assert!(stream.next().await.transpose()?.is_some());
            }
            let mut call = Box::pin(stream.next());
            timeout(Duration::from_secs(10), async {
                tokio::select! {
                    result = &mut call => panic!("key cursor completed early: {result:?}"),
                    permit = entered.acquire() => permit.unwrap().forget(),
                }
            })
            .await?;
            assert!(conn.execute("VACUUM", ()).await.is_err());
            drop(call);
            // A suspended stream retains its poll future. Invocation teardown
            // drops the stream resource as well as the temporary next() future.
            drop(stream);
            conn.execute("VACUUM", ()).await?;
        }
    }
    Ok(())
}
