use std::future::pending;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use futures_util::TryStreamExt;
use indexer_types::{BlockRow, TransactionRow};
use libsql::Connection;
use stdlib::KeyElement;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use super::storage_error::ReadError;
use super::storage_footprint::FootprintCache;
use super::storage_state::tombstone_rows as tombstone_versioned;
use crate::database::queries::{
    FOOTPRINT_BUILT_KEY, create_contract_signer, find_live_subtree, footprint_cache_get,
    footprint_callbacks, get_checkpoint_latest, get_meta_u64, insert_block, insert_contract_state,
    insert_transaction, live_deposit_gas_sum, rollback_to_height, set_meta_u64, state_callbacks,
    tombstone_rows,
};
use crate::database::types::ContractStateRow;
use crate::protocol::storage_state::WriteState;
use crate::runtime::{Storage, TransactionContext};
use crate::test_utils::{new_mock_block_hash, new_mock_transaction, new_test_db};

async fn initialize(conn: &Connection) -> Result<Vec<u64>> {
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
    let mut signers = Vec::new();
    for _ in 0..2 {
        signers.push(create_contract_signer(conn, 1).await?);
    }
    Ok(signers)
}

type StoredState = (
    u64,
    u64,
    Option<u64>,
    u64,
    Vec<u8>,
    Vec<u8>,
    bool,
    Option<u64>,
    Option<u64>,
);

async fn snapshot(conn: &Connection) -> Result<(Vec<StoredState>, Option<(u64, String)>)> {
    let mut rows = conn.query("SELECT contract_id, height, tx_id, size, path, value, deleted, depositor, deposited_gas FROM contract_state ORDER BY contract_id, height, path", ()).await?;
    let mut state = Vec::new();
    while let Some(row) = rows.next().await? {
        state.push((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
        ));
    }
    let checkpoint = get_checkpoint_latest(conn)
        .await?
        .map(|row| (row.height, row.hash));
    Ok((state, checkpoint))
}

async fn assert_floors(storage: &Storage, signers: &[u64]) -> Result<()> {
    for &signer in signers {
        assert_eq!(
            storage.footprint().total_gas(signer).await?,
            live_deposit_gas_sum(&storage.conn, signer).await?
        );
    }
    Ok(())
}

#[tokio::test]
async fn state_adapter_preserves_ordered_checkpoints_and_deposit_totals() -> Result<()> {
    let (_r1, writer1, _temp1) = new_test_db().await?;
    let (_r2, writer2, _temp2) = new_test_db().await?;
    let before = writer1.connection();
    let after = writer2.connection();
    let signers = initialize(&before).await?;
    assert_eq!(initialize(&after).await?, signers);
    let transaction = TransactionRow::builder()
        .height(1)
        .txid(new_mock_transaction(1).txid.to_string())
        .build();
    let tx_id = insert_transaction(&before, transaction.clone()).await?;
    assert_eq!(insert_transaction(&after, transaction).await?, tx_id);
    let mut storage = Storage::builder()
        .conn(after.clone())
        .tx_context(TransactionContext::builder().tx_id(tx_id).build())
        .build();
    let root = "ordered-writes".to_owned().encode();
    for (height, child, value, depositor, gas) in [
        (1, 0u64, vec![1; 8], Some(signers[0]), Some(20)),
        (1, 1u64, vec![2; 3], Some(signers[0]), Some(10)),
        (1, 0u64, vec![3; 4], Some(signers[1]), Some(12)),
        (2, 2u64, vec![], None, None),
        (2, 0u64, vec![4; 9], Some(signers[0]), Some(25)),
    ] {
        let path = [root.clone(), child.encode()].concat();
        insert_contract_state(
            &before,
            ContractStateRow::builder()
                .contract_id(1)
                .tx_id(tx_id)
                .height(height)
                .path(path.clone())
                .value(value.clone())
                .maybe_depositor(depositor)
                .maybe_deposited_gas(gas)
                .build(),
        )
        .await?;
        storage.height = height;
        storage.footprint().on_set(1, &path, depositor, gas).await?;
        storage.set(1, &path, &value, depositor, gas).await?;
        assert_eq!(snapshot(&after).await?, snapshot(&before).await?);
        assert_floors(&storage, &signers).await?;
    }
    let original = find_live_subtree(&before, 1, &root)
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    let extracted = storage
        .find_live_subtree(1, &root)
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    assert_eq!(original.len(), extracted.len());
    for (old, new) in original.iter().zip(&extracted) {
        assert_eq!(
            (&old.path, old.size, old.depositor, old.deposited_gas),
            (&new.path, new.size, new.depositor, new.deposited_gas)
        );
    }
    storage.footprint().on_free(&extracted).await?;
    assert_eq!(
        storage.tombstone_rows(1, &extracted).await?,
        tombstone_rows(&before, 1, 2, Some(tx_id), &original).await?
    );
    assert!(!storage.exists(1, &root).await?);
    assert_eq!(snapshot(&after).await?, snapshot(&before).await?);
    assert_floors(&storage, &signers).await?;
    rollback_to_height(&before, 1).await?;
    storage.rollback_with_footprint(1).await?;
    assert_eq!(snapshot(&after).await?, snapshot(&before).await?);
    assert_floors(&storage, &signers).await?;
    assert!(storage.exists(1, &root).await?);
    let saved = snapshot(&after).await?;
    assert_eq!(storage.tombstone_rows(1, &[]).await?, (false, 0));
    assert_eq!(snapshot(&after).await?, saved);
    Ok(())
}

#[tokio::test]
async fn state_adapter_partial_delete_rolls_back_rows_floors_and_checkpoint() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    let signers = initialize(&conn).await?;
    let mut storage = Storage::builder().conn(conn.clone()).build();
    let root = "partial-delete".to_owned().encode();
    for child in 0..2u64 {
        let path = [root.clone(), child.encode()].concat();
        storage
            .footprint()
            .on_set(1, &path, Some(signers[0]), Some(10))
            .await?;
        storage
            .set(1, &path, &[1], Some(signers[0]), Some(10))
            .await?;
    }
    let saved = snapshot(&conn).await?;
    storage.height = 2;
    storage.savepoint().await?;
    let rows = storage
        .find_live_subtree(1, &root)
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    storage.footprint().on_free(&rows).await?;
    let actual_write = state_callbacks(&conn).0;
    let calls = Arc::new(AtomicUsize::new(0));
    let write: WriteState = Arc::new(move |row| {
        let actual_write = actual_write.clone();
        let call = calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if call == 1 {
                return Err("injected second tombstone failure".to_owned());
            }
            actual_write(row).await
        })
    });
    assert!(
        tombstone_versioned(write, (1, 2, None), &rows)
            .await
            .is_err()
    );
    assert_ne!(snapshot(&conn).await?, saved);
    assert_eq!(storage.footprint().total_gas(signers[0]).await?, 0);
    storage.rollback().await?;
    assert_eq!(snapshot(&conn).await?, saved);
    assert_floors(&storage, &signers).await?;
    Ok(())
}

#[tokio::test]
async fn footprint_adapter_cancelled_transfer_restores_old_deposit() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    let signers = initialize(&conn).await?;
    let storage = Storage::builder().conn(conn.clone()).build();
    let path = "cancel-deposit".to_owned().encode();
    storage
        .footprint()
        .on_set(1, &path, Some(signers[0]), Some(10))
        .await?;
    storage
        .set(1, &path, &[1], Some(signers[0]), Some(10))
        .await?;
    let saved = snapshot(&conn).await?;
    storage.savepoint().await?;
    let entered = Arc::new(Semaphore::new(0));
    let mut callbacks = footprint_callbacks(&conn);
    let add = callbacks.2.clone();
    let notify = entered.clone();
    callbacks.2 = Arc::new(move |depositor, delta| {
        let add = add.clone();
        let notify = notify.clone();
        Box::pin(async move {
            add(depositor, delta).await?;
            notify.add_permits(1);
            pending::<()>().await;
            Ok(())
        })
    });
    let footprint = FootprintCache::new(callbacks);
    let mut transfer = Box::pin(footprint.on_set(1, &path, Some(signers[1]), Some(20)));
    timeout(Duration::from_secs(10), async {
        tokio::select! {
            result = &mut transfer => panic!("transfer finished before cancellation: {result:?}"),
            permit = entered.acquire() => permit.unwrap().forget(),
        }
    })
    .await?;
    assert_eq!(footprint_cache_get(&conn, signers[0]).await?, None);
    assert_eq!(footprint_cache_get(&conn, signers[1]).await?, None);
    drop(transfer);
    storage.rollback().await?;
    assert_eq!(snapshot(&conn).await?, saved);
    assert_floors(&storage, &signers).await?;
    Ok(())
}

#[tokio::test]
async fn state_adapter_rejects_optional_integer_overflow_before_writing() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    let signers = initialize(&conn).await?;
    let path = "overflow-write".to_owned().encode();
    let saved = snapshot(&conn).await?;
    for (tx_id, depositor, gas) in [
        (Some(u64::MAX), None, None),
        (None, Some(u64::MAX), Some(1)),
        (None, Some(signers[0]), Some(u64::MAX)),
        (Some(u64::MAX), Some(u64::MAX - 1), Some(u64::MAX - 2)),
    ] {
        let original = ContractStateRow::builder()
            .contract_id(1)
            .height(1)
            .maybe_tx_id(tx_id)
            .path(path.clone())
            .value(vec![1; 8])
            .maybe_depositor(depositor)
            .maybe_deposited_gas(gas)
            .build();
        let before = insert_contract_state(&conn, original).await.unwrap_err();
        assert_eq!(snapshot(&conn).await?, saved);
        let after = state_callbacks(&conn).0((
            (1, 1, tx_id),
            8,
            path.clone(),
            vec![1; 8],
            false,
            depositor,
            gas,
        ))
        .await
        .unwrap_err();
        assert_eq!(after, before.to_string());
        assert_eq!(snapshot(&conn).await?, saved);
    }
    Ok(())
}

#[tokio::test]
async fn footprint_adapter_preserves_negative_error_and_rebuild_marker() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    let signers = initialize(&conn).await?;
    let storage = Storage::builder().conn(conn.clone()).build();
    let path = "rebuild-footprint".to_owned().encode();
    storage
        .footprint()
        .on_set(1, &path, Some(signers[0]), Some(10))
        .await?;
    storage
        .set(1, &path, &[1], Some(signers[0]), Some(10))
        .await?;
    let saved = snapshot(&conn).await?;
    conn.execute("UPDATE depositor_footprint SET total_gas = -7", ())
        .await?;
    let original = footprint_cache_get(&conn, signers[0]).await.unwrap_err();
    let extracted = storage.footprint().total_gas(signers[0]).await.unwrap_err();
    assert!(matches!(extracted, ReadError::Infrastructure(_)));
    assert_eq!(extracted.to_string(), original.to_string());
    conn.execute("DELETE FROM depositor_footprint", ()).await?;
    set_meta_u64(&conn, FOOTPRINT_BUILT_KEY, 1).await?;
    storage.footprint().reconstruct().await?;
    assert_eq!(footprint_cache_get(&conn, signers[0]).await?, None);
    set_meta_u64(&conn, FOOTPRINT_BUILT_KEY, 0).await?;
    storage.footprint().reconstruct().await?;
    assert_eq!(footprint_cache_get(&conn, signers[0]).await?, Some(10));
    assert_eq!(get_meta_u64(&conn, FOOTPRINT_BUILT_KEY, 0).await?, 1);
    assert_eq!(snapshot(&conn).await?, saved);
    assert_floors(&storage, &signers).await?;
    Ok(())
}
