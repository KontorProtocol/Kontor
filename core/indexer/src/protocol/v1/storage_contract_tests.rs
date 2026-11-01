use std::any::Any;
use std::future::pending;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures_util::FutureExt;
use indexer_types::{BlockRow, OpStatus, TransactionRow};
use libsql::{Connection, Value};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use super::storage_contracts::{insert_contract as insert_versioned, result_write};
use crate::database::queries::{
    create_contract_signer, get_checkpoint_latest, get_contract_address_from_id, insert_block,
    insert_contract, insert_contract_provenance, insert_contract_result, insert_contract_state,
    insert_transaction,
};
use crate::database::storage_contracts_v1::contract_callbacks;
use crate::database::types::{
    ContractProvenanceRow, ContractResultRow, ContractRow, ContractStateRow,
};
use crate::runtime::{Storage, TransactionContext};
use crate::test_utils::{new_mock_block_hash, new_mock_transaction, new_test_db};

async fn initialize(conn: &Connection) -> Result<u64> {
    insert_block(
        conn,
        BlockRow::builder()
            .height(1)
            .hash(new_mock_block_hash(1))
            .build(),
    )
    .await?;
    insert_contract_state(
        conn,
        ContractStateRow::builder()
            .contract_id(1)
            .height(1)
            .path(b"existing-state".to_vec())
            .value(vec![42])
            .build(),
    )
    .await?;
    assert!(get_checkpoint_latest(conn).await?.is_some());
    Ok(insert_transaction(
        conn,
        TransactionRow::builder()
            .height(1)
            .txid(new_mock_transaction(1).txid.to_string())
            .build(),
    )
    .await?)
}

async fn snapshot(conn: &Connection) -> Result<(Vec<Vec<Vec<Value>>>, Option<(u64, String)>)> {
    let mut tables = Vec::new();
    for table in [
        "signers",
        "contracts",
        "contract_provenance",
        "contract_results",
    ] {
        let mut rows = conn
            .query(&format!("SELECT * FROM {table} ORDER BY id"), ())
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
    Ok((
        tables,
        get_checkpoint_latest(conn)
            .await?
            .map(|row| (row.height, row.hash)),
    ))
}

async fn original_insert(
    conn: &Connection,
    tx_index: Option<u32>,
    name: &str,
    bytes: &[u8],
) -> Result<u64> {
    let signer = create_contract_signer(conn, 1).await?;
    Ok(insert_contract(
        conn,
        ContractRow::builder()
            .height(1)
            .tx_index(tx_index.expect("Transaction index is required when inserting contract"))
            .name(name.to_owned())
            .bytes(bytes.to_vec())
            .signer_id(signer)
            .build(),
    )
    .await?)
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
async fn contract_adapter_preserves_records_results_provenance_and_checkpoints() -> Result<()> {
    let (_r1, w1, _t1) = new_test_db().await?;
    let (_r2, w2, _t2) = new_test_db().await?;
    let before = w1.connection();
    let after = w2.connection();
    let tx_id = initialize(&before).await?;
    assert_eq!(initialize(&after).await?, tx_id);
    let mut storage = Storage::builder()
        .conn(after.clone())
        .tx_context(
            TransactionContext::builder()
                .tx_id(tx_id)
                .tx_index(3)
                .input_index(2)
                .op_index(4)
                .build(),
        )
        .build();
    let original = original_insert(&before, Some(3), "records", &[0, 1, 255]).await?;
    let extracted = storage.insert_contract("records", &[0, 1, 255]).await?;
    assert_eq!(extracted, original);
    assert_eq!(snapshot(&after).await?, snapshot(&before).await?);
    let address = storage.contract_address(extracted).await?.unwrap();
    assert_eq!(storage.contract_id(&address).await?, Some(extracted));
    assert_eq!(
        storage.contract_bytes(extracted).await?,
        Some(vec![0, 1, 255])
    );
    assert!(storage.contract_address(999).await?.is_none());
    assert!(storage.contract_bytes(999).await?.is_none());
    assert!(
        storage
            .contract_provenance_publisher(extracted)
            .await?
            .is_none()
    );
    for (author, bytes) in [(7, vec![1, 2]), (8, vec![])] {
        insert_contract_provenance(
            &before,
            ContractProvenanceRow::builder()
                .contract_id(original)
                .author_signer_id(author)
                .height(1)
                .tx_index(3)
                .provenance(bytes.clone())
                .build(),
        )
        .await?;
        storage
            .insert_contract_provenance(extracted, author, &bytes)
            .await?;
        assert_eq!(snapshot(&after).await?, snapshot(&before).await?);
        assert_eq!(
            storage.contract_provenance_publisher(extracted).await?,
            Some(7)
        );
    }
    for (index, status) in [
        OpStatus::Ok,
        OpStatus::ContractErr,
        OpStatus::OutOfFuel,
        OpStatus::Trap,
        OpStatus::Other,
    ]
    .into_iter()
    .enumerate()
    {
        let value = match index {
            0 => None,
            1 => Some(String::new()),
            _ => Some("é⛓".to_owned()),
        };
        let payer = (index % 2 == 0).then_some(1);
        if index == 4 {
            storage.tx_context = None;
        }
        let context = storage.tx_context.as_ref();
        let expected_id = insert_contract_result(
            &before,
            ContractResultRow::builder()
                .contract_id(original)
                .height(1)
                .maybe_tx_id(context.and_then(|c| c.tx_id))
                .maybe_input_index(context.map(|c| c.input_index))
                .maybe_op_index(context.map(|c| c.op_index))
                .result_index(index as u32)
                .func("record".to_owned())
                .gas(25)
                .maybe_value(value.clone())
                .signer_id(1)
                .maybe_payer_signer_id(payer)
                .status(status)
                .build(),
        )
        .await?;
        assert_eq!(
            storage
                .insert_contract_result(
                    index as u32,
                    extracted,
                    "record".to_owned(),
                    25,
                    value,
                    1,
                    payer,
                    status
                )
                .await?,
            expected_id
        );
        assert_eq!(snapshot(&after).await?, snapshot(&before).await?);
    }
    Ok(())
}

#[tokio::test]
async fn contract_adapter_preserves_partial_signer_on_panic_or_insert_failure() -> Result<()> {
    let (_r1, w1, _t1) = new_test_db().await?;
    let (_r2, w2, _t2) = new_test_db().await?;
    let before = w1.connection();
    let after = w2.connection();
    initialize(&before).await?;
    initialize(&after).await?;
    let mut storage = Storage::builder().conn(after.clone()).build();
    let saved = snapshot(&after).await?;
    before.execute("BEGIN", ()).await?;
    storage.savepoint().await?;
    let old = AssertUnwindSafe(original_insert(&before, None, "missing", &[]))
        .catch_unwind()
        .await;
    let new = AssertUnwindSafe(storage.insert_contract("missing", &[]))
        .catch_unwind()
        .await;
    let old = panic_message(old.unwrap_err());
    let new = panic_message(new.unwrap_err());
    assert_eq!(new, old);
    assert_eq!(new, "Transaction index is required when inserting contract");
    assert_ne!(snapshot(&after).await?, saved);
    assert_eq!(snapshot(&after).await?, snapshot(&before).await?);
    before.execute("ROLLBACK", ()).await?;
    storage.rollback().await?;
    assert_eq!(snapshot(&after).await?, saved);
    storage.tx_context = Some(TransactionContext::builder().build());
    original_insert(&before, Some(0), "duplicate", &[]).await?;
    storage.insert_contract("duplicate", &[]).await?;
    let saved = snapshot(&after).await?;
    before.execute("BEGIN", ()).await?;
    storage.savepoint().await?;
    let old = original_insert(&before, Some(0), "duplicate", &[])
        .await
        .unwrap_err();
    let new = storage.insert_contract("duplicate", &[]).await.unwrap_err();
    assert_eq!(old.to_string(), new.to_string());
    assert_ne!(snapshot(&after).await?, saved);
    assert_eq!(snapshot(&after).await?, snapshot(&before).await?);
    before.execute("ROLLBACK", ()).await?;
    storage.rollback().await?;
    assert_eq!(snapshot(&after).await?, saved);
    Ok(())
}

#[tokio::test]
async fn contract_adapter_provenance_context_panic_preserves_prior_write_until_rollback()
-> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    initialize(&conn).await?;
    let mut storage = Storage::builder()
        .conn(conn.clone())
        .tx_context(TransactionContext::builder().tx_index(3).build())
        .build();
    let saved = snapshot(&conn).await?;
    storage.savepoint().await?;
    let contract_id = storage.insert_contract("prior-write", &[]).await?;
    let staged = snapshot(&conn).await?;
    assert_ne!(staged, saved);

    storage.tx_context = None;
    let panic = AssertUnwindSafe(storage.insert_contract_provenance(contract_id, 1, &[1, 2]))
        .catch_unwind()
        .await;
    assert_eq!(
        panic_message(panic.unwrap_err()),
        "Transaction index is required when inserting provenance"
    );
    assert_eq!(snapshot(&conn).await?, staged);
    storage.rollback().await?;
    assert_eq!(snapshot(&conn).await?, saved);
    Ok(())
}

#[tokio::test]
async fn contract_adapter_retains_address_deserialization_errors() -> Result<()> {
    let (_r, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    initialize(&conn).await?;
    let id = original_insert(&conn, Some(0), "address", &[]).await?;
    for mutation in [
        "name = X'FF'",
        "height = 'bad'",
        "tx_index = -1",
        "tx_index = 4294967296",
    ] {
        conn.execute("PRAGMA foreign_keys = OFF", ()).await?;
        conn.execute("BEGIN", ()).await?;
        conn.execute(
            &format!("UPDATE contracts SET {mutation} WHERE id = {id}"),
            (),
        )
        .await?;
        let old = get_contract_address_from_id(&conn, id).await.unwrap_err();
        let new = contract_callbacks(&conn).3(id).await.unwrap_err();
        assert_eq!(new, old.to_string(), "{mutation}");
        conn.execute("ROLLBACK", ()).await?;
    }
    Ok(())
}

#[tokio::test]
async fn contract_adapter_retains_result_conversion_failure_order() -> Result<()> {
    let (_r, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    initialize(&conn).await?;
    let saved = snapshot(&conn).await?;
    for (tx_id, payer) in [
        (Some(u64::MAX), None),
        (None, Some(u64::MAX)),
        (Some(u64::MAX), Some(u64::MAX - 1)),
    ] {
        let old = insert_contract_result(
            &conn,
            ContractResultRow::builder()
                .height(1)
                .gas(1)
                .maybe_tx_id(tx_id)
                .maybe_payer_signer_id(payer)
                .build(),
        )
        .await
        .unwrap_err();
        let new = contract_callbacks(&conn).7(result_write(
            (1, tx_id, None, None),
            0,
            0,
            String::new(),
            1,
            None,
            0,
            payer,
            "Ok",
        ))
        .await
        .unwrap_err();
        assert_eq!(new, old.to_string());
        assert_eq!(snapshot(&conn).await?, saved);
    }
    Ok(())
}

#[tokio::test]
async fn contract_adapter_cancelled_signer_allocation_rolls_back_before_reuse() -> Result<()> {
    let (_r, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    initialize(&conn).await?;
    let storage = Storage::builder().conn(conn.clone()).build();
    let saved = snapshot(&conn).await?;
    storage.savepoint().await?;
    let mut callbacks = contract_callbacks(&conn);
    let create = callbacks.0.clone();
    let entered = Arc::new(Semaphore::new(0));
    let notify = entered.clone();
    callbacks.0 = Arc::new(move |height| {
        let create = create.clone();
        let notify = notify.clone();
        Box::pin(async move {
            let id = create(height).await?;
            notify.add_permits(1);
            pending::<()>().await;
            Ok(id)
        })
    });
    let mut publish = Box::pin(insert_versioned(callbacks, 1, Some(0), "cancelled", &[]));
    timeout(Duration::from_secs(10), async {
        tokio::select! {
            result = &mut publish => panic!("publish finished before cancellation: {result:?}"),
            permit = entered.acquire() => permit.unwrap().forget(),
        }
    })
    .await?;
    assert_ne!(snapshot(&conn).await?, saved);
    drop(publish);
    storage.rollback().await?;
    assert_eq!(snapshot(&conn).await?, saved);
    let id = insert_versioned(contract_callbacks(&conn), 1, Some(0), "fresh", &[]).await?;
    assert_eq!(id, 1);
    Ok(())
}
