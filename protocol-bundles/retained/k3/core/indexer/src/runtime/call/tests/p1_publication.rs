use anyhow::Result;
use indexer_types::Payment;
use libsql::Connection;

use super::funded;
use crate::runtime::{ContractAddress, TransactionContext, native_provenance};
use crate::test_utils::test_runtime;

async fn persisted_rows(conn: &Connection) -> Result<Vec<(String, Vec<Vec<String>>)>> {
    let mut tables = conn
        .query(
            "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            (),
        )
        .await?;
    let mut snapshot = Vec::new();
    while let Some(table) = tables.next().await? {
        let name: String = table.get(0)?;
        let quoted = name.replace('"', "\"\"");
        let mut rows = conn
            .query(&format!("SELECT * FROM \"{quoted}\""), ())
            .await?;
        let count = rows.column_count();
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            let mut fields = Vec::new();
            for index in 0..count {
                fields.push(format!("{:?}", row.get_value(index)?));
            }
            values.push(fields);
        }
        values.sort();
        snapshot.push((name, values));
    }
    Ok(snapshot)
}

// Historical characterization, not the desired P2 behavior. Removing this no-op
// from P1 would change replay, including fee and receipt history.
#[tokio::test]
async fn p1_duplicate_publication_is_an_empty_success_without_persisted_effects() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let other_actor = funded(&mut runtime).await?;
    assert_ne!(actor.signer_id(), other_actor.signer_id());
    let payment = Payment {
        signer_id: actor.signer_id().unwrap(),
        gas_limit: 100_000,
    };
    let provenance = native_provenance()?;
    let bytes = include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br");
    runtime
        .set_context(
            1,
            Some(TransactionContext::builder().tx_index(7).build()),
            None,
            None,
        )
        .await;
    let unpublished = persisted_rows(&runtime.storage.conn).await?;
    let first = runtime
        .publish(&actor, payment.clone(), "p1-duplicate", bytes, &provenance)
        .await?;
    assert!(!first.is_empty());
    let address = ContractAddress {
        name: "p1-duplicate".into(),
        height: 1,
        tx_index: 7,
    };
    let original_id = runtime.storage.contract_id(&address).await?.unwrap();
    let baseline = persisted_rows(&runtime.storage.conn).await?;
    assert_ne!(baseline, unpublished);
    assert_eq!(
        runtime.execute(None, None, &address, "succeed()").await?,
        "42"
    );
    assert_eq!(persisted_rows(&runtime.storage.conn).await?, baseline);

    for (input_index, op_index, signer) in [(0, 1, &actor), (1, 0, &other_actor)] {
        runtime
            .set_context(
                1,
                Some(
                    TransactionContext::builder()
                        .tx_index(7)
                        .input_index(input_index)
                        .op_index(op_index)
                        .build(),
                ),
                None,
                None,
            )
            .await;
        // Distinct invalid bytes make accidental validation/replacement visible.
        let result = runtime
            .publish(
                signer,
                Payment {
                    signer_id: signer.signer_id().unwrap(),
                    ..payment.clone()
                },
                "p1-duplicate",
                b"different component bytes",
                &provenance,
            )
            .await?;
        assert_eq!(result, "");
        assert_eq!(
            runtime.storage.contract_id(&address).await?,
            Some(original_id)
        );
        assert_eq!(persisted_rows(&runtime.storage.conn).await?, baseline);
        assert!(runtime.stack.is_empty().await);
        assert!(runtime.storage.savepoint_stack.is_empty().await);
    }
    assert_eq!(
        runtime.execute(None, None, &address, "succeed()").await?,
        "42"
    );
    assert_eq!(persisted_rows(&runtime.storage.conn).await?, baseline);
    Ok(())
}
