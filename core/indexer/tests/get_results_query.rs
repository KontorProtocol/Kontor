use anyhow::Result;
use indexer::{
    database::{
        queries::{
            get_results_paginated, insert_block, insert_contract, insert_contract_result,
            insert_processed_block, insert_transaction,
        },
        types::{ContractResultRow, ContractRow, ResultQuery},
    },
    test_utils::{new_mock_block_hash, new_mock_transaction, new_test_db},
};
use indexer_types::{BlockRow, TransactionRow};
use testlib::ContractAddress;

#[tokio::test]
async fn test_get_results_query() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    insert_processed_block(
        &conn,
        BlockRow::builder()
            .height(1)
            .hash(new_mock_block_hash(1))
            .build(),
    )
    .await?;

    let contract_1_id = insert_contract(
        &conn,
        ContractRow::builder()
            .name("token".to_string())
            .height(1)
            .tx_index(1)
            .bytes(vec![])
            .build(),
    )
    .await?;

    let contract_2_id = insert_contract(
        &conn,
        ContractRow::builder()
            .name("storage".to_string())
            .height(1)
            .tx_index(2)
            .bytes(vec![])
            .build(),
    )
    .await?;

    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(1)
            .txid(new_mock_transaction(1003).txid.to_string())
            .tx_index(3)
            .build(),
    )
    .await?;

    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(1)
            .txid(new_mock_transaction(1004).txid.to_string())
            .tx_index(4)
            .build(),
    )
    .await?;

    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract_1_id)
            .height(1)
            .tx_index(3)
            .gas(100)
            .build(),
    )
    .await?;

    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract_2_id)
            .func("foo".to_string())
            .height(1)
            .tx_index(4)
            .gas(100)
            .build(),
    )
    .await?;

    insert_processed_block(
        &conn,
        BlockRow::builder()
            .height(2)
            .hash(new_mock_block_hash(2))
            .build(),
    )
    .await?;

    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(2)
            .txid(new_mock_transaction(2001).txid.to_string())
            .tx_index(1)
            .build(),
    )
    .await?;

    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(2)
            .txid(new_mock_transaction(2002).txid.to_string())
            .tx_index(2)
            .build(),
    )
    .await?;

    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract_1_id)
            .height(2)
            .tx_index(1)
            .gas(100)
            .build(),
    )
    .await?;

    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract_2_id)
            .height(2)
            .tx_index(2)
            .gas(100)
            .build(),
    )
    .await?;

    insert_processed_block(
        &conn,
        BlockRow::builder()
            .height(3)
            .hash(new_mock_block_hash(3))
            .build(),
    )
    .await?;

    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(3)
            .txid(new_mock_transaction(3001).txid.to_string())
            .tx_index(1)
            .build(),
    )
    .await?;

    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(3)
            .txid(new_mock_transaction(3002).txid.to_string())
            .tx_index(2)
            .build(),
    )
    .await?;

    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract_1_id)
            .height(3)
            .tx_index(1)
            .gas(100)
            .build(),
    )
    .await?;

    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract_2_id)
            .height(3)
            .tx_index(2)
            .gas(100)
            .build(),
    )
    .await?;

    insert_block(
        &conn,
        BlockRow::builder()
            .height(4)
            .hash(new_mock_block_hash(4))
            .build(),
    )
    .await?;

    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(4)
            .txid(new_mock_transaction(4001).txid.to_string())
            .tx_index(1)
            .build(),
    )
    .await?;

    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract_1_id)
            .height(4)
            .tx_index(1)
            .gas(100)
            .build(),
    )
    .await?;

    // ignores unprocessed block result
    let (_, meta) = get_results_paginated(
        &conn,
        ResultQuery::builder()
            .order(indexer::database::types::OrderDirection::Asc)
            .limit(1)
            .build(),
    )
    .await?;
    assert_eq!(meta.total_count, 6);

    // contract filtering
    let (results, meta) = get_results_paginated(
        &conn,
        ResultQuery::builder()
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 1,
                tx_index: 1,
            })
            .order(indexer::database::types::OrderDirection::Asc)
            .limit(1)
            .build(),
    )
    .await?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].contract_name, "token");
    assert_eq!(results[0].contract_height, 1);
    assert_eq!(results[0].contract_tx_index, 1);
    assert_eq!(meta.total_count, 3);

    // func filtering
    let (results, meta) = get_results_paginated(
        &conn,
        ResultQuery::builder()
            .contract(ContractAddress {
                name: "storage".to_string(),
                height: 1,
                tx_index: 2,
            })
            .func("foo".to_string())
            .order(indexer::database::types::OrderDirection::Asc)
            .limit(1)
            .build(),
    )
    .await?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].func, "foo".to_string());
    assert_eq!(results[0].contract_name, "storage");
    assert_eq!(results[0].contract_height, 1);
    assert_eq!(results[0].contract_tx_index, 2);
    assert_eq!(meta.total_count, 1);
    assert_eq!(meta.next_cursor, Some(results[0].id));

    // height filtering
    let (results, meta) = get_results_paginated(
        &conn,
        ResultQuery::builder()
            .height(2)
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 1,
                tx_index: 1,
            })
            .order(indexer::database::types::OrderDirection::Asc)
            .limit(1)
            .build(),
    )
    .await?;
    assert_eq!(results[0].height, 2);
    assert_eq!(meta.total_count, 1);

    // start height
    let (results, meta) = get_results_paginated(
        &conn,
        ResultQuery::builder()
            .start_height(2)
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 1,
                tx_index: 1,
            })
            .order(indexer::database::types::OrderDirection::Asc)
            .limit(1)
            .build(),
    )
    .await?;
    assert_eq!(results[0].height, 2);
    assert_eq!(meta.total_count, 2);
    assert!(meta.next_cursor.is_some());

    let (results, meta) = get_results_paginated(
        &conn,
        ResultQuery::builder()
            .maybe_cursor(meta.next_cursor)
            .start_height(2)
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 1,
                tx_index: 1,
            })
            .order(indexer::database::types::OrderDirection::Asc)
            .limit(1)
            .build(),
    )
    .await?;

    assert_eq!(results[0].height, 3);
    assert_eq!(meta.total_count, 1);
    assert!(!meta.has_more);
    assert_eq!(meta.next_cursor, Some(results[0].id));

    Ok(())
}
