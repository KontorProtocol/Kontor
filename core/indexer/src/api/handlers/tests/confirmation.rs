use anyhow::Result;
use axum::{Router, routing::get};
use axum_test::TestServer;
use indexer_types::{PaginatedResponse, ResultInfo, TransactionInfo, TransactionRow};
use libsql::TransactionBehavior;

use super::{ApiResult, insert_block_at, new_test_env};
use crate::api::confirmation;
use crate::api::handlers::{
    get_block_transactions, get_result, get_results, get_transaction, get_transactions,
};
use crate::database::confirmation::set_confirmation_position;
use crate::database::queries::{
    confirm_transaction, get_transaction_by_txid, insert_batch, insert_contract,
    insert_contract_result, insert_transaction, rollback_to_height,
};
use crate::database::types::{ContractResultRow, ContractRow};

#[tokio::test]
async fn confirmation_endpoints_preserve_execution_and_cursor_across_reorg() -> Result<()> {
    let (env, conn, _dir) = new_test_env().await?;
    insert_block_at(&conn, 1, &format!("{:064x}", 1)).await?;
    insert_batch(&conn, 9, 1, &format!("{:064x}", 1), b"fixture", false).await?;
    conn.execute("INSERT INTO signers (id, height) VALUES (0, 1)", ())
        .await?;
    let contract = insert_contract(
        &conn,
        ContractRow::builder()
            .name("fixture".into())
            .height(1)
            .tx_index(7)
            .bytes(vec![])
            .build(),
    )
    .await?;
    let txid = "01".repeat(32);
    let id = insert_transaction(
        &conn,
        TransactionRow::builder()
            .txid(txid.clone())
            .height(1)
            .batch_height(9)
            .build(),
    )
    .await?;
    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract)
            .height(1)
            .tx_id(id)
            .input_index(0)
            .op_index(0)
            .gas(3)
            .func("call".into())
            .value("ok".into())
            .build(),
    )
    .await?;
    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract)
            .height(1)
            .gas(0)
            .func("system".into())
            .build(),
    )
    .await?;
    let historical = "02".repeat(32);
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .txid(historical.clone())
            .height(1)
            .confirmed_height(1)
            .tx_index(1)
            .build(),
    )
    .await?;
    let router = Router::new()
        .route("/transactions", get(get_transactions))
        .route("/transactions/{txid}", get(get_transaction))
        .route(
            "/blocks/{identifier}/transactions",
            get(get_block_transactions),
        )
        .route("/results", get(get_results))
        .route("/results/{id}", get(get_result))
        .with_state(env);
    let server = TestServer::new(router);
    let first: ApiResult<PaginatedResponse<TransactionInfo>> =
        server.get("/transactions?order=asc&limit=1").await.json();
    assert_eq!(first.result.results[0].row.id, id);
    assert_eq!(first.result.results[0].confirmed_bitcoin_tx_index, None);
    let cursor = first.result.pagination.next_cursor.unwrap();

    for position in [Some(2), None, Some(4)] {
        match position {
            Some(position) => {
                insert_block_at(&conn, 2, &format!("{:064x}", position + 10)).await?;
                confirm_transaction(&conn, &txid, 2, 0).await?;
                set_confirmation_position(&conn, &txid, 2, position).await?;
            }
            None => {
                rollback_to_height(&conn, 1).await?;
            }
        }
        let transaction: ApiResult<TransactionInfo> =
            server.get(&format!("/transactions/{txid}")).await.json();
        assert_eq!(transaction.result.execution_height, 1);
        assert_eq!(transaction.result.row.height, 1);
        assert_eq!(transaction.result.row.batch_height, Some(9));
        assert_eq!(transaction.result.row.confirmed_height, position.map(|_| 2));
        assert_eq!(transaction.result.confirmed_bitcoin_tx_index, position);
        let result: ApiResult<Option<ResultInfo>> =
            server.get(&format!("/results/{txid}_0_0")).await.json();
        let result = result.result.unwrap();
        assert_eq!(result.execution_height, 1);
        assert_eq!(result.confirmed_height, position.map(|_| 2));
        assert_eq!(result.confirmed_bitcoin_tx_index, position);
        assert_eq!(result.batch_height, Some(9));
        assert_eq!(result.row.contract, "fixture_1_7");
        assert_eq!(result.row.gas, 3);
        let page: ApiResult<PaginatedResponse<TransactionInfo>> = server
            .get(&format!("/transactions?order=asc&limit=1&cursor={cursor}"))
            .await
            .json();
        assert_eq!(page.result.results.len(), 1);
        assert_eq!(page.result.results[0].row.txid, historical);
        assert_eq!(page.result.results[0].row.confirmed_height, Some(1));
        assert_eq!(page.result.results[0].confirmed_bitcoin_tx_index, None);
        assert!(!page.result.pagination.has_more);
        let block: ApiResult<PaginatedResponse<TransactionInfo>> =
            server.get("/blocks/1/transactions").await.json();
        assert_eq!(block.result.results.len(), 2);
        assert!(
            block
                .result
                .results
                .iter()
                .all(|row| row.execution_height == 1)
        );
    }
    let results: ApiResult<PaginatedResponse<ResultInfo>> = server.get("/results").await.json();
    let system = results
        .result
        .results
        .iter()
        .find(|row| row.row.func == "system")
        .unwrap();
    assert_eq!(system.row.txid, None);
    assert_eq!(system.execution_height, 1);
    assert_eq!(system.confirmed_height, None);
    assert_eq!(system.confirmed_bitcoin_tx_index, None);
    assert_eq!(system.batch_height, None);
    Ok(())
}

#[tokio::test]
async fn confirmation_enrichment_uses_the_same_snapshot_during_reorg() -> Result<()> {
    let (env, writer, _dir) = new_test_env().await?;
    for height in [1, 2] {
        insert_block_at(&writer, height, &format!("{height:064x}")).await?;
    }
    insert_batch(&writer, 9, 1, &format!("{:064x}", 1), b"fixture", false).await?;
    let txid = "03".repeat(32);
    insert_transaction(
        &writer,
        TransactionRow::builder()
            .txid(txid.clone())
            .height(1)
            .batch_height(9)
            .confirmed_height(2)
            .tx_index(0)
            .build(),
    )
    .await?;
    set_confirmation_position(&writer, &txid, 2, 3).await?;
    let conn = env.reader.connection().await?;
    let snapshot = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .await?;
    let row = get_transaction_by_txid(&snapshot, &txid).await?.unwrap();
    rollback_to_height(&writer, 1).await?;
    let info = confirmation::transactions(&snapshot, vec![row])
        .await?
        .pop()
        .unwrap();
    assert_eq!(info.row.confirmed_height, Some(2));
    assert_eq!(info.confirmed_bitcoin_tx_index, Some(3));
    snapshot.commit().await?;
    let row = get_transaction_by_txid(&conn, &txid).await?.unwrap();
    let info = confirmation::transactions(&conn, vec![row])
        .await?
        .pop()
        .unwrap();
    assert_eq!(info.row.confirmed_height, None);
    assert_eq!(info.confirmed_bitcoin_tx_index, None);
    Ok(())
}
