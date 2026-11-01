use anyhow::Result;
use axum::{Router, http::StatusCode, routing::get};
use axum_test::TestServer;
use indexer_types::{ReceiptStreamResponse, StreamResetReason};
use libsql::{Connection, params};
use tempfile::TempDir;

use super::{ResumeToken, get_receipt_stream};
use crate::api::handlers::tests::{ApiResult, insert_block_at, new_test_env};
use crate::database::queries::{insert_contract, rollback_to_height};
use crate::database::receipt_stream::{MAX_SAFE_RECEIPT_ID, rotate_stream_epoch};
use crate::database::types::ContractRow;

async fn fixture() -> Result<(TestServer, Connection, TempDir)> {
    let (env, conn, dir) = new_test_env().await?;
    for height in 0..=2 {
        insert_block_at(&conn, height, &format!("{height:064x}")).await?;
    }
    conn.execute("INSERT INTO signers (id, height) VALUES (0, 0)", ())
        .await?;
    let contract = insert_contract(
        &conn,
        ContractRow::builder()
            .name("stream".into())
            .height(0)
            .tx_index(0)
            .bytes(vec![])
            .build(),
    )
    .await?;
    for (id, height) in [(80_u64, 0_u64), (100, 2)] {
        conn.execute(
            "INSERT INTO contract_results
             (id, contract_id, func, height, result_index, gas, size, signer_id)
             VALUES (?1, ?2, 'call', ?3, 0, 1, 1, 0)",
            params![id, contract, height],
        )
        .await?;
    }
    let server = TestServer::new(
        Router::new()
            .route("/receipt-stream", get(get_receipt_stream))
            .with_state(env),
    );
    Ok((server, conn, dir))
}

async fn request(server: &TestServer, query: &str) -> ReceiptStreamResponse {
    let response = server.get(&format!("/receipt-stream?{query}")).await;
    response.assert_status_ok();
    response.json::<ApiResult<ReceiptStreamResponse>>().result
}

async fn start(server: &TestServer, query: &str) -> String {
    match request(server, query).await {
        ReceiptStreamResponse::Start { resume_token } => resume_token,
        other => panic!("expected start, got {other:?}"),
    }
}

#[tokio::test]
async fn recovery_uses_completed_token_not_unfinished_page_progress() -> Result<()> {
    let (server, conn, _dir) = fixture().await?;
    let origin = start(&server, "start=origin").await;
    let tip = start(&server, "start=tip").await;
    assert_eq!(ResumeToken::parse(&origin)?.cursor, 0);
    assert_eq!(ResumeToken::parse(&tip)?.cursor, 100);
    let ReceiptStreamResponse::Page {
        receipts,
        next_token,
        has_more,
    } = request(&server, &format!("from={origin}&limit=1")).await
    else {
        panic!("expected first page");
    };
    assert!(has_more);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].receipt.row.id, 80);
    rollback_to_height(&conn, 1).await?;
    conn.execute(
        "INSERT INTO contract_results
         (contract_id, func, height, result_index, gas, size, signer_id)
         SELECT contract_id, func, 1, 0, 1, 1, 0 FROM contract_results WHERE id = 80",
        (),
    )
    .await?;
    let ReceiptStreamResponse::Recovery {
        resume_token,
        fork_height,
        more,
    } = request(&server, &format!("from={origin}&page={next_token}")).await
    else {
        panic!("expected recovery without receipt rows");
    };
    assert_eq!(fork_height, 1);
    assert!(!more);
    assert_eq!(ResumeToken::parse(&resume_token)?.cursor, 0);
    let ReceiptStreamResponse::Page { receipts, .. } =
        request(&server, &format!("from={resume_token}")).await
    else {
        panic!("expected replacement page");
    };
    assert_eq!(
        receipts
            .iter()
            .map(|row| row.receipt.row.id)
            .collect::<Vec<_>>(),
        [80, 81]
    );
    let ReceiptStreamResponse::Recovery { resume_token, .. } =
        request(&server, &format!("from={next_token}")).await
    else {
        panic!("expected completed-group recovery");
    };
    assert_eq!(ResumeToken::parse(&resume_token)?.cursor, 80);
    Ok(())
}

#[tokio::test]
async fn token_scope_and_unsupported_lineages_fail_explicitly() -> Result<()> {
    let (server, conn, _dir) = fixture().await?;
    let origin = start(&server, "start=origin").await;
    server
        .get(&format!("/receipt-stream?from={origin}&signer_id=0"))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    server
        .get("/receipt-stream?from=v1:invalid")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let mut future = ResumeToken::parse(&origin)?;
    future.generation += 1;
    assert!(matches!(
        request(&server, &format!("from={}", future.encode())).await,
        ReceiptStreamResponse::ResetRequired {
            reason: StreamResetReason::FutureGeneration
        }
    ));
    rotate_stream_epoch(&conn).await?;
    assert!(matches!(
        request(&server, &format!("from={origin}")).await,
        ReceiptStreamResponse::ResetRequired {
            reason: StreamResetReason::EpochMismatch
        }
    ));
    conn.execute(
        "INSERT INTO contract_results
         (id, contract_id, func, height, result_index, gas, size, signer_id)
         SELECT ?1, contract_id, func, 1, 0, 1, 1, 0 FROM contract_results WHERE id = 80",
        [MAX_SAFE_RECEIPT_ID + 1],
    )
    .await?;
    assert!(matches!(
        request(&server, "start=origin").await,
        ReceiptStreamResponse::ResetRequired {
            reason: StreamResetReason::UnsupportedLineage
        }
    ));
    Ok(())
}

#[tokio::test]
async fn empty_filter_page_advances_only_its_own_stream() -> Result<()> {
    let (server, _conn, _dir) = fixture().await?;
    let origin = start(&server, "start=origin&contract=absent_0_0").await;
    let ReceiptStreamResponse::Page {
        receipts,
        next_token,
        has_more,
    } = request(&server, &format!("from={origin}&contract=absent_0_0")).await
    else {
        panic!("expected empty filtered page");
    };
    assert!(receipts.is_empty());
    assert!(!has_more);
    assert_eq!(ResumeToken::parse(&next_token)?.cursor, 100);
    server
        .get(&format!("/receipt-stream?from={next_token}"))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn invalid_page_tokens_and_divergent_history_fail_explicitly() -> Result<()> {
    let (server, _conn, _dir) = fixture().await?;
    let tip = start(&server, "start=tip").await;
    let parsed = ResumeToken::parse(&tip)?;
    for page in [
        ResumeToken {
            cursor: 99,
            ..parsed.clone()
        },
        ResumeToken {
            generation: 1,
            ..parsed.clone()
        },
        ResumeToken {
            epoch: "ff".repeat(32),
            ..parsed.clone()
        },
        ResumeToken {
            filter: "ff".repeat(32),
            ..parsed.clone()
        },
    ] {
        server
            .get(&format!(
                "/receipt-stream?from={tip}&page={}",
                page.encode()
            ))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    for invalid in [
        format!("v1:{}:00:100:{}", parsed.epoch, parsed.filter),
        format!(
            "v1:{}:9223372036854775808:100:{}",
            parsed.epoch, parsed.filter
        ),
        format!(
            "v1:{}:0:{}:{}",
            parsed.epoch,
            MAX_SAFE_RECEIPT_ID + 1,
            parsed.filter
        ),
        "x".repeat(193),
    ] {
        server
            .get(&format!("/receipt-stream?from={invalid}"))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    let ahead = ResumeToken {
        cursor: 101,
        ..parsed
    }
    .encode();
    for query in [format!("from={ahead}"), format!("from={tip}&page={ahead}")] {
        assert!(matches!(
            request(&server, &query).await,
            ReceiptStreamResponse::ResetRequired {
                reason: StreamResetReason::MissingHistory
            }
        ));
    }
    Ok(())
}

#[tokio::test]
async fn multiple_recovery_batches_precede_rows_and_missing_history_resets() -> Result<()> {
    let (server, conn, _dir) = fixture().await?;
    let tip = start(&server, "start=tip").await;
    for _ in 0..257 {
        rollback_to_height(&conn, 1).await?;
    }
    let ReceiptStreamResponse::Recovery {
        resume_token,
        fork_height,
        more,
    } = request(&server, &format!("from={tip}")).await
    else {
        panic!("expected first recovery");
    };
    assert!(more);
    assert_eq!(fork_height, 1);
    let parsed = ResumeToken::parse(&resume_token)?;
    assert_eq!((parsed.generation, parsed.cursor), (256, 80));
    let ReceiptStreamResponse::Recovery {
        resume_token, more, ..
    } = request(&server, &format!("from={resume_token}")).await
    else {
        panic!("expected remaining recovery");
    };
    assert!(!more);
    assert_eq!(ResumeToken::parse(&resume_token)?.generation, 257);
    assert!(matches!(
        request(&server, &format!("from={resume_token}")).await,
        ReceiptStreamResponse::Page {
            has_more: false,
            ..
        }
    ));
    conn.execute(
        "DELETE FROM receipt_stream_rollbacks WHERE generation = 1",
        (),
    )
    .await?;
    assert!(matches!(
        request(&server, &format!("from={tip}")).await,
        ReceiptStreamResponse::ResetRequired {
            reason: StreamResetReason::MissingHistory
        }
    ));
    Ok(())
}
