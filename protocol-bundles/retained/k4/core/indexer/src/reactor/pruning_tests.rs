use std::sync::Arc;

use anyhow::{Result, ensure};
use indexer_types::BlockRow;
use libsql::{AuthAction, AuthContext, Authorization, params};

use super::PruneConfig;
use super::execution_fixture::ExecutionFixture;
use super::executor::NoopExecutor;
use crate::consensus::signing::PrivateKey;
use crate::database::queries::{PRUNE_WATERMARK_KEY, get_meta_u64, insert_block};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::{Decimal, GenesisValidator};
use crate::test_utils::{new_mock_block_hash, test_runtime_with_genesis};

#[tokio::test]
async fn rollback_guard_preserves_deleted_history_boundary_after_reconfiguration() -> Result<()> {
    let (runtime, _directory, _name) = test_runtime_with_genesis(&[GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: PrivateKey::from([17; 32]).public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }])
    .await?;
    let mut reactor =
        ExecutionFixture::new(runtime, NoopExecutor, 1, Some(new_mock_block_hash(1))).await?;
    let conn = reactor.db_conn();
    let path = b"pruning-reconfiguration-regression".to_vec();
    for height in [100u64, 101, 102, 108] {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(height)
                .hash(new_mock_block_hash(height as u32))
                .build(),
        )
        .await?;
        conn.execute(
            "INSERT INTO contract_state (contract_id, height, tx_id, size, path, value, deleted) \
             VALUES (1, ?1, NULL, 1, ?2, ?3, 0)",
            params![height, path.clone(), vec![height as u8]],
        )
        .await?;
    }
    reactor.execution.last_height = 108;
    reactor.execution.prune = PruneConfig {
        enabled: true,
        retain_blocks: 6,
    };
    // Deadline 108 can invalidate anchor 102 and must restore height 101.
    ensure!(reactor.execution.check_rollback_depth(101).is_ok());
    ensure!(reactor.execution.check_rollback_depth(100).is_err());
    // Reproduce a database written by the previous six-block retention policy.
    // Changing configuration cannot restore its discarded predecessor values.
    conn.execute("BEGIN", ()).await?;
    ensure!(reactor.execution.prune_state(0, 102).await.is_err());
    ensure!(!conn.is_autocommit());
    conn.execute("ROLLBACK", ()).await?;
    conn.authorizer(Some(Arc::new(|context: &AuthContext<'_>| {
        if matches!(
            context.action,
            AuthAction::Delete {
                table_name: "contract_state"
            }
        ) {
            Authorization::Deny
        } else {
            Authorization::Allow
        }
    })))?;
    let failed = reactor.execution.prune_state(0, 102).await;
    conn.authorizer(None)?;
    ensure!(failed.is_err());
    ensure!(conn.is_autocommit());
    ensure!(get_meta_u64(&conn, PRUNE_WATERMARK_KEY, 0).await? == 0);
    ensure!(reactor.execution.prune_state(0, 102).await? >= 2);
    let mut rows = conn
        .query(
            "SELECT height FROM contract_state WHERE contract_id = 1 AND path = ? ORDER BY height",
            params![path],
        )
        .await?;
    let mut retained = Vec::new();
    while let Some(row) = rows.next().await? {
        retained.push(row.get::<u64>(0)?);
    }
    ensure!(retained == [102, 108]);
    reactor.execution.last_height = 108;
    reactor.execution.prune_watermark = get_meta_u64(&conn, PRUNE_WATERMARK_KEY, 0).await?;
    ensure!(reactor.execution.prune_watermark == 102);
    let mut unsafe_configurations = Vec::new();
    for (label, enabled, retain_blocks) in [
        ("original retention", true, 6),
        ("increased retention", true, 288),
        ("disabled pruning", false, 288),
    ] {
        reactor.execution.prune = PruneConfig {
            enabled,
            retain_blocks,
        };
        ensure!(reactor.execution.check_rollback_depth(102).is_ok());
        if reactor.execution.check_rollback_depth(101).is_ok() {
            unsafe_configurations.push(label);
        }
    }
    ensure!(
        unsafe_configurations.is_empty(),
        "rollback guard accepted already deleted history after: {unsafe_configurations:?}"
    );
    Ok(())
}
