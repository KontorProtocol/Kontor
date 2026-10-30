use anyhow::{Result, ensure};
use indexer_types::BlockRow;
use libsql::params;
use malachitebft_engine::node::NodeRef;

use super::PruneConfig;
use super::aggregate_error_tests::reactor;
use crate::database::queries::{PRUNE_WATERMARK_KEY, get_meta_u64, insert_block};
use crate::test_utils::{new_mock_block_hash, test_runtime};

struct StopEngine(NodeRef);

impl Drop for StopEngine {
    fn drop(&mut self) {
        self.0.stop(None);
    }
}

#[tokio::test]
async fn rollback_guard_preserves_deleted_history_boundary_after_reconfiguration() -> Result<()> {
    let (runtime, directory, _name) = test_runtime().await?;
    let mut reactor = reactor(runtime, &directory).await?;
    let _cleanup = StopEngine(reactor.consensus.engine_handle.actor.clone());
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
    // Reproduce a database written by the previous six-block retention policy.
    // Changing configuration cannot restore its discarded predecessor values.
    ensure!(reactor.runtime.storage.prune(0, 102).await? >= 2);
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
    reactor.last_height = 108;
    reactor.prune_watermark = get_meta_u64(&conn, PRUNE_WATERMARK_KEY, 0).await?;
    ensure!(reactor.prune_watermark == 102);
    let mut unsafe_configurations = Vec::new();
    for (label, enabled, retain_blocks) in [
        ("original retention", true, 6),
        ("increased retention", true, 288),
        ("disabled pruning", false, 288),
    ] {
        reactor.prune = PruneConfig {
            enabled,
            retain_blocks,
        };
        ensure!(reactor.check_rollback_depth(102).is_ok());
        if reactor.check_rollback_depth(101).is_ok() {
            unsafe_configurations.push(label);
        }
    }
    ensure!(
        unsafe_configurations.is_empty(),
        "rollback guard accepted already deleted history after: {unsafe_configurations:?}"
    );
    Ok(())
}
