use anyhow::Result;
use serde_json::json;

use super::{Runtime, filestorage, staking};
use crate::database::queries::find_live_subtree;

pub(super) async fn snapshot(runtime: &Runtime, scenario: &str, population: usize) -> Result<()> {
    let conn = runtime.get_storage_conn();
    for (name, address) in [
        ("staking", staking::address()),
        ("filestorage", filestorage::address()),
    ] {
        let id = runtime.storage.contract_id(&address).await?.unwrap();
        let rows = find_live_subtree(&conn, id, &[]).await?;
        let mut history = conn.query(
            "SELECT COUNT(*), COALESCE(SUM(length(path) + length(value)), 0) FROM contract_state WHERE contract_id = ?",
            [id],
        ).await?;
        let history = history.next().await?.unwrap();
        println!(
            "INDEX_STATE {}",
            json!({
                "scenario": scenario, "population": population, "contract": name,
                "live_rows": rows.len(),
                "live_bytes": rows.iter().map(|r| r.path.len() as u64 + r.size).sum::<u64>(),
                "version_rows": history.get::<u64>(0)?,
                "version_bytes": history.get::<u64>(1)?,
            })
        );
    }
    Ok(())
}
