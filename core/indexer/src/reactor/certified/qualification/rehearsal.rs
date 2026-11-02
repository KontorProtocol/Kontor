use std::env;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use libsql::Connection;
use serde_json::{Value, json};
use tokio::process::Command;
use tokio::time::timeout;

use crate::database::certified_history::{self, control};
use crate::protocol::v1::migration_definition;
use crate::protocol_qualification::snapshot::full_state;

pub(super) async fn run(directory: &Path, conn: &Connection) -> Result<()> {
    let frontier = certified_history::frontier(conn).await?;
    let context = frontier
        .context
        .context("rehearsal fixture lacks context")?;
    let state = control::admission::state(conn, context).await?;
    let database = directory.join("callbacks.db");
    let wal = directory.join("callbacks.db-wal");
    let database_before = fs::read(&database)?;
    let wal_before = fs::read(&wal).ok();
    let state_before = full_state(conn).await?;
    let target_file = directory.join("rehearsal-target.json");
    for registered in [true, false] {
        let mut target = state.current_manifest.clone();
        target.protocol_number += 1;
        target.predecessor = context.protocol;
        let mut definition = migration_definition::noop(target.executor);
        if !registered {
            definition.routine = "not-installed".into();
        }
        target.migration = definition.id()?;
        fs::write(
            &target_file,
            serde_json::to_vec(&json!({
                "manifest_hex": hex::encode(target.encode()?),
                "migration_definition_hex": hex::encode(definition.encode()?),
            }))?,
        )?;
        let output = timeout(
            Duration::from_secs(60),
            Command::new(env::current_exe()?)
                .arg("rehearse-migration")
                .arg("--database")
                .arg(&database)
                .args(["--network", "regtest", "--target"])
                .arg(&target_file)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .context("rehearsal CLI timed out")??;
        ensure!(
            output.status.success() == registered,
            "rehearsal CLI status differs: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout)
            .context("rehearsal CLI did not emit a JSON report")?;
        ensure!(report["outcome"] == if registered { "succeeded" } else { "failed" });
        ensure!(report["authorizes_upgrade"] == false);
        ensure!(report["target_protocol_id"] == hex::encode(target.id()?.0));
        ensure!(report["source_protocol_id"] == hex::encode(context.protocol.0));
        ensure!(report["decision_height"] == frontier.closed_height.to_string());
        ensure!(report["target_support"]["executor_registered"] == true);
        ensure!(report["target_support"]["migration_registered"] == registered);
        ensure!(report["work_consumed"]["computation_steps"] == "0");
        if registered {
            ensure!(report["error"].is_null());
            ensure!(
                report["output_lineage"].is_string()
                    && report["output_lineage"] != report["input_lineage"]
            );
        } else {
            ensure!(
                report["error"]
                    .as_str()
                    .is_some_and(|error| error.contains("not registered"))
            );
            ensure!(report["output_lineage"].is_null());
        }
        ensure!(fs::read(&database)? == database_before);
        ensure!(fs::read(&wal).ok() == wal_before);
        ensure!(
            full_state(conn).await? == state_before,
            "rehearsal mutated source state"
        );
    }
    Ok(())
}
