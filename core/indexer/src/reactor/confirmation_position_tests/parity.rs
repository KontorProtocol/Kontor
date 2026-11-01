use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::protocol_qualification::compare_baseline;

// Record the archive on the preserved pre-extraction revision. The candidate
// must consume that archive rather than regenerate its own expected results.
#[tokio::test]
#[ignore = "explicit cross-revision executor comparison using a preserved seed"]
async fn retained_executor_matches_baseline() -> Result<()> {
    let path = env::var_os("KONTOR_EXECUTOR_PARITY_DIR").context("KONTOR_EXECUTOR_PARITY_DIR")?;
    let path = Path::new(&path);
    ensure!(path.is_absolute(), "use an absolute archive path");
    ensure!(
        env::var("KONTOR_EXECUTOR_PARITY_MODE")? == "compare",
        "record the baseline using the preserved pre-extraction source"
    );
    let report = compare_baseline(path).await?;
    let output =
        env::var_os("KONTOR_EXECUTOR_PARITY_OUTPUT").context("KONTOR_EXECUTOR_PARITY_OUTPUT")?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?
        .write_all(&serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
