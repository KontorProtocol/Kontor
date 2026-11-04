use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail, ensure};
use clap::Args;

use crate::toolchain::Environment;

pub const OWNERSHIP_TESTS: &[&str] = &[
    "runtime::ownership::tests::canonical_lease_drains_native_guest_before_releasing_runtime",
    "runtime::ownership::tests::canonical_and_simulation_children_keep_no_yield_policy",
    "runtime::ownership::tests::nested_api_children_inherit_actual_fuel_yields",
    "runtime::ownership::tests::cancelling_nested_yielding_api_guest_joins_before_runtime_reuse",
    "runtime::ownership::tests::cancelling_fuel_yielding_guest_joins_before_pool_reuse",
];

pub fn validate(raw: &str, names: &[&str]) -> Result<()> {
    let expected: BTreeSet<_> = names
        .iter()
        .map(|name| format!("test {name} ... ok"))
        .collect();
    ensure!(
        !names.is_empty() && expected.len() == names.len(),
        "invalid test group"
    );
    let summaries: Vec<_> = raw
        .lines()
        .filter(|line| line.starts_with("test result:"))
        .collect();
    ensure!(summaries.len() == 1, "missing or duplicate test summary");
    ensure!(
        summaries[0].starts_with(&format!(
            "test result: ok. {} passed; 0 failed; 0 ignored;",
            names.len()
        )),
        "test group did not pass every required test"
    );
    let passed: Vec<_> = raw
        .lines()
        .filter(|line| line.starts_with("test ") && line.ends_with(" ... ok"))
        .collect();
    ensure!(
        passed.len() == names.len()
            && passed.into_iter().collect::<BTreeSet<_>>()
                == expected.iter().map(String::as_str).collect(),
        "missing, duplicate, or unexpected test result"
    );
    Ok(())
}

pub(super) fn run(
    binary: &Path,
    root: &Path,
    names: &[&str],
    log: &Path,
    environment: &Environment,
    timeout: Duration,
) -> Result<()> {
    ensure!(!names.is_empty(), "empty test group");
    let stream = File::create(log)?;
    let mut child = Command::new(binary)
        .current_dir(root)
        // Capture output so test diagnostics cannot split libtest's result lines.
        .args([
            "--exact",
            "--test-threads=1",
            "--format=pretty",
            "--color=never",
            "--show-output",
        ])
        .args(names)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(stream.try_clone()?)
        .stderr(stream)
        .spawn()?;
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < timeout => thread::sleep(Duration::from_millis(10)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                result?;
                bail!(
                    "test group timed out after {}s, see {}",
                    timeout.as_secs(),
                    log.display()
                );
            }
        }
    };
    ensure!(
        status.success(),
        "test group failed ({status}), see {}",
        log.display()
    );
    validate(&fs::read_to_string(log)?, names)
}

#[derive(Debug, Args)]
pub struct OwnershipControlsArgs {
    #[arg(long)]
    pub binary: PathBuf,
    #[arg(long)]
    pub log: PathBuf,
}

pub fn ownership_controls(root: &Path, args: OwnershipControlsArgs) -> Result<()> {
    let environment = env::vars()
        .filter(|(name, _)| !name.starts_with("KONTOR_"))
        .collect();
    run(
        &root.join(args.binary).canonicalize()?,
        root,
        OWNERSHIP_TESTS,
        &root.join(args.log),
        &environment,
        Duration::from_secs(600),
    )
}
