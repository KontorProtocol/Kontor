use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::ErrorKind;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    baseline_graphs, certified, executors, field, semantics, startup, storage, transitions,
};
use crate::container::sha256;
use crate::recipes::{consensus_graphs, executor_graphs};
use crate::write_json;

pub(super) const CASES: &[&str] = &[
    "native-genesis",
    "genesis-resume",
    "read-only-views",
    "committee",
    "registration-observer-capability",
    "execution-definition-factory-mapping",
    "malformed-recognition",
    "lifecycle-rollback-replay",
    "opaque-session-rejection",
    "transaction-recognition",
    "publication",
    "fees-and-deposits",
    "deterministic-failures",
    "simulation-inspection",
    "transaction-rollback-replay",
    "pending-host-callback-cancellation",
    "host-callback-failure-panic",
    "held-cursor-cancellation",
    "node-wide-capacity-shutdown",
    "export-panic-classification",
    "required-storage-contract-before-construction",
    "atomic-migration-and-retry",
    "migration-input-snapshot-and-work",
    "production-migration-registry-isolation",
    "retained-canonical-history-adapters",
];

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Check {
    Transition,
    Recovery,
    Authorization,
    Join,
}
impl Check {
    fn spec(self) -> (&'static str, &'static str, u64) {
        match self {
            Self::Transition => ("transition", "--cluster", 390),
            Self::Recovery => ("recovery", "--recovery", 420),
            Self::Authorization => ("authorization", "--authorized-replay", 420),
            Self::Join => ("join", "--join", 360),
        }
    }
    fn verify(self, value: &Value, root: &Path) -> Result<Value> {
        match self {
            Self::Transition => transitions::transition(value, root, false),
            Self::Recovery => transitions::recovery(value),
            Self::Authorization => transitions::authorization(value),
            Self::Join => transitions::join(value),
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Node {
        root: PathBuf,
        working_directory: PathBuf,
        report: PathBuf,
        link_set: Option<String>,
    },
    Check {
        root: PathBuf,
        working_directory: PathBuf,
        executable: PathBuf,
        directory: PathBuf,
        check: Check,
    },
}
pub fn run(request: Request) -> Result<Value> {
    match request {
        Request::Node {
            root,
            working_directory,
            report,
            link_set,
        } => {
            let cwd = working_directory.canonicalize()?;
            execute(
                &cwd.join(root),
                &cwd.join(report),
                link_set.as_deref(),
                &cwd,
            )
        }
        Request::Check {
            root,
            working_directory,
            executable,
            directory,
            check,
        } => {
            let cwd = working_directory.canonicalize()?;
            execute_check(
                check,
                &cwd.join(executable),
                &cwd.join(directory),
                &cwd.join(root),
                &cwd,
            )
        }
    }
}
pub(super) fn invalidate(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
fn capture(
    executable: &Path,
    directory: &Path,
    label: &str,
    args: &[&str],
    timeout: Duration,
    cwd: &Path,
) -> Result<(Value, Value)> {
    let stdout = directory.join(format!("node-{label}.stdout.json"));
    let stderr = directory.join(format!("node-{label}.stderr.log"));
    let mut child = Command::new(cwd.join(executable))
        .current_dir(cwd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(File::create(&stdout)?)
        .stderr(File::create(&stderr)?)
        .spawn()
        .with_context(|| format!("start node {label}"))?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(10)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                result?;
                bail!(
                    "node {label} timed out after {} seconds: {}",
                    timeout.as_secs_f64(),
                    stderr.display()
                );
            }
        }
    };
    ensure!(
        status.success(),
        "node {label} failed ({}): {}",
        status
            .code()
            .unwrap_or_else(|| -status.signal().unwrap_or(1)),
        stderr.display()
    );
    let result = serde_json::from_slice(&fs::read(&stdout)?)
        .with_context(|| format!("invalid node {label} JSON: {}", stdout.display()))?;
    Ok((
        result,
        json!({"stdout_sha256":sha256(&stdout)?, "stderr_sha256":sha256(&stderr)?}),
    ))
}
fn execute_check(
    check: Check,
    executable: &Path,
    directory: &Path,
    root: &Path,
    cwd: &Path,
) -> Result<Value> {
    let (label, argument, seconds) = check.spec();
    let (value, evidence) = capture(
        executable,
        directory,
        label,
        &["qualify-protocol-transition", argument],
        Duration::from_secs(seconds),
        cwd,
    )?;
    check.verify(&value, root)?;
    Ok(evidence)
}
fn graph_names(value: &Value) -> Result<Vec<&str>> {
    value
        .as_array()
        .context("graph list must be an array")?
        .iter()
        .map(|graph| graph["graph"].as_str().context("graph name missing"))
        .collect()
}
pub fn execute(
    root: &Path,
    report_path: &Path,
    link_set: Option<&str>,
    cwd: &Path,
) -> Result<Value> {
    let directory = report_path.parent().context("node report directory")?;
    let success = directory.join("node-execution.json");
    invalidate(&success)?;
    let report_hash = sha256(report_path)?;
    let report: Value = serde_json::from_slice(&fs::read(report_path)?)?;
    let node = field(&report, "node")?;
    ensure!(
        report["link_set"] == json!(link_set),
        "node build uses another executor link set"
    );
    let graphs = executor_graphs(link_set)?;
    let expected_graphs: Vec<_> = graphs.keys().map(String::as_str).collect();
    ensure!(
        graph_names(&report["graphs"])? == expected_graphs
            && node["qualification_command"] == json!(true),
        "node build does not contain the required qualification graphs"
    );
    let consensus = consensus_graphs();
    let expected_consensus: Vec<_> = if link_set == Some("managed-node") {
        consensus.keys().map(String::as_str).collect()
    } else {
        vec![]
    };
    let empty = json!([]);
    ensure!(
        graph_names(report.get("consensus_graphs").unwrap_or(&empty))? == expected_consensus,
        "node build does not contain the required consensus graphs"
    );
    let executable = cwd.join(
        node["installed"]["path"]
            .as_str()
            .context("installed node path missing")?,
    );
    let binary_hash = node["executable_sha256"]
        .as_str()
        .context("node executable hash missing")?;
    ensure!(
        sha256(&executable)? == binary_hash && node["installed"]["sha256"] == binary_hash,
        "installed node differs from the audited executable"
    );
    let started = Instant::now();
    let (observations, logs) = capture(
        &executable,
        directory,
        "execution",
        &["qualify-executors"],
        Duration::from_secs(300),
        cwd,
    )?;
    executors(&observations, link_set)?;
    let cases = observations["cases"]
        .as_array()
        .context("node execution case set changed")?;
    ensure!(
        observations["schema"].as_u64() == Some(1)
            && cases.len() == CASES.len()
            && cases.iter().map(Value::as_str).collect::<BTreeSet<_>>()
                == CASES.iter().map(|name| Some(*name)).collect(),
        "node execution case set changed"
    );
    storage(&observations, link_set)?;
    certified(&observations, link_set, root)?;
    startup(&observations, link_set)?;
    let semantic_baseline = semantics::verify(&observations, root, &baseline_graphs(link_set)?)?;
    let mut evidence = json!({"schema":1, "target":field(&report,"target")?, "profile":field(&report,"profile")?,
        "link_set":link_set, "node_build_sha256":report_hash, "executable_sha256":binary_hash,
        "stdout_sha256":logs["stdout_sha256"], "stderr_sha256":logs["stderr_sha256"],
        "cases":cases, "graphs":expected_graphs, "matching_observations":true, "semantic_baseline":semantic_baseline});
    if link_set == Some("managed-node") {
        for check in [
            Check::Transition,
            Check::Recovery,
            Check::Authorization,
            Check::Join,
        ] {
            evidence[check.spec().0] = execute_check(check, &executable, directory, root, cwd)?;
        }
    }
    ensure!(
        sha256(&executable)? == binary_hash && sha256(report_path)? == report_hash,
        "node executable or build report changed during execution"
    );
    evidence["seconds"] = json!(started.elapsed().as_secs_f64());
    write_json(&success, &evidence)?;
    Ok(evidence)
}

#[cfg(test)]
mod tests;
