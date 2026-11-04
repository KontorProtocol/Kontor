use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Seek};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, ensure};
use clap::Args;
use serde_json::{Value, json};
use tempfile::tempfile;
use toml::Value as TomlValue;

use super::build::{FEATURE_LOGS, FORK_REVISION, feature_logs, resolve_features, source_identity};
use super::probes::{CASES, number, reports};
use super::test_group::{self, OWNERSHIP_TESTS};
use super::{REPORT_PREFIX, parse_sweep, smoke, validate_pair};
use crate::container::sha256;
use crate::toolchain::{Environment, output as command_output};
use crate::write_json;

const TEST_NAME: &str = "runtime::call::tests::native_stack::qualification_probe";
const OWNED_TEST_NAME: &str = "runtime::call::tests::native_stack::owned_stack_control";
const DEFAULT_CASES: &[&str] = &[
    "paid_recurse",
    "paid_wide",
    "view_recurse",
    "view_wide",
    "system_recurse",
    "system_wide",
    "core_recurse",
    "core_wide",
    "paid_reenter",
    "paid_huge",
];

#[derive(Args)]
pub struct CaptureStackArgs {
    #[arg(long)]
    pub binary: PathBuf,
    #[arg(long)]
    pub cell: String,
    #[arg(long, default_value = "core/Cargo.lock")]
    pub lockfile: PathBuf,
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long="case", value_parser=CASES.to_vec())]
    pub cases: Vec<String>,
    #[arg(long)]
    pub chain_log: Option<PathBuf>,
    #[arg(long)]
    pub owned_chain_log: Option<PathBuf>,
    #[arg(long)]
    pub ownership_log: Option<PathBuf>,
    #[arg(long, default_value_t = 32768)]
    pub max_depth: u64,
    #[arg(long, default_value_t = 64)]
    pub max_reentry_depth: u64,
    #[arg(long, default_value_t = 1024)]
    pub initial_depth: u64,
    #[arg(long, default_value_t = 600)]
    pub timeout: u64,
}

struct Driver<'a> {
    root: &'a Path,
    binary: &'a Path,
    output: &'a Path,
    environment: &'a Environment,
    timeout: Duration,
}
impl Driver<'_> {
    fn process(&self, name: &str, log: &Path, environment: &Environment) -> Result<String> {
        let mut stdout = tempfile()?;
        let mut stderr = tempfile()?;
        // Keep Python's stdout-then-stderr archive order, including on timeout.
        let mut child = Command::new(self.binary)
            .current_dir(self.root)
            .args(["--ignored", "--exact", name, "--nocapture"])
            .env_clear()
            .envs(environment)
            .stdin(Stdio::null())
            .stdout(stdout.try_clone()?)
            .stderr(stderr.try_clone()?)
            .spawn()?;
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if started.elapsed() < self.timeout => {
                    thread::sleep(Duration::from_millis(10))
                }
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break match result {
                        Err(error) => Err(error.into()),
                        _ => Err(anyhow!("process timed out: {name}, see {}", log.display())),
                    };
                }
            }
        };
        stdout.rewind()?;
        stderr.rewind()?;
        let mut file = File::create(log)?;
        io::copy(&mut stdout, &mut file)?;
        io::copy(&mut stderr, &mut file)?;
        let status = status?;
        ensure!(
            status.success(),
            "process exited {status}: {name}, see {}",
            log.display()
        );
        Ok(fs::read_to_string(log)?
            .replace("\r\n", "\n")
            .replace('\r', "\n"))
    }
    fn sweep(
        &self,
        kind: &str,
        role: &str,
        max_depth: u64,
        initial_depth: u64,
        depths: Option<&[u64]>,
    ) -> Result<(Vec<Value>, Value, String)> {
        let mut environment: Environment = self
            .environment
            .iter()
            .filter(|(name, _)| !name.starts_with("KONTOR_STACK_"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        environment.insert("KONTOR_STACK_MODE".into(), role.into());
        environment.insert("KONTOR_STACK_KIND".into(), kind.into());
        environment.insert("KONTOR_STACK_MAX_DEPTH".into(), max_depth.to_string());
        environment.insert(
            "KONTOR_STACK_INITIAL_DEPTH".into(),
            initial_depth.to_string(),
        );
        if let Some(depths) = depths {
            environment.insert(
                "KONTOR_STACK_CONTROL_DEPTHS".into(),
                depths
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        let name = format!("{kind}-{role}.log");
        let raw = self.process(TEST_NAME, &self.output.join(&name), &environment)?;
        let (mut samples, summary) = parse_sweep(&raw, kind, role)?;
        for sample in &mut samples {
            let name = format!("{kind}-{role}-{:04}.log", number(&sample["sample_index"])?);
            fs::write(
                self.output.join(&name),
                format!("{REPORT_PREFIX}{sample}\n"),
            )?;
            sample["log"] = json!(name);
        }
        eprintln!(
            "{kind} {role}: {} samples, {}",
            samples.len(),
            summary["boundaries"]
        );
        Ok((samples, summary, name))
    }
    fn owned(&self, kind: &str, depths: &[u64]) -> Result<(Vec<Value>, Value, String)> {
        let mut environment: Environment = self
            .environment
            .iter()
            .filter(|(name, _)| !name.starts_with("KONTOR_"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        environment.insert("KONTOR_STACK_KIND".into(), kind.into());
        environment.insert(
            "KONTOR_OWNED_DEPTHS".into(),
            depths
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
        let name = format!("{kind}-owned.log");
        self.process(OWNED_TEST_NAME, &self.output.join(&name), &environment)?;
        let observations = reports(self.output, &json!(name), "KONTOR_OWNED_STACK_REPORT:")?;
        let summaries = reports(self.output, &json!(name), "KONTOR_OWNED_STACK_SUMMARY:")?;
        ensure!(
            observations.len() == depths.len() && summaries.len() == 1,
            "missing or duplicate owned evidence"
        );
        let summary = &summaries[0];
        let outcomes = observations
            .iter()
            .map(|s| s["outcome"].clone())
            .collect::<Vec<_>>();
        ensure!(
            *summary == json!({"kind":kind,"depths":depths,"outcomes":outcomes,"owned":true}),
            "owned summary differs from observations"
        );
        Ok((observations, summary.clone(), name))
    }
    fn case(&self, kind: &str, max_depth: u64, initial_depth: u64) -> Result<Value> {
        let (worker, ws, wl) = self.sweep(kind, "worker", max_depth, initial_depth, None)?;
        let depths = if kind == "paid_huge" {
            vec![0]
        } else {
            vec![
                number(&ws["boundaries"]["last_success"])?,
                number(&ws["boundaries"]["first_failure"])?,
            ]
        };
        let (control, cs, cl) =
            self.sweep(kind, "control", max_depth, initial_depth, Some(&depths))?;
        validate_pair(&worker, &ws, &control, &cs)?;
        let (owned, summary, log) = self.owned(kind, &depths)?;
        let mut result = if kind == "paid_huge" {
            json!({})
        } else {
            ws["boundaries"].clone()
        };
        result["kind"] = json!(kind);
        result["boundary"] = json!(if kind == "paid_huge" {
            "bounded"
        } else {
            "first_failure"
        });
        result["observations"] = json!(worker);
        result["worker_summary"] = ws;
        result["worker_log"] = json!(wl);
        result["control_observations"] = json!(control);
        result["control_summary"] = cs;
        result["control_log"] = json!(cl);
        result["owned_observations"] = json!(owned);
        result["owned_summary"] = summary;
        result["owned_log"] = json!(log);
        Ok(result)
    }
}

fn acceptable(results: &[Value]) -> Result<()> {
    for case in results {
        let kind = case["kind"].as_str().context("missing case kind")?;
        if kind == "paid_huge" {
            ensure!(
                case["observations"][0]["outcome"] == "ok",
                "bounded case failed"
            );
            continue;
        }
        let expected = if kind == "paid_reenter" {
            "invocation_limit"
        } else {
            "stack_overflow"
        };
        let success = number(&case["last_success"])?;
        ensure!(
            case["boundary"] == "first_failure"
                && case["first_failure_outcome"] == expected
                && success.checked_add(1) == Some(number(&case["first_failure"])?),
            "invalid qualification boundary"
        );
        if kind == "paid_reenter" {
            ensure!(success == 63, "reentry must admit64Stores and reject65");
        }
    }
    Ok(())
}
fn copy_log(root: &Path, source: &Path, directory: &Path, name: &str) -> Result<()> {
    let source = root.join(source);
    let destination = directory.join(name);
    if !destination.exists() || source.canonicalize()? != destination.canonicalize()? {
        fs::copy(source, destination)?;
    }
    Ok(())
}

pub fn capture_stack(root: &Path, args: CaptureStackArgs) -> Result<Value> {
    capture_with_environment(root, args, &env::vars().collect())
}
fn capture_with_environment(
    root: &Path,
    args: CaptureStackArgs,
    environment: &Environment,
) -> Result<Value> {
    let directory = root.join(args.output);
    fs::create_dir_all(&directory)?;
    let path = directory.join("qualification.json");
    match fs::remove_file(&path) {
        Ok(()) => (),
        Err(e) if e.kind() == ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    ensure!(
        args.initial_depth > 0 && args.timeout > 0,
        "initial depth and timeout must be positive"
    );
    let (platform, profile) = args
        .cell
        .split_once('/')
        .context("invalid qualification cell")?;
    ensure!(
        ["dev", "release"].contains(&profile),
        "invalid qualification profile"
    );
    let target = smoke::CELLS
        .iter()
        .find(|(_, cell, _)| cell.split_once('/').map(|(p, _)| p) == Some(platform))
        .map(|(_, _, target)| *target)
        .context("unknown qualification platform")?;
    let source = source_identity(root, environment)?;
    let binary = root.join(args.binary);
    let binary_hash = sha256(&binary)?;
    let lock_path = root.join(args.lockfile);
    let lock_hash = sha256(&lock_path)?;
    let lock: TomlValue = toml::from_str(&fs::read_to_string(&lock_path)?)?;
    let packages = lock
        .get("package")
        .and_then(TomlValue::as_array)
        .context("invalid lock packages")?;
    let wasmtime: Vec<_> = packages
        .iter()
        .filter(|p| p.get("name").and_then(TomlValue::as_str) == Some("wasmtime"))
        .collect();
    ensure!(
        wasmtime.len() == 1
            && wasmtime[0].get("version").and_then(TomlValue::as_str) == Some("51.0.0-kontor.2")
            && wasmtime[0]
                .get("source")
                .and_then(TomlValue::as_str)
                .is_some_and(|s| s.rsplit('#').next() == Some(FORK_REVISION)),
        "qualification requires the exact approved Wasmtime fork revision"
    );
    let features = resolve_features(root, environment, target, &directory)?;
    let cases: Vec<&str> = if args.cases.is_empty() {
        DEFAULT_CASES.to_vec()
    } else {
        args.cases.iter().map(String::as_str).collect()
    };
    ensure!(
        cases.iter().all(|kind| CASES.contains(kind))
            && cases.iter().collect::<BTreeSet<_>>().len() == cases.len(),
        "invalid or duplicate qualification case"
    );
    let driver = Driver {
        root,
        binary: &binary,
        output: &directory,
        environment,
        timeout: Duration::from_secs(args.timeout),
    };
    let mut results = Vec::new();
    for kind in cases {
        results.push(driver.case(
            kind,
            if kind == "paid_reenter" {
                args.max_reentry_depth
            } else {
                args.max_depth
            },
            args.initial_depth,
        )?);
    }
    acceptable(&results)?;
    let mut logs = BTreeSet::new();
    for case in &results {
        for field in ["observations", "control_observations"] {
            for sample in case[field].as_array().context("invalid sample list")? {
                logs.insert(
                    sample["log"]
                        .as_str()
                        .context("missing sample log")?
                        .to_owned(),
                );
            }
        }
        for field in ["worker_log", "control_log", "owned_log"] {
            logs.insert(
                case[field]
                    .as_str()
                    .context("missing transcript")?
                    .to_owned(),
            );
        }
    }
    logs.extend(FEATURE_LOGS.iter().map(|(_, name)| (*name).to_owned()));
    let cargo = if directory.join("cargo.json").is_file() {
        logs.insert("cargo.json".into());
        json!("cargo.json")
    } else {
        Value::Null
    };
    let (chain_log, chains) = if let Some(log) = args.chain_log {
        copy_log(root, &log, &directory, "chain-matrix.log")?;
        logs.insert("chain-matrix.log".into());
        (
            json!("chain-matrix.log"),
            reports(
                &directory,
                &json!("chain-matrix.log"),
                "CHAIN_PROBE_REPORT:",
            )?,
        )
    } else {
        (Value::Null, vec![])
    };
    copy_log(
        root,
        &args.owned_chain_log.context("owned chain log required")?,
        &directory,
        "owned-chain-matrix.log",
    )?;
    let owned = reports(
        &directory,
        &json!("owned-chain-matrix.log"),
        "CHAIN_OWNED_PROBE_REPORT:",
    )?;
    ensure!(
        owned.len() == 6,
        "owned chain matrix lacks six boundary reports"
    );
    logs.insert("owned-chain-matrix.log".into());
    copy_log(
        root,
        &args
            .ownership_log
            .context("ownership lifecycle log required")?,
        &directory,
        "ownership-controls.log",
    )?;
    let lifecycle = fs::read_to_string(directory.join("ownership-controls.log"))?;
    test_group::validate(&lifecycle, OWNERSHIP_TESTS)?;
    logs.insert("ownership-controls.log".into());
    let compiler = command_output(
        root,
        Path::new("rustc"),
        &["--version", "--verbose"],
        Some(environment),
    )?;
    let host = command_output(root, Path::new("uname"), &["-a"], Some(environment))?;
    ensure!(
        source_identity(root, environment)? == source
            && sha256(&binary)? == binary_hash
            && sha256(&lock_path)? == lock_hash,
        "qualification source, lockfile or test binary changed during capture"
    );
    let hashes: Value = logs
        .into_iter()
        .map(|name| Ok((name.clone(), json!(sha256(&directory.join(name))?))))
        .collect::<Result<_>>()?;
    let report = json!({"schema_version":6,"cell":args.cell,"source_sha":source,"lockfile_sha256":lock_hash,
        "wasmtime_revision":FORK_REVISION,"wasmtime_features":features,"feature_logs":feature_logs(),"cargo_log":cargo,
        "binary":binary,"binary_sha256":binary_hash,"rustc_version_verbose":compiler,"host":host.trim(),"cases":results,
        "chains":chains,"chain_log":chain_log,"owned_chains":owned,"owned_chain_log":"owned-chain-matrix.log","ownership_log":"ownership-controls.log","log_sha256":hashes});
    write_json(&path, &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests;
