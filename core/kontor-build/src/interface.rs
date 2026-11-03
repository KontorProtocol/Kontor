use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Seek};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::tempfile;

use crate::canonical_json::{Style, encode as canonical};
use crate::container::sha256;
use crate::recipes::executor_graphs;
use crate::toolchain::Environment;

mod probes;
use probes::{ADAPTER_TESTS, CONSENSUS, PROBES};

#[derive(PartialEq)]
pub struct Probe {
    name: &'static str,
    expected: Option<&'static str>,
    source: &'static str,
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("missing or invalid {field}"))
}
fn labels(graphs: &[Value]) -> Result<Vec<&str>> {
    graphs.iter().map(|graph| text(graph, "graph")).collect()
}
fn selection(graphs: &[Value]) -> Result<&'static [Probe]> {
    let consensus: Vec<_> = graphs
        .iter()
        .map(|graph| match graph.get("identity") {
            Some(identity) => {
                ensure!(identity.is_object(), "invalid graph identity");
                Ok(identity["kind"] == "consensus")
            }
            None => Ok(false),
        })
        .collect::<Result<_>>()?;
    let names = labels(graphs)?;
    if consensus.iter().any(|value| *value) || graphs.len() == 1 {
        ensure!(
            consensus.iter().all(|value| *value) && names == ["first"],
            "consensus interface controls require the pinned runtime graph"
        );
        return Ok(CONSENSUS);
    }
    if names == ["first", "observer"] {
        let recipe = executor_graphs(Some("managed-node"))?
            .remove("first")
            .unwrap();
        if graphs[0]["identity"]["source_root"] == recipe.source_root
            && graphs[0]["identity"]["source_snapshot"] == json!(recipe.source_snapshot)
        {
            return Ok(PROBES);
        }
        bail!("unknown retained executor interface");
    }
    Ok(PROBES)
}
fn is_consensus(graphs: &[Value]) -> Result<bool> {
    Ok(selection(graphs)? == CONSENSUS)
}
fn catalog(probes: &[Probe]) -> Value {
    json!(
        probes
            .iter()
            .map(|p| json!([p.name, p.expected, p.source]))
            .collect::<Vec<_>>()
    )
}
pub fn check_diagnostics(returncode: i32, source: &str, expected: Option<&str>) -> Result<()> {
    let mut codes = BTreeSet::new();
    let mut errors = 0;
    for line in source.lines().filter(|line| !line.trim().is_empty()) {
        let item: Value = serde_json::from_str(line)?;
        ensure!(item.is_object(), "invalid compiler diagnostic");
        if item["level"] == "error" {
            errors += 1;
            if let Some(code) = item.get("code").filter(|code| !code.is_null()) {
                codes.insert(text(code, "code")?.to_owned());
            }
        }
    }
    let valid = match expected {
        None => returncode == 0 && errors == 0,
        Some(code) => returncode != 0 && codes == BTreeSet::from([code.to_owned()]),
    };
    ensure!(
        valid,
        "interface control failed: expected {}, exit={returncode}, codes={codes:?}",
        expected.unwrap_or("success")
    );
    Ok(())
}
pub fn inputs_for(graphs: &[Value], check_files: bool, cwd: &Path) -> Result<(Vec<String>, Value)> {
    let names = labels(graphs)?;
    ensure!(
        names == ["first"] || names == ["first", "second"] || names == ["first", "observer"],
        "interface controls require both production graphs"
    );
    let dependencies: &[&str] = if is_consensus(graphs)? {
        &["tokio"]
    } else {
        &["wasmtime", "tokio"]
    };
    let mut args = Vec::new();
    let mut inputs = BTreeMap::new();
    for (alias, graph) in ["first", "second"].iter().zip(graphs) {
        let artifacts = graph["artifacts"]
            .as_array()
            .context("missing interface artifacts")?;
        let mut libraries = vec![(alias.to_string(), text(graph, "facade")?.to_string())];
        let mut recorded = BTreeMap::new();
        for item in artifacts {
            recorded.insert(text(item, "path")?, text(item, "sha256")?);
        }
        for dependency in dependencies {
            let candidates: Vec<_> = artifacts
                .iter()
                .filter_map(|item| item["path"].as_str())
                .filter(|path| {
                    Path::new(path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .is_some_and(|s| s.starts_with(&format!("lib{dependency}-")))
                })
                .collect();
            ensure!(
                candidates.len() == 1,
                "ambiguous {alias} {dependency} artifact"
            );
            libraries.push((format!("{alias}_{dependency}"), candidates[0].to_owned()));
        }
        for (name, path) in libraries {
            let path: PathBuf = Path::new(&path).components().collect();
            let path = path.to_str().context("non-UTF-8 interface path")?;
            let hash = recorded
                .get(path)
                .with_context(|| format!("interface library changed: {path}"))?;
            ensure!(
                !check_files || sha256(&cwd.join(path))? == **hash,
                "interface library changed: {path}"
            );
            args.extend(["--extern".into(), format!("{name}={path}")]);
            inputs.insert(name, hash.to_string());
        }
        args.extend([
            "-L".into(),
            format!("dependency={}", text(graph, "link_inputs")?),
        ]);
    }
    Ok((args, json!(inputs)))
}
fn encoded(value: &Value, pretty: bool) -> Result<String> {
    canonical(
        value,
        if pretty {
            Style::Pretty
        } else {
            Style::Compact
        },
    )
}
fn graph_inputs(graphs: &[Value]) -> Result<Value> {
    graphs
        .iter()
        .map(|graph| {
            Ok((
                text(graph, "graph")?.to_owned(),
                json!(hex::encode(Sha256::digest(
                    encoded(graph, false)?.as_bytes()
                ))),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()
        .map(|map| json!(map))
}
fn control_names(probes: &[Probe]) -> Value {
    json!(probes.iter().map(|p| p.name).collect::<Vec<_>>())
}
pub fn verify_report(
    directory: &Path,
    binding: &Value,
    graphs: &[Value],
    target: &str,
) -> Result<()> {
    let probes = selection(graphs)?;
    let report_path = directory.join("result.json");
    ensure!(
        sha256(&report_path)? == text(binding, "report_sha256")?
            && binding["controls"] == control_names(probes),
        "interface report binding changed"
    );
    let report: Value = serde_json::from_slice(&fs::read(report_path)?)?;
    let controls = report["controls"]
        .as_object()
        .context("invalid interface controls")?;
    ensure!(
        report["schema"] == json!(1)
            && report["status"] == "passed"
            && report["target"] == target
            && report["graph_inputs"] == graph_inputs(graphs)?
            && report["libraries"] == inputs_for(graphs, false, directory)?.1
            && controls.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == probes.iter().map(|p| p.name).collect(),
        "interface report inputs changed"
    );
    for probe in probes {
        let control = &controls[probe.name];
        let path = directory.join(format!("{}.rs", probe.name));
        let log = directory.join(format!("{}.log", probe.name));
        ensure!(
            fs::read_to_string(&path)? == probe.source
                && sha256(&path)? == text(control, "source_sha256")?
                && sha256(&log)? == text(control, "diagnostics_sha256")?
                && control.get("expected_error") == Some(&json!(probe.expected)),
            "interface source or diagnostic binding changed"
        );
        let code = control["returncode"]
            .as_i64()
            .and_then(|n| i32::try_from(n).ok())
            .context("invalid compiler returncode")?;
        check_diagnostics(code, &fs::read_to_string(log)?, probe.expected)?;
    }
    Ok(())
}
fn adapter_tests_passed(returncode: i32, output: &str) -> bool {
    returncode == 0
        && output.contains(&format!(
            "test result: ok. {} passed; 0 failed; 0 ignored;",
            ADAPTER_TESTS.len()
        ))
        && ADAPTER_TESTS
            .iter()
            .all(|name| output.contains(&format!("test {name} ... ok")))
}
pub fn verify_adapter_report(directory: &Path, binding: &Value, graphs: &[Value]) -> Result<()> {
    ensure!(
        is_consensus(graphs)?
            && binding["tests"] == json!(ADAPTER_TESTS)
            && binding["libraries"] == inputs_for(graphs, false, directory)?.1
            && binding["graph_inputs"] == graph_inputs(graphs)?,
        "node adapter inputs changed"
    );
    for (file, key) in [
        ("adapter.rs", "source_sha256"),
        ("compile.log", "compiler_log_sha256"),
        ("test.log", "test_log_sha256"),
    ] {
        ensure!(
            sha256(&directory.join(file))? == text(binding, key)?,
            "node adapter evidence binding changed"
        );
    }
    let source = fs::read_to_string(directory.join("adapter.rs"))?;
    let pattern = Regex::new(
        r#"\Amod managed \{\n#\[path = ("[^\n]+")\]\npub\(crate\) mod types;\n#\[path = ("[^\n]+")\]\npub\(crate\) mod adapter;\n}\n\z"#,
    )?;
    let capture = pattern
        .captures(&source)
        .context("node adapter source changed")?;
    let modules: Vec<PathBuf> = [1, 2]
        .into_iter()
        .map(|i| serde_json::from_str(&capture[i]))
        .collect::<std::result::Result<_, _>>()?;
    let suffix = Path::new("core/indexer/src/protocol/coordinator/managed");
    ensure!(
        modules[0].parent() == modules[1].parent()
            && modules[0].is_absolute()
            && modules[0].ends_with(suffix.join("types.rs"))
            && modules[1].ends_with(suffix.join("adapter.rs")),
        "node adapter source does not use production modules"
    );
    ensure!(
        adapter_tests_passed(0, &fs::read_to_string(directory.join("test.log"))?),
        "node adapter tests missing or failed"
    );
    Ok(())
}

fn capture(
    cwd: &Path,
    env: &Environment,
    program: &str,
    args: &[String],
    timeout: Duration,
) -> Result<(i32, String, String)> {
    let mut stdout = tempfile()?;
    let mut stderr = tempfile()?;
    let path = Path::new(program);
    let program = if path.components().count() > 1 {
        cwd.join(path)
    } else {
        path.to_owned()
    };
    let mut child = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?))
        .spawn()?;
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
                    "interface subprocess timed out after {} seconds",
                    timeout.as_secs_f64()
                );
            }
        }
    };
    let mut out = String::new();
    let mut err = String::new();
    stdout.rewind()?;
    stderr.rewind()?;
    stdout.read_to_string(&mut out)?;
    stderr.read_to_string(&mut err)?;
    Ok((
        status
            .code()
            .unwrap_or_else(|| -status.signal().unwrap_or(1)),
        out.replace("\r\n", "\n").replace('\r', "\n"),
        err.replace("\r\n", "\n").replace('\r', "\n"),
    ))
}
pub fn verify(
    graphs: &[Value],
    target: &str,
    env: &Environment,
    output: &Path,
    cwd: &Path,
) -> Result<Value> {
    let probes = selection(graphs)?;
    let directory = output.join("type-boundary");
    fs::create_dir_all(&directory)?;
    let report_path = directory.join("result.json");
    match fs::remove_file(&report_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let (arguments, inputs) = inputs_for(graphs, true, cwd)?;
    let mut controls = BTreeMap::new();
    let compiler = env.get("RUSTC").context("missing RUSTC")?;
    for probe in probes {
        let path = directory.join(format!("{}.rs", probe.name));
        fs::write(&path, probe.source)?;
        let mut args = vec![
            "--edition=2024".into(),
            "--target".into(),
            target.into(),
            "--crate-type=lib".into(),
            "--crate-name".into(),
            probe.name.replace('-', "_"),
            "--emit=metadata".into(),
            "--error-format=json".into(),
            "-Cpanic=unwind".into(),
        ];
        args.extend(arguments.clone());
        args.extend([
            path.display().to_string(),
            "-o".into(),
            directory
                .join(format!("{}.rmeta", probe.name))
                .display()
                .to_string(),
        ]);
        let (code, _, stderr) = capture(cwd, env, compiler, &args, Duration::from_secs(60))?;
        let log = directory.join(format!("{}.log", probe.name));
        fs::write(&log, &stderr)?;
        check_diagnostics(code, &stderr, probe.expected)
            .with_context(|| format!("{}; diagnostics: {}", probe.name, log.display()))?;
        controls.insert(probe.name,json!({"expected_error":probe.expected,"returncode":code,"source_sha256":sha256(&path)?,"diagnostics_sha256":sha256(&log)?}));
    }
    let report = json!({"schema":1,"status":"passed","target":target,"libraries":inputs,"graph_inputs":graph_inputs(graphs)?,"controls":controls});
    fs::write(&report_path, format!("{}\n", encoded(&report, true)?))?;
    Ok(json!({"report_sha256":sha256(&report_path)?,"controls":control_names(probes)}))
}
pub fn verify_adapter(
    root: &Path,
    graphs: &[Value],
    target: &str,
    env: &Environment,
    output: &Path,
    cwd: &Path,
) -> Result<Value> {
    ensure!(
        is_consensus(graphs)?,
        "node adapter checks require consensus graphs"
    );
    let directory = output.join("node-adapter");
    fs::create_dir_all(&directory)?;
    let source = directory.join("adapter.rs");
    let module = root.join("core/indexer/src/protocol/coordinator/managed");
    // Explicit child paths preserve the actual adapter files' module roots.
    let mut contents = "mod managed {\n".to_string();
    for name in ["types", "adapter"] {
        contents.push_str(&format!(
            "#[path = {}]\npub(crate) mod {name};\n",
            encoded(&json!(module.join(format!("{name}.rs"))), false)?
        ));
    }
    contents.push_str("}\n");
    fs::write(&source, contents)?;
    let (mut args, libraries) = inputs_for(graphs, true, cwd)?;
    for graph in graphs {
        args.extend([
            "--extern".into(),
            format!(
                "kontor_consensus_{}={}",
                text(graph, "graph")?,
                text(graph, "facade")?
            ),
        ]);
    }
    let binary = directory.join("adapter-tests");
    let mut command = vec![
        "--edition=2024".into(),
        "--target".into(),
        target.into(),
        "--test".into(),
        "--crate-name".into(),
        "node_adapter".into(),
        "-Cpanic=unwind".into(),
    ];
    command.extend(args);
    command.extend([
        source.display().to_string(),
        "-o".into(),
        binary.display().to_string(),
    ]);
    let (code, out, err) = capture(
        cwd,
        env,
        env.get("RUSTC").context("missing RUSTC")?,
        &command,
        Duration::from_secs(120),
    )?;
    let compiler_log = directory.join("compile.log");
    fs::write(&compiler_log, out + &err)?;
    ensure!(
        code == 0,
        "actual node adapter failed to compile: {}",
        compiler_log.display()
    );
    let (code, out, err) = capture(
        cwd,
        env,
        &binary.to_string_lossy(),
        &["--test-threads=1".into()],
        Duration::from_secs(30),
    )?;
    let log = directory.join("test.log");
    fs::write(&log, out.clone() + &err)?;
    ensure!(
        adapter_tests_passed(code, &out),
        "actual node adapter tests failed or did not execute: {}",
        log.display()
    );
    Ok(
        json!({"tests":ADAPTER_TESTS,"source_sha256":sha256(&source)?,"binary_sha256":sha256(&binary)?,"compiler_log_sha256":sha256(&compiler_log)?,"test_log_sha256":sha256(&log)?,"libraries":libraries,"graph_inputs":graph_inputs(graphs)?}),
    )
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Catalog,
    Probes {
        graphs: Vec<Value>,
    },
    Diagnostics {
        returncode: i32,
        text: String,
        expected: Option<String>,
    },
    Inputs {
        graphs: Vec<Value>,
        check_files: bool,
        cwd: PathBuf,
    },
    VerifyReport {
        directory: PathBuf,
        binding: Value,
        graphs: Vec<Value>,
        target: String,
    },
    Verify {
        graphs: Vec<Value>,
        target: String,
        env: Environment,
        output: PathBuf,
        cwd: PathBuf,
    },
    AdapterPassed {
        returncode: i32,
        output: String,
    },
    VerifyAdapterReport {
        directory: PathBuf,
        binding: Value,
        graphs: Vec<Value>,
    },
    VerifyAdapter {
        root: PathBuf,
        graphs: Vec<Value>,
        target: String,
        env: Environment,
        output: PathBuf,
        cwd: PathBuf,
    },
}
pub fn run(request: Request) -> Result<Value> {
    match request {
        Request::Catalog => Ok(
            json!({"probes":catalog(PROBES),"consensus":catalog(CONSENSUS),"adapter_tests":ADAPTER_TESTS}),
        ),
        Request::Probes { graphs } => Ok(catalog(selection(&graphs)?)),
        Request::Diagnostics {
            returncode,
            text,
            expected,
        } => {
            check_diagnostics(returncode, &text, expected.as_deref())?;
            Ok(Value::Null)
        }
        Request::Inputs {
            graphs,
            check_files,
            cwd,
        } => {
            let (arguments, inputs) = inputs_for(&graphs, check_files, &cwd)?;
            Ok(json!({"arguments":arguments,"inputs":inputs}))
        }
        Request::VerifyReport {
            directory,
            binding,
            graphs,
            target,
        } => {
            verify_report(&directory, &binding, &graphs, &target)?;
            Ok(Value::Null)
        }
        Request::Verify {
            graphs,
            target,
            env,
            output,
            cwd,
        } => verify(&graphs, &target, &env, &output, &cwd),
        Request::AdapterPassed { returncode, output } => {
            Ok(json!(adapter_tests_passed(returncode, &output)))
        }
        Request::VerifyAdapterReport {
            directory,
            binding,
            graphs,
        } => {
            verify_adapter_report(&directory, &binding, &graphs)?;
            Ok(Value::Null)
        }
        Request::VerifyAdapter {
            root,
            graphs,
            target,
            env,
            output,
            cwd,
        } => verify_adapter(&root, &graphs, &target, &env, &output, &cwd),
    }
}
#[cfg(test)]
mod tests;
