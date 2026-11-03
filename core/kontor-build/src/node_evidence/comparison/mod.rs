use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::Deserialize;
use serde_json::{Value, json};

use super::runner::{CASES, invalidate};
use super::{baseline_graphs, certified, executors, semantics, startup, storage, transitions};
use crate::container::sha256;
use crate::graph_build::{fingerprint, write_json};
use crate::interface::{verify_adapter_report, verify_report};
use crate::linker_record::validate as validate_linker;
use crate::provenance::GraphKind;
use crate::recipes::{consensus_graphs, executor_graphs, graph_root, identity};
use crate::toolchain::TOOLCHAIN;

mod sources;
const TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "aarch64-apple-darwin",
];
const OWNERSHIP: &[&str] = &[
    "common-reference-ownership.json",
    "node-input-ownership.json",
    "input-ownership.json",
    "input-local-ownership.json",
    "final-ownership.json",
];
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .with_context(|| format!("missing text field {key}"))
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value[key]
        .as_array()
        .with_context(|| format!("missing array {key}"))
}
fn read(path: &Path) -> Result<Value> {
    serde_json::from_slice(&fs::read(path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("invalid JSON {}", path.display()))
}
fn file_hash(path: &Path, expected: &Value) -> Result<()> {
    ensure!(
        json!(sha256(path)?) == *expected,
        "evidence hash mismatch: {}",
        path.display()
    );
    Ok(())
}
fn digest(value: &Value) -> bool {
    value.as_str().is_some_and(|v| {
        v.len() == 64
            && v.bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    })
}
fn names(graphs: &[Value]) -> Result<Vec<&str>> {
    graphs.iter().map(|v| text(v, "graph")).collect()
}
type Cell = (String, String);
fn load_cell(path: &Path, root: &Path, link_set: Option<&str>) -> Result<(Cell, Value, Value)> {
    let directory = path.parent().context("execution report parent")?;
    let execution = read(path)?;
    ensure!(
        execution["schema"].as_u64() == Some(1) && execution["matching_observations"] == true,
        "invalid execution result"
    );
    let build_path = directory.join("node-build.json");
    file_hash(&build_path, &execution["node_build_sha256"])?;
    let build = read(&build_path)?;
    ensure!(
        build["link_set"] == json!(link_set) && execution["link_set"] == json!(link_set),
        "executor link set mismatch"
    );
    let recipes = executor_graphs(link_set)?;
    let cell = (
        text(&build, "target")?.to_owned(),
        text(&build, "profile")?.to_owned(),
    );
    ensure!(
        execution["target"] == cell.0 && execution["profile"] == cell.1,
        "execution/build cell mismatch"
    );
    let node = &build["node"];
    ensure!(
        node["qualification_command"] == true,
        "node lacks qualification command"
    );
    ensure!(
        execution["executable_sha256"] == node["executable_sha256"]
            && node["installed"]["sha256"] == node["executable_sha256"],
        "execution/installed binary mismatch"
    );
    let stdout = directory.join("node-execution.stdout.json");
    file_hash(&stdout, &execution["stdout_sha256"])?;
    file_hash(
        &directory.join("node-execution.stderr.log"),
        &execution["stderr_sha256"],
    )?;
    let mut observations = read(&stdout)?;
    ensure!(
        observations["schema"].as_u64() == Some(1),
        "unknown observation schema"
    );
    let cases = array(&observations, "cases")?;
    ensure!(
        cases.len() == CASES.len()
            && cases.iter().map(Value::as_str).collect::<BTreeSet<_>>()
                == CASES.iter().map(|name| Some(*name)).collect(),
        "case set changed"
    );
    ensure!(
        observations["cases"] == execution["cases"],
        "case record differs from raw output"
    );
    storage(&observations, link_set)?;
    certified(&observations, link_set, root)?;
    startup(&observations, link_set)?;
    let graphs: Vec<_> = recipes.keys().map(String::as_str).collect();
    ensure!(
        execution["graphs"] == json!(graphs),
        "missing or duplicate execution graph"
    );
    executors(&observations, link_set)?;
    let built_graphs = array(&build, "graphs")?;
    ensure!(
        names(built_graphs)? == graphs,
        "missing or duplicate build graph"
    );
    ensure!(
        execution["semantic_baseline"]
            == semantics::verify(&observations, root, &baseline_graphs(link_set)?)?,
        "historical semantic comparison record differs"
    );
    for label in ["transition", "recovery", "authorization", "join"] {
        if link_set != Some("managed-node") {
            ensure!(
                execution.get(label).is_none(),
                "unmanaged execution cannot claim managed {label}"
            );
            continue;
        }
        let record = &execution[label];
        ensure!(
            record.as_object().is_some_and(|map| map
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == ["stdout_sha256", "stderr_sha256"].into_iter().collect()),
            "missing managed {label} evidence"
        );
        let path = directory.join(format!("node-{label}.stdout.json"));
        file_hash(&path, &record["stdout_sha256"])?;
        file_hash(
            &directory.join(format!("node-{label}.stderr.log")),
            &record["stderr_sha256"],
        )?;
        let value = read(&path)?;
        observations[label] = match label {
            "transition" => transitions::transition(&value, root, true)?,
            "recovery" => transitions::recovery(&value)?,
            "authorization" => transitions::authorization(&value)?,
            _ => transitions::join(&value)?,
        };
    }
    let compiler: BTreeMap<_, _> = text(&build, "compiler")?
        .lines()
        .filter_map(|line| line.split_once(": "))
        .collect();
    ensure!(
        compiler.get("release") == Some(&TOOLCHAIN)
            && compiler.get("host") == Some(&cell.0.as_str()),
        "wrong compiler or host"
    );
    ensure!(
        build["toolchain_inputs"]["compiler"] == build["compiler"],
        "compiler records disagree"
    );
    let node_dir = directory.join("node");
    sources::verify(&node_dir, node, root, GraphKind::Node, None)?;
    file_hash(
        &root.join("protocol-bundles/node/Cargo.lock"),
        &node["lock_sha256"],
    )?;
    for (file, field) in [
        ("build.log", "build_log_sha256"),
        ("link-spec.json", "link_spec_sha256"),
        ("root-objects.json", "root_codegen_sha256"),
        ("linker-record.json", "linker_record_sha256"),
    ] {
        file_hash(&node_dir.join(file), &node[field])?;
    }
    file_hash(
        &root.join("core/kontor-build/src/bin/kontor-node-rustc.rs"),
        &node["wrapper_sha256"],
    )?;
    let spec = read(&node_dir.join("link-spec.json"))?;
    let wrapper_hash = &node["wrapper_binary_sha256"];
    ensure!(
        digest(wrapper_hash),
        "node compiler wrapper binary identity is missing"
    );
    let wrapper = Path::new(text(node, "wrapper")?);
    let expected_name = format!(
        "rustc-wrapper-{}-{}",
        fingerprint(&spec)?,
        wrapper_hash.as_str().unwrap()
    );
    ensure!(
        wrapper.is_absolute()
            && wrapper
                .file_name()
                .is_some_and(|name| name == expected_name.as_str()),
        "node compiler wrapper path does not match its build inputs"
    );
    ensure!(
        spec["link_set"] == json!(link_set),
        "node link specification uses another link set"
    );
    ensure!(
        spec["features"] == json!(["protocol-qualification"])
            && spec["lock_sha256"] == node["lock_sha256"]
            && spec["source_inputs_sha256"] == node["source_inputs_sha256"],
        "node link inputs disagree"
    );
    let compiler_record = read(&node_dir.join("root-objects.json"))?;
    ensure!(
        compiler_record["spec_sha256"] == node["link_spec_sha256"],
        "stale root objects"
    );
    let mut linker_sources = BTreeMap::new();
    for name in [
        "core/kontor-build/src/bin/kontor-node-linker.rs",
        "core/kontor-build/src/linker_record.rs",
    ] {
        linker_sources.insert(name, sha256(&root.join(name))?);
    }
    ensure!(
        node["linker_wrapper_sha256"] == fingerprint(&json!(linker_sources))?,
        "linker wrapper source differs"
    );
    let linker_hash = &node["linker_wrapper_binary_sha256"];
    ensure!(
        digest(linker_hash),
        "linker wrapper binary identity is missing"
    );
    let linker = Path::new(text(&spec, "linker_wrapper")?);
    ensure!(
        spec["linker_wrapper_sha256"] == *linker_hash
            && linker.is_absolute()
            && linker
                .file_name()
                .is_some_and(|name| name == "kontor-node-linker")
            && linker
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                == linker_hash.as_str(),
        "linker wrapper differs"
    );
    ensure!(
        compiler_record["linker_record_sha256"] == node["linker_record_sha256"],
        "compiler and linker records disagree"
    );
    ensure!(
        compiler_record["compiler_output"].is_object(),
        "missing completed compiler output"
    );
    validate_linker(
        &read(&node_dir.join("linker-record.json"))?,
        text(node, "link_spec_sha256")?,
        text(node, "executable_sha256")?,
        Some(&compiler_record["compiler_output"]),
    )?;
    let ownership = node["ownership"]
        .as_object()
        .context("missing ownership audit")?;
    ensure!(
        ownership
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == OWNERSHIP.iter().copied().collect(),
        "missing ownership audit"
    );
    for (name, expected) in ownership {
        file_hash(&node_dir.join(name), expected)?;
    }
    let empty = vec![];
    let consensus = match build.get("consensus_graphs") {
        Some(v) => v.as_array().context("invalid consensus graph set")?,
        None => &empty,
    };
    let selected_consensus = consensus_graphs();
    let expected_consensus: Vec<_> = if link_set == Some("managed-node") {
        selected_consensus.keys().map(String::as_str).collect()
    } else {
        vec![]
    };
    ensure!(
        names(consensus)? == expected_consensus,
        "consensus graph set changed"
    );
    let expected_roles: Vec<_> = graphs
        .iter()
        .map(|name| ("executor", *name))
        .chain(expected_consensus.iter().map(|name| ("consensus", *name)))
        .collect();
    let linked = array(&spec, "graphs")?;
    let roles: Vec<_> = linked
        .iter()
        .map(|g| {
            Ok((
                g.get("role")
                    .map(|v| v.as_str().context("invalid graph role"))
                    .transpose()?
                    .unwrap_or("executor"),
                text(g, "graph")?,
            ))
        })
        .collect::<Result<_>>()?;
    ensure!(roles == expected_roles, "link graph set changed");
    for (graph, linked) in built_graphs.iter().chain(consensus).zip(linked) {
        let name = text(graph, "graph")?;
        let role = linked
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("executor");
        let selected = if role == "consensus" {
            &selected_consensus
        } else {
            &recipes
        };
        let graph_dir = if role == "consensus" {
            directory
                .ancestors()
                .nth(2)
                .context("consensus evidence parent missing")?
                .join("consensus")
                .join(name)
        } else {
            directory.join(name)
        };
        let expected_identity = identity(root, name, selected)?;
        ensure!(
            graph["identity"] == expected_identity,
            "{name} graph identity changed"
        );
        ensure!(
            graph["lock_sha256"] == expected_identity["lock_sha256"]
                && graph["manifest_sha256"] == expected_identity["manifest_sha256"],
            "{name} lock/manifest mismatch"
        );
        ensure!(
            linked["build_inputs_sha256"] == fingerprint(graph)?,
            "{name} link graph inputs differ"
        );
        ensure!(
            read(&graph_dir.join("build-inputs.json"))? == *graph,
            "{role}/{name} graph report differs"
        );
        sources::verify(
            &graph_dir,
            graph,
            &graph_root(root, &selected[name])?,
            if role == "consensus" {
                GraphKind::Consensus
            } else {
                GraphKind::Executor
            },
            Some(root),
        )?;
        file_hash(&graph_dir.join("build.log"), &graph["build_log_sha256"])?;
        file_hash(
            &root.join("core/kontor-build/src/bin/kontor-graph-rustc.rs"),
            &graph["wrapper_sha256"],
        )?;
        let hash = &graph["wrapper_binary_sha256"];
        ensure!(
            digest(hash),
            "graph compiler wrapper binary identity is missing"
        );
        let wrapper = Path::new(text(graph, "wrapper")?);
        ensure!(
            wrapper.is_absolute()
                && wrapper
                    .file_name()
                    .is_some_and(|name| name == "kontor-graph-rustc")
                && wrapper
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    == hash.as_str(),
            "graph compiler wrapper path does not match its binary identity"
        );
    }
    verify_report(
        &node_dir.join("type-boundary"),
        &node["interface_checks"],
        built_graphs,
        &cell.0,
    )?;
    if !consensus.is_empty() {
        verify_report(
            &node_dir.join("consensus/type-boundary"),
            &node["consensus_interface_checks"],
            consensus,
            &cell.0,
        )?;
        verify_adapter_report(
            &node_dir.join("consensus/node-adapter"),
            &node["consensus_adapter_checks"],
            consensus,
        )?;
    }
    let compiler = ["release", "commit-hash", "LLVM version"]
        .into_iter()
        .map(|key| {
            Ok((
                key,
                *compiler
                    .get(key)
                    .with_context(|| format!("missing compiler {key}"))?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok((cell, observations, json!(compiler)))
}
fn reports(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    if !directory.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_name() == "node-execution.json" {
            paths.push(entry.path());
        }
        if entry.file_type()?.is_dir() {
            reports(&entry.path(), paths)?;
        }
    }
    Ok(())
}
fn compare(
    directory: &Path,
    root: &Path,
    profiles: &str,
    upstream_status: &str,
    link_set: Option<&str>,
) -> Result<Value> {
    ensure!(
        upstream_status == "success",
        "upstream qualification did not succeed: {upstream_status}"
    );
    ensure!(
        matches!(profiles, "release" | "full"),
        "unknown qualification profile policy"
    );
    executor_graphs(link_set)?;
    let profiles_list = if profiles == "release" {
        vec!["release"]
    } else {
        vec!["dev", "release"]
    };
    let expected: BTreeSet<_> = TARGETS
        .iter()
        .flat_map(|target| {
            profiles_list
                .iter()
                .map(|profile| (target.to_string(), profile.to_string()))
        })
        .collect();
    let mut found = BTreeMap::new();
    let mut reference = None;
    let mut compiler_reference = None;
    let mut paths = vec![];
    reports(directory, &mut paths)?;
    paths.sort();
    for path in paths {
        let (cell, observations, compiler) = load_cell(&path, root, link_set)?;
        ensure!(
            expected.contains(&cell) && !found.contains_key(&cell),
            "unexpected or duplicate cell: {cell:?}"
        );
        if reference.is_none() {
            reference = Some(observations.clone());
            compiler_reference = Some(compiler.clone());
        }
        ensure!(
            Some(&observations) == reference.as_ref(),
            "cross-platform execution differs: {cell:?}"
        );
        ensure!(
            Some(&compiler) == compiler_reference.as_ref(),
            "compiler version differs: {cell:?}"
        );
        found.insert(
            cell,
            json!({"execution_sha256":sha256(&path)?,"report":path}),
        );
    }
    ensure!(
        found.keys().cloned().collect::<BTreeSet<_>>() == expected,
        "missing required cells: {:?}",
        expected
            .difference(&found.keys().cloned().collect())
            .collect::<Vec<_>>()
    );
    let cells: Vec<_> = found
        .into_iter()
        .map(|((target, profile), mut value)| {
            value["target"] = json!(target);
            value["profile"] = json!(profile);
            value
        })
        .collect();
    Ok(
        json!({"schema":1,"status":"passed","policy":profiles,"upstream_status":upstream_status,"link_set":link_set,"cells":cells,"matching_observations":true,"observations_sha256":fingerprint(&reference.unwrap())?,"compiler":compiler_reference.unwrap()}),
    )
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Sources {
        directory: PathBuf,
        report: Value,
        root: PathBuf,
        kind: GraphKind,
        tool_root: Option<PathBuf>,
    },
    Compare {
        directory: PathBuf,
        root: PathBuf,
        profiles: String,
        upstream_status: String,
        link_set: Option<String>,
    },
}
pub fn run(request: Request) -> Result<Value> {
    match request {
        Request::Sources {
            directory,
            report,
            root,
            kind,
            tool_root,
        } => {
            sources::verify(&directory, &report, &root, kind, tool_root.as_deref())?;
            Ok(Value::Null)
        }
        Request::Compare {
            directory,
            root,
            profiles,
            upstream_status,
            link_set,
        } => compare(
            &directory,
            &root,
            &profiles,
            &upstream_status,
            link_set.as_deref(),
        ),
    }
}
#[derive(Debug, Args)]
pub struct CompareNodeArgs {
    /// Evidence directory, relative to the checkout root.
    #[arg(long)]
    pub directory: PathBuf,
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long,value_parser=["release","full"])]
    pub profiles: String,
    #[arg(long)]
    pub upstream_status: String,
    #[arg(long,default_value="managed-node",value_parser=["legacy-qualification","managed-node"])]
    pub link_set: String,
}
pub fn compare_node(root: &Path, args: CompareNodeArgs) -> Result<Value> {
    let output = root.join(args.output);
    invalidate(&output)?;
    let result = compare(
        &root.join(args.directory),
        root,
        &args.profiles,
        &args.upstream_status,
        Some(&args.link_set),
    );
    let value = match &result {
        Ok(value) => value.clone(),
        Err(error) => {
            json!({"schema":1,"status":"failed","policy":args.profiles,"upstream_status":args.upstream_status,"error":error.to_string()})
        }
    };
    write_json(&output, &value)?;
    result
}

#[cfg(test)]
mod tests;
