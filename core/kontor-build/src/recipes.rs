use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use toml::Value as Toml;

use crate::container::sha256;
use crate::snapshot::verify_snapshot;
use crate::symbol_audit::suffix;

pub const MALACHITE_REVISION: &str = "6d99c0a43a21ff48ff3f69a5f9e834310d0b0b09";
pub const MALACHITE_VERSION: &str = "0.9.0-kontor.1";
const K3_SNAPSHOT: &str = "d9d80e4af271ff122aea598778b2f36d0a2d170ffa86ff32a9f42a6328a01c09";
const P1_SNAPSHOT: &str = "8302f1341414c82ce744f872357f4b919dca3925cac0b38dea68023687ca71d4";
const HISTORICAL: &[(&str, &str, &str)] = &[
    (
        "first",
        "75a06735d294f3fc04a4ffff54492d3bf80e4121faa2e2aae64434e5b252db6b",
        "0a84113a26aea6aa3faef82eba2c5fd3164db061082da3fc4497517962d243de",
    ),
    (
        "second",
        "66dc6afb0e37b34158ec0333962c5f29fec3d3b545f253d7dc9cebe78ea4fae5",
        "6e7f58ee120e85b853541827993512f2ace20b71dc65afa25c63ac08576a95c3",
    ),
];

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Proof,
    Executor,
    Consensus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Graph {
    pub directory: String,
    pub revision: Option<String>,
    pub version: Option<String>,
    pub itoa: Option<String>,
    pub lift_rate: u64,
    pub kind: Kind,
    pub native_patches: Vec<String>,
    pub malachite_engine: bool,
    pub source_root: String,
    pub source_snapshot: Option<String>,
}
pub type Graphs = BTreeMap<String, Graph>;

pub fn execution() -> Value {
    json!({"target":"pulley64-unknown-unknown-elf", "max_wasm_stack":524288, "async_stack_size":2097152, "logical_stack_alignment":16, "guest_concurrency":false})
}

pub fn proof_graphs() -> Graphs {
    [
        (
            "first",
            "0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7",
            "51.0.0-kontor.2",
            "1.0.14",
            512,
        ),
        (
            "second",
            "0dbc68b31c0bcf1a05c93122f1939fb8784e4e48",
            "51.0.0-kontor.3",
            "1.0.15",
            513,
        ),
    ]
    .into_iter()
    .map(|(label, revision, version, itoa, lift_rate)| {
        (
            label.into(),
            Graph {
                directory: format!("pulley-{label}"),
                revision: Some(revision.into()),
                version: Some(version.into()),
                itoa: Some(itoa.into()),
                lift_rate,
                kind: Kind::Proof,
                native_patches: ["blst", "ring", "secp256k1-sys"].map(String::from).into(),
                malachite_engine: true,
                source_root: ".".into(),
                source_snapshot: None,
            },
        )
    })
    .collect()
}

fn current_executors() -> Graphs {
    proof_graphs()
        .into_iter()
        .map(|(label, mut graph)| {
            graph.directory = format!("executor-{label}");
            graph.itoa = None;
            graph.lift_rate = 512;
            graph.kind = Kind::Executor;
            graph.native_patches = ["blst", "secp256k1-sys", "psm", "wit-bindgen"]
                .map(String::from)
                .into();
            graph.malachite_engine = false;
            (label, graph)
        })
        .collect()
}
fn retained_executors() -> Graphs {
    current_executors()
        .into_iter()
        .map(|(label, mut graph)| {
            graph.source_root = "protocol-bundles/retained/k3".into();
            graph.source_snapshot = Some(K3_SNAPSHOT.into());
            (label, graph)
        })
        .collect()
}
fn p1() -> Graph {
    let mut graph = current_executors().remove("first").unwrap();
    graph.source_root = "protocol-bundles/retained/p1".into();
    graph.source_snapshot = Some(P1_SNAPSHOT.into());
    graph
}
fn observer() -> Graph {
    let mut graph = current_executors().remove("second").unwrap();
    graph.directory = "executor-observer".into();
    graph
}
pub fn executor_graphs(link_set: Option<&str>) -> Result<Graphs> {
    Ok(match link_set {
        None => current_executors(),
        Some("legacy-qualification") => retained_executors(),
        Some("managed-node") => {
            BTreeMap::from([("first".into(), p1()), ("observer".into(), observer())])
        }
        Some(name) => bail!("unknown executor link set: {name}"),
    })
}
pub fn consensus_graphs() -> Graphs {
    BTreeMap::from([(
        "first".into(),
        Graph {
            directory: "consensus-first".into(),
            revision: None,
            version: None,
            itoa: None,
            lift_rate: 0,
            kind: Kind::Consensus,
            native_patches: ["ring", "secp256k1-sys"].map(String::from).into(),
            malachite_engine: true,
            source_root: ".".into(),
            source_snapshot: None,
        },
    )])
}
fn catalog() -> Result<Value> {
    let links: BTreeMap<_, _> = ["legacy-qualification", "managed-node"]
        .into_iter()
        .map(|name| Ok((name, executor_graphs(Some(name))?)))
        .collect::<Result<_>>()?;
    Ok(
        json!({"graphs":proof_graphs(), "executor_graphs":current_executors(), "retained_executor_graphs":retained_executors(), "p1_graph":p1(), "observer_graph":observer(),
        "executor_link_sets":links, "consensus_graphs":consensus_graphs(), "malachite_revision":MALACHITE_REVISION, "malachite_version":MALACHITE_VERSION,
        "execution":execution(), "historical":HISTORICAL.iter().map(|(name, manifest, lock)| (*name, [*manifest, *lock])).collect::<BTreeMap<_, _>>()}),
    )
}

pub fn graph_root(root: &Path, graph: &Graph) -> Result<PathBuf> {
    let name = &graph.source_root;
    ensure!(
        name == "."
            || (!name.is_empty() && name.split('/').all(|part| !["", ".", ".."].contains(&part))),
        "graph source root must be a canonical repository-relative path"
    );
    let root = root.canonicalize()?;
    let selected = root
        .join(name)
        .canonicalize()
        .context("resolve graph source root")?;
    ensure!(
        selected.starts_with(&root) && selected.is_dir(),
        "graph source root escapes the repository"
    );
    if let Some(expected) = &graph.source_snapshot {
        verify_snapshot(&selected, expected)?;
    }
    Ok(selected)
}

fn dependencies(path: &Path) -> Result<Toml> {
    let manifest: Toml = toml::from_str(&fs::read_to_string(path)?)?;
    let dependencies = manifest
        .get("dependencies")
        .context("manifest dependencies missing")?;
    ensure!(dependencies.is_table(), "invalid manifest dependencies");
    Ok(dependencies.clone())
}
pub fn verify_consensus_manifest(manifest: &Path) -> Result<()> {
    let dependencies = dependencies(manifest)?;
    ensure!(
        dependencies.get("wasmtime").is_none(),
        "consensus graph must not contain Wasmtime"
    );
    let mut engines = Vec::new();
    for value in dependencies.as_table().unwrap().values() {
        if let Some(package) = value.get("package") {
            let name = package
                .as_str()
                .context("invalid dependency package name")?;
            if name.starts_with("arc-malachite") {
                engines.push(value);
            }
        }
    }
    ensure!(
        !engines.is_empty()
            && engines
                .iter()
                .all(|value| value.get("git").and_then(Toml::as_str)
                    == Some("https://github.com/KontorProtocol/malachite")
                    && value.get("rev").and_then(Toml::as_str) == Some(MALACHITE_REVISION)
                    && value.get("version").and_then(Toml::as_str)
                        == Some(&format!("={MALACHITE_VERSION}"))),
        "consensus manifest has the wrong immutable identity"
    );
    Ok(())
}
pub fn verify_reservations(root: &Path, graphs: &Graphs) -> Result<()> {
    let mut versions = BTreeSet::new();
    let mut prefixes = BTreeSet::new();
    for (directory, manifest_hash, lock_hash) in HISTORICAL {
        let base = root.join("protocol-bundles").join(directory);
        ensure!(
            sha256(&base.join("Cargo.toml"))? == *manifest_hash
                && sha256(&base.join("Cargo.lock"))? == *lock_hash,
            "historical proof inputs changed: {directory}"
        );
        let dependencies = dependencies(&base.join("Cargo.toml"))?;
        let version = dependencies
            .get("wasmtime")
            .and_then(|value| value.get("version"))
            .and_then(Toml::as_str)
            .context("historical Wasmtime version missing")?;
        let version = version.strip_prefix('=').unwrap_or(version);
        versions.insert(version.to_string());
        prefixes.insert(suffix(version));
    }
    for (label, graph) in graphs {
        let manifest = graph_root(root, graph)?
            .join("protocol-bundles")
            .join(&graph.directory)
            .join("Cargo.toml");
        if graph.kind == Kind::Consensus {
            ensure!(
                graph.version.is_none() && graph.revision.is_none(),
                "consensus recipe has an unexpected Wasmtime identity"
            );
            verify_consensus_manifest(&manifest)?;
            continue;
        }
        let version = graph
            .version
            .as_deref()
            .context("recipe Wasmtime version missing")?;
        ensure!(
            versions.insert(version.to_string()) && prefixes.insert(suffix(version)),
            "reserved Wasmtime version or native prefix: {label}"
        );
        let dependencies = dependencies(&manifest)?;
        let dependency = dependencies
            .get("wasmtime")
            .context("manifest Wasmtime dependency missing")?;
        ensure!(
            dependency.get("rev").and_then(Toml::as_str) == graph.revision.as_deref()
                && dependency.get("version").and_then(Toml::as_str) == Some(&format!("={version}")),
            "proof manifest has the wrong immutable identity: {label}"
        );
    }
    Ok(())
}
pub fn identity(root: &Path, label: &str, graphs: &Graphs) -> Result<Value> {
    let graph = graphs.get(label).context("unknown graph label")?;
    let base = graph_root(root, graph)?
        .join("protocol-bundles")
        .join(&graph.directory);
    let manifest = sha256(&base.join("Cargo.toml"))?;
    let lock = sha256(&base.join("Cargo.lock"))?;
    if graph.kind == Kind::Consensus {
        Ok(
            json!({"kind":"consensus", "directory":graph.directory, "source_root":graph.source_root, "source_snapshot":graph.source_snapshot,
            "malachite_revision":MALACHITE_REVISION, "malachite_version":MALACHITE_VERSION, "manifest_sha256":manifest, "lock_sha256":lock}),
        )
    } else {
        Ok(
            json!({"directory":graph.directory, "wasmtime_revision":graph.revision, "source_root":graph.source_root, "source_snapshot":graph.source_snapshot,
            "wasmtime_version":graph.version, "manifest_sha256":manifest, "lock_sha256":lock, "execution":execution(), "lift_rate":graph.lift_rate}),
        )
    }
}
pub fn verify_identity(root: &Path, report: &Value, graphs: &Graphs) -> Result<()> {
    let label = report
        .get("graph")
        .and_then(Value::as_str)
        .filter(|label| graphs.contains_key(*label))
        .context("graph identity or execution attestation changed")?;
    ensure!(
        report.get("identity") == Some(&identity(root, label, graphs)?),
        "graph identity or execution attestation changed"
    );
    Ok(())
}
pub fn verify_engine_observations(log: &str) -> Result<Vec<Value>> {
    let graphs = proof_graphs();
    let mut observations = Vec::new();
    let mut seen = BTreeSet::new();
    for line in log.lines() {
        if let Some(text) = line.strip_prefix("KONTOR_VM_ATTESTATION ") {
            let item: Value = serde_json::from_str(text)?;
            let label = item
                .get("graph")
                .and_then(Value::as_str)
                .context("resolved proof engine differs from its recipe")?;
            let graph = graphs
                .get(label)
                .context("resolved proof engine differs from its recipe")?;
            let mut expected = execution();
            expected["graph"] = json!(label);
            expected["lift_rate"] = json!(graph.lift_rate);
            ensure!(
                item == expected,
                "resolved proof engine differs from its recipe"
            );
            seen.insert(label.to_string());
            observations.push(item);
        }
    }
    ensure!(
        seen == graphs.keys().cloned().collect(),
        "missing resolved proof engine observations"
    );
    Ok(observations)
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Catalog,
    GraphRoot {
        root: PathBuf,
        graph: Graph,
    },
    VerifyConsensusManifest {
        manifest: PathBuf,
    },
    VerifyReservations {
        root: PathBuf,
        graphs: Graphs,
    },
    Identity {
        root: PathBuf,
        label: String,
        graphs: Graphs,
    },
    VerifyIdentity {
        root: PathBuf,
        report: Value,
        graphs: Graphs,
    },
    VerifyEngineObservations {
        log: String,
    },
}
pub fn run(request: Request) -> Result<Value> {
    match request {
        Request::Catalog => catalog(),
        Request::GraphRoot { root, graph } => Ok(json!(graph_root(&root, &graph)?)),
        Request::VerifyConsensusManifest { manifest } => {
            verify_consensus_manifest(&manifest)?;
            Ok(Value::Null)
        }
        Request::VerifyReservations { root, graphs } => {
            verify_reservations(&root, &graphs)?;
            Ok(Value::Null)
        }
        Request::Identity {
            root,
            label,
            graphs,
        } => identity(&root, &label, &graphs),
        Request::VerifyIdentity {
            root,
            report,
            graphs,
        } => {
            verify_identity(&root, &report, &graphs)?;
            Ok(Value::Null)
        }
        Request::VerifyEngineObservations { log } => Ok(json!(verify_engine_observations(&log)?)),
    }
}

#[cfg(test)]
mod tests;
