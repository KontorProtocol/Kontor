use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::canonical_json::{Style, encode};
use crate::container::sha256;
use crate::execution_definition::{anchor_metadata, resolve};
use crate::provenance::{consensus_sources, local_source_files};

const ROOTS: &[&str] = &[
    "bitcoin", "bytes", "libsql", "prost", "serde", "sha2", "sha3", "tokio",
];
const TREES: &[&str] = &[
    "core/indexer/src/consensus",
    "core/indexer/proto",
    "core/indexer/src/protocol",
    "core/indexer/src/reactor",
    "core/indexer/src/database",
    "core/indexer/src/bitcoin_follower",
];
const FILES: &[&str] = &[
    "core/indexer/src/protocol/canonical_codec.rs",
    "core/indexer/src/protocol/identity.rs",
    "core/indexer/build.rs",
    "tools/protocol-bundles/symbol_tool.py",
    "tools/protocol-bundles/build.py",
    "tools/protocol-bundles/coordinator_definition.py",
];
const BASELINE: &str = "core/indexer/src/protocol/coordinator/baseline/consensus.json";
const POLICY: &str =
    "kontor/coordinator-rules-v1; locked all-target dependency closure; canonical JSON v1";
const DIRECTORY: &str = "core/indexer/src/protocol/coordinator/managed/definitions/";
const GRAPH: &str = "protocol-bundles/consensus-first/Cargo.toml";
const BUILD_INPUTS: &[&str] = &[
    "tools/protocol-bundles/managed_definition.py",
    "tools/protocol-bundles/provenance.py",
    "core/kontor-build/src/bin/kontor-node-rustc.rs",
    "tools/protocol-bundles/recipes.py",
];
type Sources = BTreeMap<String, String>;
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing or invalid {key}"))
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .with_context(|| format!("missing or invalid {key}"))
}
fn relative(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)
        .context("consensus source escapes root")?
        .to_str()
        .context("non-UTF-8 source path")?
        .into())
}
fn source(package: &Value) -> Result<Option<&str>> {
    match package.get("source").filter(|v| !v.is_null()) {
        Some(v) => Ok(Some(v.as_str().context("invalid package source")?)),
        None => Ok(None),
    }
}
fn sorted(items: Vec<Value>) -> Result<Vec<Value>> {
    let mut items = items
        .into_iter()
        .map(|v| Ok((encode(&v, Style::Compact)?, v)))
        .collect::<Result<Vec<_>>>()?;
    items.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(items.into_iter().map(|(_, v)| v).collect())
}
struct Graph<'a> {
    packages: BTreeMap<String, &'a Value>,
    nodes: BTreeMap<String, &'a Value>,
    checksums: BTreeMap<(String, String, Option<String>), Value>,
}
impl<'a> Graph<'a> {
    fn new(metadata: &'a Value, lock: &Value) -> Result<Self> {
        let index = |items: &'a [Value]| -> Result<BTreeMap<String, &'a Value>> {
            let mut map = BTreeMap::new();
            for item in items {
                ensure!(
                    map.insert(text(item, "id")?.into(), item).is_none(),
                    "duplicate metadata identity"
                );
            }
            Ok(map)
        };
        let mut checksums = BTreeMap::new();
        for item in array(lock, "package")? {
            let key = Self::key(item)?;
            ensure!(
                checksums
                    .insert(key, item.get("checksum").cloned().unwrap_or(Value::Null))
                    .is_none(),
                "duplicate lock package"
            );
        }
        Ok(Self {
            packages: index(array(metadata, "packages")?)?,
            nodes: index(array(&metadata["resolve"], "nodes")?)?,
            checksums,
        })
    }
    fn key(package: &Value) -> Result<(String, String, Option<String>)> {
        Ok((
            text(package, "name")?.into(),
            text(package, "version")?.into(),
            source(package)?.map(str::to_owned),
        ))
    }
    fn package(&self, id: &str) -> Result<&'a Value> {
        self.packages
            .get(id)
            .copied()
            .context("missing resolved package")
    }
    fn node(&self, id: &str) -> Result<&'a Value> {
        self.nodes.get(id).copied().context("missing resolve node")
    }
    fn closure(&self, roots: &BTreeSet<String>) -> Result<BTreeSet<String>> {
        let mut selected = BTreeSet::new();
        let mut pending: Vec<_> = roots.iter().cloned().collect();
        while let Some(id) = pending.pop() {
            if selected.insert(id.clone()) {
                self.package(&id)?;
                for dep in array(self.node(&id)?, "deps")? {
                    pending.push(text(dep, "pkg")?.into());
                }
            }
        }
        Ok(selected)
    }
    fn identity(&self, root: &Path, id: &str) -> Result<String> {
        let package = self.package(id)?;
        let src = match source(package)? {
            Some(src) => src.into(),
            None => relative(root, &resolve(Path::new(text(package, "manifest_path")?))?)?,
        };
        Ok(format!(
            "{}@{}:{src}",
            text(package, "name")?,
            text(package, "version")?
        ))
    }
    fn edges(&self, root: &Path, items: &[Value]) -> Result<Vec<Value>> {
        let edges = items
            .iter()
            .map(|item| {
                let kinds = match item.get("dep_kinds") {
                    Some(value) => value
                        .as_array()
                        .context("invalid dependency kinds")?
                        .clone(),
                    None => vec![],
                };
                Ok(json!({
                    "name": text(item, "name")?,
                    "package": self.identity(root, text(item, "pkg")?)?,
                    "kinds": sorted(kinds)?,
                }))
            })
            .collect::<Result<_>>()?;
        sorted(edges)
    }
    fn dependencies(&self, root: &Path, selected: &BTreeSet<String>) -> Result<Vec<Value>> {
        let mut identities = selected
            .iter()
            .map(|id| Ok((self.identity(root, id)?, id)))
            .collect::<Result<Vec<_>>>()?;
        identities.sort();
        identities
            .into_iter()
            .map(|(identity, id)| {
                let package = self.package(id)?;
                let checksum = self
                    .checksums
                    .get(&Self::key(package)?)
                    .context("resolved dependency absent from lock")?;
                if source(package)?.is_some_and(|s| s.starts_with("registry+")) {
                    ensure!(
                        checksum.as_str().is_some_and(|s| !s.is_empty()),
                        "registry dependency lacks checksum"
                    );
                }
                let node = self.node(id)?;
                let mut features: Vec<String> = serde_json::from_value(node["features"].clone())?;
                features.sort();
                Ok(json!({
                    "package": identity, "checksum": checksum, "features": features,
                    "dependencies": self.edges(root, array(node, "deps")?)?,
                }))
            })
            .collect()
    }
}
fn add(sources: &mut Sources, root: &Path, path: &Path) -> Result<()> {
    relative(root, &path.canonicalize()?)?;
    let name = relative(root, path)?;
    if name != BASELINE {
        sources.insert(name, sha256(path)?);
    }
    Ok(())
}
fn visit(
    sources: &mut Sources,
    root: &Path,
    directory: &Path,
    ancestors: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let resolved = directory.canonicalize()?;
    relative(root, &resolved)?;
    ensure!(
        ancestors.insert(resolved.clone()),
        "cyclic coordinator source directory"
    );
    let mut paths = fs::read_dir(directory)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    for path in paths {
        if path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| ["target", ".git", ".build-cache", "__pycache__"].contains(&s))
        {
            continue;
        }
        let metadata = fs::metadata(&path)?;
        if metadata.is_dir() {
            visit(sources, root, &path, ancestors)?;
        } else {
            ensure!(metadata.is_file(), "unsupported coordinator input");
            add(sources, root, &path)?;
        }
    }
    ancestors.remove(&resolved);
    Ok(())
}
pub fn coordinator(root: &Path, metadata: &Value, lock: &Value) -> Result<Value> {
    let root = root.canonicalize()?;
    let graph = Graph::new(metadata, lock)?;
    let nodes = graph
        .packages
        .values()
        .filter(|p| p["name"] == "kontor-node")
        .collect::<Vec<_>>();
    ensure!(nodes.len() == 1, "expected one kontor-node package");
    let direct = array(graph.node(text(nodes[0], "id")?)?, "deps")?;
    let mut roots = BTreeSet::new();
    for dep in direct {
        let name = text(dep, "name")?;
        if ROOTS.contains(&name)
            || name.starts_with("malachitebft_")
            || name.starts_with("malachitebft-")
        {
            roots.insert(text(dep, "pkg")?.to_string());
        }
    }
    let names = roots
        .iter()
        .map(|id| text(graph.package(id)?, "name"))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        ROOTS.iter().all(|name| names.contains(name))
            && names
                .iter()
                .any(|name| name.starts_with("arc-malachitebft-")),
        "missing consensus dependency roots"
    );
    let selected = graph.closure(&roots)?;
    let mut sources = Sources::new();
    for tree in TREES {
        visit(&mut sources, &root, &root.join(tree), &mut BTreeSet::new())?;
    }
    for file in FILES {
        add(&mut sources, &root, &root.join(file))?;
    }
    for id in &selected {
        let package = graph.package(id)?;
        if source(package)?.is_none() {
            let manifest = resolve(Path::new(text(package, "manifest_path")?))?;
            visit(
                &mut sources,
                &root,
                manifest.parent().context("invalid manifest path")?,
                &mut BTreeSet::new(),
            )?;
        }
    }
    let edges = direct
        .iter()
        .filter(|dep| dep["pkg"].as_str().is_some_and(|id| roots.contains(id)))
        .cloned()
        .collect::<Vec<_>>();
    Ok(
        json!({"schema":1,"policy":POLICY,"sources":sources,"roots":graph.edges(&root,&edges)?,"dependencies":graph.dependencies(&root,&selected)?}),
    )
}
fn graph_manifest(label: &str) -> Result<&'static str> {
    ensure!(label == "first", "unknown managed consensus graph");
    Ok(GRAPH)
}
fn destination(label: &str) -> Result<String> {
    graph_manifest(label)?;
    Ok(format!("{DIRECTORY}{label}.json"))
}
pub fn graph_reference(root: &Path, metadata: &Value, lock: &Value, label: &str) -> Result<Value> {
    let root = root.canonicalize()?;
    let graph = Graph::new(metadata, lock)?;
    let id = text(&metadata["resolve"], "root")?;
    let package = graph.package(id)?;
    ensure!(
        package["name"] == format!("kontor-consensus-{label}")
            && source(package)?.is_none()
            && Path::new(text(package, "manifest_path")?).canonicalize()?
                == root.join(graph_manifest(label)?),
        "managed definition requires the consensus-{label} graph"
    );
    let selected = graph.closure(&BTreeSet::from([id.into()]))?;
    let mut sources = consensus_sources(&root)?
        .into_iter()
        .map(|(path, hash)| {
            Ok((
                path.to_str().context("non-UTF-8 source path")?.to_owned(),
                hash,
            ))
        })
        .collect::<Result<Sources>>()?;
    for id in &selected {
        let package = graph.package(id)?;
        if source(package)?.is_none() {
            let manifest = Path::new(text(package, "manifest_path")?).canonicalize()?;
            relative(&root, &manifest)?;
            for path in local_source_files(manifest.parent().context("invalid manifest")?, &root)? {
                sources.insert(relative(&root, &path)?, sha256(&path)?);
            }
        }
    }
    Ok(
        json!({"root":graph.identity(&root,id)?,"sources":sources,"dependencies":graph.dependencies(&root,&selected)?}),
    )
}
pub fn managed(
    root: &Path,
    node: &Value,
    node_lock: &Value,
    graph: &Value,
    graph_lock: &Value,
    label: &str,
) -> Result<Value> {
    let root = root.canonicalize()?;
    let mut coordinator = coordinator(&root, node, node_lock)?;
    let sources = coordinator["sources"]
        .as_object_mut()
        .context("invalid coordinator inventory")?;
    sources.retain(|name, _| !name.starts_with(DIRECTORY));
    for file in BUILD_INPUTS {
        let path = root.join(file);
        relative(&root, &path.canonicalize()?)?;
        sources.insert((*file).into(), json!(sha256(&path)?));
    }
    Ok(
        json!({"schema":1,"policy":"kontor/managed-consensus-v1; locked all-target closure","coordinator":coordinator,"consensus":graph_reference(&root,graph,graph_lock,label)?}),
    )
}
fn bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(encode(value, Style::Compact)?.into_bytes())
}
fn verify(path: &Path, value: &Value, managed: bool) -> Result<Value> {
    let expected = bytes(value)?;
    ensure!(
        fs::read(path)? == expected,
        "{} reference differs; do not overwrite a released definition",
        if managed {
            "managed consensus"
        } else {
            "coordinator"
        }
    );
    let mut digest = Sha256::new();
    digest.update(b"kontor/consensus-definition/v1\0");
    digest.update(&expected);
    Ok(json!({"bytes":expected.len(),"consensus_definition":hex::encode(digest.finalize())}))
}
fn metadata(root: &Path, manifest: &Path, saved: Option<PathBuf>) -> Result<Value> {
    let bytes = if let Some(path) = saved {
        fs::read(root.join(path))?
    } else {
        let result = Command::new("cargo")
            .args([
                "metadata",
                "--locked",
                "--offline",
                "--format-version=1",
                "--manifest-path",
            ])
            .arg(manifest)
            .current_dir(root)
            .output()?;
        ensure!(
            result.status.success(),
            "resolve consensus metadata: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        result.stdout
    };
    Ok(serde_json::from_slice(&bytes)?)
}
#[derive(Args)]
pub struct FreezeArgs {
    #[arg(long)]
    pub baseline: bool,
    #[arg(long)]
    pub write: bool,
    #[arg(long,default_value="first",value_parser=["first"])]
    pub graph: String,
    #[arg(long)]
    pub node_metadata: Option<PathBuf>,
    #[arg(long)]
    pub graph_metadata: Option<PathBuf>,
}
pub fn freeze(root: &Path, args: FreezeArgs) -> Result<Value> {
    let node_manifest = root.join("protocol-bundles/node/Cargo.toml");
    let node = metadata(root, &node_manifest, args.node_metadata)?;
    let node_lock: Value = toml::from_str(&fs::read_to_string(
        node_manifest.with_file_name("Cargo.lock"),
    )?)?;
    let (path, value) = if args.baseline {
        (root.join(BASELINE), coordinator(root, &node, &node_lock)?)
    } else {
        let manifest = root.join(graph_manifest(&args.graph)?);
        let graph = metadata(root, &manifest, args.graph_metadata)?;
        let lock: Value =
            toml::from_str(&fs::read_to_string(manifest.with_file_name("Cargo.lock"))?)?;
        (
            root.join(destination(&args.graph)?),
            managed(root, &node, &node_lock, &graph, &lock, &args.graph)?,
        )
    };
    if args.write {
        fs::create_dir_all(path.parent().context("invalid reference destination")?)?;
        fs::write(&path, bytes(&value)?)?;
    }
    verify(&path, &value, !args.baseline)
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Catalog,
    Canonical {
        value: Value,
    },
    Coordinator {
        root: PathBuf,
        metadata: Value,
        lock: Value,
        verify: bool,
        cwd: PathBuf,
    },
    Graph {
        root: PathBuf,
        metadata: Value,
        lock: Value,
        label: String,
        cwd: PathBuf,
    },
    Managed {
        root: PathBuf,
        node: Value,
        node_lock: Value,
        graph: Value,
        graph_lock: Value,
        label: String,
        verify: bool,
        cwd: PathBuf,
    },
    Freeze {
        root: PathBuf,
        baseline: bool,
        write: bool,
        graph: String,
        node_metadata: Option<PathBuf>,
        graph_metadata: Option<PathBuf>,
    },
}
pub fn run(request: Request) -> Result<Value> {
    match request {
        Request::Catalog => Ok(
            json!({"roots":ROOTS,"trees":TREES,"files":FILES,"baseline":BASELINE,"policy":POLICY,"directory":DIRECTORY,"graph":GRAPH,"build_inputs":BUILD_INPUTS,"destination":destination("first")?}),
        ),
        Request::Canonical { value } => Ok(json!(encode(&value, Style::Compact)?)),
        Request::Coordinator {
            root,
            mut metadata,
            lock,
            verify: check,
            cwd,
        } => {
            anchor_metadata(&mut metadata, &cwd)?;
            let value = coordinator(&root, &metadata, &lock)?;
            if check {
                verify(&root.join(BASELINE), &value, false)
            } else {
                Ok(json!(encode(&value, Style::Compact)?))
            }
        }
        Request::Graph {
            root,
            mut metadata,
            lock,
            label,
            cwd,
        } => {
            anchor_metadata(&mut metadata, &cwd)?;
            graph_reference(&root, &metadata, &lock, &label)
        }
        Request::Managed {
            root,
            mut node,
            node_lock,
            mut graph,
            graph_lock,
            label,
            verify: check,
            cwd,
        } => {
            anchor_metadata(&mut node, &cwd)?;
            anchor_metadata(&mut graph, &cwd)?;
            let value = managed(&root, &node, &node_lock, &graph, &graph_lock, &label)?;
            if check {
                verify(&root.join(destination(&label)?), &value, true)
            } else {
                Ok(json!(encode(&value, Style::Compact)?))
            }
        }
        Request::Freeze {
            root,
            baseline,
            write,
            graph,
            node_metadata,
            graph_metadata,
        } => freeze(
            &root,
            FreezeArgs {
                baseline,
                write,
                graph,
                node_metadata,
                graph_metadata,
            },
        ),
    }
}
#[cfg(test)]
mod tests;
