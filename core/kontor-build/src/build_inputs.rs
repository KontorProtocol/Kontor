use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::build_artifacts::{Request as ArtifactRequest, run as artifacts};
use crate::recipes::{Graph, Kind, MALACHITE_REVISION, MALACHITE_VERSION, graph_root};

#[derive(Deserialize)]
pub struct Metadata {
    packages: Vec<Package>,
    resolve: Resolve,
}
#[derive(Deserialize)]
struct Package {
    id: String,
    name: String,
    version: String,
    #[serde(deserialize_with = "Option::<String>::deserialize")]
    source: Option<String>,
    manifest_path: Option<PathBuf>,
}
#[derive(Deserialize)]
struct Resolve {
    root: String,
    nodes: Vec<Node>,
}
#[derive(Deserialize)]
struct Node {
    id: String,
    features: Vec<String>,
    deps: Vec<Dependency>,
}
#[derive(Deserialize)]
struct Dependency {
    pkg: String,
}

fn patched(package: &Package, root: &Path) -> bool {
    package
        .manifest_path
        .as_deref()
        .and_then(Path::parent)
        .and_then(|path| path.canonicalize().ok())
        .is_some_and(|path| path == root.join("core/vendor").join(&package.name))
}
fn revision(package: &Package, expected: &str) -> bool {
    package
        .source
        .as_deref()
        .is_some_and(|source| source.ends_with(&format!("#{expected}")))
}

pub fn identities(root: &Path, recipe: &Graph, data: &Metadata) -> Result<Value> {
    let source_root = graph_root(root, recipe)?;
    let packages: BTreeMap<_, _> = data.packages.iter().map(|p| (&p.id, p)).collect();
    let nodes: BTreeMap<_, _> = data.resolve.nodes.iter().map(|n| (&n.id, n)).collect();
    ensure!(
        packages.len() == data.packages.len() && nodes.len() == data.resolve.nodes.len(),
        "duplicate package or resolve node identity"
    );
    let mut reachable = BTreeSet::new();
    let mut pending = vec![&data.resolve.root];
    while let Some(id) = pending.pop() {
        if reachable.insert(id) {
            let node = nodes.get(id).context("missing reachable resolve node")?;
            ensure!(packages.contains_key(id), "missing reachable package");
            pending.extend(node.deps.iter().map(|dep| &dep.pkg));
        }
    }
    let selected: Vec<_> = reachable.iter().map(|id| packages[id]).collect();
    let one = |name: &str| -> Result<&Package> {
        let found: Vec<_> = selected.iter().filter(|p| p.name == name).collect();
        ensure!(
            found.len() == 1,
            "expected one {name}, found {}",
            found.len()
        );
        Ok(found[0])
    };
    if recipe.kind == Kind::Consensus {
        ensure!(
            !selected
                .iter()
                .any(|p| ["wasmtime", "libsql"].contains(&p.name.as_str())),
            "consensus graph contains execution or storage services"
        );
        for package in &selected {
            if package.name.starts_with("arc-malachite") {
                ensure!(
                    package.version == MALACHITE_VERSION && revision(package, MALACHITE_REVISION),
                    "unqualified {} source or version",
                    package.name
                );
            }
        }
    } else {
        let vm = one("wasmtime")?;
        ensure!(
            Some(vm.version.as_str()) == recipe.version.as_deref()
                && revision(
                    vm,
                    recipe
                        .revision
                        .as_deref()
                        .context("missing Wasmtime revision")?
                ),
            "immutable Wasmtime identity changed"
        );
        ensure!(
            !nodes[&vm.id]
                .features
                .iter()
                .any(|name| ["cache", "profiling", "debug-builtins"].contains(&name.as_str())),
            "forbidden Wasmtime feature"
        );
    }
    if recipe.malachite_engine {
        for name in ["arc-malachitebft-app-channel", "if-watch"] {
            ensure!(
                revision(one(name)?, MALACHITE_REVISION),
                "unqualified {name} source"
            );
        }
    }
    if let Some(expected) = &recipe.itoa {
        ensure!(
            &one("itoa")?.version == expected,
            "missing conflicting itoa version"
        );
    }
    for name in &recipe.native_patches {
        ensure!(
            patched(one(name)?, &source_root),
            "missing native patch for {name}"
        );
    }
    if recipe.kind == Kind::Executor {
        ensure!(
            !selected
                .iter()
                .any(|p| ["libsql", "arc-malachitebft-app-channel", "if-watch"]
                    .contains(&p.name.as_str())),
            "executor graph contains node-owned storage or consensus services"
        );
        // Optional native libraries still require ownership when made reachable.
        for package in &selected {
            if package.name == "ring" {
                ensure!(
                    patched(package, &source_root),
                    "missing native patch for ring"
                );
            }
        }
    }
    Ok(json!(
        selected
            .into_iter()
            .map(|p| {
                let mut features = nodes[&p.id].features.clone();
                features.sort();
                json!({"name":p.name, "version":p.version, "source":p.source, "features":features})
            })
            .collect::<Vec<_>>()
    ))
}

pub fn current_artifacts(
    log: &Path,
    target_dir: &Path,
    target: &str,
    package: &str,
) -> Result<Value> {
    let target_root = target_dir.join(target);
    let mut archives = BTreeSet::new();
    let mut proc_macros = BTreeSet::new();
    let mut facades = BTreeSet::new();
    let mut native_outputs = Vec::new();
    for line in fs::read_to_string(log)?.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        match value.get("reason").and_then(Value::as_str) {
            Some("compiler-artifact") => {
                let kinds: Vec<String> = serde_json::from_value(value["target"]["kind"].clone())?;
                let files: Vec<PathBuf> = serde_json::from_value(value["filenames"].clone())?;
                for path in files {
                    let extension = path.extension().and_then(|value| value.to_str());
                    if kinds.iter().any(|kind| kind == "proc-macro")
                        && matches!(extension, Some("so" | "dylib"))
                    {
                        proc_macros.insert(path.clone());
                    }
                    if extension == Some("rlib") && path.starts_with(&target_root) {
                        if value["target"]["name"]
                            .as_str()
                            .context("missing artifact target name")?
                            == package.replace('-', "_")
                        {
                            facades.insert(path.clone());
                        }
                        archives.insert(path);
                    }
                }
            }
            Some("build-script-executed") => {
                let output = Path::new(
                    value["out_dir"]
                        .as_str()
                        .context("missing build script output directory")?,
                );
                if output.starts_with(&target_root) {
                    native_outputs.push(value);
                }
            }
            _ => {}
        }
    }
    ensure!(
        facades.len() == 1 && !archives.is_empty(),
        "missing or ambiguous current bundle rlib: {facades:?}"
    );
    Ok(
        json!({"archives":archives, "facade":facades.first().unwrap(), "native_outputs":native_outputs, "proc_macros":proc_macros}),
    )
}

const DISABLED: &[&str] = &[
    "wasm_component_model_async",
    "wasm_component_model_more_async_builtins",
    "wasm_component_model_async_stackful",
    "wasm_component_model_threading",
    "wasm_component_model_error_context",
    "wasm_shared_everything_threads",
    "wasm_stack_switching",
    "concurrency_support",
    "wasm_threads",
];
fn settings(source: &str) -> Result<()> {
    let pattern = Regex::new(r"\.([a-z_]+)\(\s*(true|false)\s*\)")?;
    let selected: Vec<_> = pattern
        .captures_iter(source)
        .filter(|captures| DISABLED.contains(&&captures[1]))
        .map(|captures| (captures[1].to_owned(), captures[2].to_owned()))
        .collect();
    let names: BTreeSet<_> = selected.iter().map(|(name, _)| name.as_str()).collect();
    ensure!(
        selected.len() == DISABLED.len()
            && names.len() == DISABLED.len()
            && selected.iter().all(|(_, value)| value == "false"),
        "guest capability settings differ from the synchronous baseline"
    );
    Ok(())
}
pub fn capabilities(root: &Path) -> Result<()> {
    let source = fs::read_to_string(root.join("core/indexer/src/runtime/mod.rs"))?;
    let pattern = Regex::new(r"pub fn new_engine\(\) -> Result<Engine>\s*\{([^}]+)\}")?;
    let facade = pattern.captures(&source);
    ensure!(
        facade.is_some_and(|capture| capture[1].trim() == "engine::new_engine()")
            && source.contains("use crate::protocol::v1::engine;"),
        "node engine does not delegate to retained P1 configuration"
    );
    settings(&fs::read_to_string(
        root.join("core/indexer/src/protocol/v1/engine.rs"),
    )?)?;
    settings(&fs::read_to_string(
        root.join("protocol-bundles/proof/vm.rs"),
    )?)?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Artifacts {
        #[serde(flatten)]
        request: ArtifactRequest,
    },
    Identities {
        root: PathBuf,
        recipe: Graph,
        data: Metadata,
    },
    CurrentArtifacts {
        log: PathBuf,
        target_dir: PathBuf,
        target: String,
        package: String,
    },
    Capabilities {
        root: PathBuf,
    },
}
pub fn run(request: Request) -> Result<Value> {
    match request {
        Request::Artifacts { request } => artifacts(request),
        Request::Identities { root, recipe, data } => identities(&root, &recipe, &data),
        Request::CurrentArtifacts {
            log,
            target_dir,
            target,
            package,
        } => current_artifacts(&log, &target_dir, &target, &package),
        Request::Capabilities { root } => {
            capabilities(&root)?;
            Ok(Value::Null)
        }
    }
}

#[cfg(test)]
mod tests;
