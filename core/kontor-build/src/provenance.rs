use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::container::sha256;
use crate::metadata_control::{Graph as MetadataGraph, proc_macro_hashes};
use crate::source_identity::{Metadata, verify_sources};
use crate::source_policy::{
    Kind as PolicyKind, Metadata as PolicyMetadata, check as source_policy,
};
use crate::toolchain::{Environment, Graph, runtime_libraries, tools};

pub const RETAINED_TREES: &[&str] = &[
    "protocol-bundles/executor",
    "core/indexer/src/runtime",
    "core/indexer/src/protocol",
    "core/indexer/src/bls",
    "native-contracts/token/wit",
    "native-contracts/filestorage/wit",
    "native-contracts/staking/wit",
    "native-contracts/system/wit",
    "native-contracts/nft/wit",
];
const CONSENSUS_TREES: &[&str] = &[
    "protocol-bundles/consensus",
    "core/indexer/src/consensus",
    "core/indexer/proto",
];
const CONSENSUS_FILES: &[&str] = &[
    "identity.rs",
    "canonical_codec.rs",
    "migration_work.rs",
    "coordinator/activation.rs",
    "coordinator/certified_input.rs",
    "coordinator/certified_decision.rs",
    "coordinator/control.rs",
    "coordinator/manifest.rs",
];
const EXECUTION_FILES: &[&str] = &[
    "core/indexer/src/runtime/mod.rs",
    "core/indexer/src/protocol/v1/engine.rs",
    "core/indexer/src/protocol/v1/resources.rs",
    "core/indexer/src/protocol/v1/gas.rs",
    "core/indexer/src/protocol/v1/native.rs",
    "core/indexer/src/protocol/v1/errors.rs",
    "core/indexer/src/protocol/v1/fuel.rs",
    "core/indexer/src/protocol/v1/fees.rs",
    "core/indexer/src/protocol/v1/deposit.rs",
];
const NON_SOURCE: &[&str] = &[".git", "target", "__pycache__"];

pub type Inventory = BTreeMap<PathBuf, String>;

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GraphKind {
    Proof,
    Executor,
    Node,
    Consensus,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    SourcePolicy {
        root: PathBuf,
        data: PolicyMetadata,
        kind: PolicyKind,
    },
    ProcMacroHashes {
        graphs: Vec<MetadataGraph>,
        options: Vec<String>,
        env: Environment,
        output: PathBuf,
        working_directory: PathBuf,
    },
    LockedPackages {
        lock: PathBuf,
    },
    Toolchain {
        working_directory: PathBuf,
        env: Environment,
        target: String,
    },
    RuntimeLibraries {
        working_directory: PathBuf,
        executable: PathBuf,
        env: Environment,
        graphs: Vec<Graph>,
    },
    RetainedTrees,
    LocalFiles {
        directory: PathBuf,
        root: PathBuf,
    },
    PackageSources {
        directory: PathBuf,
        root: Option<PathBuf>,
    },
    RetainedSources {
        root: PathBuf,
    },
    NodeSources {
        root: PathBuf,
    },
    ConsensusSources {
        root: PathBuf,
    },
    RepositorySources {
        root: PathBuf,
        kind: GraphKind,
    },
    SourceInputs {
        root: PathBuf,
        data: Metadata,
        kind: GraphKind,
        tool_root: Option<PathBuf>,
        cargo_home: PathBuf,
    },
}

pub fn run(request: Request) -> Result<Value> {
    match request {
        Request::SourcePolicy { root, data, kind } => source_policy(&root, &data, kind),
        Request::ProcMacroHashes {
            graphs,
            options,
            env,
            output,
            working_directory,
        } => proc_macro_hashes(&graphs, &options, &env, &output, &working_directory),
        Request::LockedPackages { lock } => {
            let data: toml::Value = toml::from_str(&fs::read_to_string(lock)?)?;
            Ok(serde_json::to_value(
                data.get("package").context("missing lockfile packages")?,
            )?)
        }
        Request::Toolchain {
            working_directory,
            env,
            target,
        } => tools(&working_directory, &env, &target),
        Request::RuntimeLibraries {
            working_directory,
            executable,
            env,
            graphs,
        } => Ok(json!(runtime_libraries(
            &working_directory,
            &executable,
            &env,
            &graphs
        )?)),
        Request::RetainedTrees => Ok(json!(RETAINED_TREES)),
        Request::LocalFiles { directory, root } => Ok(serde_json::to_value(local_source_files(
            &directory, &root,
        )?)?),
        Request::PackageSources { directory, root } => Ok(serde_json::to_value(package_sources(
            &directory,
            root.as_deref(),
        )?)?),
        Request::RetainedSources { root } => Ok(serde_json::to_value(retained_sources(&root)?)?),
        Request::NodeSources { root } => Ok(serde_json::to_value(node_sources(&root)?)?),
        Request::ConsensusSources { root } => Ok(serde_json::to_value(consensus_sources(&root)?)?),
        Request::RepositorySources { root, kind } => {
            Ok(serde_json::to_value(repository_sources(&root, kind)?)?)
        }
        Request::SourceInputs {
            root,
            data,
            kind,
            tool_root,
            cargo_home,
        } => source_inputs(&root, &data, kind, tool_root.as_deref(), &cargo_home),
    }
}

fn local_files(
    directory: &Path,
    root: &Path,
    ancestors: &mut BTreeSet<PathBuf>,
    result: &mut Vec<PathBuf>,
) -> Result<()> {
    let resolved = directory
        .canonicalize()
        .with_context(|| format!("resolve source directory {}", directory.display()))?;
    ensure!(
        resolved.starts_with(root),
        "local source escapes its graph root: {}",
        directory.display()
    );
    ensure!(
        ancestors.insert(resolved.clone()),
        "cyclic local source directory: {}",
        directory.display()
    );
    let mut entries = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort();
    for path in entries {
        if NON_SOURCE
            .iter()
            .any(|name| path.file_name().is_some_and(|file| file == *name))
        {
            continue;
        }
        ensure!(
            path.canonicalize()?.starts_with(root),
            "local source escapes its graph root: {}",
            path.display()
        );
        if path.is_dir() {
            local_files(&path, root, ancestors, result)?;
        } else if path.is_file() {
            result.push(path);
        } else {
            bail!("unsupported local source entry: {}", path.display());
        }
    }
    ancestors.remove(&resolved);
    Ok(())
}

pub fn local_source_files(directory: &Path, root: &Path) -> Result<Vec<PathBuf>> {
    let root = root.canonicalize()?;
    let mut result = Vec::new();
    local_files(directory, &root, &mut BTreeSet::new(), &mut result)?;
    Ok(result)
}

fn excluded(path: &Path, names: &[&str]) -> bool {
    path.components()
        .any(|part| names.iter().any(|name| part.as_os_str() == *name))
}

// These inventories intentionally match rglob: file symlinks are hashed, but
// directory symlinks are not followed. Strict local-package walks are separate.
fn glob_files(directory: &Path, exclusions: &[&str]) -> Result<Vec<PathBuf>> {
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let mut pending = vec![directory.to_owned()];
    let mut result = Vec::new();
    while let Some(parent) = pending.pop() {
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            let path = entry.path();
            if excluded(path.strip_prefix(directory)?, exclusions) {
                continue;
            }
            if entry.file_type()?.is_dir() {
                pending.push(path);
            } else if path.is_file() {
                result.push(path);
            }
        }
    }
    result.sort();
    Ok(result)
}

fn add(sources: &mut Inventory, root: &Path, path: &Path) -> Result<()> {
    let relative = path.strip_prefix(root)?;
    ensure!(
        relative.to_str().is_some(),
        "source inventory paths must be UTF8: {}",
        path.display()
    );
    sources.insert(relative.to_owned(), sha256(path)?);
    Ok(())
}

pub fn package_sources(directory: &Path, root: Option<&Path>) -> Result<Inventory> {
    let paths = match root {
        Some(root) => local_source_files(directory, root)?,
        None => glob_files(directory, NON_SOURCE)?,
    };
    let mut sources = Inventory::new();
    for path in paths {
        add(&mut sources, directory, &path)?;
    }
    Ok(sources)
}

pub fn retained_sources(root: &Path) -> Result<Inventory> {
    let boundary = root.canonicalize()?;
    let mut sources = Inventory::new();
    // WIT generators and #[path] imports read beyond Cargo package roots.
    for relative in RETAINED_TREES {
        let directory = root.join(relative);
        ensure!(
            directory.is_dir(),
            "missing retained source tree: {relative}"
        );
        for path in local_source_files(&directory, &boundary)? {
            add(&mut sources, root, &path)?;
        }
    }
    Ok(sources)
}

pub fn node_sources(root: &Path) -> Result<Inventory> {
    let mut sources = Inventory::new();
    for relative in ["core/indexer/src", "core/indexer/proto"] {
        let directory = root.join(relative);
        ensure!(directory.is_dir(), "missing node source tree: {relative}");
        for path in glob_files(&directory, &["__pycache__"])? {
            if !excluded(&path, &["__pycache__"]) {
                add(&mut sources, root, &path)?;
            }
        }
    }
    for name in ["counter", "proxy"] {
        let path = root.join(format!("test-contracts/binaries/{name}.wasm.br"));
        if path.is_file() {
            add(&mut sources, root, &path)?;
        }
    }
    add(&mut sources, root, &root.join("core/indexer/build.rs"))?;
    Ok(sources)
}

pub fn consensus_sources(root: &Path) -> Result<Inventory> {
    let boundary = root.canonicalize()?;
    let mut sources = Inventory::new();
    for relative in CONSENSUS_TREES {
        for path in local_source_files(&root.join(relative), &boundary)? {
            add(&mut sources, root, &path)?;
        }
    }
    for relative in CONSENSUS_FILES {
        let path = root.join("core/indexer/src/protocol").join(relative);
        add(&mut sources, root, &path)?;
        let children = path.with_extension("");
        if children.is_dir() {
            for path in local_source_files(&children, &boundary)? {
                add(&mut sources, root, &path)?;
            }
        }
    }
    Ok(sources)
}

pub fn repository_sources(root: &Path, kind: GraphKind) -> Result<Inventory> {
    if matches!(kind, GraphKind::Consensus) {
        let mut sources = consensus_sources(root)?;
        let adapter = root.join("core/indexer/src/protocol/coordinator/managed.rs");
        add(&mut sources, root, &adapter)?;
        for directory in [
            adapter.with_extension(""),
            root.join("tools/protocol-bundles"),
        ] {
            for path in local_source_files(&directory, &root.canonicalize()?)? {
                add(&mut sources, root, &path)?;
            }
        }
        return Ok(sources);
    }
    let mut sources = Inventory::new();
    for relative in EXECUTION_FILES {
        add(&mut sources, root, &root.join(relative))?;
    }
    for relative in [
        "core/indexer/src/protocol/v1/native",
        "protocol-bundles/proof",
        "tools/protocol-bundles",
        "tools/native-crypto/fixtures",
    ] {
        for path in glob_files(&root.join(relative), &["__pycache__"])? {
            if !excluded(&path, &["__pycache__"]) {
                add(&mut sources, root, &path)?;
            }
        }
    }
    match kind {
        GraphKind::Executor => sources.extend(retained_sources(root)?),
        GraphKind::Node => sources.extend(node_sources(root)?),
        GraphKind::Proof => (),
        GraphKind::Consensus => unreachable!(),
    }
    Ok(sources)
}

pub fn source_inputs(
    root: &Path,
    data: &Metadata,
    kind: GraphKind,
    tool_root: Option<&Path>,
    cargo_home: &Path,
) -> Result<Value> {
    let root = root.canonicalize()?;
    let tool_root = tool_root.unwrap_or(&root).canonicalize()?;
    let verified = verify_sources(data)?;
    let mut packages = Vec::new();
    let mut trees = BTreeSet::new();
    let mut inherited = Inventory::new();
    for package in &data.packages {
        let directory = package
            .manifest_path
            .parent()
            .context("package source directory")?
            .canonicalize()?;
        let local = package.source.is_none();
        ensure!(
            !local || directory.starts_with(&root),
            "local package escapes its graph root: {}",
            directory.display()
        );
        for parent in directory.ancestors() {
            for relative in ["Cargo.toml", ".cargo/config", ".cargo/config.toml"] {
                let path = parent.join(relative);
                if path.is_file() {
                    ensure!(
                        !local || path.canonicalize()?.starts_with(&root),
                        "inherited package input escapes its graph root: {}",
                        path.display()
                    );
                    inherited.insert(path.clone(), sha256(&path)?);
                }
            }
            // A frozen root deliberately has no .git marker. Inheritance stops
            // here rather than absorbing manifests from the current node tree.
            if local && parent == root {
                break;
            }
            if parent.join(".git").exists() {
                if package
                    .source
                    .as_deref()
                    .is_some_and(|source| source.starts_with("git+"))
                {
                    trees.insert(parent.to_owned());
                }
                break;
            }
        }
        let identity = package.id.replace(
            root.to_str().context("source root must be UTF8")?,
            "<repository>",
        );
        packages.push(json!({"package": identity, "files": package_sources(&directory, local.then_some(root.as_path()))?}));
    }
    let sources = repository_sources(&root, kind)?;
    let mut git_sources = BTreeMap::new();
    for directory in trees {
        git_sources.insert(directory.clone(), package_sources(&directory, None)?);
    }
    for directory in root.ancestors().chain([cargo_home]) {
        for relative in [
            ".cargo/config",
            ".cargo/config.toml",
            "config",
            "config.toml",
        ] {
            let path = directory.join(relative);
            if path.is_file() {
                inherited.insert(path.clone(), sha256(&path)?);
            }
        }
    }
    let inherited =
        serde_json::to_value(inherited).context("inherited source paths must be UTF8")?;
    let git_sources = serde_json::to_value(git_sources).context("Git source paths must be UTF8")?;
    let mut result = json!({
        "verified_external_sources": verified, "packages": packages, "qualification_sources": sources,
        "inherited_manifests_and_configuration": inherited, "git_source_trees": git_sources,
        "rust_build_tools": package_sources(&tool_root.join("core/kontor-build"), Some(&tool_root))?,
    });
    if tool_root != root {
        result["build_tools"] = serde_json::to_value(package_sources(
            &tool_root.join("tools/protocol-bundles"),
            Some(&tool_root),
        )?)?;
    }
    Ok(result)
}
