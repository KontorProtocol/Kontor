use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf, absolute};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::canonical_json::{Style, encode as canonical};
use crate::container::sha256;

const POLICY: &[u8] = include_bytes!("execution_definition/policy.txt");
pub const SEMANTIC_TREES: &[&str] = &[
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
const NODE_ONLY: &[&str] = &[
    "core/indexer/src/protocol/coordinator",
    "core/indexer/src/runtime/ownership.rs",
    "core/indexer/src/runtime/ownership",
    "core/indexer/src/runtime/pool.rs",
    "core/indexer/src/runtime/pool",
    "core/indexer/src/runtime/node.rs",
];
const IGNORED: &[&str] = &[".git", "target", ".build-cache", "__pycache__"];
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("missing or invalid {field}"))
}
fn relative(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)
        .context("reference input escapes root")?
        .to_str()
        .context("non-UTF-8 reference path")?
        .to_owned())
}
// Metadata can name not-yet-generated targets. Resolve existing symlinks while
// retaining missing suffixes, as the original effective-manifest projection did.
pub(crate) fn resolve(path: &Path) -> Result<PathBuf> {
    resolve_inner(path, &mut BTreeSet::new())
}
fn resolve_inner(path: &Path, links: &mut BTreeSet<PathBuf>) -> Result<PathBuf> {
    let mut result = PathBuf::new();
    for component in absolute(path)?.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            other => {
                result.push(other);
                match result.canonicalize() {
                    Ok(path) => result = path,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        match fs::symlink_metadata(&result) {
                            Ok(metadata) if metadata.file_type().is_symlink() => {
                                let link = result.clone();
                                ensure!(links.insert(link.clone()), "cyclic metadata symlink");
                                let target = link
                                    .parent()
                                    .context("invalid symlink parent")?
                                    .join(fs::read_link(&link)?);
                                result = resolve_inner(&target, links)?;
                                links.remove(&link);
                            }
                            Ok(_) => {}
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    Ok(result)
}
fn sort_values(values: Vec<Value>) -> Result<Vec<Value>> {
    let mut keyed = values
        .into_iter()
        .map(|value| Ok((canonical(&value, Style::Spaced)?, value)))
        .collect::<Result<Vec<_>>>()?;
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(keyed.into_iter().map(|(_, value)| value).collect())
}
pub fn effective_manifest(root: &Path, package: &Value) -> Result<String> {
    let mut fields = BTreeMap::new();
    for key in ["name", "version", "edition", "rust_version", "links"] {
        fields.insert(key, package.get(key).cloned().unwrap_or(Value::Null));
    }
    let mut dependencies = Vec::new();
    if let Some(items) = package.get("dependencies") {
        for item in items.as_array().context("invalid package dependencies")? {
            let mut item = item.clone();
            ensure!(item.is_object(), "invalid dependency");
            if let Some(path) = item
                .get("path")
                .filter(|v| !v.is_null() && **v != json!(""))
            {
                item["path"] = json!(relative(
                    root,
                    &resolve(Path::new(path.as_str().context("invalid dependency path")?))?
                )?);
            }
            dependencies.push(item);
        }
    }
    fields.insert("dependencies", json!(sort_values(dependencies)?));
    let mut targets = Vec::new();
    if let Some(items) = package.get("targets") {
        for target in items.as_array().context("invalid package targets")? {
            let mut item = BTreeMap::new();
            for key in [
                "name",
                "kind",
                "crate_types",
                "edition",
                "required-features",
            ] {
                item.insert(key, target.get(key).cloned().unwrap_or(Value::Null));
            }
            item.insert(
                "src_path",
                json!(relative(
                    root,
                    &resolve(Path::new(text(target, "src_path")?))?
                )?),
            );
            targets.push(json!(item));
        }
    }
    fields.insert("targets", json!(sort_values(targets)?));
    Ok(hex::encode(Sha256::digest(
        canonical(&json!(fields), Style::Compact)?.as_bytes(),
    )))
}
fn count(output: &mut Vec<u8>, value: usize) -> Result<()> {
    output.extend(
        u32::try_from(value)
            .context("reference count exceeds u32")?
            .to_be_bytes(),
    );
    Ok(())
}
fn blob(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    count(output, value.len())?;
    output.extend(value);
    Ok(())
}
pub fn encode(
    sources: &BTreeMap<String, String>,
    locks: &BTreeMap<String, String>,
    features: &[String],
    policy: &str,
) -> Result<Vec<u8>> {
    let mut output = vec![1];
    for entries in [sources, locks] {
        ensure!(!entries.is_empty(), "empty reference input set");
        count(&mut output, entries.len())?;
        for (path, hash) in entries {
            let digest = hex::decode(hash)?;
            ensure!(
                digest.len() == 32 && path.split('/').all(|part| !["", ".", ".."].contains(&part)),
                "invalid reference source"
            );
            blob(&mut output, path.as_bytes())?;
            output.extend(digest);
        }
    }
    let features: BTreeSet<_> = features.iter().collect();
    count(&mut output, features.len())?;
    for feature in features {
        blob(&mut output, feature.as_bytes())?;
    }
    let policy = hex::decode(policy)?;
    ensure!(policy.len() == 32, "invalid build policy digest");
    output.extend(policy);
    Ok(output)
}
struct Inventory<'a> {
    root: &'a Path,
    excluded: BTreeSet<PathBuf>,
    lock: PathBuf,
    sources: BTreeMap<String, String>,
}
impl Inventory<'_> {
    fn add(&mut self, path: &Path) -> Result<()> {
        let name = relative(self.root, path)?;
        if self.excluded.contains(path) || path == self.lock {
            return Ok(());
        }
        relative(self.root, &path.canonicalize()?)?;
        self.sources.insert(name, sha256(path)?);
        Ok(())
    }
    fn visit(&mut self, directory: &Path, ancestors: &mut BTreeSet<PathBuf>) -> Result<()> {
        let resolved = directory.canonicalize()?;
        relative(self.root, &resolved)?;
        ensure!(
            ancestors.insert(resolved.clone()),
            "cyclic semantic source directory: {}",
            directory.display()
        );
        let mut entries = fs::read_dir(directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort();
        for path in entries {
            if path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|name| IGNORED.contains(&name))
            {
                continue;
            }
            let name = relative(self.root, &path)?;
            if NODE_ONLY
                .iter()
                .any(|prefix| name == *prefix || name.starts_with(&format!("{prefix}/")))
            {
                continue;
            }
            let metadata = fs::metadata(&path)?;
            if metadata.is_dir() {
                self.visit(&path, ancestors)?;
            } else {
                ensure!(
                    metadata.is_file(),
                    "unsupported semantic source entry: {}",
                    path.display()
                );
                self.add(&path)?;
            }
        }
        ancestors.remove(&resolved);
        Ok(())
    }
}
pub fn reference(root: &Path, manifest: &Path, metadata: &Value) -> Result<Vec<u8>> {
    let root = root.canonicalize()?;
    let manifest = manifest.canonicalize()?;
    relative(&root, &manifest)?;
    let lock = manifest.with_file_name("Cargo.lock");
    let excluded = [
        root.join("protocol-bundles/executor-first/definition.bin"),
        root.join("protocol-bundles/executor-second/definition.bin"),
        manifest.with_file_name("definition.bin"),
    ]
    .into();
    let mut inventory = Inventory {
        root: &root,
        excluded,
        lock: lock.clone(),
        sources: BTreeMap::new(),
    };
    let mut directories: BTreeSet<_> = SEMANTIC_TREES.iter().map(|name| root.join(name)).collect();
    let mut packages = BTreeMap::new();
    for package in metadata["packages"]
        .as_array()
        .context("missing packages")?
    {
        ensure!(
            packages.insert(text(package, "id")?, package).is_none(),
            "duplicate package identity"
        );
        if package.get("source").is_none_or(Value::is_null) {
            let manifest = resolve(Path::new(text(package, "manifest_path")?))?;
            let directory = manifest.parent().context("invalid package manifest")?;
            relative(&root, directory)?;
            directories.insert(directory.to_owned());
            for ancestor in directory
                .ancestors()
                .take_while(|path| path.starts_with(&root))
            {
                for name in [".cargo/config", ".cargo/config.toml"] {
                    let path = ancestor.join(name);
                    if path.is_file() {
                        inventory.add(&path)?;
                    }
                }
            }
        }
    }
    for directory in directories {
        ensure!(
            directory.is_dir(),
            "missing semantic source tree: {}",
            directory.display()
        );
        inventory.visit(&directory, &mut BTreeSet::new())?;
    }
    let mut features = vec!["cfg:kontor_retained".into()];
    for package in packages.values() {
        if package.get("source").is_none_or(Value::is_null) {
            let path = relative(&root, &resolve(Path::new(text(package, "manifest_path")?))?)?;
            features.push(format!(
                "effective-manifest:{path}:{}",
                effective_manifest(&root, package)?
            ));
        }
    }
    for node in metadata["resolve"]["nodes"]
        .as_array()
        .context("missing resolve nodes")?
    {
        let package = packages
            .get(text(node, "id")?)
            .context("missing resolved package")?;
        let source = match package.get("source").filter(|source| !source.is_null()) {
            Some(source) => source
                .as_str()
                .context("invalid package source")?
                .to_owned(),
            None => relative(&root, &resolve(Path::new(text(package, "manifest_path")?))?)?,
        };
        let identity = format!(
            "{}@{}:{source}",
            text(package, "name")?,
            text(package, "version")?
        );
        for feature in node["features"]
            .as_array()
            .context("missing package features")?
        {
            features.push(format!(
                "{identity}:{}",
                feature.as_str().context("invalid feature")?
            ));
        }
    }
    encode(
        &inventory.sources,
        &BTreeMap::from([(relative(&root, &lock)?, sha256(&lock)?)]),
        &features,
        &hex::encode(Sha256::digest(POLICY)),
    )
}
pub fn verify(root: &Path, manifest: &Path, metadata: &Value) -> Result<Value> {
    let encoded = reference(root, manifest, metadata)?;
    let destination = manifest.with_file_name("definition.bin");
    ensure!(
        fs::read(&destination)? == encoded,
        "reference differs from current source; do not overwrite a released definition"
    );
    let mut id = Sha256::new();
    id.update(b"kontor/execution-definition/v1\0");
    id.update(&encoded);
    Ok(
        json!({"path":relative(&root.canonicalize()?,&destination.canonicalize()?)?,"bytes":encoded.len(),"sha256":hex::encode(Sha256::digest(&encoded)),"execution_definition_id":hex::encode(id.finalize())}),
    )
}
#[derive(Args)]
pub struct FreezeArgs {
    #[arg(value_parser=["first","second","observer"])]
    pub graph: String,
    #[arg(long)]
    pub write: bool,
}
pub fn freeze(root: &Path, args: FreezeArgs) -> Result<Value> {
    ensure!(
        ["first", "second", "observer"].contains(&args.graph.as_str()),
        "unknown executor graph"
    );
    let manifest = root.join(format!(
        "protocol-bundles/executor-{}/Cargo.toml",
        args.graph
    ));
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--format-version=1",
            "--manifest-path",
        ])
        .arg(&manifest)
        .current_dir(root)
        .output()?;
    ensure!(
        output.status.success(),
        "resolve execution metadata: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = output.stdout;
    let metadata = serde_json::from_slice(&bytes)?;
    finish(root, &manifest, &metadata, args.write)
}
fn finish(root: &Path, manifest: &Path, metadata: &Value, write: bool) -> Result<Value> {
    if write {
        fs::write(
            manifest.with_file_name("definition.bin"),
            reference(root, manifest, metadata)?,
        )?;
    }
    verify(root, manifest, metadata)
}
fn anchor_path(value: &mut Value, cwd: &Path) {
    if let Some(path) = value
        .as_str()
        .filter(|path| !path.is_empty() && Path::new(path).is_relative())
    {
        *value = json!(cwd.join(path));
    }
}
fn anchor_package(package: &mut Value, cwd: &Path) -> Result<()> {
    if let Some(path) = package.get_mut("manifest_path") {
        anchor_path(path, cwd);
    }
    for (field, key) in [("dependencies", "path"), ("targets", "src_path")] {
        if let Some(items) = package.get_mut(field) {
            for item in items
                .as_array_mut()
                .context("invalid metadata path entries")?
            {
                if let Some(path) = item.get_mut(key) {
                    anchor_path(path, cwd);
                }
            }
        }
    }
    Ok(())
}
pub(crate) fn anchor_metadata(metadata: &mut Value, cwd: &Path) -> Result<()> {
    for package in metadata["packages"]
        .as_array_mut()
        .context("missing packages")?
    {
        anchor_package(package, cwd)?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Catalog,
    Encode {
        sources: BTreeMap<String, String>,
        locks: BTreeMap<String, String>,
        features: Vec<String>,
        policy: String,
    },
    EffectiveManifest {
        root: PathBuf,
        package: Value,
        cwd: PathBuf,
    },
    Reference {
        root: PathBuf,
        manifest: PathBuf,
        metadata: Value,
        cwd: PathBuf,
    },
    Verify {
        root: PathBuf,
        manifest: PathBuf,
        metadata: Value,
        cwd: PathBuf,
    },
    Freeze {
        root: PathBuf,
        graph: String,
        write: bool,
    },
}
pub fn run(request: Request) -> Result<Value> {
    match request {
        Request::Catalog => Ok(json!({"semantic_trees":SEMANTIC_TREES})),
        Request::Encode {
            sources,
            locks,
            features,
            policy,
        } => Ok(json!(hex::encode(encode(
            &sources, &locks, &features, &policy
        )?))),
        Request::EffectiveManifest {
            root,
            mut package,
            cwd,
        } => {
            anchor_package(&mut package, &cwd)?;
            Ok(json!(effective_manifest(&root, &package)?))
        }
        Request::Reference {
            root,
            manifest,
            mut metadata,
            cwd,
        } => {
            anchor_metadata(&mut metadata, &cwd)?;
            Ok(json!(hex::encode(reference(&root, &manifest, &metadata)?)))
        }
        Request::Verify {
            root,
            manifest,
            mut metadata,
            cwd,
        } => {
            anchor_metadata(&mut metadata, &cwd)?;
            verify(&root, &manifest, &metadata)
        }
        Request::Freeze { root, graph, write } => freeze(&root, FreezeArgs { graph, write }),
    }
}
#[cfg(test)]
mod tests;
