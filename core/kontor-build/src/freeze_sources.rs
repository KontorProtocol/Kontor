use std::collections::BTreeSet;
use std::fs::{self, File};
use std::os::unix::fs::symlink;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde_json::{Map, Value, json};
use tar::Archive;
use tempfile::Builder;
use toml::Value as Toml;

use crate::canonical_json::{Style, encode};
use crate::container::sha256;
use crate::execution_definition::{SEMANTIC_TREES, resolve, verify};
use crate::snapshot::{normalized_link, verify_snapshot};

const GRAPHS: &[&str] = &["executor-first", "executor-second"];
const SUPPORT_TREES: &[&str] = &["protocol-bundles/proof", "tools/native-crypto/fixtures"];
const SUPPORT_FILES: &[&str] = &[
    "tools/protocol-bundles/historical-qualification-fixture.rs",
    "tools/protocol-bundles/historical_semantics.rs",
    "tools/protocol-bundles/semantic-baseline.json",
    "tools/protocol-bundles/semantic-baseline.log",
    "tools/protocol-bundles/protocol-manifest-vector.json",
];

#[derive(Debug, Args)]
pub struct FreezeSourcesArgs {
    /// Full immutable Git commit ID, not a branch, tag or abbreviated hash.
    #[arg(long)]
    pub revision: String,
    /// New snapshot directory, relative to the checkout root or absolute.
    #[arg(long)]
    pub destination: PathBuf,
    /// Only executor snapshots are supported; the K4 coordinator mode is retired.
    #[arg(long, default_value = "executors", value_parser = ["executors"])]
    pub kind: String,
}

fn manifest(root: &Path, graph: &str) -> PathBuf {
    root.join("protocol-bundles").join(graph).join("Cargo.toml")
}
fn metadata(root: &Path, graph: &str) -> Result<Value> {
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--format-version=1",
            "--manifest-path",
        ])
        .arg(manifest(root, graph))
        .current_dir(root)
        .output()?;
    ensure!(
        output.status.success(),
        "snapshot metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
fn definitions(root: &Path, resolutions: &[Value]) -> Result<Value> {
    ensure!(
        resolutions.len() == GRAPHS.len(),
        "missing executor resolutions"
    );
    Ok(Value::Array(
        GRAPHS
            .iter()
            .zip(resolutions)
            .map(|(graph, data)| verify(root, &manifest(root, graph), data))
            .collect::<Result<_>>()?,
    ))
}
fn include(
    root: &Path,
    path: &Path,
    ancestors: &mut BTreeSet<PathBuf>,
    paths: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let resolved = path.canonicalize()?;
    ensure!(
        resolved.starts_with(root),
        "frozen input escapes source root: {}",
        path.display()
    );
    ensure!(
        !ancestors.contains(&resolved),
        "cyclic frozen input: {}",
        path.display()
    );
    let kind = fs::symlink_metadata(path)?.file_type();
    if kind.is_symlink() {
        paths.insert(path.to_owned());
        include(root, &resolved, ancestors, paths)?;
    } else if kind.is_dir() {
        ancestors.insert(resolved.clone());
        for entry in fs::read_dir(path)? {
            include(root, &entry?.path(), ancestors, paths)?;
        }
        ancestors.remove(&resolved);
    } else if kind.is_file() {
        paths.insert(path.to_owned());
    } else {
        bail!("unsupported frozen input: {}", path.display());
    }
    Ok(())
}
fn inputs(root: &Path, resolutions: &[Value]) -> Result<BTreeSet<PathBuf>> {
    let mut paths = BTreeSet::new();
    let mut add = |path: &Path| include(root, path, &mut BTreeSet::new(), &mut paths);
    for name in SEMANTIC_TREES.iter().chain(SUPPORT_TREES) {
        add(&root.join(name))?;
    }
    for name in SUPPORT_FILES {
        let path = root.join(name);
        if path.try_exists()? {
            add(&path)?;
        }
    }
    // Cargo reads unused path patches too, even if they are absent from metadata.
    for graph in GRAPHS {
        let path = manifest(root, graph);
        let contents: Toml = toml::from_str(&fs::read_to_string(&path)?)?;
        if let Some(patches) = contents.get("patch") {
            for registry in patches.as_table().context("invalid patch table")?.values() {
                for dependency in registry
                    .as_table()
                    .context("invalid registry patch")?
                    .values()
                {
                    if let Some(relative) = dependency.get("path") {
                        let relative = relative.as_str().context("invalid path patch")?;
                        add(&path.parent().unwrap().join(relative).canonicalize()?)?;
                    }
                }
            }
        }
    }
    for data in resolutions {
        for package in data["packages"].as_array().context("missing packages")? {
            if package
                .get("source")
                .is_some_and(|source| !source.is_null())
            {
                continue;
            }
            let path = Path::new(
                package["manifest_path"]
                    .as_str()
                    .context("missing package manifest")?,
            )
            .canonicalize()?;
            let directory = path.parent().context("invalid package manifest")?;
            add(directory)?;
            for ancestor in directory
                .ancestors()
                .take_while(|path| path.starts_with(root))
            {
                for name in ["Cargo.toml", ".cargo/config", ".cargo/config.toml"] {
                    let path = ancestor.join(name);
                    if path.is_file() {
                        add(&path)?;
                    }
                }
            }
        }
    }
    for name in [
        "rust-toolchain",
        "rust-toolchain.toml",
        "core/rust-toolchain.toml",
    ] {
        let path = root.join(name);
        if path.is_file() {
            add(&path)?;
        }
    }
    Ok(paths)
}
fn extract(archive: &Path, root: &Path) -> Result<()> {
    let mut archive = Archive::new(File::open(archive)?);
    // Match the previous data-filter extraction, including executable modes.
    archive.set_mask(0o022);
    for member in archive.entries()? {
        let mut member = member?;
        let kind = member.header().entry_type();
        // Git writes a global PAX record containing the source commit ID.
        if kind.is_pax_global_extensions() {
            continue;
        }
        let path = member.path()?.into_owned();
        ensure!(
            path.components()
                .all(|part| matches!(part, Component::Normal(_))),
            "invalid Git archive path"
        );
        ensure!(
            kind.is_file() || kind.is_dir() || kind.is_symlink(),
            "unsupported Git archive entry"
        );
        if kind.is_symlink() {
            let target = member
                .link_name()?
                .context("missing archive symlink target")?;
            ensure!(!target.is_absolute(), "absolute Git archive symlink");
            let target = resolve(&root.join(&path).parent().unwrap().join(&target))?;
            ensure!(
                target.starts_with(root),
                "Git archive symlink escapes source root"
            );
        }
        ensure!(
            member.unpack_in(root)?,
            "Git archive entry escaped source root"
        );
    }
    Ok(())
}
fn stage(root: &Path, staged: &Path, paths: &BTreeSet<PathBuf>) -> Result<Map<String, Value>> {
    let mut records = Map::new();
    for path in paths {
        let relative = path.strip_prefix(root)?;
        let name = relative.to_str().context("non-UTF-8 frozen path")?;
        let destination = staged.join(relative);
        fs::create_dir_all(destination.parent().context("invalid frozen path")?)?;
        let record = if fs::symlink_metadata(path)?.file_type().is_symlink() {
            let target = fs::read_link(path)?;
            let spelling = normalized_link(target.to_str().context("non-UTF-8 frozen symlink")?);
            symlink(&target, destination)?;
            json!({"symlink":spelling})
        } else {
            fs::copy(path, destination)?;
            json!({"sha256":sha256(path)?})
        };
        records.insert(name.into(), record);
    }
    Ok(records)
}

pub fn freeze_sources(repository: &Path, args: FreezeSourcesArgs) -> Result<Value> {
    ensure!(
        args.kind == "executors",
        "coordinator snapshots are retired"
    );
    let revision = Command::new("git")
        .args(["rev-parse", "--verify", "--end-of-options"])
        .arg(format!("{}^{{commit}}", args.revision))
        .current_dir(repository)
        .output()?;
    ensure!(
        revision.status.success(),
        "cannot resolve snapshot commit: {}",
        String::from_utf8_lossy(&revision.stderr)
    );
    let commit = String::from_utf8(revision.stdout)?.trim().to_owned();
    ensure!(
        args.revision == commit,
        "freeze requires the full immutable commit ID"
    );
    let destination = repository.join(&args.destination);
    let parent = destination
        .parent()
        .context("snapshot destination needs a parent")?;
    fs::create_dir_all(parent)?;
    let parent = parent.canonicalize()?;
    let name = destination
        .file_name()
        .context("invalid snapshot destination")?;
    let destination = parent.join(name);
    let lock = File::options()
        .append(true)
        .create(true)
        .open(parent.join(format!(
            ".{}.freeze.lock",
            name.to_str().context("non-UTF-8 destination")?
        )))?;
    lock.try_lock()
        .context("another freezer owns this snapshot destination")?;
    ensure!(
        !destination.symlink_metadata().is_ok(),
        "refusing to overwrite a retained source root"
    );
    let temporary = Builder::new()
        .prefix("freeze-executors-")
        .tempdir_in(&parent)?;
    let archive = temporary.path().join("source.tar");
    let status = Command::new("git")
        .args(["archive", "--format=tar", "--output"])
        .arg(&archive)
        .arg(&commit)
        .current_dir(repository)
        .status()?;
    ensure!(status.success(), "git archive failed");
    let root = temporary.path().join("original");
    fs::create_dir(&root)?;
    extract(&archive, &root)?;
    let resolutions = GRAPHS
        .iter()
        .map(|graph| metadata(&root, graph))
        .collect::<Result<Vec<_>>>()?;
    let expected = definitions(&root, &resolutions)?;
    let selected = inputs(&root, &resolutions)?;
    let staged = temporary.path().join("retained");
    fs::create_dir(&staged)?;
    let records = stage(&root, &staged, &selected)?;
    let actual = GRAPHS
        .iter()
        .map(|graph| metadata(&staged, graph))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        definitions(&staged, &actual)? == expected,
        "relocation changed a retained definition"
    );
    let record = json!({"source_commit":commit,"definitions":expected,"files":records});
    let inventory = staged.join("snapshot.json");
    fs::write(&inventory, format!("{}\n", encode(&record, Style::Pretty)?))?;
    let hash = sha256(&inventory)?;
    verify_snapshot(&staged, &hash)?;
    ensure!(
        !destination.symlink_metadata().is_ok(),
        "snapshot destination appeared while freezing"
    );
    fs::rename(&staged, &destination)?;
    Ok(
        json!({"source_commit":commit,"files":records.len(),"definitions":expected,"snapshot_sha256":hash}),
    )
}

#[cfg(test)]
mod tests;
