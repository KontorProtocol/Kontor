use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::Deserialize;
use serde_json::{Value, json};

use super::build::FORK_REVISION;
use crate::container::sha256;
use crate::source_identity::Package;

const SOURCE_INPUTS: &str = include_str!("../../../../tools/native-stack/fiber-source-inputs.json");

#[derive(Args)]
pub struct CaptureSourcesArgs {
    #[arg(long)]
    pub metadata: PathBuf,
    #[arg(long)]
    pub evidence_dir: PathBuf,
}

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    resolve: Resolve,
}
#[derive(Deserialize)]
struct Resolve {
    nodes: Vec<Node>,
}
#[derive(Deserialize)]
struct Node {
    id: String,
    deps: Vec<Dependency>,
}
#[derive(Deserialize)]
struct Dependency {
    name: String,
    pkg: String,
}

pub fn capture_sources(args: CaptureSourcesArgs) -> Result<Value> {
    let metadata = serde_json::from_slice(&fs::read(args.metadata)?)?;
    let sources = serde_json::from_str(SOURCE_INPUTS)?;
    capture(&metadata, &args.evidence_dir, FORK_REVISION, &sources)
}

fn capture(
    metadata: &Metadata,
    directory: &Path,
    revision: &str,
    sources: &BTreeMap<String, String>,
) -> Result<Value> {
    let expected_source =
        format!("git+https://github.com/wilfreddenton/wasmtime?rev={revision}#{revision}");
    let mut packages = BTreeMap::new();
    let mut roots = BTreeMap::new();
    for (name, crate_dir) in [
        ("wasmtime", "wasmtime"),
        ("wasmtime-internal-fiber", "fiber"),
    ] {
        let matches: Vec<_> = metadata
            .packages
            .iter()
            .filter(|p| p.name == name)
            .collect();
        ensure!(
            matches.len() == 1,
            "Cargo metadata lacks one {name} package"
        );
        let package = matches[0];
        ensure!(
            package.source.as_deref() == Some(expected_source.as_str())
                && package.version == "51.0.0-kontor.2",
            "Cargo metadata does not resolve pinned {name}"
        );
        let manifest = &package.manifest_path;
        ensure!(
            manifest.is_absolute()
                && manifest.ends_with(Path::new("crates").join(crate_dir).join("Cargo.toml")),
            "{name} package manifest path is unexpected"
        );
        let root = manifest
            .ancestors()
            .nth(3)
            .context("missing checkout root")?;
        let result = Command::new("git")
            .args(["--no-replace-objects", "-C"])
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()?;
        ensure!(
            result.status.success() && String::from_utf8(result.stdout)?.trim() == revision,
            "Cargo checkout revision differs from pinned {name}"
        );
        packages.insert(name, package);
        roots.insert(name, root);
    }
    let parents: Vec<_> = metadata
        .resolve
        .nodes
        .iter()
        .filter(|node| node.id == packages["wasmtime"].id)
        .collect();
    ensure!(
        parents.len() == 1
            && parents[0]
                .deps
                .iter()
                .any(|dep| dep.name == "wasmtime_fiber"
                    && dep.pkg == packages["wasmtime-internal-fiber"].id),
        "Cargo resolve does not bind Wasmtime to the pinned fiber crate"
    );
    // Authenticate all inputs before writing any archive files.
    let mut inputs = Vec::new();
    for (relative, expected) in sources {
        let owner = if relative.starts_with("crates/fiber/") {
            "wasmtime-internal-fiber"
        } else {
            "wasmtime"
        };
        let source = roots[owner].join(relative);
        ensure!(
            source.is_file() && sha256(&source)? == *expected,
            "Wasmtime fiber source differs from pinned fork: {relative}"
        );
        inputs.push((relative, expected, source));
    }
    fs::create_dir_all(directory)?;
    let directory = directory.canonicalize()?;
    let mut archived = BTreeMap::new();
    for (relative, expected, source) in inputs {
        let archive_relative = Path::new("wasmtime-source").join(relative);
        let destination = directory.join(&archive_relative);
        let parent = destination.parent().context("missing archive parent")?;
        let existing = parent
            .ancestors()
            .find(|p| p.exists() || p.is_symlink())
            .context("missing archive ancestor")?;
        ensure!(
            existing.canonicalize()?.starts_with(&directory),
            "archive path escapes evidence directory"
        );
        fs::create_dir_all(parent)?;
        ensure!(
            parent.canonicalize()?.starts_with(&directory),
            "archive path escapes evidence directory"
        );
        // Refuse existing files, including symlinks and hard links, rather than overwriting evidence.
        let mut file = File::create_new(&destination)?;
        file.write_all(&fs::read(source)?)?;
        ensure!(
            sha256(&destination)? == *expected,
            "archived Wasmtime fiber source changed: {relative}"
        );
        archived.insert(relative, json!({"path":archive_relative,"sha256":expected}));
    }
    Ok(serde_json::to_value(archived)?)
}

#[cfg(test)]
mod tests;
