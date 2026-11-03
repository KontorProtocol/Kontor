use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use glob::{Pattern, glob};
use toml::Value;

use super::paths::REPRO_PREFIXES;

fn manifest(path: &Path) -> Result<Value> {
    toml::from_str(&fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

fn table_values(value: Option<&Value>) -> Result<Vec<&Value>> {
    match value {
        Some(value) => Ok(value
            .as_table()
            .context("expected manifest table")?
            .values()
            .collect()),
        None => Ok(Vec::new()),
    }
}

pub(super) fn validate_repro_dependencies(root: &Path) -> Result<()> {
    let root = root.canonicalize()?;
    let mut pending = vec![
        root.join("core/kontor-build"),
        root.join("core/kontor-sdk-wasm"),
    ];
    for name in ["native-contracts", "test-contracts"] {
        let workspace = root.join(name);
        let data = manifest(&workspace.join("Cargo.toml"))?;
        for member in data
            .get("workspace")
            .and_then(|value| value.get("members"))
            .and_then(Value::as_array)
            .context("missing workspace members")?
        {
            let pattern = format!(
                "{}/{}",
                Pattern::escape(workspace.to_str().context("non UTF-8 workspace")?),
                member.as_str().context("invalid workspace member")?
            );
            let matches = glob(&pattern)?.collect::<Result<Vec<_>, _>>()?;
            ensure!(
                !matches.is_empty(),
                "workspace member matched no directories: {pattern}"
            );
            pending.extend(matches);
        }
    }
    let mut visited = BTreeSet::new();
    while let Some(package) = pending.pop() {
        let package = package.canonicalize()?;
        if !visited.insert(package.clone()) {
            continue;
        }
        let relative = format!(
            "{}/",
            package
                .strip_prefix(&root)?
                .to_str()
                .context("non UTF-8 package path")?
        );
        ensure!(
            REPRO_PREFIXES
                .iter()
                .any(|prefix| relative.starts_with(prefix)),
            "uncovered artifact dependency: {relative}"
        );
        let data = manifest(&package.join("Cargo.toml"))?;
        let candidates =
            if let Some(value) = data.get("package").and_then(|value| value.get("workspace")) {
                vec![package.join(value.as_str().context("invalid workspace path")?)]
            } else {
                package.ancestors().map(PathBuf::from).collect()
            };
        let mut workspace = None;
        for candidate in candidates {
            if !candidate.join("Cargo.toml").is_file() {
                continue;
            }
            let owner = manifest(&candidate.join("Cargo.toml"))?;
            if owner.get("workspace").is_some() {
                for registry in table_values(owner.get("patch"))? {
                    for dependency in table_values(Some(registry))? {
                        if let Some(path) = dependency.get("path") {
                            pending
                                .push(candidate.join(path.as_str().context("invalid patch path")?));
                        }
                    }
                }
                workspace = Some((candidate, owner));
                break;
            }
        }
        let mut tables = vec![&data];
        tables.extend(table_values(data.get("target"))?);
        for table in tables {
            for kind in ["dependencies", "build-dependencies", "dev-dependencies"] {
                let Some(dependencies) = table.get(kind) else {
                    continue;
                };
                for (name, dependency) in dependencies.as_table().context("invalid dependencies")? {
                    let (parent, dependency) =
                        if dependency.get("workspace").and_then(Value::as_bool) == Some(true) {
                            let (parent, owner) =
                                workspace.as_ref().context("missing package workspace")?;
                            let inherited = owner
                                .get("workspace")
                                .and_then(|value| value.get("dependencies"))
                                .and_then(|value| value.get(name))
                                .with_context(|| {
                                    format!("unresolved workspace dependency: {name}")
                                })?;
                            (parent, inherited)
                        } else {
                            (&package, dependency)
                        };
                    if let Some(path) = dependency.get("path") {
                        pending
                            .push(parent.join(path.as_str().context("invalid dependency path")?));
                    }
                }
            }
        }
    }
    Ok(())
}

fn resolve_target(path: &Path) -> Result<PathBuf> {
    let mut resolved = PathBuf::new();
    // Explicit targets may be newly deleted or not generated yet. Resolve
    // existing links while normalizing the remaining lexical components.
    for part in path.components() {
        match part {
            Component::CurDir => (),
            Component::ParentDir => {
                ensure!(resolved.pop(), "target escapes filesystem root");
            }
            _ => {
                resolved.push(part);
                if resolved.exists() || resolved.is_symlink() {
                    resolved = resolved.canonicalize()?;
                }
            }
        }
    }
    Ok(resolved)
}

pub(super) fn docker_target_paths(root: &Path) -> Result<BTreeSet<String>> {
    let root = root.canonicalize()?;
    let mut directories = vec![root.join("core"), root.join("protocol-bundles")];
    let mut targets = BTreeSet::new();
    while let Some(directory) = directories.pop() {
        if !directory.exists() {
            continue;
        }
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                if !["target", ".git", ".build-cache", "__pycache__"]
                    .iter()
                    .any(|name| entry.file_name() == *name)
                {
                    directories.push(path);
                }
            } else if entry.file_name() == "Cargo.toml" {
                ensure!(
                    path.canonicalize()?.starts_with(&root),
                    "manifest escapes repository"
                );
                let data = manifest(&path)?;
                let mut entries = Vec::new();
                if let Some(lib) = data.get("lib") {
                    entries.push(lib);
                }
                for kind in ["bin", "example", "test", "bench"] {
                    if let Some(value) = data.get(kind) {
                        entries.extend(value.as_array().context("invalid target list")?);
                    }
                }
                let mut paths = Vec::new();
                if let Some(build) = data
                    .get("package")
                    .and_then(|value| value.get("build"))
                    .and_then(Value::as_str)
                {
                    paths.push(build);
                }
                for entry in entries {
                    if let Some(path) = entry.get("path") {
                        paths.push(path.as_str().context("invalid target path")?);
                    }
                }
                for target in paths {
                    let target =
                        resolve_target(&path.parent().context("manifest directory")?.join(target))?;
                    targets.insert(
                        target
                            .strip_prefix(&root)?
                            .to_str()
                            .context("non UTF-8 target")?
                            .into(),
                    );
                }
            }
        }
    }
    Ok(targets)
}
