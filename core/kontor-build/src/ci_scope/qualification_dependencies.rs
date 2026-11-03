use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use toml::Value;

use super::CiScope;

type PackageId = (String, String, Option<String>);
type Versions = BTreeMap<String, (String, String)>;

#[derive(Deserialize)]
struct Lockfile {
    version: u32,
    package: Vec<Package>,
}

#[derive(Clone, Deserialize, PartialEq)]
struct Package {
    name: String,
    version: String,
    source: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(flatten)]
    attributes: BTreeMap<String, Value>,
}

fn native_or_engine(name: &str, kind: CiScope) -> bool {
    name.starts_with("wasmtime")
        || name.starts_with("cranelift-")
        || name.starts_with("pulley-")
        || name.ends_with("-sys")
        || [
            "tokio",
            "deadpool",
            "psm",
            "stacker",
            "libsql",
            "libsql-ffi",
            "blst",
            "ring",
        ]
        .contains(&name)
        || (kind == CiScope::Bundles && name.starts_with("arc-malachitebft-"))
}

fn parse_lock(raw: &str) -> Result<Lockfile> {
    let mut lock: Lockfile = toml::from_str(raw).context("cannot parse Cargo lockfile")?;
    ensure!(
        [3, 4].contains(&lock.version),
        "unsupported Cargo lockfile format"
    );
    let mut identities = BTreeSet::new();
    for package in &mut lock.package {
        ensure!(
            identities.insert((&package.name, &package.version, &package.source)),
            "duplicate lockfile package"
        );
        package.dependencies.sort();
    }
    Ok(lock)
}

fn closure(lock: &Lockfile, kind: CiScope) -> Result<BTreeMap<PackageId, Package>> {
    let mut by_name: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut pending = Vec::new();
    for (index, package) in lock.package.iter().enumerate() {
        by_name.entry(&package.name).or_default().push(index);
        if native_or_engine(&package.name, kind) {
            pending.push(index);
        }
    }
    let mut dependencies = vec![Vec::new(); lock.package.len()];
    let mut dependents = vec![Vec::new(); lock.package.len()];
    for (index, package) in lock.package.iter().enumerate() {
        for dependency in &package.dependencies {
            let parts: Vec<_> = dependency.split_whitespace().collect();
            ensure!(
                (1..=3).contains(&parts.len()),
                "invalid lockfile dependency: {dependency}"
            );
            let source = if parts.len() == 3 {
                Some(
                    parts[2]
                        .strip_prefix('(')
                        .and_then(|text| text.strip_suffix(')'))
                        .context("invalid dependency source")?,
                )
            } else {
                None
            };
            let candidates: Vec<_> = by_name
                .get(parts[0])
                .into_iter()
                .flatten()
                .copied()
                .filter(|index| {
                    let candidate = &lock.package[*index];
                    (parts.len() == 1 || candidate.version == parts[1])
                        && source.is_none_or(|source| candidate.source.as_deref() == Some(source))
                })
                .collect();
            ensure!(
                candidates.len() == 1,
                "unresolved or ambiguous lockfile dependency: {dependency}"
            );
            let dependency = candidates[0];
            dependencies[index].push(dependency);
            dependents[dependency].push(index);
        }
    }
    let mut visited = BTreeSet::new();
    while let Some(index) = pending.pop() {
        if visited.insert(index) {
            pending.extend(&dependencies[index]);
        }
    }
    // Lockfiles omit feature flags. A caller of a shared engine dependency can
    // change its unified features even without changing that dependency's version.
    pending.extend(&visited);
    let mut expanded = BTreeSet::new();
    while let Some(index) = pending.pop() {
        if expanded.insert(index) {
            visited.insert(index);
            pending.extend(&dependents[index]);
        }
    }
    Ok(visited
        .into_iter()
        .map(|index| {
            let package = lock.package[index].clone();
            (
                (
                    package.name.clone(),
                    package.version.clone(),
                    package.source.clone(),
                ),
                package,
            )
        })
        .collect())
}

fn read_revision(root: &Path, revision: &str, path: &str) -> Result<String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["show", &format!("{revision}:{path}")])
        .output()?;
    ensure!(output.status.success(), "cannot read {path} at {revision}");
    Ok(String::from_utf8(output.stdout)?)
}

fn normalize_dependencies(owner: &mut Value, prefix: &str, versions: &mut Versions) -> Result<()> {
    for kind in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(table) = owner.get_mut(kind) else {
            continue;
        };
        for (alias, dependency) in table.as_table_mut().context("invalid dependency table")? {
            let package = dependency
                .get("package")
                .and_then(Value::as_str)
                .unwrap_or(alias)
                .to_owned();
            let version = if dependency.is_str() {
                Some(dependency)
            } else {
                dependency.get_mut("version")
            };
            if let Some(version) = version {
                versions.insert(
                    format!("{prefix}/{kind}/{alias}"),
                    (
                        package,
                        version
                            .as_str()
                            .context("invalid dependency version")?
                            .into(),
                    ),
                );
                *version = Value::String(String::new());
            }
        }
    }
    Ok(())
}

fn normalize_manifest(raw: &str) -> Result<(Value, Versions)> {
    let mut value: Value = toml::from_str(raw)?;
    let mut versions = BTreeMap::new();
    normalize_dependencies(&mut value, "package", &mut versions)?;
    if let Some(workspace) = value.get_mut("workspace") {
        normalize_dependencies(workspace, "workspace", &mut versions)?;
    }
    if let Some(targets) = value.get_mut("target") {
        for (target, owner) in targets.as_table_mut().context("invalid target table")? {
            normalize_dependencies(owner, &format!("target/{target}"), &mut versions)?;
        }
    }
    Ok((value, versions))
}

fn owning_lock(root: &Path, revision: &str, manifest: &str) -> Result<Lockfile> {
    for directory in Path::new(manifest)
        .parent()
        .context("manifest has no parent")?
        .ancestors()
    {
        let path = directory.join("Cargo.lock");
        if let Ok(raw) = read_revision(
            root,
            revision,
            path.to_str().context("non-UTF-8 lockfile path")?,
        ) {
            return parse_lock(&raw);
        }
    }
    bail!("cannot locate lockfile for {manifest} at {revision}")
}

pub(super) fn dependency_change_relevant(
    root: &Path,
    kind: CiScope,
    base: &str,
    head: &str,
    path: &str,
) -> Result<bool> {
    let filename = Path::new(path).file_name().and_then(|name| name.to_str());
    // Retained bundle manifests and locks contribute to protocol identity.
    if (kind == CiScope::Bundles && path.starts_with("protocol-bundles/"))
        || !matches!(filename, Some("Cargo.lock" | "Cargo.toml"))
    {
        return Ok(true);
    }
    let before = read_revision(root, base, path)?;
    let after = read_revision(root, head, path)?;
    if filename == Some("Cargo.lock") {
        return Ok(closure(&parse_lock(&before)?, kind)? != closure(&parse_lock(&after)?, kind)?);
    }
    let (before, old_versions) = normalize_manifest(&before)?;
    let (after, new_versions) = normalize_manifest(&after)?;
    // Only known version-only updates can skip. Features, patches, profiles,
    // dependency additions/removals and source changes still require qualification.
    if before != after {
        return Ok(true);
    }
    let changed: BTreeSet<_> = old_versions
        .iter()
        .filter(|(key, value)| new_versions.get(*key) != Some(*value))
        .map(|(_, (package, _))| package.as_str())
        .collect();
    if changed.is_empty() {
        return Ok(false);
    }
    for revision in [base, head] {
        let lock = owning_lock(root, revision, path)?;
        ensure!(
            changed
                .iter()
                .all(|name| lock.package.iter().any(|package| package.name == *name)),
            "changed dependency absent from lockfile"
        );
        if closure(&lock, kind)?
            .values()
            .any(|package| changed.contains(package.name.as_str()))
        {
            return Ok(true);
        }
    }
    Ok(false)
}
