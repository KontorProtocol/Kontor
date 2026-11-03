use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use super::{file_hash, read, text};
use crate::container::sha256;
use crate::graph_build::fingerprint;
use crate::provenance::{GraphKind, package_sources, repository_sources};

type Inventory = BTreeMap<String, String>;
fn filtered(value: &Value, keep: impl Fn(&str) -> bool) -> Result<Inventory> {
    Ok(serde_json::from_value::<Inventory>(value.clone())?
        .into_iter()
        .filter(|(name, _)| keep(name))
        .collect())
}
fn comparator(name: &str) -> bool {
    Path::new(name)
        .file_name()
        .and_then(|v| v.to_str())
        .is_some_and(|name| name.starts_with("test_") || name == "compare_node.py")
}
fn markdown(name: &str) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "md")
}
fn rust_tools(name: &str) -> bool {
    !name.starts_with("tests/") && !markdown(name) && !archive_checker(name)
}
fn archive_checker(name: &str) -> bool {
    // Only the archive checker is evidence-only. Its shared validators and CLI
    // wiring remain bound, so introducing a build/runtime caller invalidates evidence.
    name.starts_with("src/node_evidence/comparison/")
}
fn compiled(name: &str) -> bool {
    !markdown(name)
        && Path::new(name)
            .file_name()
            .is_none_or(|v| v != ".gitignore")
}
pub(super) fn verify(
    directory: &Path,
    report: &Value,
    root: &Path,
    kind: GraphKind,
    tool_root: Option<&Path>,
) -> Result<()> {
    let data = read(&directory.join("source-inputs.json"))?;
    ensure!(
        fingerprint(&data)? == text(report, "source_inputs_sha256")?,
        "source inventory hash mismatch"
    );
    let keep = |name: &str| !(name.starts_with("tools/protocol-bundles/") && comparator(name));
    ensure!(
        filtered(&data["qualification_sources"], keep)?
            == filtered(&json!(repository_sources(root, kind)?), keep)?,
        "source inventory differs from checked-out qualification inputs"
    );
    let tools_root = tool_root.unwrap_or(root);
    ensure!(
        filtered(&data["rust_build_tools"], rust_tools)?
            == filtered(
                &json!(package_sources(
                    &tools_root.join("core/kontor-build"),
                    Some(tools_root)
                )?),
                rust_tools
            )?,
        "Rust build-tool inventory differs"
    );
    if tool_root.is_some_and(|tool_root| tool_root != root) {
        ensure!(
            filtered(&data["build_tools"], |name| !comparator(name))?
                == filtered(
                    &json!(package_sources(
                        &tools_root.join("tools/protocol-bundles"),
                        Some(tools_root)
                    )?),
                    |name| !comparator(name)
                )?,
            "executor current build-tool inventory differs"
        );
    }
    let root = root.canonicalize()?;
    let packages = data["packages"]
        .as_array()
        .context("missing source package inventory")?;
    let mut local = Vec::new();
    for package in packages {
        if let Some(relative) = text(package, "package")?.strip_prefix("path+file://<repository>/")
        {
            let relative = relative.split('#').next().unwrap();
            let path = root.join(relative).canonicalize()?;
            ensure!(
                path.starts_with(&root),
                "repository package path escapes checkout"
            );
            let keep = |name: &str| {
                compiled(name) && !(relative == "core/kontor-build" && archive_checker(name))
            };
            ensure!(
                filtered(&package["files"], keep)?
                    == filtered(&json!(package_sources(&path, Some(&root))?), keep)?,
                "local package source differs: {relative}"
            );
            local.push(PathBuf::from(relative));
        }
    }
    ensure!(!local.is_empty(), "repository package inventory missing");
    let inherited: Inventory =
        serde_json::from_value(data["inherited_manifests_and_configuration"].clone())?;
    let graph_directory = if matches!(kind, GraphKind::Node) {
        "node"
    } else {
        text(&report["identity"], "directory")?
    };
    let manifest = format!("protocol-bundles/{graph_directory}/Cargo.toml");
    let manifests: Vec<_> = inherited
        .keys()
        .filter(|name| name.ends_with(&format!("/{manifest}")))
        .collect();
    ensure!(
        manifests.len() == 1,
        "repository graph manifest missing or ambiguous"
    );
    ensure!(
        inherited[manifests[0]] == sha256(&root.join(&manifest))?,
        "repository graph manifest changed"
    );
    let recorded_root = Path::new(manifests[0])
        .ancestors()
        .nth(3)
        .context("recorded graph checkout missing")?;
    let workspace = recorded_root.join("core/Cargo.toml");
    ensure!(
        inherited.get(workspace.to_str().context("non-UTF8 workspace")?)
            == Some(&sha256(&root.join("core/Cargo.toml"))?),
        "inherited core workspace changed"
    );
    let mut recorded = Inventory::new();
    for (name, value) in &inherited {
        if let Ok(relative) = Path::new(name).strip_prefix(recorded_root) {
            file_hash(&root.join(relative), &Value::String(value.clone()))?;
            recorded.insert(
                relative.to_str().context("non-UTF8 recorded path")?.into(),
                value.clone(),
            );
        }
    }
    local.push(PathBuf::from(&manifest).parent().unwrap().into());
    let ancestors: BTreeSet<_> = local.iter().flat_map(|path| path.ancestors()).collect();
    for parent in ancestors {
        for name in ["Cargo.toml", ".cargo/config", ".cargo/config.toml"] {
            let path = parent.join(name);
            if root.join(&path).is_file() {
                ensure!(
                    recorded.get(path.to_str().context("non-UTF8 inherited path")?)
                        == Some(&sha256(&root.join(&path))?),
                    "inherited repository input changed: {}",
                    path.display()
                );
            }
        }
    }
    Ok(())
}
