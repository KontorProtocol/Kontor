use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::container::sha256;
use crate::provenance::{RETAINED_TREES, consensus_sources};

static CONTROL: LazyLock<Regex> = LazyLock::new(|| {
    expression(
    r"tokio\s*::\s*(?:signal|process)|signal_hook|ctrl_c|SIGCHLD|SIGTERM|SIGINT|sigaction|sighandler|(?P<command>Command\s*::)|(?P<process>(?:std|tokio)\s*::\s*process\s*::)|(?:fork|vfork|posix_spawn|execve|waitpid|signal)\s*\("
).expect("process-control expression")
});
static WORD: LazyLock<Regex> =
    LazyLock::new(|| expression(r"^[\p{L}\p{N}_]$").expect("word character"));
static IMPORT: LazyLock<Regex> =
    LazyLock::new(|| expression(r#"#\[path\s*=\s*"([^"]+)"\]"#).expect("path import"));

fn expression(pattern: &str) -> Result<Regex> {
    // Python also treats these four ASCII separators as whitespace.
    Ok(Regex::new(&pattern.replace(r"\s", r"[\s\x1c-\x1f]"))?)
}

fn word(character: char) -> bool {
    let mut bytes = [0; 4];
    WORD.is_match(character.encode_utf8(&mut bytes))
}

fn starts_word(text: &str, prefix: &str) -> bool {
    text.strip_prefix(prefix)
        .is_some_and(|tail| tail.chars().next().is_none_or(|character| !word(character)))
}

// A review tripwire, not a Rust parser or sandbox. Keep the historical exceptions
// for certified-input enum variants and std::process::id explicit.
pub fn needs_review(source: &str) -> bool {
    for captures in CONTROL.captures_iter(source) {
        let found = captures.get(0).expect("matched expression");
        if source[..found.start()]
            .chars()
            .next_back()
            .is_some_and(word)
        {
            continue;
        }
        let tail = source[found.end()..]
            .trim_start_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c));
        if captures.name("command").is_some()
            && ["Block", "Batch", "Control"]
                .iter()
                .any(|name| starts_word(tail, name))
        {
            continue;
        }
        if captures.name("process").is_some() && starts_word(tail, "id") {
            continue;
        }
        return true;
    }
    false
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Proof,
    Executor,
    Consensus,
}

#[derive(Deserialize)]
pub struct Metadata {
    packages: Vec<Package>,
}
#[derive(Deserialize)]
struct Package {
    name: String,
    manifest_path: Option<PathBuf>,
}

fn rust_sources(directory: &Path, recursive: bool) -> Result<BTreeSet<PathBuf>> {
    let mut paths = BTreeSet::new();
    if !directory.is_dir() {
        return Ok(paths);
    }
    let mut pending = vec![directory.to_owned()];
    while let Some(parent) = pending.pop() {
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "rs") {
                paths.insert(path.clone());
            }
            if recursive && entry.file_type()?.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(paths)
}

fn excluded_module(
    root: &Path,
    parent: &str,
    module: &str,
    guard: &str,
) -> Result<BTreeSet<PathBuf>> {
    let path = root.join(parent);
    let declaration = expression(&format!(
        r"{}\s*(?:pub(?:\([^)]*\))?\s+)?mod {};",
        regex::escape(guard),
        regex::escape(module)
    ))?;
    ensure!(
        declaration.is_match(&fs::read_to_string(&path)?),
        "retained module exclusion guard changed: {parent}::{module}"
    );
    let directory = if path.file_name().is_some_and(|name| name == "mod.rs") {
        path.parent().context("module parent")?.to_owned()
    } else {
        path.with_extension("")
    };
    let mut paths = rust_sources(&directory.join(module), true)?;
    paths.insert(directory.join(format!("{module}.rs")));
    Ok(paths)
}

fn record(path: &Path) -> Result<Value> {
    Ok(
        json!({"path": path.to_str().context("source-policy paths must be UTF8")?, "sha256": sha256(path)?}),
    )
}

fn remove(paths: &mut BTreeSet<PathBuf>, excluded: BTreeSet<PathBuf>) -> Result<Vec<Value>> {
    let records = paths
        .intersection(&excluded)
        .map(|path| record(path))
        .collect::<Result<_>>()?;
    paths.retain(|path| !excluded.contains(path));
    Ok(records)
}

pub fn check(root: &Path, metadata: &Metadata, kind: Kind) -> Result<Value> {
    let mut paths = BTreeSet::new();
    for package in &metadata.packages {
        if package.name.starts_with("arc-malachite") || package.name == "if-watch" {
            let directory = package
                .manifest_path
                .as_deref()
                .and_then(Path::parent)
                .context("process-policy package manifest")?;
            paths.extend(rust_sources(&directory.join("src"), true)?);
        }
    }
    let mut test_sources = Vec::new();
    let mut node_sources = Vec::new();
    match kind {
        Kind::Proof => {
            paths.extend(
                rust_sources(&root.join("protocol-bundles/proof"), false)?
                    .into_iter()
                    .filter(|path| {
                        !path.file_name().is_some_and(|name| {
                            name == "host.rs" || name == "cross_graph_rejected.rs"
                        })
                    }),
            );
        }
        Kind::Consensus => {
            paths.extend(
                consensus_sources(root)?
                    .keys()
                    .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
                    .map(|path| root.join(path)),
            );
            let mut imported = BTreeSet::new();
            for source in rust_sources(&root.join("protocol-bundles/consensus"), true)? {
                for captures in IMPORT.captures_iter(&fs::read_to_string(&source)?) {
                    imported.insert(
                        source
                            .parent()
                            .context("import parent")?
                            .join(&captures[1])
                            .canonicalize()
                            .context("resolve consensus path import")?,
                    );
                }
            }
            let node_root = root.join("core/indexer");
            let mut selected = BTreeSet::new();
            for path in paths {
                if !path.starts_with(&node_root) {
                    selected.insert(path);
                    continue;
                }
                let resolved = path.canonicalize()?;
                if imported.contains(&resolved)
                    || imported
                        .iter()
                        .any(|source| resolved.starts_with(source.with_extension("")))
                {
                    selected.insert(path);
                }
            }
            paths = selected;
        }
        Kind::Executor => {
            for relative in RETAINED_TREES {
                paths.extend(rust_sources(&root.join(relative), true)?);
            }
            test_sources = remove(
                &mut paths,
                excluded_module(
                    root,
                    "core/indexer/src/runtime/call.rs",
                    "tests",
                    "#[cfg(test)]",
                )?,
            )?;
            let mut excluded = BTreeSet::new();
            for (parent, module) in [
                ("core/indexer/src/runtime/mod.rs", "ownership"),
                ("core/indexer/src/runtime/mod.rs", "pool"),
                ("core/indexer/src/protocol/mod.rs", "coordinator"),
            ] {
                excluded.extend(excluded_module(
                    root,
                    parent,
                    module,
                    "#[cfg(not(kontor_retained))]",
                )?);
            }
            node_sources = remove(&mut paths, excluded)?;
        }
    }
    let mut maintained = Vec::new();
    for path in paths {
        ensure!(
            !needs_review(&fs::read_to_string(&path)?),
            "maintained bundle source needs process-ownership review: {}",
            path.display()
        );
        maintained.push(record(&path)?);
    }
    ensure!(
        !maintained.is_empty(),
        "empty maintained bundle source-policy inventory"
    );
    let mut exceptions = Vec::new();
    if matches!(kind, Kind::Proof) {
        exceptions.push("node-owned proof/host.rs signals and child reaping");
    }
    exceptions.extend([
        "pinned Tokio Unix registry pairs without bundle subscribers",
        "pinned futures-timer helper",
    ]);
    if !matches!(kind, Kind::Consensus) {
        exceptions.extend([
            "pinned Wasmtime F1 Unix VM trap handlers and Rayon pool",
            "blst crypto-only pool",
        ]);
    }
    Ok(
        json!({"maintained_sources": maintained, "test_only_sources": test_sources, "node_only_sources": node_sources, "exceptions": exceptions}),
    )
}
