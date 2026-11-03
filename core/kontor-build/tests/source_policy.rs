#![cfg(unix)]

use std::fs;
use std::path::Path;

use anyhow::Result;
use kontor_build::provenance::RETAINED_TREES;
use kontor_build::source_policy::{Kind, Metadata, check, needs_review};
use serde_json::json;
use tempfile::tempdir;

fn write(root: &Path, relative: &str, source: &str) -> Result<()> {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(path, source)?;
    Ok(())
}

fn empty() -> Metadata {
    serde_json::from_value(json!({"packages": []})).unwrap()
}

#[test]
fn process_tripwire_preserves_word_boundaries_and_narrow_exceptions() {
    for source in [
        "Command::Block { height }",
        "Command :: Batch { anchor }",
        "Command::Control { anchor }",
        "std::process:: id()",
        "prefixfork()",
        "πfork()",
        "²fork()",
        "Command::Block\u{301}",
    ] {
        assert!(!needs_review(source), "{source}");
    }
    for source in [
        "Command::new(\"child\")",
        "std::process::exit(1)",
        "tokio::process::Command",
        "tokio::signal::ctrl_c()",
        "waitpid(pid)",
        "fork()",
        "vfork ()",
        "signal_hooked",
        "Command::Blocker",
        "std::process::id2()",
        "tokio::process::id()",
        "\u{301}fork()",
        "xCommand::signal()",
    ] {
        assert!(needs_review(source), "{source}");
    }
    for space in [
        ' ', '\n', '\r', '\t', '\u{1c}', '\u{1d}', '\u{1e}', '\u{1f}', '\u{85}', '\u{a0}',
    ] {
        assert!(needs_review(&format!("fork{space}(")));
        assert!(!needs_review(&format!("Command{space}::{space}Block")));
        assert!(!needs_review(&format!(
            "std{space}::{space}process{space}::{space}id()"
        )));
    }
}

#[test]
fn excluded_sources_remain_bound_and_require_their_guards() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    for relative in RETAINED_TREES {
        fs::create_dir_all(root.join(relative))?;
    }
    write(
        root,
        "core/indexer/src/runtime/mod.rs",
        "#[cfg(not(kontor_retained))]\npub mod ownership;\n#[cfg(not(kontor_retained))]\npub mod pool;\n",
    )?;
    write(
        root,
        "core/indexer/src/protocol/mod.rs",
        "#[cfg(not(kontor_retained))]\npub(crate) mod coordinator;\n",
    )?;
    write(
        root,
        "core/indexer/src/runtime/call.rs",
        "#[cfg(test)]\nmod tests;\n",
    )?;
    write(
        root,
        "core/indexer/src/runtime/call/tests/process.rs",
        "Command::new(\"child\");",
    )?;
    write(
        root,
        "core/indexer/src/runtime/ownership.rs",
        "std::process::abort();",
    )?;
    let report = check(root, &empty(), Kind::Executor)?;
    assert_eq!(report["test_only_sources"].as_array().unwrap().len(), 1);
    assert_eq!(report["node_only_sources"].as_array().unwrap().len(), 1);
    write(
        root,
        "core/indexer/src/runtime/ownership.rs",
        "std::process::exit(1);",
    )?;
    assert_ne!(check(root, &empty(), Kind::Executor)?, report);
    write(
        root,
        "core/indexer/src/runtime/production.rs",
        "Command::new(\"child\");",
    )?;
    assert!(
        check(root, &empty(), Kind::Executor)
            .unwrap_err()
            .to_string()
            .contains("process-ownership review")
    );
    fs::remove_file(root.join("core/indexer/src/runtime/production.rs"))?;
    for (path, source) in [
        ("core/indexer/src/runtime/call.rs", "mod tests;"),
        ("core/indexer/src/runtime/mod.rs", "pub mod ownership;"),
        ("core/indexer/src/protocol/mod.rs", "pub mod coordinator;"),
    ] {
        let old = fs::read(root.join(path))?;
        write(root, path, source)?;
        assert!(
            check(root, &empty(), Kind::Executor)
                .unwrap_err()
                .to_string()
                .contains("exclusion guard changed")
        );
        fs::write(root.join(path), old)?;
    }
    Ok(())
}

#[test]
fn proof_inventory_excludes_host_and_scans_selected_dependency_sources() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    write(root, "protocol-bundles/proof/host.rs", "ctrl_c()")?;
    write(
        root,
        "protocol-bundles/proof/cross_graph_rejected.rs",
        "Command::new(\"compile fixture\")",
    )?;
    assert!(
        check(root, &empty(), Kind::Proof)
            .unwrap_err()
            .to_string()
            .contains("empty maintained")
    );
    write(
        root,
        "protocol-bundles/proof/bundle.rs",
        "pub fn shape() {}",
    )?;
    write(
        root,
        "watch/src/nested/process.rs",
        "tokio::signal::ctrl_c()",
    )?;
    let data: Metadata = serde_json::from_value(
        json!({"packages": [{"name": "if-watch", "manifest_path": root.join("watch/Cargo.toml")}]}),
    )?;
    assert!(check(root, &data, Kind::Proof).is_err());
    write(root, "watch/src/nested/process.rs", "pub fn watch() {}")?;
    assert_eq!(
        check(root, &data, Kind::Proof)?["maintained_sources"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let data: Metadata = serde_json::from_value(
        json!({"packages": [{"name": "arc-malachite-extra", "manifest_path": root.join("watch/Cargo.toml")}]}),
    )?;
    assert_eq!(
        check(root, &data, Kind::Proof)?["maintained_sources"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    Ok(())
}

#[test]
fn actual_consensus_policy_keeps_imported_children_without_node_adapters() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let report = check(root, &empty(), Kind::Consensus)?;
    let paths: Vec<_> = report["maintained_sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["path"].as_str().unwrap())
        .collect();
    assert!(
        paths
            .iter()
            .any(|path| path.ends_with("protocol-bundles/consensus/owner.rs"))
    );
    assert!(
        paths
            .iter()
            .any(|path| path.ends_with("coordinator/certified_decision/proof_stream.rs"))
    );
    assert!(
        !paths
            .iter()
            .any(|path| path.ends_with("coordinator/managed.rs"))
    );
    Ok(())
}
