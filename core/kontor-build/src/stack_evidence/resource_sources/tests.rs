use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

use super::{Metadata, capture};
use crate::container::sha256;

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn fixture() -> (TempDir, String, Value, BTreeMap<String, String>) {
    let root = tempdir().unwrap();
    let mut pins = BTreeMap::new();
    for relative in [
        "crates/wasmtime/src/runtime/fiber.rs",
        "crates/fiber/src/unix.rs",
    ] {
        let path = root.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, relative).unwrap();
        pins.insert(relative.to_owned(), sha256(&path).unwrap());
    }
    git(root.path(), &["init", "-q"]);
    git(root.path(), &["add", "."]);
    git(
        root.path(),
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        ],
    );
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let source = format!("git+https://github.com/wilfreddenton/wasmtime?rev={revision}#{revision}");
    let metadata = json!({"packages":[
        {"name":"wasmtime","version":"51.0.0-kontor.2","source":source,"id":"runtime",
         "manifest_path":root.path().join("crates/wasmtime/Cargo.toml")},
        {"name":"wasmtime-internal-fiber","version":"51.0.0-kontor.2","source":source,"id":"fiber",
         "manifest_path":root.path().join("crates/fiber/Cargo.toml")}],
        "resolve":{"nodes":[{"id":"runtime","deps":[{"name":"wasmtime_fiber","pkg":"fiber"}]}]}});
    (root, revision, metadata, pins)
}

#[test]
fn archives_bound_sources_and_rejects_changed_inputs_and_existing_evidence() {
    let (root, revision, metadata, pins) = fixture();
    let data: Metadata = serde_json::from_value(metadata).unwrap();
    let evidence = tempdir().unwrap();
    let archive = capture(&data, evidence.path(), &revision, &pins).unwrap();
    for (relative, hash) in &pins {
        let path = format!("wasmtime-source/{relative}");
        assert_eq!(archive[relative], json!({"path":path,"sha256":hash}));
        assert_eq!(sha256(&evidence.path().join(path)).unwrap(), *hash);
    }
    assert!(capture(&data, evidence.path(), &revision, &pins).is_err());
    fs::write(root.path().join("crates/fiber/src/unix.rs"), "changed").unwrap();
    let fresh = tempdir().unwrap();
    assert!(capture(&data, fresh.path(), &revision, &pins).is_err());
    assert_eq!(fs::read_dir(fresh.path()).unwrap().count(), 0);
}

#[test]
fn rejects_unpinned_or_ambiguous_packages_paths_revisions_and_dependency_edges() {
    let (root, revision, valid, pins) = fixture();
    let mut mutants = Vec::new();
    for (pointer, replacement) in [
        ("/packages/0/version", json!("51.0.0")),
        ("/packages/1/source", Value::Null),
        (
            "/packages/0/manifest_path",
            json!("crates/wasmtime/Cargo.toml"),
        ),
        (
            "/packages/1/manifest_path",
            json!("/tmp/crates/wrong/Cargo.toml"),
        ),
        ("/resolve/nodes/0/deps/0/pkg", json!("unbound")),
        ("/resolve/nodes/0/deps/0/name", json!("wrong")),
        ("/resolve/nodes/0/id", json!("wrong")),
    ] {
        let mut value = valid.clone();
        *value.pointer_mut(pointer).unwrap() = replacement;
        mutants.push(value);
    }
    let mut duplicate = valid.clone();
    duplicate["packages"]
        .as_array_mut()
        .unwrap()
        .push(valid["packages"][0].clone());
    mutants.push(duplicate);
    let mut duplicate = valid.clone();
    duplicate["resolve"]["nodes"]
        .as_array_mut()
        .unwrap()
        .push(valid["resolve"]["nodes"][0].clone());
    mutants.push(duplicate);
    for invalid in mutants {
        let data = serde_json::from_value(invalid).unwrap();
        let evidence = tempdir().unwrap();
        assert!(capture(&data, evidence.path(), &revision, &pins).is_err());
        assert_eq!(fs::read_dir(evidence.path()).unwrap().count(), 0);
    }
    let data = serde_json::from_value(valid).unwrap();
    assert!(capture(&data, tempdir().unwrap().path(), "wrong-revision", &pins).is_err());
    git(
        root.path(),
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-qm",
            "different checkout",
        ],
    );
    assert!(capture(&data, tempdir().unwrap().path(), &revision, &pins).is_err());
}

#[test]
fn refuses_archive_symlink_escape() {
    let (_root, revision, metadata, pins) = fixture();
    let data = serde_json::from_value(metadata).unwrap();
    let evidence = tempdir().unwrap();
    let outside = tempdir().unwrap();
    symlink(outside.path(), evidence.path().join("wasmtime-source")).unwrap();
    assert!(capture(&data, evidence.path(), &revision, &pins).is_err());
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
}
