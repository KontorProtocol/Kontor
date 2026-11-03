#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Result;
use kontor_build::provenance::{
    GraphKind, RETAINED_TREES, consensus_sources, local_source_files, node_sources,
    package_sources, repository_sources, retained_sources, source_inputs,
};
use kontor_build::source_identity::Metadata;
use kontor_build::source_policy::{Kind, check};
use regex::Regex;
use serde_json::{Value, json};
use tempfile::tempdir;

fn write(root: &Path, relative: &str, text: &str) -> Result<PathBuf> {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(&path, text)?;
    Ok(path)
}

fn sources(root: &Path) -> Result<()> {
    for relative in RETAINED_TREES {
        fs::create_dir_all(root.join(relative))?;
    }
    write(root, "core/indexer/src/runtime/mod.rs", "runtime")?;
    for name in [
        "engine",
        "resources",
        "gas",
        "native",
        "errors",
        "fuel",
        "fees",
        "deposit",
    ] {
        write(
            root,
            &format!("core/indexer/src/protocol/v1/{name}.rs"),
            name,
        )?;
    }
    Ok(())
}

fn metadata(root: &Path) -> Result<Metadata> {
    write(root, "core/local/Cargo.toml", "package manifest")?;
    write(root, "core/local/lib.rs", "execution rules")?;
    write(root, "core/Cargo.toml", "inherited manifest")?;
    write(root, "core/Cargo.lock", "package = []\n")?;
    Ok(serde_json::from_value(
        json!({"workspace_root": root.join("core"), "packages": [{
            "manifest_path": root.join("core/local/Cargo.toml"), "id": format!("path+file://{}/core/local#local", root.display()),
            "name": "local", "version": "0.1.0", "source": null,
        }]}),
    )?)
}

#[test]
fn local_walk_contains_links_detects_cycles_and_excludes_build_outputs() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path().canonicalize()?;
    write(&root, "pkg/a.rs", "a")?;
    write(&root, "pkg/child/b.rs", "b")?;
    for excluded in ["target", ".git", "__pycache__"] {
        write(&root, &format!("pkg/{excluded}/ignored"), "ignored")?;
    }
    let package = root.join("pkg");
    symlink("child", package.join("alias"))?;
    symlink("a.rs", package.join("file.rs"))?;
    let inventory = package_sources(&package, Some(&root))?;
    assert_eq!(inventory.len(), 4);
    assert_eq!(
        inventory[Path::new("child/b.rs")],
        inventory[Path::new("alias/b.rs")]
    );
    assert_eq!(
        inventory[Path::new("a.rs")],
        inventory[Path::new("file.rs")]
    );
    assert_eq!(local_source_files(&package, &root)?.len(), 4);
    symlink(".", package.join("cycle"))?;
    assert!(
        format!("{:#}", package_sources(&package, Some(&root)).unwrap_err()).contains("cyclic")
    );
    fs::remove_file(package.join("cycle"))?;
    let outside = tempdir()?;
    write(outside.path(), "outside.rs", "outside")?;
    for target in [outside.path().to_owned(), outside.path().join("outside.rs")] {
        symlink(target, package.join("escape"))?;
        assert!(
            format!("{:#}", package_sources(&package, Some(&root)).unwrap_err())
                .contains("escapes")
        );
        fs::remove_file(package.join("escape"))?;
    }
    symlink("absent", package.join("missing"))?;
    assert!(local_source_files(&package, &root).is_err());
    Ok(())
}

#[test]
fn external_package_inventory_follows_file_but_not_directory_links() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    write(root, "package/a.rs", "a")?;
    write(root, "outside/b.rs", "b")?;
    write(root, "package/target/output.rs", "artifact")?;
    symlink("../outside", root.join("package/directory"))?;
    symlink("../outside/b.rs", root.join("package/file.rs"))?;
    let inventory = package_sources(&root.join("package"), None)?;
    assert_eq!(inventory.len(), 2);
    assert!(inventory.contains_key(Path::new("file.rs")));
    assert!(package_sources(&root.join("absent"), None)?.is_empty());
    Ok(())
}

#[test]
fn retained_inventory_binds_non_package_inputs_and_missing_roots() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    sources(root)?;
    let paths = [
        "protocol-bundles/executor/build.rs",
        "core/indexer/src/runtime/call.rs",
        "core/indexer/src/runtime/wit/context.wit",
        "core/indexer/src/protocol/v1/native/token.wasm.br",
        "core/indexer/src/bls/mod.rs",
        "native-contracts/token/wit/types.wit",
    ];
    for relative in paths {
        write(root, relative, "original")?;
    }
    let initial = retained_sources(root)?;
    for relative in paths {
        write(root, relative, "changed")?;
        assert_ne!(retained_sources(root)?, initial, "{relative}");
        fs::remove_file(root.join(relative))?;
        assert_ne!(retained_sources(root)?, initial, "{relative}");
        write(root, relative, "original")?;
    }
    write(root, "core/indexer/src/runtime/new.rs", "new")?;
    assert_ne!(retained_sources(root)?, initial);
    fs::remove_dir(root.join("native-contracts/nft/wit"))?;
    assert!(
        format!("{:#}", retained_sources(root).unwrap_err())
            .contains("missing retained source tree")
    );
    Ok(())
}

#[test]
fn node_inventory_binds_schema_generator_and_qualification_artifacts() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    let paths = [
        "core/indexer/src/main.rs",
        "core/indexer/src/protocol/coordinator/linked.rs",
        "core/indexer/src/database/storage_callbacks_v1.rs",
        "core/indexer/src/database/sql/current_state.sql",
        "core/indexer/proto/consensus.proto",
        "core/indexer/build.rs",
        "test-contracts/binaries/counter.wasm.br",
        "test-contracts/binaries/proxy.wasm.br",
    ];
    for relative in paths {
        write(root, relative, "original")?;
    }
    let initial = node_sources(root)?;
    for relative in paths {
        write(root, relative, "changed")?;
        assert_ne!(node_sources(root)?, initial);
        write(root, relative, "original")?;
    }
    write(root, "core/indexer/src/__pycache__/ignored", "ignored")?;
    assert_eq!(node_sources(root)?, initial);
    fs::remove_file(root.join("core/indexer/proto/consensus.proto"))?;
    fs::remove_dir(root.join("core/indexer/proto"))?;
    assert!(format!("{:#}", node_sources(root).unwrap_err()).contains("missing node source tree"));
    Ok(())
}

#[test]
fn frozen_inheritance_stops_at_root_and_current_tools_remain_bound() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path().canonicalize()?;
    let frozen = root.join("retained/k3");
    sources(&frozen)?;
    let data = metadata(&frozen)?;
    write(&root, "Cargo.toml", "live workspace")?;
    write(&root, "tools/protocol-bundles/wrapper", "tool")?;
    write(&root, "core/kontor-build/wrapper.rs", "rust tool")?;
    write(&root, "cargo-home/config.toml", "cargo config")?;
    let inputs = || {
        source_inputs(
            &frozen,
            &data,
            GraphKind::Executor,
            Some(&root),
            &root.join("cargo-home"),
        )
    };
    let initial = inputs()?;
    let inherited = initial["inherited_manifests_and_configuration"]
        .as_object()
        .unwrap();
    assert!(inherited.contains_key(frozen.join("core/Cargo.toml").to_str().unwrap()));
    assert!(!inherited.contains_key(root.join("Cargo.toml").to_str().unwrap()));
    assert_eq!(
        initial["packages"][0]["package"],
        "path+file://<repository>/core/local#local"
    );
    write(&root, "Cargo.toml", "different live workspace")?;
    assert_eq!(inputs()?, initial);
    for relative in [
        "tools/protocol-bundles/wrapper",
        "core/kontor-build/wrapper.rs",
        "cargo-home/config.toml",
        "retained/k3/core/local/lib.rs",
        "retained/k3/core/Cargo.toml",
        "retained/k3/core/indexer/src/runtime/mod.rs",
        "retained/k3/core/indexer/src/protocol/v1/engine.rs",
        "retained/k3/core/indexer/src/protocol/v1/resources.rs",
        "retained/k3/core/indexer/src/protocol/v1/gas.rs",
        "retained/k3/core/indexer/src/protocol/v1/native.rs",
        "retained/k3/core/indexer/src/protocol/v1/errors.rs",
        "retained/k3/core/indexer/src/protocol/v1/fuel.rs",
        "retained/k3/core/indexer/src/protocol/v1/fees.rs",
        "retained/k3/core/indexer/src/protocol/v1/deposit.rs",
    ] {
        let before = inputs()?;
        write(&root, relative, "changed")?;
        assert_ne!(inputs()?, before, "{relative}");
    }
    Ok(())
}

#[test]
fn consensus_inventory_binds_imported_sources_protobuf_and_control_vectors() -> Result<()> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let inventory = consensus_sources(repository)?;
    for name in [
        "core/indexer/proto/consensus/v1/consensus.proto",
        "core/indexer/src/protocol/coordinator/certified_decision/proof_stream.rs",
        "core/indexer/src/protocol/coordinator/control/test-vector.json",
    ] {
        assert!(inventory.contains_key(Path::new(name)), "missing {name}");
    }
    assert!(
        !repository_sources(repository, GraphKind::Consensus)?
            .contains_key(Path::new("core/indexer/src/protocol/v1/engine.rs"))
    );
    let imports = Regex::new(r#"#\[path\s*=\s*"([^"]+)"\]"#)?;
    for source in local_source_files(&repository.join("protocol-bundles/consensus"), repository)? {
        if source.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        assert!(inventory.contains_key(source.strip_prefix(repository)?));
        for capture in imports.captures_iter(&fs::read_to_string(&source)?) {
            let imported = source.parent().unwrap().join(&capture[1]).canonicalize()?;
            assert!(inventory.contains_key(imported.strip_prefix(repository)?));
        }
    }
    let dir = tempdir()?;
    let root = dir.path();
    for relative in inventory.keys() {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::copy(repository.join(relative), path)?;
    }
    assert_eq!(consensus_sources(root)?, inventory);
    for relative in [
        "protocol-bundles/consensus/owner.rs",
        "core/indexer/src/consensus/value.rs",
        "core/indexer/src/protocol/coordinator/activation.rs",
        "core/indexer/src/protocol/coordinator/certified_input.rs",
        "core/indexer/src/protocol/coordinator/certified_decision/proof_stream.rs",
        "core/indexer/src/protocol/coordinator/control/test-vector.json",
        "core/indexer/proto/consensus/v1/sync.proto",
    ] {
        let path = root.join(relative);
        let contents = fs::read(&path)?;
        fs::write(&path, "changed")?;
        assert_ne!(consensus_sources(root)?, inventory, "{relative}");
        fs::write(path, contents)?;
    }
    write(
        root,
        "protocol-bundles/consensus/owner.rs",
        "std::process::exit(1);",
    )?;
    let empty = serde_json::from_value(json!({"packages":[]}))?;
    assert!(check(root, &empty, Kind::Consensus).is_err());
    Ok(())
}

#[test]
fn source_inputs_reject_local_packages_and_inherited_configs_outside_root() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path().canonicalize()?;
    let frozen = root.join("retained");
    sources(&frozen)?;
    let data = metadata(&frozen)?;
    write(&frozen, "core/kontor-build/tool.rs", "tool")?;
    write(&root, "node/config", "node config")?;
    let config = frozen.join("core/.cargo/config.toml");
    fs::create_dir(config.parent().unwrap())?;
    symlink(root.join("node/config"), &config)?;
    let error = source_inputs(
        &frozen,
        &data,
        GraphKind::Executor,
        None,
        &root.join("cargo-home"),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("inherited package input escapes")
    );
    fs::remove_file(config)?;
    let external = metadata(&root.join("node"))?;
    let error = source_inputs(
        &frozen,
        &external,
        GraphKind::Executor,
        None,
        &root.join("cargo-home"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("local package escapes"));
    Ok(())
}

#[test]
fn cli_provenance_request_rejects_unknown_kinds_and_returns_inventory() -> Result<()> {
    let dir = tempdir()?;
    write(dir.path(), "source.rs", "source")?;
    let run = |value: Value| -> Result<_> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kontor-build"))
            .arg("provenance")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(value.to_string().as_bytes())?;
        Ok(child.wait_with_output()?)
    };
    let output = run(json!({"operation": "package_sources", "directory": dir.path()}))?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let inventory: Value = serde_json::from_slice(&output.stdout)?;
    assert!(inventory["source.rs"].as_str().is_some());
    let output =
        run(json!({"operation": "repository_sources", "root": dir.path(), "kind": "unknown"}))?;
    assert!(!output.status.success());
    Ok(())
}
