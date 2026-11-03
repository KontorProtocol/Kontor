use super::*;
use std::os::unix::fs::symlink;
use tempfile::tempdir;

fn fixture(root: &Path) -> Result<(PathBuf, Value)> {
    for name in SEMANTIC_TREES {
        fs::create_dir_all(root.join(name))?;
    }
    let manifest = root.join("protocol-bundles/executor-first/Cargo.toml");
    fs::create_dir_all(manifest.parent().unwrap())?;
    fs::write(&manifest, "[package]\nname='executor'\nversion='1.0.0'\n")?;
    fs::write(manifest.with_file_name("Cargo.lock"), "locked inputs")?;
    fs::write(
        root.join("core/indexer/src/runtime/semantics.rs"),
        "execution rules",
    )?;
    Ok((
        manifest.clone(),
        json!({"packages":[{"id":"root","name":"executor","version":"1.0.0","source":null,"manifest_path":manifest}],"resolve":{"nodes":[{"id":"root","features":["z","a"]}]}}),
    ))
}
#[test]
fn binary_encoding_matches_runtime_golden_and_rejects_malformed_inputs() -> Result<()> {
    let sources = BTreeMap::from([("core/main.rs".into(), "11".repeat(32))]);
    let locks = BTreeMap::from([("core/Cargo.lock".into(), "22".repeat(32))]);
    let bytes = encode(
        &sources,
        &locks,
        &["b".into(), "a".into(), "b".into()],
        &"33".repeat(32),
    )?;
    let mut id = Sha256::new();
    id.update(b"kontor/execution-definition/v1\0");
    id.update(bytes);
    assert_eq!(
        hex::encode(id.finalize()),
        "042b0f0715621140a44437d8e2dc62dc74ae72cc8ba5e68afdd263e98c70f592"
    );
    for path in ["", "/absolute", "../escape", "a//b", "a/./b", "a/../b"] {
        assert!(
            encode(
                &BTreeMap::from([(path.into(), "11".repeat(32))]),
                &locks,
                &[],
                &"33".repeat(32)
            )
            .is_err()
        );
    }
    assert!(encode(&sources, &BTreeMap::new(), &[], &"33".repeat(32)).is_err());
    assert!(encode(&sources, &locks, &[], "33").is_err());
    Ok(())
}
#[test]
fn references_bind_semantics_lock_features_config_and_inherited_properties() -> Result<()> {
    let dir = tempdir()?;
    let (manifest, data) = fixture(dir.path())?;
    let original = reference(dir.path(), &manifest, &data)?;
    for path in [
        dir.path().join("core/indexer/src/runtime/semantics.rs"),
        manifest.with_file_name("Cargo.lock"),
    ] {
        let old = fs::read(&path)?;
        fs::write(&path, "changed")?;
        assert_ne!(reference(dir.path(), &manifest, &data)?, original);
        fs::write(path, old)?;
    }
    let mut changed = data.clone();
    changed["resolve"]["nodes"][0]["features"] = json!(["new"]);
    assert_ne!(reference(dir.path(), &manifest, &changed)?, original);
    changed = data.clone();
    changed["packages"][0]["edition"] = json!("2024");
    assert_ne!(reference(dir.path(), &manifest, &changed)?, original);
    fs::create_dir_all(dir.path().join(".cargo"))?;
    fs::write(
        dir.path().join(".cargo/config.toml"),
        "[build]\nrustflags=['--cfg=changed']",
    )?;
    assert_ne!(reference(dir.path(), &manifest, &data)?, original);
    Ok(())
}
#[test]
fn platform_outputs_node_modules_and_checkout_location_do_not_change_identity() -> Result<()> {
    let first = tempdir()?;
    let second = tempdir()?;
    let (manifest, data) = fixture(first.path())?;
    let (other, other_data) = fixture(second.path())?;
    let original = reference(first.path(), &manifest, &data)?;
    assert_eq!(reference(second.path(), &other, &other_data)?, original);
    for relative in [
        "protocol-bundles/executor-first/definition.bin",
        "protocol-bundles/executor-first/target/binary",
        "core/indexer/src/protocol/coordinator/migration.rs",
        "core/indexer/src/runtime/ownership.rs",
        "core/indexer/src/runtime/ownership/adapter.rs",
        "core/indexer/src/runtime/pool.rs",
        "core/indexer/src/runtime/node.rs",
        "core/indexer/src/database/storage_callbacks_v1.rs",
        "core/Cargo.toml",
        "protocol-bundles/node/Cargo.lock",
    ] {
        let path = first.path().join(relative);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, "unrelated implementation")?;
        assert_eq!(
            reference(first.path(), &manifest, &data)?,
            original,
            "{relative}"
        );
    }
    let contract = first
        .path()
        .join("core/indexer/src/protocol/v1/storage-contract.json");
    fs::create_dir_all(contract.parent().unwrap())?;
    fs::write(contract, "required storage contract")?;
    assert_ne!(reference(first.path(), &manifest, &data)?, original);
    Ok(())
}
#[test]
fn linked_inputs_are_bound_and_escape_cycles_or_missing_trees_fail() -> Result<()> {
    let dir = tempdir()?;
    let outside = tempdir()?;
    let (manifest, data) = fixture(dir.path())?;
    let runtime = dir.path().join("core/indexer/src/runtime");
    symlink(&runtime, manifest.parent().unwrap().join("wit"))?;
    let original = reference(dir.path(), &manifest, &data)?;
    fs::write(runtime.join("semantics.rs"), "changed")?;
    assert_ne!(reference(dir.path(), &manifest, &data)?, original);
    symlink(&runtime, runtime.join("cycle"))?;
    assert!(reference(dir.path(), &manifest, &data).is_err());
    fs::remove_file(runtime.join("cycle"))?;
    symlink(outside.path(), runtime.join("outside"))?;
    assert!(reference(dir.path(), &manifest, &data).is_err());
    fs::remove_file(runtime.join("outside"))?;
    fs::remove_dir(dir.path().join("native-contracts/nft/wit"))?;
    assert!(reference(dir.path(), &manifest, &data).is_err());
    Ok(())
}
#[test]
fn verification_never_overwrites_and_named_graph_excludes_own_definition() -> Result<()> {
    let dir = tempdir()?;
    let (old, mut data) = fixture(dir.path())?;
    let directory = old.parent().unwrap().with_file_name("executor-observer");
    fs::rename(old.parent().unwrap(), &directory)?;
    let manifest = directory.join("Cargo.toml");
    data["packages"][0]["manifest_path"] = json!(manifest);
    assert!(verify(dir.path(), &manifest, &data).is_err());
    let original = reference(dir.path(), &manifest, &data)?;
    let output = directory.join("definition.bin");
    fs::write(&output, &original)?;
    verify(dir.path(), &manifest, &data)?;
    for path in [
        dir.path().join("core/indexer/src/runtime/semantics.rs"),
        manifest.with_file_name("Cargo.lock"),
    ] {
        let contents = fs::read(&path)?;
        fs::write(&path, "substituted")?;
        assert!(verify(dir.path(), &manifest, &data).is_err());
        assert_eq!(fs::read(&output)?, original);
        assert_eq!(fs::read(&path)?, b"substituted");
        fs::write(path, contents)?;
    }
    let mut changed = data.clone();
    changed["resolve"]["nodes"][0]["features"] = json!(["changed"]);
    assert!(verify(dir.path(), &manifest, &changed).is_err());
    assert_eq!(fs::read(&output)?, original);
    fs::write(&output, "stale")?;
    assert!(verify(dir.path(), &manifest, &data).is_err());
    assert_eq!(fs::read(&output)?, b"stale");
    finish(dir.path(), &manifest, &data, true)?;
    assert_eq!(fs::read(output)?, original);
    Ok(())
}
#[test]
fn effective_manifest_resolves_local_paths_but_allows_missing_generated_targets() -> Result<()> {
    let dir = tempdir()?;
    let (manifest, mut data) = fixture(dir.path())?;
    data["packages"][0]["targets"] =
        json!([{"name":"generated","src_path":dir.path().join("missing/../generated.rs")}]);
    let digest = effective_manifest(dir.path(), &data["packages"][0])?;
    data["packages"][0]["targets"][0]["src_path"] = json!(dir.path().join("generated.rs"));
    assert_eq!(
        effective_manifest(dir.path(), &data["packages"][0])?,
        digest
    );
    data["packages"][0]["dependencies"] = json!([{"name":"local","path":manifest.parent()}]);
    assert_ne!(
        effective_manifest(dir.path(), &data["packages"][0])?,
        digest
    );
    data["packages"][0]["dependencies"][0]["path"] = json!(dir.path().parent().unwrap());
    assert!(effective_manifest(dir.path(), &data["packages"][0]).is_err());
    Ok(())
}

#[test]
fn effective_manifest_accepts_aliased_roots_without_allowing_escaped_inputs() -> Result<()> {
    let dir = tempdir()?;
    let aliases = tempdir()?;
    let (_, mut data) = fixture(dir.path())?;
    let alias = aliases.path().join("checkout");
    symlink(dir.path(), &alias)?;
    data["packages"][0]["targets"] = json!([{"src_path":alias.join("generated.rs")}]);
    data["packages"][0]["dependencies"] = json!([{"name":"local","path":alias.join("core")}]);
    assert_eq!(
        effective_manifest(&alias, &data["packages"][0])?,
        effective_manifest(dir.path(), &data["packages"][0])?
    );
    symlink(aliases.path(), alias.join("outside"))?;
    data["packages"][0]["targets"][0]["src_path"] = json!(alias.join("outside/generated.rs"));
    assert!(effective_manifest(&alias, &data["packages"][0]).is_err());
    Ok(())
}

#[test]
fn dangling_metadata_links_keep_their_targets_and_reject_escape_or_cycles() -> Result<()> {
    let dir = tempdir()?;
    let outside = tempdir()?;
    let (_, mut data) = fixture(dir.path())?;
    let link = dir.path().join("generated.rs");
    symlink("missing.rs", &link)?;
    data["packages"][0]["targets"] = json!([{"src_path":link}]);
    let original = effective_manifest(dir.path(), &data["packages"][0])?;
    data["packages"][0]["targets"][0]["src_path"] = json!(dir.path().join("missing.rs"));
    assert_eq!(
        effective_manifest(dir.path(), &data["packages"][0])?,
        original
    );
    data["packages"][0]["targets"][0]["src_path"] = json!(link);
    fs::remove_file(&link)?;
    symlink(outside.path().join("missing.rs"), &link)?;
    assert!(effective_manifest(dir.path(), &data["packages"][0]).is_err());
    fs::remove_file(&link)?;
    symlink("missing/../generated.rs", &link)?;
    assert!(resolve(&link).is_err());
    Ok(())
}

#[test]
fn json_requests_resolve_relative_metadata_from_the_caller_directory() -> Result<()> {
    let dir = tempdir()?;
    let (manifest, mut data) = fixture(dir.path())?;
    let expected = reference(dir.path(), &manifest, &data)?;
    data["packages"][0]["manifest_path"] = json!("protocol-bundles/executor-first/Cargo.toml");
    let value = run(Request::Reference {
        root: dir.path().into(),
        manifest,
        metadata: data,
        cwd: dir.path().into(),
    })?;
    assert_eq!(value, json!(hex::encode(expected)));
    Ok(())
}
