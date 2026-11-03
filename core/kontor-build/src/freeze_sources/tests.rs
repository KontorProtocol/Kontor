use super::*;
use std::os::unix::fs::PermissionsExt;

use tempfile::tempdir;

use crate::execution_definition::reference;

fn write(root: &Path, name: &str, contents: &str) -> Result<()> {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(path, contents)?;
    Ok(())
}
fn git(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    ensure!(
        output.status.success(),
        "git fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().into())
}
fn fixture(root: &Path) -> Result<String> {
    for tree in SEMANTIC_TREES.iter().chain(SUPPORT_TREES) {
        write(root, &format!("{tree}/source.rs"), "// frozen source\n")?;
    }
    write(root, "tools/build.json", "{}")?;
    write(
        root,
        "tools/protocol-bundles/build.py",
        "obsolete orchestration",
    )?;
    for asset in SUPPORT_FILES.iter().take(SUPPORT_FILES.len() - 1) {
        write(root, asset, "historical fixture")?;
    }
    write(
        root,
        "vendor/helper/Cargo.toml",
        "[package]\nname='helper'\nversion='1.0.0'\nedition='2024'\n[lib]\npath='lib.rs'\n",
    )?;
    write(root, "vendor/helper/lib.rs", "pub fn helper() {}\n")?;
    write(root, ".cargo/config.toml", "[build]\njobs=1\n")?;
    write(
        root,
        "core/Cargo.toml",
        "[workspace]\nmembers=['local']\n[workspace.package]\nversion='1.0.0'\nedition='2024'\n",
    )?;
    write(
        root,
        "core/local/Cargo.toml",
        "[package]\nname='local'\nversion.workspace=true\nedition.workspace=true\n[lib]\npath='lib.rs'\n",
    )?;
    write(root, "core/local/lib.rs", "pub fn local() {}\n")?;
    for graph in GRAPHS {
        write(
            root,
            &format!("protocol-bundles/{graph}/Cargo.toml"),
            &format!(
                "[package]\nname='{graph}'\nversion='1.0.0'\nedition='2024'\n[workspace]\n[lib]\npath='lib.rs'\n[dependencies]\nlocal={{path='../../core/local'}}\n[patch.crates-io.helper]\npath='../../vendor/helper'\n"
            ),
        )?;
        write(
            root,
            &format!("protocol-bundles/{graph}/lib.rs"),
            "pub fn run() {}\n",
        )?;
        let status = Command::new("cargo")
            .args(["generate-lockfile", "--offline", "--manifest-path"])
            .arg(manifest(root, graph))
            .current_dir(root)
            .status()?;
        ensure!(status.success(), "generate fixture lock");
    }
    let executable = root.join("protocol-bundles/proof/script");
    fs::write(&executable, "#!/bin/sh\nexit 0\n")?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
    symlink("./source.rs", root.join("protocol-bundles/proof/alias"))?;
    for graph in GRAPHS {
        let path = manifest(root, graph);
        fs::write(
            path.with_file_name("definition.bin"),
            reference(root, &path, &metadata(root, graph)?)?,
        )?;
    }
    git(root, &["init", "-q"])?;
    git(root, &["add", "."])?;
    git(
        root,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "Fixture",
        ],
    )?;
    git(root, &["rev-parse", "HEAD"])
}
fn args(revision: &str, destination: &Path) -> FreezeSourcesArgs {
    FreezeSourcesArgs {
        revision: revision.into(),
        destination: destination.into(),
        kind: "executors".into(),
    }
}

#[test]
fn real_git_freeze_preserves_identity_modes_links_and_ignores_worktree_changes() -> Result<()> {
    let repository = tempdir()?;
    let output = tempdir()?;
    let root = repository.path();
    let revision = fixture(root)?;
    let expected = definitions(
        root,
        &GRAPHS
            .iter()
            .map(|graph| metadata(root, graph))
            .collect::<Result<Vec<_>>>()?,
    )?;
    write(
        root,
        "core/indexer/src/runtime/source.rs",
        "uncommitted change",
    )?;
    let destination = output.path().join("retained");
    let report = freeze_sources(root, args(&revision, &destination))?;
    assert_eq!(report["definitions"], expected);
    let record = verify_snapshot(&destination, report["snapshot_sha256"].as_str().unwrap())?;
    assert_eq!(record["source_commit"], revision);
    assert_eq!(
        record["files"]["protocol-bundles/proof/alias"],
        json!({"symlink":"source.rs"})
    );
    assert_eq!(
        fs::read_link(destination.join("protocol-bundles/proof/alias"))?,
        Path::new("./source.rs")
    );
    assert_eq!(
        fs::metadata(destination.join("protocol-bundles/proof/script"))?
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert!(destination.join("vendor/helper/lib.rs").is_file());
    assert!(destination.join("core/local/lib.rs").is_file());
    assert!(destination.join("core/Cargo.toml").is_file());
    assert!(destination.join(".cargo/config.toml").is_file());
    assert!(destination.join(SUPPORT_FILES[0]).is_file());
    assert!(!destination.join("tools/protocol-bundles/build.py").exists());
    assert!(
        !destination
            .join(SUPPORT_FILES[SUPPORT_FILES.len() - 1])
            .exists()
    );
    let original = fs::read(destination.join("snapshot.json"))?;
    assert!(freeze_sources(root, args(&revision, &destination)).is_err());
    assert_eq!(fs::read(destination.join("snapshot.json"))?, original);
    for invalid in ["HEAD", &revision[..12], "--all"] {
        assert!(freeze_sources(root, args(invalid, &output.path().join("invalid"))).is_err());
    }
    assert!(!output.path().join("invalid").exists());
    let dangling = output.path().join("dangling");
    symlink("missing", &dangling)?;
    assert!(freeze_sources(root, args(&revision, &dangling)).is_err());
    assert!(dangling.symlink_metadata()?.file_type().is_symlink());
    Ok(())
}

#[test]
fn failed_reference_and_destination_lock_leave_no_snapshot() -> Result<()> {
    let repository = tempdir()?;
    let output = tempdir()?;
    let root = repository.path();
    let revision = fixture(root)?;
    let destination = output.path().join("retained");
    let lock = File::options()
        .create(true)
        .append(true)
        .open(output.path().join(".retained.freeze.lock"))?;
    lock.try_lock()?;
    assert!(
        freeze_sources(root, args(&revision, &destination))
            .unwrap_err()
            .to_string()
            .contains("another freezer")
    );
    lock.unlock()?;
    let mut retired = args(&revision, &destination);
    retired.kind = "coordinator".into();
    assert!(freeze_sources(root, retired).is_err());
    write(
        root,
        "protocol-bundles/executor-first/definition.bin",
        "stale",
    )?;
    git(root, &["add", "."])?;
    git(
        root,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "Stale reference",
        ],
    )?;
    let revision = git(root, &["rev-parse", "HEAD"])?;
    assert!(
        freeze_sources(root, args(&revision, &destination))
            .unwrap_err()
            .to_string()
            .contains("reference differs")
    );
    assert!(!destination.exists());
    assert!(!fs::read_dir(output.path())?.any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("freeze-executors-")
    }));
    Ok(())
}

#[test]
fn source_closure_rejects_missing_escaping_and_cyclic_inputs() -> Result<()> {
    let directory = tempdir()?;
    let root = directory.path().canonicalize()?;
    let outside = tempdir()?;
    let path = root.join("source.rs");
    fs::write(&path, "source")?;
    let mut paths = BTreeSet::new();
    symlink("source.rs", root.join("alias"))?;
    include(&root, &root.join("alias"), &mut BTreeSet::new(), &mut paths)?;
    assert_eq!(paths, BTreeSet::from([path, root.join("alias")]));
    symlink(outside.path(), root.join("outside"))?;
    assert!(
        include(
            &root,
            &root.join("outside"),
            &mut BTreeSet::new(),
            &mut paths
        )
        .is_err()
    );
    fs::remove_file(root.join("outside"))?;
    symlink(".", root.join("cycle"))?;
    assert!(include(&root, &root, &mut BTreeSet::new(), &mut paths).is_err());
    assert!(
        include(
            &root,
            &root.join("missing"),
            &mut BTreeSet::new(),
            &mut paths
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn git_archive_rejects_escaping_symlinks_even_outside_the_selected_closure() -> Result<()> {
    let root = tempdir()?;
    let output = tempdir()?;
    let revision = fixture(root.path())?;
    assert!(!revision.is_empty());
    symlink("../../outside", root.path().join("unused"))?;
    git(root.path(), &["add", "."])?;
    git(
        root.path(),
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "Escaping link",
        ],
    )?;
    let revision = git(root.path(), &["rev-parse", "HEAD"])?;
    let destination = output.path().join("retained");
    assert!(
        freeze_sources(root.path(), args(&revision, &destination))
            .unwrap_err()
            .to_string()
            .contains("escapes")
    );
    assert!(!destination.exists());
    Ok(())
}
