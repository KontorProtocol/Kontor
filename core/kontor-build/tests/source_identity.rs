#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Result;
use flate2::Compression;
use flate2::write::{GzEncoder, ZlibEncoder};
use kontor_build::source_identity::{
    Metadata, verify_git_tree, verify_registry_tree, verify_sources,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tar::{Builder, EntryType, Header};
use tempfile::{TempDir, tempdir};

fn git(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-C",
        ])
        .arg(root)
        .args(args)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn commit(root: &Path) -> Result<String> {
    git(root, &["add", "."])?;
    git(root, &["commit", "-qm", "Fixture"])?;
    git(root, &["rev-parse", "HEAD"])
}

fn fails(result: Result<Value>, expected: &str) {
    let error = format!("{:#}", result.unwrap_err());
    assert!(
        error.contains(expected),
        "{error:?} did not contain {expected:?}"
    );
}

struct GitFixture {
    _temporary: TempDir,
    root: PathBuf,
    revision: String,
}

impl GitFixture {
    fn new(format: &str) -> Result<Self> {
        let temporary = tempdir()?;
        let root = temporary.path().join("repo");
        fs::create_dir(&root)?;
        git(&root, &["init", "-q", &format!("--object-format={format}")])?;
        fs::write(root.join("lib.rs"), "original")?;
        fs::write(root.join(".gitignore"), "ignored\n")?;
        fs::create_dir(root.join("nested"))?;
        fs::write(root.join("nested/child.rs"), "child")?;
        let revision = commit(&root)?;
        Ok(Self {
            _temporary: temporary,
            root,
            revision,
        })
    }

    fn verify(&self) -> Result<Value> {
        verify_git_tree(&self.root, &self.revision)
    }

    fn corrupt(&self, identity: &str, kind: &str, data: &[u8]) -> Result<()> {
        let path = self
            .root
            .join(".git/objects")
            .join(&identity[..2])
            .join(&identity[2..]);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        let mut compressed = ZlibEncoder::new(Vec::new(), Compression::default());
        compressed.write_all(format!("{kind} {}\0", data.len()).as_bytes())?;
        compressed.write_all(data)?;
        fs::write(path, compressed.finish()?)?;
        Ok(())
    }
}

#[test]
fn git_checks_both_object_formats_and_raw_paths() -> Result<()> {
    for format in ["sha1", "sha256"] {
        let mut f = GitFixture::new(format)?;
        fs::write(
            f.root.join(OsString::from_vec(b"raw-\xff.rs".to_vec())),
            "raw",
        )?;
        fs::write(f.root.join("new\nline.rs"), "newline")?;
        f.revision = commit(&f.root)?;
        fs::write(f.root.join(".cargo-ok"), "")?;
        assert_eq!(
            f.verify()?,
            json!({"revision": f.revision, "files": 5, "submodules": {}})
        );
        fails(
            verify_git_tree(&f.root, "--help"),
            "invalid pinned Git revision",
        );
        fails(
            verify_git_tree(&f.root, &"0".repeat(f.revision.len())),
            "revision mismatch",
        );
    }
    Ok(())
}

#[test]
fn git_rejects_ignored_files_false_markers_and_modes() -> Result<()> {
    let f = GitFixture::new("sha1")?;
    for name in ["ignored", "extra.rs", ".cargo-ok", "nested/extra.rs"] {
        fs::write(f.root.join(name), "extra")?;
        fails(f.verify(), "unexpected source input");
        fs::remove_file(f.root.join(name))?;
    }
    fs::set_permissions(f.root.join("lib.rs"), fs::Permissions::from_mode(0o755))?;
    fails(f.verify(), "Git source differs");
    Ok(())
}

#[test]
fn git_does_not_trust_index_flags_or_staging() -> Result<()> {
    let f = GitFixture::new("sha1")?;
    git(&f.root, &["update-index", "--assume-unchanged", "lib.rs"])?;
    fs::write(f.root.join("lib.rs"), "changed")?;
    fails(f.verify(), "Git source differs");
    git(
        &f.root,
        &["update-index", "--no-assume-unchanged", "lib.rs"],
    )?;
    git(&f.root, &["add", "lib.rs"])?;
    fs::write(f.root.join("lib.rs"), "original")?;
    fails(f.verify(), "Git index differs");
    Ok(())
}

#[test]
fn git_replacement_refs_and_grafts_cannot_rewrite_pins() -> Result<()> {
    let f = GitFixture::new("sha1")?;
    fs::write(f.root.join("lib.rs"), "replacement")?;
    let replacement = commit(&f.root)?;
    git(&f.root, &["replace", &f.revision, &replacement])?;
    git(&f.root, &["reset", "--hard", &f.revision])?;
    fails(f.verify(), "Git index differs");
    git(&f.root, &["replace", "-d", &f.revision])?;
    git(&f.root, &["reset", "--hard", &f.revision])?;
    fs::write(f.root.join(".git/info/grafts"), format!("{}\n", f.revision))?;
    fails(f.verify(), "grafts are not permitted");
    Ok(())
}

#[test]
fn git_rehashes_commit_and_nested_tree_objects() -> Result<()> {
    let f = GitFixture::new("sha1")?;
    let data = git(&f.root, &["cat-file", "commit", &f.revision])? + "\nmodified\n";
    f.corrupt(&f.revision, "commit", data.as_bytes())?;
    fails(f.verify(), "Git commit object differs");
    for path in ["HEAD^{tree}", "HEAD:nested"] {
        let f = GitFixture::new("sha1")?;
        let identity = git(&f.root, &["rev-parse", path])?;
        let mut data = Command::new("git")
            .arg("-C")
            .arg(&f.root)
            .args(["cat-file", "tree", &identity])
            .output()?
            .stdout;
        // Relabel the entry without changing its size or its referenced object.
        let position = data.iter().position(|byte| *byte == b' ').unwrap() + 1;
        data[position] = b'X';
        f.corrupt(&identity, "tree", &data)?;
        let error = format!("{:#}", f.verify().unwrap_err());
        assert!(
            error.contains("Git tree object differs") || error.contains("hash mismatch"),
            "{error}"
        );
    }
    Ok(())
}

#[test]
fn git_checks_symlinks_without_reading_their_targets() -> Result<()> {
    let mut f = GitFixture::new("sha1")?;
    let path = f.root.join("link.rs");
    symlink("missing.rs", &path)?;
    f.revision = commit(&f.root)?;
    f.verify()?;
    fs::remove_file(&path)?;
    symlink("lib.rs", &path)?;
    fails(f.verify(), "Git source differs");
    Ok(())
}

#[test]
fn git_checks_submodule_contents_and_revision() -> Result<()> {
    let mut f = GitFixture::new("sha1")?;
    let child = GitFixture::new("sha1")?;
    git(
        &f.root,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            child.root.to_str().unwrap(),
            "module",
        ],
    )?;
    f.revision = commit(&f.root)?;
    let module = f.root.join("module");
    fs::write(module.join(".cargo-ok"), "")?;
    assert_eq!(
        f.verify()?["submodules"]["module"]["revision"],
        child.revision
    );
    fs::write(module.join("lib.rs"), "changed")?;
    fails(f.verify(), "Git source differs");
    commit(&module)?;
    // Some Git versions also flag the changed gitlink in the parent's index check.
    assert!(f.verify().is_err());
    Ok(())
}

struct RegistryFixture {
    _temporary: TempDir,
    directory: PathBuf,
    archive: PathBuf,
    checksum: String,
}

impl RegistryFixture {
    fn new() -> Result<Self> {
        let temporary = tempdir()?;
        let directory = temporary.path().join("src/index/example-1.0.0");
        fs::create_dir_all(&directory)?;
        let archive = temporary.path().join("cache/index/example-1.0.0.crate");
        fs::create_dir_all(archive.parent().unwrap())?;
        let mut f = Self {
            _temporary: temporary,
            directory,
            archive,
            checksum: String::new(),
        };
        f.pack(&[(
            "example-1.0.0/lib.rs",
            b"original",
            0o644,
            EntryType::Regular,
        )])?;
        fs::write(f.directory.join("lib.rs"), "original")?;
        fs::write(f.directory.join(".cargo-ok"), "{\"v\":1}")?;
        Ok(f)
    }

    fn pack(&mut self, entries: &[(&str, &[u8], u32, EntryType)]) -> Result<()> {
        let mut builder = Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (path, data, mode, kind) in entries {
            let mut header = Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(*mode);
            header.set_entry_type(*kind);
            // Raw names deliberately allow invalid paths for rejection tests.
            header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
            header.set_cksum();
            builder.append(&header, *data)?;
        }
        let data = builder.into_inner()?.finish()?;
        self.checksum = hex::encode(Sha256::digest(&data));
        fs::write(&self.archive, data)?;
        Ok(())
    }

    fn verify(&self) -> Result<Value> {
        verify_registry_tree(&self.directory, &self.checksum)
    }
}

#[test]
fn registry_archive_and_extracted_manifest_bind_bytes_and_modes() -> Result<()> {
    let f = RegistryFixture::new()?;
    assert_eq!(
        f.verify()?,
        json!({"archive_sha256": f.checksum, "files": 1})
    );
    let manifest = json!({"files": {"lib.rs": hex::encode(Sha256::digest(b"original"))}, "package": f.checksum});
    fs::write(
        f.directory.join(".cargo-checksum.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    f.verify()?;
    fs::write(f.directory.join("lib.rs"), "changed")?;
    fails(f.verify(), "registry source differs");
    fs::write(f.directory.join("lib.rs"), "original")?;
    fs::set_permissions(
        f.directory.join("lib.rs"),
        fs::Permissions::from_mode(0o755),
    )?;
    fails(f.verify(), "registry source differs");
    fs::set_permissions(
        f.directory.join("lib.rs"),
        fs::Permissions::from_mode(0o644),
    )?;
    fs::write(f.directory.join(".cargo-checksum.json"), "{}")?;
    fails(f.verify(), "extracted checksum manifest differs");
    fs::write(&f.archive, "substituted archive")?;
    fails(f.verify(), "archive checksum differs");
    Ok(())
}

#[test]
fn registry_rejects_extra_files_markers_and_symlink_substitution() -> Result<()> {
    let f = RegistryFixture::new()?;
    for name in ["extra.rs", ".cargo-ok"] {
        fs::write(f.directory.join(name), "extra")?;
        fails(f.verify(), "unexpected source input");
        fs::remove_file(f.directory.join(name))?;
    }
    let outside = f._temporary.path().join("outside");
    fs::write(&outside, "original")?;
    fs::remove_file(f.directory.join("lib.rs"))?;
    symlink(outside, f.directory.join("lib.rs"))?;
    fails(f.verify(), "registry source differs");
    Ok(())
}

#[test]
fn registry_rejects_paths_links_and_duplicate_entries() -> Result<()> {
    let mut f = RegistryFixture::new()?;
    for path in [
        "/example-1.0.0/lib.rs",
        "wrong/lib.rs",
        "example-1.0.0/../lib.rs",
        "example-1.0.0",
    ] {
        f.pack(&[(path, b"original", 0o644, EntryType::Regular)])?;
        assert!(f.verify().is_err(), "accepted {path}");
    }
    for kind in [EntryType::Symlink, EntryType::Link, EntryType::Fifo] {
        f.pack(&[("example-1.0.0/lib.rs", b"original", 0o644, kind)])?;
        fails(f.verify(), "unexpected registry archive entry");
    }
    f.pack(&[
        (
            "example-1.0.0/lib.rs",
            b"original",
            0o644,
            EntryType::Regular,
        ),
        (
            "./example-1.0.0//lib.rs",
            b"original",
            0o644,
            EntryType::Regular,
        ),
    ])?;
    fails(f.verify(), "duplicate registry archive entry");
    Ok(())
}

#[test]
fn registry_rejects_unsupported_global_archive_metadata() -> Result<()> {
    let mut f = RegistryFixture::new()?;
    f.pack(&[
        (
            "example-1.0.0/PaxHeaders",
            b"13 comment=x\n",
            0o644,
            EntryType::new(b'g'),
        ),
        (
            "example-1.0.0/lib.rs",
            b"original",
            0o644,
            EntryType::Regular,
        ),
    ])?;
    fails(f.verify(), "unexpected registry archive entry");
    Ok(())
}

#[test]
fn metadata_uses_lock_checksums_and_deduplicates_git_roots() -> Result<()> {
    let f = GitFixture::new("sha1")?;
    let r = RegistryFixture::new()?;
    let source = format!("git+https://example.invalid/repo#{}", f.revision);
    fs::write(
        f.root.join("Cargo.lock"),
        format!(
            "[[package]]\nname = 'example'\nversion = '1.0.0'\nsource = 'registry+https://example.invalid/index'\nchecksum = '{}'\n",
            r.checksum
        ),
    )?;
    // Keep the metadata workspace independent from the verified Git checkout.
    let workspace = tempdir()?;
    fs::rename(
        f.root.join("Cargo.lock"),
        workspace.path().join("Cargo.lock"),
    )?;
    let mut data = json!({"workspace_root": workspace.path(), "packages": [
        {"id": "git-root", "name": "root", "version": "0.1.0", "source": source, "manifest_path": f.root.join("Cargo.toml")},
        {"id": "git-child", "name": "child", "version": "0.1.0", "source": source, "manifest_path": f.root.join("nested/Cargo.toml")},
        {"id": "registry", "name": "example", "version": "1.0.0", "source": "registry+https://example.invalid/index", "manifest_path": r.directory.join("Cargo.toml")},
        {"id": "local", "name": "local", "version": "0.1.0", "source": null, "manifest_path": workspace.path().join("Cargo.toml")}
    ]});
    let verify = |data: &Value| -> Result<Value> {
        let metadata: Metadata = serde_json::from_value(data.clone())?;
        verify_sources(&metadata)
    };
    let result = verify(&data)?;
    assert_eq!(result["git"].as_object().unwrap().len(), 1);
    assert_eq!(result["registry"]["registry"]["files"], 1);
    let mut cli = Command::new(env!("CARGO_BIN_EXE_kontor-build"))
        .arg("verify-sources")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    cli.stdin
        .take()
        .unwrap()
        .write_all(data.to_string().as_bytes())?;
    let output = cli.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(serde_json::from_slice::<Value>(&output.stdout)?, result);
    data["packages"][1]["source"] = json!(format!(
        "git+https://example.invalid/repo#{}",
        "0".repeat(40)
    ));
    fails(verify(&data), "conflicting Git revisions");
    data["packages"][1]["source"] = json!(source);
    fs::write(workspace.path().join("Cargo.lock"), "package = []\n")?;
    fails(verify(&data), "missing locked registry checksum");
    Ok(())
}
