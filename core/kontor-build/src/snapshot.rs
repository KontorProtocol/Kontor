use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::container::sha256;

#[derive(Debug, Args)]
pub struct VerifySnapshotArgs {
    /// Directory containing snapshot.json, relative to the checkout root or absolute.
    pub root: PathBuf,
    /// SHA-256 of the trusted snapshot.json, from the selected build recipe.
    #[arg(long)]
    pub sha256: String,
}

pub fn verify_snapshot(root: &Path, expected: &str) -> Result<Value> {
    ensure!(
        expected.len() == 64
            && expected
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "expected inventory hash must be a lowercase SHA-256 digest"
    );
    let root = root
        .canonicalize()
        .context("resolve retained source root")?;
    let manifest = root.join("snapshot.json");
    ensure!(
        fs::symlink_metadata(&manifest)?.file_type().is_file(),
        "retained source inventory must be a regular file"
    );
    // Parse the same bytes that were authenticated, not a second read that
    // could observe a replaced inventory.
    let bytes = fs::read(&manifest)?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == expected,
        "retained source inventory changed"
    );
    let record: Value =
        serde_json::from_slice(&bytes).context("parse retained source inventory")?;
    let mut files = Map::new();
    inventory(&root, &root, &mut files)?;
    ensure!(
        !files.is_empty() && record.get("files") == Some(&Value::Object(files)),
        "retained source files differ from frozen inventory"
    );
    Ok(record)
}

fn inventory(root: &Path, directory: &Path, files: &mut Map<String, Value>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path == root.join("snapshot.json") {
            continue;
        }
        ensure!(
            path.canonicalize()?.starts_with(root),
            "retained source escapes its root: {}",
            path.display()
        );
        let relative = path
            .strip_prefix(root)?
            .components()
            .map(|part| {
                part.as_os_str()
                    .to_str()
                    .context("retained source path is not UTF-8")
            })
            .collect::<Result<Vec<_>>>()?
            .join("/");
        let kind = fs::symlink_metadata(&path)?.file_type();
        if kind.is_symlink() {
            // Record the link itself. Its in-root target is visited at its own
            // location, so directory links are never recursively traversed.
            let target = fs::read_link(&path)?;
            let target = target.to_str().context("retained symlink is not UTF-8")?;
            files.insert(relative, json!({"symlink": normalized_link(target)}));
        } else if kind.is_file() {
            files.insert(relative, json!({"sha256": sha256(&path)?}));
        } else if kind.is_dir() {
            inventory(root, &path, files)?;
        } else {
            bail!("unsupported retained source entry: {}", path.display());
        }
    }
    Ok(())
}

pub(crate) fn normalized_link(target: &str) -> String {
    // Existing inventories use pathlib's lexical POSIX spelling. Preserve
    // parent components and exactly two leading slashes; do not resolve links.
    let prefix = if target.starts_with("//") && !target.starts_with("///") {
        "//"
    } else if target.starts_with('/') {
        "/"
    } else {
        ""
    };
    let parts = target
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/");
    let result = format!("{prefix}{parts}");
    if result.is_empty() {
        ".".into()
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use anyhow::Result;
    use serde_json::{Value, json};
    use tempfile::tempdir;

    use super::{normalized_link, verify_snapshot};
    use crate::container::sha256;

    fn manifest(root: &Path, files: Value) -> Result<String> {
        let path = root.join("snapshot.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({"files": files, "source_commit": "fixture"}))?,
        )?;
        sha256(&path)
    }

    #[test]
    fn inventory_is_relocatable_and_returns_authenticated_metadata() -> Result<()> {
        let first = tempdir()?;
        let second = tempdir()?;
        fs::create_dir(first.path().join("src"))?;
        fs::create_dir(second.path().join("src"))?;
        for root in [first.path(), second.path()] {
            fs::write(root.join("src/lib.rs"), b"retained code")?;
        }
        let files = json!({"src/lib.rs": {"sha256": sha256(&first.path().join("src/lib.rs"))?}});
        let expected = manifest(first.path(), files)?;
        fs::copy(
            first.path().join("snapshot.json"),
            second.path().join("snapshot.json"),
        )?;
        let record = verify_snapshot(first.path(), &expected)?;
        assert_eq!(record["source_commit"], "fixture");
        assert_eq!(record, verify_snapshot(second.path(), &expected)?);
        Ok(())
    }

    #[test]
    fn changed_missing_and_added_files_are_rejected() -> Result<()> {
        let root = tempdir()?;
        let source = root.path().join("lib.rs");
        fs::write(&source, b"original")?;
        let expected = manifest(root.path(), json!({"lib.rs": {"sha256": sha256(&source)?}}))?;
        verify_snapshot(root.path(), &expected)?;
        fs::write(&source, b"changed")?;
        assert!(verify_snapshot(root.path(), &expected).is_err());
        fs::remove_file(&source)?;
        assert!(verify_snapshot(root.path(), &expected).is_err());
        fs::write(&source, b"original")?;
        fs::write(root.path().join("extra"), b"unrecorded")?;
        assert!(verify_snapshot(root.path(), &expected).is_err());
        Ok(())
    }

    #[test]
    fn substituted_empty_and_malformed_inventories_are_rejected() -> Result<()> {
        let root = tempdir()?;
        let source = root.path().join("lib.rs");
        fs::write(&source, b"original")?;
        let expected = manifest(root.path(), json!({"lib.rs": {"sha256": sha256(&source)?}}))?;
        let empty = manifest(root.path(), json!({}))?;
        assert!(verify_snapshot(root.path(), &expected).is_err());
        assert!(verify_snapshot(root.path(), &empty).is_err());
        fs::remove_file(source)?;
        assert!(verify_snapshot(root.path(), &empty).is_err());
        let path = root.path().join("snapshot.json");
        fs::write(&path, b"{")?;
        assert!(verify_snapshot(root.path(), &sha256(&path)?).is_err());
        assert!(verify_snapshot(root.path(), "untrusted hash").is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn backslash_in_a_filename_is_not_a_directory_separator() -> Result<()> {
        let root = tempdir()?;
        let source = root.path().join("directory\\file.rs");
        fs::write(&source, b"original")?;
        let expected = manifest(
            root.path(),
            json!({"directory\\file.rs": {"sha256": sha256(&source)?}}),
        )?;
        verify_snapshot(root.path(), &expected)?;
        let incorrect = manifest(
            root.path(),
            json!({"directory/file.rs": {"sha256": sha256(&source)?}}),
        )?;
        assert!(verify_snapshot(root.path(), &incorrect).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn links_are_bound_without_traversing_directories() -> Result<()> {
        let root = tempdir()?;
        let source = root.path().join("lib.rs");
        fs::write(&source, b"original")?;
        symlink("lib.rs", root.path().join("alias"))?;
        symlink(".", root.path().join("loop"))?;
        let expected = manifest(
            root.path(),
            json!({
                "lib.rs": {"sha256": sha256(&source)?},
                "alias": {"symlink": "lib.rs"}, "loop": {"symlink": "."}
            }),
        )?;
        verify_snapshot(root.path(), &expected)?;
        fs::remove_file(root.path().join("alias"))?;
        symlink("./lib.rs", root.path().join("alias"))?;
        verify_snapshot(root.path(), &expected)?;
        fs::remove_file(root.path().join("alias"))?;
        symlink("loop", root.path().join("alias"))?;
        assert!(verify_snapshot(root.path(), &expected).is_err());
        fs::remove_file(root.path().join("alias"))?;
        symlink("missing", root.path().join("alias"))?;
        assert!(verify_snapshot(root.path(), &expected).is_err());
        Ok(())
    }

    #[test]
    fn link_spelling_matches_the_existing_inventory_format() {
        for (input, expected) in [
            ("./lib.rs", "lib.rs"),
            ("a//./b/../c", "a/b/../c"),
            ("//root//file", "//root/file"),
            ("///root/file", "/root/file"),
            ("./.", "."),
            ("name\\part", "name\\part"),
        ] {
            assert_eq!(normalized_link(input), expected);
        }
    }

    #[cfg(unix)]
    #[test]
    fn escaping_links_and_symlinked_inventory_are_rejected() -> Result<()> {
        let root = tempdir()?;
        let outside = tempdir()?;
        fs::write(outside.path().join("lib.rs"), b"outside")?;
        let alias = root.path().join("alias");
        symlink(outside.path().join("lib.rs"), &alias)?;
        let expected = manifest(
            root.path(),
            json!({"alias": {
                "symlink": outside.path().join("lib.rs").to_str().unwrap()
            }}),
        )?;
        assert!(verify_snapshot(root.path(), &expected).is_err());
        fs::remove_file(alias)?;
        let path = root.path().join("snapshot.json");
        fs::rename(&path, outside.path().join("snapshot.json"))?;
        symlink(outside.path().join("snapshot.json"), path)?;
        assert!(verify_snapshot(root.path(), &expected).is_err());
        Ok(())
    }
}
