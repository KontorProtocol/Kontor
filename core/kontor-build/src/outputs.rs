use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

pub fn files(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                visit(root, &entry.path(), out)?;
            } else if kind.is_file() {
                out.insert(
                    entry.path().strip_prefix(root)?.into(),
                    fs::read(entry.path())?,
                );
            } else {
                bail!("unexpected generated output: {}", entry.path().display());
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out)?;
    Ok(out)
}

pub fn differences(current: &Path, candidate: &Path) -> Result<Vec<String>> {
    let current = files(current)?;
    let candidate = files(candidate)?;
    let paths: BTreeSet<_> = current.keys().chain(candidate.keys()).collect();
    Ok(paths
        .into_iter()
        .filter_map(|path| {
            let label = match (current.get(path), candidate.get(path)) {
                (None, Some(_)) => "added",
                (Some(_), None) => "removed",
                (Some(a), Some(b)) if a != b => "changed",
                _ => return None,
            };
            Some(format!("{label}: {}", path.display()))
        })
        .collect())
}

// Keep backups until every replacement succeeds: SDK generation and contracts
// form one update even though their committed outputs live in different folders.
pub fn install(root: &Path, stage: &Path, paths: &[PathBuf], backup: &Path) -> Result<()> {
    if backup.exists() {
        bail!(
            "recovery backup exists at {}; restore it before building",
            backup.display()
        );
    }
    fs::create_dir_all(backup)?;
    let mut applied = Vec::new();
    let result = (|| -> Result<()> {
        for relative in paths {
            let destination = root.join(relative);
            let saved = backup.join(relative);
            let existed = destination.exists();
            fs::create_dir_all(saved.parent().context("backup parent")?)?;
            fs::create_dir_all(destination.parent().context("output parent")?)?;
            if existed {
                fs::rename(&destination, &saved)?;
            }
            applied.push((relative, existed));
            fs::rename(stage.join(relative), destination)
                .with_context(|| format!("install {}", relative.display()))?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        for (relative, existed) in applied.into_iter().rev() {
            let destination = root.join(relative);
            remove(&destination)
                .with_context(|| format!("rollback failed; backups: {}", backup.display()))?;
            if existed {
                fs::rename(backup.join(relative), destination)
                    .with_context(|| format!("rollback failed; backups: {}", backup.display()))?;
            }
        }
        fs::remove_dir_all(backup)?;
        return Err(error);
    }
    fs::remove_dir_all(backup)?;
    Ok(())
}

fn remove(path: &Path) -> Result<()> {
    if path.is_dir() {
        fs::remove_dir_all(path)?;
    } else if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn check_detects_additions_deletions_and_nested_changes_without_writing() -> Result<()> {
        let dir = tempdir()?;
        let old = dir.path().join("old");
        let new = dir.path().join("new");
        fs::create_dir_all(old.join("interfaces"))?;
        fs::create_dir_all(new.join("interfaces"))?;
        fs::write(old.join("obsolete.wasm"), "old")?;
        fs::write(new.join("added.wasm"), "new")?;
        fs::write(old.join("interfaces/api.d.ts"), "before")?;
        fs::write(new.join("interfaces/api.d.ts"), "after")?;
        let before = files(&old)?;
        assert_eq!(
            differences(&old, &new)?,
            [
                "added: added.wasm",
                "changed: interfaces/api.d.ts",
                "removed: obsolete.wasm"
            ]
        );
        assert_eq!(files(&old)?, before);
        Ok(())
    }

    #[test]
    fn failed_later_install_restores_preexisting_and_removes_new_outputs() -> Result<()> {
        let dir = tempdir()?;
        let root = dir.path().join("repo");
        let stage = dir.path().join("stage");
        fs::create_dir_all(root.join("component"))?;
        fs::create_dir_all(stage.join("component"))?;
        fs::write(root.join("component/old"), "old bytes")?;
        fs::write(stage.join("component/new"), "new bytes")?;
        fs::write(stage.join("new-bindings"), "new bindings")?;
        let before = files(&root)?;
        let backup = dir.path().join("backup");
        assert!(
            install(
                &root,
                &stage,
                &["component".into(), "new-bindings".into(), "missing".into()],
                &backup
            )
            .is_err()
        );
        assert_eq!(files(&root)?, before);
        assert!(!backup.exists());
        Ok(())
    }

    #[test]
    fn successful_install_removes_obsolete_outputs() -> Result<()> {
        let dir = tempdir()?;
        let root = dir.path().join("repo");
        let stage = dir.path().join("stage");
        fs::create_dir_all(root.join("component"))?;
        fs::create_dir_all(stage.join("component"))?;
        fs::write(root.join("component/old"), "old")?;
        fs::write(stage.join("component/new"), "new")?;
        install(
            &root,
            &stage,
            &["component".into()],
            &dir.path().join("backup"),
        )?;
        assert!(!root.join("component/old").exists());
        assert_eq!(fs::read(root.join("component/new"))?, b"new");
        Ok(())
    }
}
