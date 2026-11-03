use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use clap::Args;
use flate2::read::GzDecoder;
use serde::Deserialize;
use serde_json::Value;
use tar::Archive;
use tempfile::tempdir;

use crate::container::sha256;
use crate::execution_definition::resolve;

#[derive(Args, Default)]
pub struct VendorArgs {
    #[arg(long, conflicts_with = "apply")]
    pub refresh_patches: bool,
    #[arg(long)]
    pub apply: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    pub name: String,
    pub version: String,
    pub archive_sha256: String,
    upstream_git: Value,
    vendor_directory: String,
    patch: String,
}

pub(super) fn sources(root: &Path) -> Result<Vec<Source>> {
    let entries: Vec<Source> =
        serde_json::from_slice(&fs::read(root.join("tools/native-crypto/sources.json"))?)?;
    for entry in &entries {
        for value in [
            &entry.name,
            &entry.version,
            &entry.vendor_directory,
            &entry.patch,
        ] {
            ensure!(
                !value.is_empty()
                    && Path::new(value)
                        .components()
                        .all(|p| matches!(p, Component::Normal(_)))
                    && Path::new(value).components().count() == 1,
                "invalid native vendor configuration path"
            );
        }
        ensure!(
            entry.upstream_git.is_object(),
            "missing upstream provenance"
        );
    }
    Ok(entries)
}

pub(super) fn archive(entry: &Source, destination: &Path) -> Result<PathBuf> {
    let name = format!("{}-{}", entry.name, entry.version);
    let filename = format!("{name}.crate");
    let cargo = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|p| PathBuf::from(p).join(".cargo")))
        .context("Cargo home unavailable")?;
    let cache = cargo.join("registry/cache");
    let cached = if cache.is_dir() {
        fs::read_dir(cache)?
            .filter_map(|item| item.ok().map(|i| i.path().join(&filename)))
            .find(|p| p.is_file())
    } else {
        None
    };
    let path = destination.join(&filename);
    if let Some(cached) = cached {
        fs::copy(cached, &path)?;
    } else {
        let result = Command::new("curl")
            .args(["--fail", "--location", "--max-time", "60", "--output"])
            .arg(&path)
            .arg(format!(
                "https://static.crates.io/crates/{}/{filename}",
                entry.name
            ))
            .status()?;
        ensure!(result.success(), "download native crate archive failed");
    }
    ensure!(
        sha256(&path)? == entry.archive_sha256,
        "{filename}: archive SHA256 mismatch"
    );
    extract(&path, destination, &name)?;
    Ok(destination.join(name))
}

fn extract(path: &Path, destination: &Path, prefix: &str) -> Result<()> {
    let root = destination.canonicalize()?;
    let mut archive = Archive::new(GzDecoder::new(File::open(path)?));
    archive.set_mask(0o022);
    for member in archive.entries()? {
        let mut member = member?;
        let path = member.path()?.into_owned();
        ensure!(
            path.components()
                .all(|part| matches!(part, Component::Normal(_)))
                && path.starts_with(prefix),
            "vendor archive path escapes package"
        );
        let kind = member.header().entry_type();
        ensure!(
            kind.is_file() || kind.is_dir() || kind.is_symlink(),
            "unsupported vendor archive entry"
        );
        if kind.is_symlink() {
            let target = member.link_name()?.context("missing symlink target")?;
            ensure!(!target.is_absolute(), "absolute vendor symlink");
            ensure!(
                resolve(&root.join(&path).parent().unwrap().join(&target))?
                    .starts_with(root.join(prefix)),
                "vendor symlink escapes package"
            );
        }
        ensure!(
            member.unpack_in(&root)?,
            "vendor archive entry escaped root"
        );
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    bytes: Vec<u8>,
    executable: bool,
    link: Option<PathBuf>,
}

fn files(root: &Path) -> Result<BTreeMap<PathBuf, Entry>> {
    fn walk(root: &Path, directory: &Path, entries: &mut BTreeMap<PathBuf, Entry>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                walk(root, &path, entries)?;
                continue;
            }
            ensure!(
                metadata.is_file() || metadata.file_type().is_symlink(),
                "unsupported vendor file type"
            );
            let link = metadata
                .file_type()
                .is_symlink()
                .then(|| fs::read_link(&path))
                .transpose()?;
            if link.is_some() {
                ensure!(
                    path.canonicalize()?.starts_with(root),
                    "vendor symlink escapes tree"
                );
            }
            let entry = Entry {
                bytes: fs::read(&path)?,
                executable: fs::metadata(&path)?.permissions().mode() & 0o111 != 0,
                link,
            };
            entries.insert(path.strip_prefix(root)?.to_owned(), entry);
        }
        Ok(())
    }
    let root = root.canonicalize()?;
    let mut entries = BTreeMap::new();
    walk(&root, &root, &mut entries)?;
    Ok(entries)
}

fn patch(pristine: &Path, vendor: &Path) -> Result<Vec<u8>> {
    let before = files(pristine)?;
    let after = files(vendor)?;
    let mut output = Vec::new();
    for name in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
        let old = before.get(name);
        let new = after.get(name);
        if old.map(|v| &v.bytes) == new.map(|v| &v.bytes) {
            continue;
        }
        for entry in [old, new].into_iter().flatten() {
            ensure!(
                !entry.bytes.contains(&0),
                "unexpected binary vendor change: {}",
                name.display()
            );
            std::str::from_utf8(&entry.bytes)?;
        }
        let old_path = if old.is_some() {
            pristine.join(name)
        } else {
            PathBuf::from("/dev/null")
        };
        let new_path = if new.is_some() {
            vendor.join(name)
        } else {
            PathBuf::from("/dev/null")
        };
        let result = Command::new("diff")
            .args(["-u", "-L"])
            .arg(if old.is_some() {
                format!("a/{}", name.display())
            } else {
                "/dev/null".into()
            })
            .arg("-L")
            .arg(if new.is_some() {
                format!("b/{}", name.display())
            } else {
                "/dev/null".into()
            })
            .arg(old_path)
            .arg(new_path)
            .output()?;
        ensure!(
            matches!(result.status.code(), Some(0 | 1)),
            "vendor diff failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        output.extend(result.stdout);
    }
    Ok(output)
}

fn apply_patch(pristine: &Path, patch: &Path) -> Result<()> {
    if fs::metadata(patch)?.len() != 0 {
        let output = Command::new("git")
            .args(["apply", "--whitespace=error"])
            .arg(patch)
            .current_dir(pristine)
            .output()?;
        ensure!(
            output.status.success(),
            "apply vendor patch: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn replace_files(pristine: &Path, vendor: &Path) -> Result<()> {
    let expected = files(pristine)?;
    fs::create_dir_all(vendor)?;
    let actual = files(vendor)?;
    for (name, entry) in &expected {
        let destination = vendor.join(name);
        fs::create_dir_all(destination.parent().context("vendor parent")?)?;
        if destination.symlink_metadata().is_ok() {
            fs::remove_file(&destination)?;
        }
        if let Some(target) = &entry.link {
            symlink(target, &destination)?;
        } else {
            fs::copy(pristine.join(name), &destination)?;
        }
    }
    for name in actual.keys().filter(|name| !expected.contains_key(*name)) {
        fs::remove_file(vendor.join(name))?;
    }
    Ok(())
}

pub fn verify(root: &Path, args: VendorArgs) -> Result<String> {
    ensure!(
        !(args.apply && args.refresh_patches),
        "refresh and apply are mutually exclusive"
    );
    let root = root.canonicalize()?;
    let patches = root.join("tools/native-crypto/patches");
    fs::create_dir_all(&patches)?;
    let mut report = String::new();
    for entry in sources(&root)? {
        let temporary = tempdir()?;
        let pristine = archive(&entry, temporary.path())?;
        let vendor = root.join("core/vendor").join(&entry.vendor_directory);
        let patch_path = patches.join(&entry.patch);
        ensure!(
            resolve(&vendor)?.starts_with(&root) && resolve(&patch_path)?.starts_with(&root),
            "vendor or patch path escapes checkout"
        );
        if args.refresh_patches {
            fs::write(&patch_path, patch(&pristine, &vendor)?)?;
        }
        apply_patch(&pristine, &patch_path)?;
        if args.apply {
            replace_files(&pristine, &vendor)?;
        }
        let expected = files(&pristine)?;
        let actual = files(&vendor)?;
        ensure!(
            expected == actual,
            "{}: vendor differs from pristine plus patch (bytes, type or executable mode)",
            entry.name
        );
        report.push_str(&format!(
            "{} {}: source digest and patched tree verified\n",
            entry.name, entry.version
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests;
