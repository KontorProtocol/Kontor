use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use anyhow::{Context, Result, bail, ensure};
use flate2::read::GzDecoder;
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest, Sha256};
use tar::Archive;

#[derive(Deserialize)]
pub struct Metadata {
    workspace_root: PathBuf,
    pub(crate) packages: Vec<Package>,
}

#[derive(Deserialize)]
pub(crate) struct Package {
    name: String,
    version: String,
    pub(crate) source: Option<String>,
    pub(crate) manifest_path: PathBuf,
    pub(crate) id: String,
}

#[derive(Deserialize)]
struct Lockfile {
    package: Vec<LockedPackage>,
}

#[derive(Deserialize)]
struct LockedPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

fn git_command(directory: &Path) -> Command {
    let mut command = Command::new("git");
    command.args(["--no-replace-objects", "-c", "core.fsmonitor=false", "-C"]);
    command.arg(directory);
    command
}

fn git(directory: &Path, args: &[&str], input: Option<Vec<u8>>) -> Result<Vec<u8>> {
    let mut command = git_command(directory);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = command.spawn().context("start Git source verification")?;
    // Large tree inventories and their objects can fill both pipes at once.
    let writer = input.map(|input| {
        let mut stdin = child.stdin.take().expect("piped Git stdin");
        thread::spawn(move || stdin.write_all(&input))
    });
    let output = child.wait_with_output()?;
    if let Some(writer) = writer {
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("Git input writer panicked"))??;
    }
    ensure!(
        output.status.success(),
        "Git source verification failed in {}: {}",
        directory.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

fn object_digest(algorithm: &str, kind: &str, data: &[u8]) -> Result<String> {
    let header = format!("{kind} {}\0", data.len());
    match algorithm {
        "sha1" => {
            let mut digest = Sha1::new();
            Sha1Digest::update(&mut digest, header.as_bytes());
            Sha1Digest::update(&mut digest, data);
            Ok(hex::encode(Sha1Digest::finalize(digest)))
        }
        "sha256" => {
            let mut digest = Sha256::new();
            Digest::update(&mut digest, header.as_bytes());
            Digest::update(&mut digest, data);
            Ok(hex::encode(Digest::finalize(digest)))
        }
        _ => bail!("unsupported Git object format: {algorithm}"),
    }
}

fn tree_entry(entry: &[u8]) -> Result<(&str, &str, &str, &Path)> {
    let tab = entry
        .iter()
        .position(|byte| *byte == b'\t')
        .context("invalid Git tree entry")?;
    let fields: Vec<_> = std::str::from_utf8(&entry[..tab])?
        .split_whitespace()
        .collect();
    ensure!(fields.len() == 3, "invalid Git tree header");
    let path = Path::new(OsStr::from_bytes(&entry[tab + 1..]));
    ensure!(
        !path.as_os_str().is_empty()
            && path
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "invalid Git source path"
    );
    Ok((fields[0], fields[1], fields[2], path))
}

fn verify_tree_objects(directory: &Path, revision: &str, algorithm: &str) -> Result<()> {
    let commit = git(directory, &["cat-file", "commit", revision], None)?;
    ensure!(
        object_digest(algorithm, "commit", &commit)? == revision,
        "pinned Git commit object differs: {}",
        directory.display()
    );
    let root = commit
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| line.strip_prefix(b"tree "))
        .context("missing pinned Git tree")?;
    let root = std::str::from_utf8(root)?;
    let entries = git(
        directory,
        &["ls-tree", "-r", "-t", "-z", "--full-tree", root],
        None,
    )?;
    let mut trees = BTreeSet::from([root.to_owned()]);
    for entry in entries
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let (_, kind, identity, _) = tree_entry(entry)?;
        if kind == "tree" {
            trees.insert(identity.to_owned());
        }
    }
    // Git does not consistently rehash stored objects when reading them.
    let requested = format!("{}\n", trees.iter().cloned().collect::<Vec<_>>().join("\n"));
    let output = git(
        directory,
        &["cat-file", "--batch"],
        Some(requested.into_bytes()),
    )?;
    let mut remaining = output.as_slice();
    for identity in trees {
        let end = remaining
            .iter()
            .position(|byte| *byte == b'\n')
            .context("missing Git object header")?;
        let fields: Vec<_> = std::str::from_utf8(&remaining[..end])?
            .split_whitespace()
            .collect();
        ensure!(fields.len() == 3, "invalid Git object response");
        let size: usize = fields[2].parse()?;
        let body = &remaining[end + 1..];
        ensure!(size < body.len(), "truncated Git object response");
        ensure!(
            fields[0] == identity
                && fields[1] == "tree"
                && body[size] == b'\n'
                && object_digest(algorithm, "tree", &body[..size])? == identity,
            "pinned Git tree object differs: {}: {identity}",
            directory.display()
        );
        remaining = &body[size + 1..];
    }
    ensure!(remaining.is_empty(), "unexpected Git object response");
    Ok(())
}

fn contents(path: &Path) -> Result<(&'static str, Vec<u8>)> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("read source {}", path.display()))?;
    if metadata.is_symlink() {
        Ok(("120000", fs::read_link(path)?.into_os_string().into_vec()))
    } else if metadata.is_file() {
        Ok((
            if metadata.permissions().mode() & 0o100 != 0 {
                "100755"
            } else {
                "100644"
            },
            fs::read(path)?,
        ))
    } else {
        bail!("unexpected source file type: {}", path.display())
    }
}

fn reject_extra_files(
    root: &Path,
    expected: &BTreeSet<PathBuf>,
    excluded: &BTreeSet<PathBuf>,
    markers: &BTreeMap<PathBuf, Vec<u8>>,
) -> Result<()> {
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(root)?;
            if excluded.contains(relative) {
                continue;
            }
            if entry.file_type()?.is_dir() {
                pending.push(path);
            } else if !expected.contains(relative) {
                if let Some(marker) = markers.get(relative) {
                    let (mode, data) = contents(&path)?;
                    if mode == "100644" && &data == marker {
                        continue;
                    }
                }
                bail!("unexpected source input: {}", path.display());
            }
        }
    }
    Ok(())
}

pub fn verify_git_tree(directory: &Path, revision: &str) -> Result<Value> {
    ensure!(
        matches!(revision.len(), 40 | 64)
            && revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid pinned Git revision: {revision}"
    );
    ensure!(
        directory.join(".git").exists(),
        "missing pinned Git checkout: {}",
        directory.display()
    );
    let actual = git(directory, &["rev-parse", "--verify", "HEAD"], None)?;
    ensure!(
        std::str::from_utf8(&actual)?.trim() == revision,
        "Git revision mismatch: {}",
        directory.display()
    );
    let raw = git(directory, &["rev-parse", "--git-path", "info/grafts"], None)?;
    let grafts = PathBuf::from(OsString::from_vec(
        raw.strip_suffix(b"\n").unwrap_or(&raw).to_vec(),
    ));
    let grafts = directory.join(grafts);
    ensure!(
        !grafts.exists(),
        "Git grafts are not permitted: {}",
        grafts.display()
    );
    let algorithm = git(directory, &["rev-parse", "--show-object-format"], None)?;
    let algorithm = std::str::from_utf8(&algorithm)?.trim();
    verify_tree_objects(directory, revision, algorithm)?;
    let status = git_command(directory)
        .args([
            "diff",
            "--cached",
            "--quiet",
            "--no-ext-diff",
            "--no-textconv",
            revision,
            "--",
        ])
        .status()?;
    ensure!(
        status.success(),
        "pinned Git index differs: {}",
        directory.display()
    );
    let entries = git(
        directory,
        &["ls-tree", "-r", "-z", "--full-tree", revision],
        None,
    )?;
    let mut expected = BTreeSet::new();
    let mut submodules = BTreeMap::new();
    let mut excluded = BTreeSet::from([PathBuf::from(".git")]);
    for entry in entries
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let (mode, kind, identity, relative) = tree_entry(entry)?;
        let path = directory.join(relative);
        if mode == "160000" && kind == "commit" {
            let name = relative
                .to_str()
                .context("non-UTF8 submodule path cannot be represented in source evidence")?;
            submodules.insert(name.to_owned(), verify_git_tree(&path, identity)?);
            excluded.insert(relative.to_owned());
            continue;
        }
        ensure!(
            kind == "blob",
            "unexpected Git object type: {}",
            path.display()
        );
        let (actual_mode, data) = contents(&path)?;
        ensure!(
            actual_mode == mode && object_digest(algorithm, "blob", &data)? == identity,
            "pinned Git source differs: {}",
            path.display()
        );
        expected.insert(relative.to_owned());
    }
    reject_extra_files(
        directory,
        &expected,
        &excluded,
        &BTreeMap::from([(PathBuf::from(".cargo-ok"), Vec::new())]),
    )?;
    Ok(json!({"revision": revision, "files": expected.len(), "submodules": submodules}))
}

fn archive_relative(name: &[u8], prefix: &OsStr) -> Result<PathBuf> {
    ensure!(!name.starts_with(b"/"), "invalid registry archive path");
    let parts: Vec<_> = name
        .split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty() && *part != b".")
        .collect();
    ensure!(
        parts.first().copied() == Some(prefix.as_bytes()) && !parts.contains(&b"..".as_slice()),
        "invalid registry archive path: {}",
        String::from_utf8_lossy(name)
    );
    Ok(parts[1..]
        .iter()
        .map(|part| OsStr::from_bytes(part))
        .collect())
}

pub fn verify_registry_tree(directory: &Path, checksum: &str) -> Result<Value> {
    let index = directory.parent().context("registry index directory")?;
    let registry = index
        .parent()
        .and_then(Path::parent)
        .context("registry cache directory")?;
    let name = directory.file_name().context("registry package name")?;
    let mut archive_name = name.to_os_string();
    archive_name.push(".crate");
    let archive = registry
        .join("cache")
        .join(index.file_name().context("registry index name")?)
        .join(archive_name);
    let data = fs::read(&archive).with_context(|| {
        format!(
            "missing locked registry archive for source verification: {}",
            archive.display()
        )
    })?;
    ensure!(
        hex::encode(Sha256::digest(&data)) == checksum,
        "locked registry archive checksum differs: {}",
        archive.display()
    );
    let mut source = Archive::new(GzDecoder::new(data.as_slice()));
    let mut expected = BTreeMap::new();
    for member in source.entries()? {
        let mut member = member?;
        let relative = archive_relative(&member.path_bytes(), name)?;
        let kind = member.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        ensure!(
            (kind.is_file() || kind.as_byte() == b'7') && !relative.as_os_str().is_empty(),
            "unexpected registry archive entry"
        );
        ensure!(
            !expected.contains_key(&relative),
            "duplicate registry archive entry: {}",
            relative.display()
        );
        let mut archived = Vec::new();
        member.read_to_end(&mut archived)?;
        let (mode, current) = contents(&directory.join(&relative))?;
        let required_mode = if member.header().mode()? & 0o100 != 0 {
            "100755"
        } else {
            "100644"
        };
        ensure!(
            mode == required_mode && current == archived,
            "locked registry source differs: {}",
            directory.join(&relative).display()
        );
        expected.insert(relative, hex::encode(Sha256::digest(&archived)));
    }
    let mut markers = BTreeMap::from([(PathBuf::from(".cargo-ok"), b"{\"v\":1}".to_vec())]);
    let checksum_file = directory.join(".cargo-checksum.json");
    if checksum_file.exists() {
        let raw = fs::read(&checksum_file)?;
        let manifest: Value = serde_json::from_slice(&raw)?;
        let files = serde_json::to_value(&expected)
            .context("registry source paths must be UTF8 in checksum evidence")?;
        ensure!(
            manifest == json!({"files": files, "package": checksum}),
            "registry extracted checksum manifest differs: {}",
            checksum_file.display()
        );
        markers.insert(PathBuf::from(".cargo-checksum.json"), raw);
    }
    reject_extra_files(
        directory,
        &expected.keys().cloned().collect(),
        &BTreeSet::new(),
        &markers,
    )?;
    Ok(json!({"archive_sha256": checksum, "files": expected.len()}))
}

pub fn verify_sources(data: &Metadata) -> Result<Value> {
    let lock: Lockfile =
        toml::from_str(&fs::read_to_string(data.workspace_root.join("Cargo.lock"))?)?;
    let checksums: BTreeMap<_, _> = lock
        .package
        .into_iter()
        .map(|p| ((p.name, p.version, p.source), p.checksum))
        .collect();
    let mut registry = BTreeMap::new();
    let mut trees = BTreeMap::<PathBuf, Value>::new();
    for package in &data.packages {
        let source = package.source.as_deref().unwrap_or_default();
        let directory = package
            .manifest_path
            .parent()
            .context("package directory")?;
        if source.starts_with("registry+") {
            let key = (
                package.name.clone(),
                package.version.clone(),
                package.source.clone(),
            );
            let checksum = checksums
                .get(&key)
                .and_then(Option::as_deref)
                .context("missing locked registry checksum")?;
            registry.insert(&package.id, verify_registry_tree(directory, checksum)?);
        } else if source.starts_with("git+") {
            let checkout = directory
                .ancestors()
                .find(|parent| parent.join(".git").exists())
                .context("missing pinned Git source")?;
            let (_, revision) = source
                .rsplit_once('#')
                .context("missing pinned Git revision")?;
            if let Some(tree) = trees.get(checkout) {
                ensure!(
                    tree["revision"] == revision,
                    "conflicting Git revisions for {}",
                    checkout.display()
                );
            } else {
                trees.insert(checkout.to_owned(), verify_git_tree(checkout, revision)?);
            }
        }
    }
    Ok(json!({"git": trees, "registry": registry}))
}
