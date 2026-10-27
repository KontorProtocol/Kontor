"""Verify external source bytes against pinned Git objects or registry archives."""

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tomllib


def git(directory, *args):
    try:
        return subprocess.check_output(["git", "--no-replace-objects", "-c", "core.fsmonitor=false",
            "-C", str(directory), *args], stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"Git source verification failed in {directory}: {error.stderr.decode(errors='replace')}") from error


def object_digest(algorithm, kind, data):
    return hashlib.new(algorithm, kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()


def verify_tree_objects(directory, revision, algorithm):
    commit = git(directory, "cat-file", "commit", revision)
    if object_digest(algorithm, "commit", commit) != revision:
        raise RuntimeError(f"pinned Git commit object differs: {directory}")
    root = commit.split(b"\n", 1)[0]
    if not root.startswith(b"tree "):
        raise RuntimeError(f"missing pinned Git tree: {directory}")
    root = root.removeprefix(b"tree ").decode()
    entries = git(directory, "ls-tree", "-r", "-t", "-z", "--full-tree", root)
    trees = {root}
    for entry in entries.split(b"\0"):
        if entry:
            header = entry.split(b"\t", 1)[0].decode().split()
            if header[1] == "tree":
                trees.add(header[2])
    requested = sorted(trees)
    # Verify raw objects explicitly as well as working files. Whether Git itself
    # rehashes an object depends on the operation and Git version.
    output = subprocess.check_output(["git", "--no-replace-objects", "-c", "core.fsmonitor=false",
        "-C", str(directory), "cat-file", "--batch"], input=("\n".join(requested) + "\n").encode())
    position = 0
    for identity in requested:
        end = output.index(b"\n", position)
        reported, kind, size = output[position:end].decode().split()
        size = int(size)
        data = output[end + 1:end + 1 + size]
        position = end + 2 + size
        if reported != identity or kind != "tree" or object_digest(algorithm, kind, data) != identity:
            raise RuntimeError(f"pinned Git tree object differs: {directory}: {identity}")
    if position != len(output):
        raise RuntimeError(f"unexpected Git object response: {directory}")


def contents(path):
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        return "120000", os.fsencode(os.readlink(path))
    if stat.S_ISREG(mode):
        return "100755" if mode & stat.S_IXUSR else "100644", path.read_bytes()
    raise RuntimeError(f"unexpected source file type: {path}")


def reject_extra_files(directory, expected, excluded=(), markers=None):
    markers = markers or {}
    for parent, directories, files in os.walk(directory, followlinks=False):
        parent = Path(parent)
        for name in list(directories):
            path = parent / name
            relative = path.relative_to(directory).as_posix()
            if relative in excluded:
                directories.remove(name)
            elif path.is_symlink():
                directories.remove(name)
                files.append(name)
        for name in files:
            path = parent / name
            relative = path.relative_to(directory).as_posix()
            if relative in expected or relative in excluded:
                continue
            if relative in markers and contents(path) == ("100644", markers[relative]):
                continue
            raise RuntimeError(f"unexpected source input: {path}")


def verify_git_tree(directory, revision):
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise RuntimeError(f"invalid pinned Git revision: {revision}")
    if not (directory / ".git").exists():
        raise RuntimeError(f"missing pinned Git checkout: {directory}")
    actual = git(directory, "rev-parse", "--verify", "HEAD").decode().strip()
    if actual != revision:
        raise RuntimeError(f"Git revision mismatch: {directory}: {actual} != {revision}")
    grafts = Path(os.fsdecode(git(directory, "rev-parse", "--git-path", "info/grafts")).strip())
    if not grafts.is_absolute():
        grafts = directory / grafts
    if grafts.exists():
        raise RuntimeError(f"Git grafts are not permitted: {grafts}")
    algorithm = git(directory, "rev-parse", "--show-object-format").decode().strip()
    verify_tree_objects(directory, revision, algorithm)
    index = subprocess.run(["git", "--no-replace-objects", "-c", "core.fsmonitor=false", "-C", str(directory),
                            "diff", "--cached", "--quiet", "--no-ext-diff", "--no-textconv",
                            revision, "--"])
    if index.returncode:
        raise RuntimeError(f"pinned Git index differs: {directory}")
    expected = set()
    submodules = {}
    for entry in git(directory, "ls-tree", "-r", "-z", "--full-tree", revision).split(b"\0"):
        if not entry:
            continue
        header, raw_path = entry.split(b"\t", 1)
        mode, kind, identity = header.decode().split()
        relative = os.fsdecode(raw_path)
        path = directory / relative
        if mode == "160000" and kind == "commit":
            submodules[relative] = verify_git_tree(path, identity)
            continue
        if kind != "blob":
            raise RuntimeError(f"unexpected Git object type: {path}")
        actual_mode, data = contents(path)
        digest = object_digest(algorithm, "blob", data)
        if actual_mode != mode or digest != identity:
            raise RuntimeError(f"pinned Git source differs: {path}")
        expected.add(relative)
    # Cargo creates this empty administrative marker in each Git checkout,
    # including submodules. Git status alone reports those submodules dirty.
    reject_extra_files(directory, expected, excluded={".git", *submodules}, markers={".cargo-ok": b""})
    return {"revision": revision, "files": len(expected), "submodules": submodules}


def verify_registry_tree(directory, checksum):
    archive = directory.parents[2] / "cache" / directory.parent.name / (directory.name + ".crate")
    if not archive.is_file():
        raise RuntimeError(f"missing locked registry archive for source verification: {archive}")
    data = archive.read_bytes()
    if hashlib.sha256(data).hexdigest() != checksum:
        raise RuntimeError(f"locked registry archive checksum differs: {archive}")
    expected = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as source:
        for member in source:
            parts = PurePosixPath(member.name).parts
            if not parts or parts[0] != directory.name or ".." in parts:
                raise RuntimeError(f"invalid registry archive path: {member.name}")
            if member.isdir():
                continue
            if not member.isfile() or len(parts) < 2:
                raise RuntimeError(f"unexpected registry archive entry: {member.name}")
            relative = PurePosixPath(*parts[1:]).as_posix()
            if relative in expected:
                raise RuntimeError(f"duplicate registry archive entry: {member.name}")
            archived = source.extractfile(member).read()
            mode, current = contents(directory / relative)
            required_mode = "100755" if member.mode & stat.S_IXUSR else "100644"
            if mode != required_mode or current != archived:
                raise RuntimeError(f"locked registry source differs: {directory / relative}")
            expected[relative] = hashlib.sha256(archived).hexdigest()
    markers = {".cargo-ok": b'{"v":1}'}
    checksum_file = directory / ".cargo-checksum.json"
    if checksum_file.exists():
        raw = checksum_file.read_bytes()
        if json.loads(raw) != {"files": expected, "package": checksum}:
            raise RuntimeError(f"registry extracted checksum manifest differs: {checksum_file}")
        markers[checksum_file.name] = raw
    reject_extra_files(directory, expected, markers=markers)
    return {"archive_sha256": checksum, "files": len(expected)}


def verify_sources(data):
    lock = tomllib.loads((Path(data["workspace_root"]) / "Cargo.lock").read_text())
    checksums = {(p["name"], p["version"], p.get("source")): p.get("checksum") for p in lock["package"]}
    registry = {}
    trees = {}
    for package in data["packages"]:
        source = package.get("source") or ""
        directory = Path(package["manifest_path"]).parent
        if source.startswith("registry+"):
            checksum = checksums[(package["name"], package["version"], source)]
            registry[package["id"]] = verify_registry_tree(directory, checksum)
        elif source.startswith("git+"):
            checkout = next((p for p in (directory, *directory.parents) if (p / ".git").exists()), None)
            revision = source.rsplit("#", 1)[-1]
            if checkout is None or "#" not in source:
                raise RuntimeError(f"missing pinned Git source: {source}")
            if str(checkout) in trees:
                if trees[str(checkout)]["revision"] != revision:
                    raise RuntimeError(f"conflicting Git revisions for {checkout}")
            else:
                trees[str(checkout)] = verify_git_tree(checkout, revision)
    return {"git": trees, "registry": registry}
