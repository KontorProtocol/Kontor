#!/usr/bin/env python3
"""Relocate retained executor inputs from an exact Git commit without redefining them."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

from execution_definition import SEMANTIC_TREES, verify_reference


GRAPHS = ("first", "second")
SUPPORT_TREES = ("protocol-bundles/proof", "tools/protocol-bundles", "tools/native-crypto/fixtures")


def verify_snapshot(root, expected):
    root = root.resolve(strict=True)
    manifest = root / "snapshot.json"
    if manifest.is_symlink() or hashlib.sha256(manifest.read_bytes()).hexdigest() != expected:
        raise ValueError("retained source inventory changed")
    record = json.loads(manifest.read_text())
    found = {}
    # Do not traverse symlink directories: their targets are separately included
    # in the frozen closure and both the link spelling and target are checked.
    for path in sorted(root.rglob("*")):
        if path == manifest:
            continue
        relative = path.relative_to(root).as_posix()
        path.resolve(strict=True).relative_to(root)
        if path.is_symlink():
            found[relative] = {"symlink": str(path.readlink())}
        elif path.is_file():
            found[relative] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        elif not path.is_dir():
            raise ValueError(f"unsupported retained source entry: {path}")
    if not found or found != record["files"]:
        raise ValueError("retained source files differ from frozen inventory")
    return record


def metadata(root, graph):
    manifest = root / f"protocol-bundles/executor-{graph}/Cargo.toml"
    return json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--offline", "--format-version=1",
        "--manifest-path", str(manifest),
    ], cwd=root))


def inputs(root, resolutions):
    paths = set()

    def include(path, ancestors=()):
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        if resolved in ancestors:
            raise ValueError(f"cyclic frozen input: {path}")
        if path.is_symlink():
            paths.add(path)
            include(resolved, ancestors)
        elif path.is_dir():
            for child in sorted(path.iterdir()):
                include(child, (*ancestors, resolved))
        elif path.is_file():
            paths.add(path)
        else:
            raise ValueError(f"unsupported frozen input: {path}")

    for relative in (*SEMANTIC_TREES, *SUPPORT_TREES):
        include(root / relative)
    # Cargo reads even unused path patches while resolving a locked graph.
    for graph in GRAPHS:
        manifest = root / f"protocol-bundles/executor-{graph}/Cargo.toml"
        for registry in tomllib.loads(manifest.read_text()).get("patch", {}).values():
            for dependency in registry.values():
                if "path" in dependency:
                    include((manifest.parent / dependency["path"]).resolve(strict=True))
    for resolution in resolutions:
        for package in resolution["packages"]:
            if package.get("source") is not None:
                continue
            directory = Path(package["manifest_path"]).resolve().parent
            directory.relative_to(root)
            include(directory)
            for ancestor in (directory, *directory.parents):
                if not ancestor.is_relative_to(root):
                    break
                for name in ("Cargo.toml", ".cargo/config", ".cargo/config.toml"):
                    path = ancestor / name
                    if path.is_file():
                        include(path)
    for name in ("rust-toolchain", "rust-toolchain.toml", "core/rust-toolchain.toml"):
        path = root / name
        if path.is_file():
            include(path)
    return sorted(paths)


def freeze(repository, revision, destination):
    commit = subprocess.check_output(["git", "rev-parse", "--verify", revision + "^{commit}"],
                                     cwd=repository, text=True).strip()
    if revision != commit:
        raise ValueError("freeze requires the full immutable commit ID")
    if destination.exists():
        raise ValueError("refusing to overwrite a retained source root")
    archive = subprocess.check_output(["git", "archive", "--format=tar", commit], cwd=repository)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="freeze-executors-", dir=destination.parent) as temporary:
        root = Path(temporary) / "original"
        root.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as source:
            source.extractall(root, filter="data")
        resolutions = [metadata(root, graph) for graph in GRAPHS]
        definitions = [verify_reference(root, root / f"protocol-bundles/executor-{graph}/Cargo.toml", data)
                       for graph, data in zip(GRAPHS, resolutions, strict=True)]
        selected = inputs(root, resolutions)
        staged = Path(temporary) / "retained"
        records = {}
        for path in selected:
            relative = path.relative_to(root)
            target = staged / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                target.symlink_to(path.readlink())
                records[relative.as_posix()] = {"symlink": str(path.readlink())}
            else:
                shutil.copy2(path, target)
                records[relative.as_posix()] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for graph, expected in zip(GRAPHS, definitions, strict=True):
            actual = verify_reference(staged, staged / f"protocol-bundles/executor-{graph}/Cargo.toml",
                                      metadata(staged, graph))
            if actual != expected:
                raise ValueError("relocation changed a released execution definition")
        record = {"source_commit": commit, "definitions": definitions, "files": records}
        (staged / "snapshot.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        verify_snapshot(staged, hashlib.sha256((staged / "snapshot.json").read_bytes()).hexdigest())
        staged.rename(destination)
    return {"source_commit": commit, "files": len(records), "definitions": definitions,
            "snapshot_sha256": hashlib.sha256((destination / "snapshot.json").read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    print(json.dumps(freeze(root, args.revision, args.destination.resolve()), indent=2))


if __name__ == "__main__":
    main()
