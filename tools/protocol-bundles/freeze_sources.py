#!/usr/bin/env python3
"""Preserve executor or coordinator inputs from an exact Git commit without redefining them."""

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

from coordinator_definition import (
    DESTINATION as CONSENSUS_REFERENCE,
    FILES as COORDINATOR_FILES,
    verify as verify_coordinator,
)
from execution_definition import SEMANTIC_TREES, verify_reference


GRAPHS = ("first", "second")
SUPPORT_TREES = ("protocol-bundles/proof", "tools/native-crypto/fixtures")
SUPPORT_FILES = (
    "tools/protocol-bundles/historical_semantics.rs",
    "tools/protocol-bundles/semantic-baseline.json",
    "tools/protocol-bundles/semantic-baseline.log",
    "tools/protocol-bundles/protocol-manifest-vector.json",
)


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
    manifest = root / f"protocol-bundles/{graph}/Cargo.toml"
    return json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--offline", "--format-version=1",
        "--manifest-path", str(manifest),
    ], cwd=root))


def inputs(root, resolutions, graphs, extra_trees=()):
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

    for relative in (*SEMANTIC_TREES, *SUPPORT_TREES, *extra_trees):
        include(root / relative)
    # Build orchestration comes from the current checkout. Retain historical
    # fixtures referenced by source/tests, without copying obsolete tool programs.
    for relative in SUPPORT_FILES:
        path = root / relative
        if path.exists():
            include(path)
    # Cargo reads even unused path patches while resolving a locked graph.
    for graph in graphs:
        manifest = root / f"protocol-bundles/{graph}/Cargo.toml"
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


def definitions(root, resolutions, kind):
    if kind == "coordinator":
        node_lock = tomllib.loads((root / "protocol-bundles/node/Cargo.lock").read_text())
        return {
            "coordinator": verify_coordinator(root, resolutions[0], node_lock),
            "observer": verify_reference(root, root / "protocol-bundles/executor-observer/Cargo.toml",
                                         resolutions[1]),
            "consensus_reference_sha256": hashlib.sha256((root / CONSENSUS_REFERENCE).read_bytes()).hexdigest(),
            "retained_executor_reference_sha256": hashlib.sha256((root /
                "protocol-bundles/retained/k3/protocol-bundles/executor-first/definition.bin"
            ).read_bytes()).hexdigest(),
        }
    return [verify_reference(root, root / f"protocol-bundles/executor-{graph}/Cargo.toml", data)
            for graph, data in zip(GRAPHS, resolutions, strict=True)]


def freeze(repository, revision, destination, kind="executors"):
    if kind not in {"executors", "coordinator"}:
        raise ValueError("unknown snapshot kind")
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
        graphs = ("node", "executor-observer") if kind == "coordinator" else tuple(
            f"executor-{graph}" for graph in GRAPHS)
        resolutions = [metadata(root, graph) for graph in graphs]
        expected = definitions(root, resolutions, kind)
        extra_trees = (
            # The legacy coordinator definition binds tool sources too, unlike
            # executor definitions. Keep that closure until this mode is retired.
            *COORDINATOR_FILES,
            "core/indexer",
            "protocol-bundles/retained/k3/protocol-bundles/executor-first/definition.bin",
            "protocol-bundles/executor-first/definition.bin",
            "protocol-bundles/executor-second/definition.bin",
        ) if kind == "coordinator" else ()
        selected = inputs(root, resolutions, graphs, extra_trees)
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
        actual = definitions(staged, [metadata(staged, graph) for graph in graphs], kind)
        if actual != expected:
            raise ValueError("relocation changed a retained definition")
        record = {"source_commit": commit, "definitions": expected, "files": records}
        if kind == "coordinator":
            record["kind"] = kind
            retained = root / "protocol-bundles/retained/k3"
            retained_hash = hashlib.sha256((retained / "snapshot.json").read_bytes()).hexdigest()
            verify_snapshot(retained, retained_hash)
            record["retained_executor_snapshot"] = {
                "source_root": "protocol-bundles/retained/k3", "snapshot_sha256": retained_hash,
            }
        (staged / "snapshot.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        verify_snapshot(staged, hashlib.sha256((staged / "snapshot.json").read_bytes()).hexdigest())
        staged.rename(destination)
    return {"source_commit": commit, "files": len(records), "definitions": expected,
            "snapshot_sha256": hashlib.sha256((destination / "snapshot.json").read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--kind", choices=("executors", "coordinator"), default="executors")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    print(json.dumps(freeze(root, args.revision, args.destination.resolve(), args.kind), indent=2))


if __name__ == "__main__":
    main()
