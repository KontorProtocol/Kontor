"""Bind the baseline consensus/coordinator implementation and its resolved dependencies.

The committed reference is checked, never refreshed implicitly. --write is only
for this unreleased baseline; later protocols must retain their old reference.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

ROOTS = {"bitcoin", "bytes", "libsql", "prost", "serde", "sha2", "sha3", "tokio"}
TREES = (
    "core/indexer/src/consensus", "core/indexer/proto",
    "core/indexer/src/protocol", "core/indexer/src/reactor",
    "core/indexer/src/database", "core/indexer/src/bitcoin_follower",
)
FILES = (
    "core/indexer/src/protocol/canonical_codec.rs",
    "core/indexer/src/protocol/identity.rs",
    "core/indexer/build.rs", "tools/protocol-bundles/symbol_tool.py",
    "tools/protocol-bundles/build.py",
    "tools/protocol-bundles/coordinator_definition.py",
)
DESTINATION = "core/indexer/src/protocol/coordinator/baseline/consensus.json"
POLICY = "kontor/coordinator-rules-v1; locked all-target dependency closure; canonical JSON v1"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def reference(root, metadata, lock):
    root = root.resolve()
    packages = {item["id"]: item for item in metadata["packages"]}
    nodes = {item["id"]: item for item in metadata["resolve"]["nodes"]}
    node = next(item for item in packages.values() if item["name"] == "kontor-node")
    direct = nodes[node["id"]]["deps"]
    selected = {item["pkg"] for item in direct
                if item["name"] in ROOTS or item["name"].startswith("malachitebft_")
                or item["name"].startswith("malachitebft-")}
    names = {packages[item]["name"] for item in selected}
    if not ROOTS <= names or not any(name.startswith("arc-malachitebft-") for name in names):
        raise ValueError("missing consensus dependency roots")
    roots = set(selected)
    pending = list(selected)
    while pending:
        for dependency in nodes[pending.pop()]["deps"]:
            if dependency["pkg"] not in selected:
                selected.add(dependency["pkg"])
                pending.append(dependency["pkg"])

    checksums = {(item["name"], item["version"], item.get("source")): item.get("checksum")
                 for item in lock["package"]}
    sources = {}

    def add(path):
        path.resolve(strict=True).relative_to(root)
        name = path.relative_to(root).as_posix()
        if name != DESTINATION:
            sources[name] = hashlib.sha256(path.read_bytes()).hexdigest()

    def visit(directory, ancestors=()):
        resolved = directory.resolve(strict=True)
        resolved.relative_to(root)
        if resolved in ancestors:
            raise ValueError("cyclic coordinator source directory")
        for path in sorted(directory.iterdir()):
            if path.name in {"target", ".git", ".build-cache", "__pycache__"}:
                continue
            if path.is_dir():
                visit(path, (*ancestors, resolved))
            elif path.is_file():
                add(path)
            else:
                raise ValueError(f"unsupported coordinator input: {path}")

    for name in TREES:
        visit(root / name)
    for name in FILES:
        add(root / name)

    def identity(package):
        source = package.get("source")
        if source is None:
            source = Path(package["manifest_path"]).resolve().relative_to(root).as_posix()
        return f"{package['name']}@{package['version']}:{source}"

    def edges(items):
        return sorted(({
            "name": item["name"], "package": identity(packages[item["pkg"]]),
            "kinds": sorted(item.get("dep_kinds", []), key=canonical),
        } for item in items), key=canonical)

    dependencies = []
    for package_id in sorted(selected, key=lambda key: identity(packages[key])):
        package = packages[package_id]
        key = (package["name"], package["version"], package.get("source"))
        if key not in checksums:
            raise ValueError(f"resolved dependency absent from lock: {key}")
        checksum = checksums[key]
        if str(package.get("source", "")).startswith("registry+") and not checksum:
            raise ValueError(f"registry dependency lacks checksum: {key}")
        if package.get("source") is None:
            visit(Path(package["manifest_path"]).resolve().parent)
        dependencies.append({
            "package": identity(package), "checksum": checksum,
            "features": sorted(nodes[package_id]["features"]),
            "dependencies": edges(nodes[package_id]["deps"]),
        })
    return canonical({"schema": 1, "policy": POLICY, "sources": sources,
                      "roots": edges(item for item in direct if item["pkg"] in roots),
                      "dependencies": dependencies})


def verify(root, metadata, lock):
    expected = reference(root, metadata, lock)
    if (root / DESTINATION).read_bytes() != expected:
        raise ValueError("coordinator reference differs; do not overwrite a released definition")
    return {"bytes": len(expected), "consensus_definition": hashlib.sha256(
        b"kontor/consensus-definition/v1\0" + expected).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--metadata", type=Path, help="already acquired locked, unfiltered node metadata")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    manifest = root / "protocol-bundles/node/Cargo.toml"
    metadata = json.loads(args.metadata.read_bytes() if args.metadata else subprocess.check_output([
        "cargo", "metadata", "--locked", "--offline", "--format-version=1",
        "--manifest-path", str(manifest)], cwd=root))
    lock = tomllib.loads(manifest.with_name("Cargo.lock").read_text())
    if args.write:
        destination = root / DESTINATION
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(reference(root, metadata, lock))
    print(json.dumps(verify(root, metadata, lock)))


if __name__ == "__main__":
    main()
