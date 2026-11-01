"""Explicitly freeze a target-independent executor reference, never during a build."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

POLICY = b"""Kontor execution reference build policy v1
Independently locked retained graph with kontor_retained configuration.
Requires the immutable storage contract referenced by the retained definition.
Shared node adapters and SQL dependencies are separately artifact-qualified.
Effective local-package manifests bind inherited workspace build properties.
One pinned compiler per node build; qualified compiler/platform artifact mappings.
Pulley64 execution, portable lifting accounting, sequential guest call-return.
Retained native namespaces and node-owned process resources.
Release Linux x86-64, Linux ARM64 and macOS ARM64 qualification; bounded dev smoke.
Reference inputs remain immutable after release; compatible artifacts are separate.
"""
IGNORED = {".git", "target", ".build-cache", "__pycache__"}
SEMANTIC_TREES = (
    "protocol-bundles/executor",
    "core/indexer/src/runtime",
    "core/indexer/src/protocol",
    "core/indexer/src/bls",
    *(f"native-contracts/{name}/wit" for name in ("token", "filestorage", "staking", "system", "nft")),
)
# These whole modules are excluded by kontor_retained. Mixed modules and shared
# callback interfaces stay bound; artifact provenance still includes every file.
NODE_ONLY = (
    "core/indexer/src/protocol/coordinator",
    "core/indexer/src/runtime/ownership.rs",
    "core/indexer/src/runtime/ownership",
    "core/indexer/src/runtime/pool.rs",
    "core/indexer/src/runtime/pool",
    "core/indexer/src/runtime/node.rs",
)


def effective_manifest(root, package):
    fields = {key: package.get(key) for key in ("name", "version", "edition", "rust_version", "links")}
    fields["dependencies"] = []
    for dependency in package.get("dependencies", []):
        item = dict(dependency)
        if item.get("path"):
            item["path"] = Path(item["path"]).resolve().relative_to(root).as_posix()
        fields["dependencies"].append(item)
    fields["dependencies"].sort(key=lambda item: json.dumps(item, sort_keys=True))
    fields["targets"] = []
    for target in package.get("targets", []):
        item = {key: target.get(key) for key in ("name", "kind", "crate_types", "edition", "required-features")}
        item["src_path"] = Path(target["src_path"]).resolve().relative_to(root).as_posix()
        fields["targets"].append(item)
    fields["targets"].sort(key=lambda item: json.dumps(item, sort_keys=True))
    return hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def count(value):
    return struct.pack(">I", value)


def blob(value):
    return count(len(value)) + value


def encode(sources, locks, features, policy):
    output = bytearray(b"\x01")
    for entries in (sources, locks):
        if not entries:
            raise ValueError("empty reference input set")
        output.extend(count(len(entries)))
        for path, digest in sorted(entries.items()):
            if len(digest) != 32 or any(part in ("", ".", "..") for part in path.split("/")):
                raise ValueError("invalid reference source")
            output.extend(blob(path.encode()))
            output.extend(digest)
    features = sorted(set(features))
    output.extend(count(len(features)))
    for feature in features:
        output.extend(blob(feature.encode()))
    if len(policy) != 32:
        raise ValueError("invalid build policy digest")
    output.extend(policy)
    return bytes(output)


def reference(root, manifest, metadata):
    root, manifest = root.resolve(), manifest.resolve()
    lock = manifest.with_name("Cargo.lock")
    sources = {}
    excluded = {
        root / f"protocol-bundles/executor-{graph}/definition.bin" for graph in ("first", "second")
    }

    def add(path):
        path.relative_to(root)
        if path in excluded or path == lock:
            return
        path.resolve(strict=True).relative_to(root)
        sources[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).digest()

    def visit(directory, ancestors=()):
        resolved = directory.resolve(strict=True)
        resolved.relative_to(root)
        if resolved in ancestors:
            raise ValueError(f"cyclic semantic source directory: {directory}")
        for path in sorted(directory.iterdir()):
            if path.name in IGNORED:
                continue
            relative = path.relative_to(root).as_posix()
            if any(relative == prefix or relative.startswith(prefix + "/") for prefix in NODE_ONLY):
                continue
            if path.is_dir():
                visit(path, (*ancestors, resolved))
            elif path.is_file():
                add(path)
            else:
                raise ValueError(f"unsupported semantic source entry: {path}")

    directories = {root / relative for relative in SEMANTIC_TREES}
    packages = {package["id"]: package for package in metadata["packages"]}
    for package in packages.values():
        if package.get("source") is None:
            directory = Path(package["manifest_path"]).resolve().parent
            directory.relative_to(root)
            directories.add(directory)
            for ancestor in (directory, *directory.parents):
                if ancestor != root and root not in ancestor.parents:
                    break
                # The effective package projection below commits inherited
                # properties without binding unrelated workspace dependencies.
                for name in (".cargo/config", ".cargo/config.toml"):
                    path = ancestor / name
                    if path.is_file():
                        add(path)
    for directory in sorted(directories):
        if not directory.is_dir():
            raise ValueError(f"missing semantic source tree: {directory}")
        visit(directory)
    features = ["cfg:kontor_retained"]
    for package in packages.values():
        if package.get("source") is None:
            path = Path(package["manifest_path"]).resolve().relative_to(root).as_posix()
            features.append(f"effective-manifest:{path}:{effective_manifest(root, package)}")
    for node in metadata["resolve"]["nodes"]:
        package = packages[node["id"]]
        source = package.get("source")
        if source is None:
            source = Path(package["manifest_path"]).resolve().relative_to(root).as_posix()
        identity = f"{package['name']}@{package['version']}:{source}"
        features.extend(f"{identity}:{feature}" for feature in node["features"])
    return encode(sources, {lock.relative_to(root).as_posix(): hashlib.sha256(lock.read_bytes()).digest()},
                  features, hashlib.sha256(POLICY).digest())


def verify_reference(root, manifest, metadata):
    encoded = reference(root, manifest, metadata)
    destination = manifest.with_name("definition.bin")
    if destination.read_bytes() != encoded:
        raise ValueError("reference differs from current source; do not overwrite a released definition")
    return {"path": destination.resolve().relative_to(root.resolve()).as_posix(),
            "bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest(),
            "execution_definition_id": hashlib.sha256(
                b"kontor/execution-definition/v1\0" + encoded).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("graph", choices=("first", "second"))
    parser.add_argument("--write", action="store_true", help="explicitly replace the pre-release reference")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    manifest = root / f"protocol-bundles/executor-{args.graph}/Cargo.toml"
    # An unfiltered resolution covers all target dependencies. A platform-filtered
    # qualification inventory must not define the network's semantic identity.
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--offline", "--format-version=1",
        "--manifest-path", str(manifest),
    ], cwd=root))
    if args.write:
        manifest.with_name("definition.bin").write_bytes(reference(root, manifest, metadata))
    print(json.dumps(verify_reference(root, manifest, metadata)))


if __name__ == "__main__":
    main()
