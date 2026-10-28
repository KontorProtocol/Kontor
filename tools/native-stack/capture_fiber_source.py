#!/usr/bin/env python3
"""Archive the pinned Wasmtime fiber allocation sources from Cargo metadata."""

import argparse
import json
import shutil
import subprocess
from pathlib import Path

from resource_manifest import FIBER_SOURCE_FILES, WASMTIME_REVISION, sha256


def capture(metadata_path, evidence_dir):
    metadata = json.loads(metadata_path.read_text())
    expected_source = ("git+https://github.com/wilfreddenton/wasmtime?rev="
                       f"{WASMTIME_REVISION}#{WASMTIME_REVISION}")
    roots = {}
    packages = {}
    for name, crate_dir in (("wasmtime", "wasmtime"),
                            ("wasmtime-internal-fiber", "fiber")):
        matches = [package for package in metadata.get("packages", [])
                   if package.get("name") == name]
        if len(matches) != 1:
            raise ValueError(f"Cargo metadata lacks one {name} package")
        package = matches[0]
        if package.get("source") != expected_source or package.get("version") != "51.0.0-kontor.2":
            raise ValueError(f"Cargo metadata does not resolve pinned {name}")
        manifest_path = Path(package["manifest_path"])
        if not manifest_path.is_absolute() or manifest_path.parts[-3:] != (
                "crates", crate_dir, "Cargo.toml"):
            raise ValueError(f"{name} package manifest path is unexpected")
        checkout = manifest_path.parents[2]
        revision = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        if revision != WASMTIME_REVISION:
            raise ValueError(f"Cargo checkout revision differs from pinned {name}")
        roots[name] = checkout
        packages[name] = package
    nodes = metadata.get("resolve", {}).get("nodes", [])
    parent = [node for node in nodes if node.get("id") == packages["wasmtime"]["id"]]
    if len(parent) != 1 or not any(
            dep.get("name") == "wasmtime_fiber"
            and dep.get("pkg") == packages["wasmtime-internal-fiber"]["id"]
            for dep in parent[0].get("deps", [])):
        raise ValueError("Cargo resolve does not bind Wasmtime to the pinned fiber crate")
    archived = {}
    for relative, pinned_sha256 in FIBER_SOURCE_FILES.items():
        owner = "wasmtime-internal-fiber" if relative.startswith("crates/fiber/") else "wasmtime"
        source = roots[owner] / relative
        if not source.is_file() or sha256(source) != pinned_sha256:
            raise ValueError(f"Wasmtime fiber source differs from pinned fork: {relative}")
        destination_relative = Path("wasmtime-source") / relative
        destination = evidence_dir / destination_relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        if sha256(destination) != pinned_sha256:
            raise ValueError(f"archived Wasmtime fiber source changed: {relative}")
        archived[relative] = {"path": destination_relative.as_posix(),
                              "sha256": pinned_sha256}
    return archived


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(capture(args.metadata, args.evidence_dir), sort_keys=True))


if __name__ == "__main__":
    main()
