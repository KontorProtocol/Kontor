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
    packages = [package for package in metadata.get("packages", [])
                if package.get("name") == "wasmtime"]
    if len(packages) != 1:
        raise ValueError("Cargo metadata lacks one Wasmtime package")
    package = packages[0]
    expected_source = ("git+https://github.com/wilfreddenton/wasmtime?rev="
                       f"{WASMTIME_REVISION}#{WASMTIME_REVISION}")
    if package.get("source") != expected_source:
        raise ValueError("Cargo metadata does not resolve the pinned Wasmtime fork")
    manifest_path = Path(package["manifest_path"])
    if not manifest_path.is_absolute() or manifest_path.parts[-3:] != (
            "crates", "wasmtime", "Cargo.toml"):
        raise ValueError("Wasmtime package manifest path is unexpected")
    checkout = manifest_path.parents[2]
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if revision != WASMTIME_REVISION:
        raise ValueError("Cargo checkout revision differs from pinned Wasmtime")
    archived = {}
    for relative, pinned_sha256 in FIBER_SOURCE_FILES.items():
        source = checkout / relative
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
