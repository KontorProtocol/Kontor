#!/usr/bin/env python3
"""Check six-cell archive coverage and common source without qualifying it."""

import argparse
import json
import re
import subprocess
from pathlib import Path

from resource_evidence import load_json_strict, require, sha256
from resource_manifest import CELLS, ROOT
from resource_suite_registry import MANIFEST as REGISTRY_MANIFEST
from resource_suite_registry import build_registry


def checkout_source():
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"],
                           check=True, capture_output=True, text=True).stdout
    require(not dirty, "suite closure requires a clean source checkout")
    return head


def capture_path(root, entry):
    require(isinstance(entry, dict) and set(entry) == {"path", "sha256"},
            "suite capture reference has unexpected fields")
    require(isinstance(entry["path"], str) and entry["path"]
            and isinstance(entry["sha256"], str),
            "suite capture path or digest is invalid")
    relative = Path(entry["path"])
    require(not relative.is_absolute() and ".." not in relative.parts
            and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]),
            "suite capture path or digest is invalid")
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()) and path.is_file()
            and sha256(path) == entry["sha256"],
            "suite capture file is missing or changed")
    return path


def validate_index(index, root, check_checkout=True):
    registry = build_registry()
    require(load_json_strict(REGISTRY_MANIFEST) == registry,
            "suite source registry differs from committed manifest")
    require(isinstance(index, dict)
            and set(index) == {"schema_version", "claim_status",
                               "registry_sha256", "source_sha", "cells"}
            and index["schema_version"] == 1
            and index["claim_status"] == "closure_only"
            and index["registry_sha256"] == sha256(REGISTRY_MANIFEST)
            and isinstance(index["source_sha"], str)
            and re.fullmatch(r"[0-9a-f]{40}", index["source_sha"])
            and isinstance(index["cells"], dict)
            and set(index["cells"]) == set(CELLS),
            "suite index source, status, or six cells changed")
    if check_checkout:
        require(index["source_sha"] == checkout_source(),
                "suite index source differs from checkout HEAD")
    paths = set()
    for cell in CELLS:
        record = index["cells"][cell]
        require(isinstance(record, dict) and set(record) == {"groups", "binary"}
                and isinstance(record["groups"], dict)
                and isinstance(record["binary"], dict)
                and set(record["binary"]) == {"path", "sha256"}
                and set(record["groups"]) == set(registry["groups"]),
                f"{cell}: suite group registry is incomplete")
        binaries = set()
        controls = set()
        for group_id, group in registry["groups"].items():
            entry = record["groups"][group_id]
            path = capture_path(root, entry)
            expected_relative = (Path(cell.replace("/", "_")) / group_id
                                 / group["capture_name"])
            require(path not in paths
                    and Path(entry["path"]) == expected_relative,
                    "suite capture path is duplicated or mislabeled")
            paths.add(path)
            bundle = load_json_strict(path)
            require(isinstance(bundle, dict)
                    and bundle.get("cell") == cell
                    and bundle.get("source_sha") == index["source_sha"]
                    and bundle.get("manifest_sha256") == group["manifest_sha256"]
                    and bundle.get("qualification_status") == "missing"
                    and isinstance(bundle.get("binary_sha256"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", bundle["binary_sha256"])
                    and isinstance(bundle.get("binary_path"), str)
                    and bundle["binary_path"]
                    and isinstance(bundle.get("control_capture"), dict)
                    and re.fullmatch(r"[0-9a-f]{64}",
                                     bundle["control_capture"].get("sha256", ""))
                    and isinstance(bundle.get("runs"), dict)
                    and all(isinstance(run, dict)
                            and isinstance(run.get("case_id"), str)
                            for run in bundle["runs"].values())
                    and {run["case_id"] for run in bundle["runs"].values()}
                        == set(group["case_ids"])
                    and all(run.get("cell") == cell
                            and run.get("source_sha") == index["source_sha"]
                            for run in bundle["runs"].values()),
                    f"{cell}/{group_id}: source, control, or case coverage changed")
            if group["manifest"] == "boundary":
                require(bundle.get("phase") == "final",
                        f"{cell}: boundary discovery cannot close the suite")
            if group["manifest"] == "v2":
                require(bundle.get("schema_version") == 2,
                        f"{cell}: chain bundle is not v2 evidence")
            binaries.add((bundle["binary_path"], bundle["binary_sha256"]))
            controls.add(bundle["control_capture"]["sha256"])
        require(len(binaries) == len(controls) == 1,
                f"{cell}: groups used different binaries or guard controls")
        binary_path, binary_sha256 = next(iter(binaries))
        capture_path(root, record["binary"])
        require(Path(record["binary"]["path"]) ==
                Path(cell.replace("/", "_")) / Path(binary_path).name
                and record["binary"]["sha256"] == binary_sha256,
                f"{cell}: archived binary path or hash differs from child evidence")
    return {"status": "closure_only", "cells": len(CELLS),
            "groups_per_cell": len(registry["groups"]),
            "case_count": registry["case_count"]}


def collect(root, source_sha):
    registry = build_registry()
    require(load_json_strict(REGISTRY_MANIFEST) == registry,
            "suite source registry differs from committed manifest")
    index = {
        "schema_version": 1, "claim_status": "closure_only",
        "registry_sha256": sha256(REGISTRY_MANIFEST),
        "source_sha": source_sha, "cells": {},
    }
    for cell in CELLS:
        groups = {}
        binary_origin = None
        for group_id, group in registry["groups"].items():
            relative = Path(cell.replace("/", "_")) / group_id / group["capture_name"]
            path = root / relative
            require(path.is_file(), f"missing suite capture: {relative}")
            groups[group_id] = {"path": str(relative), "sha256": sha256(path)}
            if binary_origin is None:
                binary_origin = load_json_strict(path)["binary_path"]
        binary_relative = (Path(cell.replace("/", "_")) /
                           Path(binary_origin).name)
        binary_archive = root / binary_relative
        require(binary_archive.is_file(),
                f"{cell}: suite archived test binary is missing")
        index["cells"][cell] = {
            "groups": groups,
            "binary": {"path": str(binary_relative),
                       "sha256": sha256(binary_archive)},
        }
    validate_index(index, root, check_checkout=False)
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    source_sha = checkout_source()
    if args.verify_existing:
        index = load_json_strict(args.output)
        result = validate_index(index, root)
    else:
        index = collect(root, source_sha)
        with args.output.open("x") as destination:
            json.dump(index, destination, indent=2, sort_keys=True)
            destination.write("\n")
        result = validate_index(index, root)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
