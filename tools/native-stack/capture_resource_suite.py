#!/usr/bin/env python3
"""Run all S2 case captures for one host/profile cell at one source commit."""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from capture_resource_diagnostic import validate_control
from resource_boundary_manifest import build_boundary_manifest
from resource_evidence import load_json_strict, require, sha256
from resource_evidence_v2 import HISTORICAL_BUNDLE_SHA256, cell_target
from resource_manifest import ROOT, build_manifest
from resource_manifest_v2 import build_manifest_v2
from resource_suite_closure import checkout_source
from resource_suite_registry import MANIFEST as REGISTRY_MANIFEST
from resource_suite_registry import build_registry


def capture_commands(registry, cell, control_path, control_sha256,
                     historical_path, reviewed_path, reviewed_sha256, root):
    require(cell in registry["cells"], "unknown suite cell")
    commands = {}
    for group_id, group in registry["groups"].items():
        command = [
            sys.executable, str(ROOT / group["capture"]["path"]),
            "--cell", cell,
            "--control-capture", str(control_path),
            "--control-sha256", control_sha256,
            "--evidence-dir", str(root / cell.replace("/", "_") / group_id),
        ]
        if group_id == "chain_v2":
            command.extend(["--historical-bundle", str(historical_path)])
        elif group_id == "pulley_boundary":
            command.extend(["--phase", "final",
                            "--reviewed-discovery-capture", str(reviewed_path),
                            "--reviewed-discovery-sha256", reviewed_sha256])
        commands[group_id] = command
    return commands


def preflight(cell, control_path, control_sha256, historical_path,
              reviewed_path, reviewed_sha256, root):
    source_sha = checkout_source()
    require(not root.resolve().is_relative_to(ROOT.resolve()),
            "suite archive must be outside the source checkout")
    registry = build_registry()
    require(load_json_strict(REGISTRY_MANIFEST) == registry,
            "suite source registry differs from committed manifest")
    boundary = build_boundary_manifest()
    v2 = build_manifest_v2()
    require(boundary["claim_status"] == "candidate_only"
            and v2["auxiliary_count_status"] == "frozen",
            "suite boundary depths or v2 Store counts are not frozen")
    require(sha256(historical_path) == HISTORICAL_BUNDLE_SHA256,
            "suite historical chain archive differs from pinned phase10")
    require(sha256(reviewed_path) == reviewed_sha256
            and reviewed_sha256 == boundary["reviewed_discovery_sha256"],
            "suite reviewed boundary discovery archive differs")
    control, binary = validate_control(control_path, control_sha256, build_manifest())
    cell_target(cell, control["cargo_artifact"], check_host=True)
    require(control["source_sha"] == source_sha,
            "suite guard control differs from source checkout")
    cell_dir = root / cell.replace("/", "_")
    require(not cell_dir.exists(), "suite cell archive already exists")
    commands = capture_commands(registry, cell, control_path, control_sha256,
                                historical_path, reviewed_path,
                                reviewed_sha256, root)
    return registry, control, binary, source_sha, commands


def capture_cell(cell, control_path, control_sha256, historical_path,
                 reviewed_path, reviewed_sha256, root):
    root = root.resolve()
    control_path = control_path.resolve()
    historical_path = historical_path.resolve()
    reviewed_path = reviewed_path.resolve()
    registry, control, binary, source_sha, commands = preflight(
        cell, control_path, control_sha256, historical_path,
        reviewed_path, reviewed_sha256, root)
    cell_dir = root / cell.replace("/", "_")
    cell_dir.mkdir(parents=True)
    archived_binary = cell_dir / binary.name
    with binary.open("rb") as source, archived_binary.open("xb") as destination:
        shutil.copyfileobj(source, destination)
    require(sha256(archived_binary) == control["binary_sha256"],
            "suite archived binary differs from guard control")
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    captures = {}
    for group_id, command in commands.items():
        subprocess.run(command, check=True, cwd=ROOT, env=environment)
        group = registry["groups"][group_id]
        path = (root / cell.replace("/", "_") / group_id
                / group["capture_name"])
        bundle = load_json_strict(path)
        require(bundle["cell"] == cell
                and bundle["source_sha"] == source_sha
                and bundle["manifest_sha256"] == group["manifest_sha256"]
                and bundle["binary_sha256"] == control["binary_sha256"]
                and bundle["binary_path"] == control["binary_path"]
                and bundle["control_capture"]["sha256"] == control_sha256,
                f"{group_id}: capture differs from common source or control")
        captures[group_id] = {"path": str(path), "sha256": sha256(path)}
    return {"status": "captured_not_qualified", "cell": cell,
            "source_sha": source_sha,
            "binary_archive": {"path": str(archived_binary),
                               "sha256": sha256(archived_binary)},
            "captures": captures}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell", required=True)
    parser.add_argument("--control-capture", type=Path, required=True)
    parser.add_argument("--control-sha256", required=True)
    parser.add_argument("--historical-bundle", type=Path, required=True)
    parser.add_argument("--reviewed-discovery-capture", type=Path, required=True)
    parser.add_argument("--reviewed-discovery-sha256", required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    args = parser.parse_args()
    result = capture_cell(
        args.cell, args.control_capture, args.control_sha256,
        args.historical_bundle, args.reviewed_discovery_capture,
        args.reviewed_discovery_sha256, args.archive_root.resolve())
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
