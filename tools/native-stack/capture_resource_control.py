#!/usr/bin/env python3
"""Capture the native stack guard control and pinned fiber source evidence."""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True

from capture_fiber_source import capture as capture_fiber_source
from resource_evidence import (check_guard_control, load_json_strict,
                               no_duplicate_keys, no_nonfinite_constants, sha256)
from resource_manifest import MANIFEST, ROOT, build_manifest


def selected_binary(artifacts_path, metadata):
    records = []
    for line in artifacts_path.read_text().splitlines():
        if line.strip():
            records.append(json.loads(line, object_pairs_hook=no_duplicate_keys,
                                      parse_constant=no_nonfinite_constants))
    indexers = [package for package in metadata["packages"]
                if package.get("name") == "indexer"]
    if len(indexers) != 1:
        raise ValueError("Cargo metadata lacks one indexer package")
    selected = [record for record in records
                if record.get("reason") == "compiler-artifact"
                and record.get("package_id") == indexers[0]["id"]
                and record.get("target", {}).get("name") == "indexer"
                and record.get("target", {}).get("kind") == ["lib"]
                and record.get("profile", {}).get("test") is True
                and record.get("executable")]
    if len(selected) != 1 or not any(record.get("reason") == "build-finished"
                                     and record.get("success") is True for record in records):
        raise ValueError("Cargo output lacks one successful indexer test artifact")
    binary = Path(selected[0]["executable"])
    if not binary.is_absolute() or not binary.is_file() or not binary.name.startswith("indexer-"):
        raise ValueError("selected Cargo test artifact is missing")
    return binary.resolve(), selected[0]


def capture(artifacts_path, metadata_path, source_sha, evidence_dir, timeout_seconds):
    if sys.platform != "linux":
        raise ValueError("guard control capture is not implemented on this platform")
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("source revision is not a Git SHA-1")
    manifest = build_manifest()
    if load_json_strict(MANIFEST) != manifest:
        raise ValueError("resource manifest differs from pinned source")
    manifest_sha256 = sha256(MANIFEST)
    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if head != source_sha:
        raise ValueError("requested source revision differs from checkout HEAD")
    dirty = subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain"],
        check=True, capture_output=True, text=True,
    ).stdout
    if dirty:
        raise ValueError("source checkout is not clean")
    metadata = load_json_strict(metadata_path)
    if metadata.get("workspace_root") != str(ROOT / "core"):
        raise ValueError("Cargo metadata workspace differs from source checkout")
    binary, artifact = selected_binary(artifacts_path, metadata)
    binary_sha256 = sha256(binary)
    artifacts_sha256 = sha256(artifacts_path)
    metadata_sha256 = sha256(metadata_path)
    if evidence_dir.exists() and any(evidence_dir.iterdir()):
        raise ValueError("capture output directory is not empty")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    for source, name in ((artifacts_path, "cargo-artifacts.jsonl"),
                         (metadata_path, "cargo-metadata.json")):
        with (evidence_dir / name).open("xb") as destination, source.open("rb") as original:
            shutil.copyfileobj(original, destination)
    if (sha256(evidence_dir / "cargo-artifacts.jsonl") != artifacts_sha256
            or sha256(evidence_dir / "cargo-metadata.json") != metadata_sha256):
        raise ValueError("Cargo input changed during evidence archive")
    raw_path = evidence_dir / "guard-control.log"
    fragment_path = evidence_dir / "resource-control-capture.json"
    failure_path = evidence_dir / "resource-control-failure.json"
    command = [str(binary), "--exact", manifest["guard_control_runner"]["test_name"],
               "--ignored", "--nocapture"]
    started = time.time_ns()
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    timed_out = False
    try:
        output, _ = child.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        child.kill()
        output, _ = child.communicate()
    ended = time.time_ns()
    with raw_path.open("xb") as raw:
        raw.write(output)
    page_size = os.sysconf("SC_PAGE_SIZE")
    guard_control = {
        "process": {
            "pid": child.pid, "command": command,
            "started_unix_ns": started, "ended_unix_ns": ended,
            "exit_code": child.returncode if child.returncode >= 0 else None,
            "signal": -child.returncode if child.returncode < 0 else None,
            "timed_out": timed_out,
            "complete": not timed_out and child.returncode == 0,
            "test_harness_passed": not timed_out and child.returncode == 0,
        },
        "raw_log": {"path": raw_path.name, "sha256": sha256(raw_path)},
    }
    report_view = {
        "host": {"os": "linux"}, "binary_path": str(binary),
        "binary_sha256": binary_sha256, "source_sha": source_sha,
        "configurations": {
            mode: {"engine": {"page_size_bytes": page_size},
                   "process_log": {"path": f"{mode}-workload.jsonl"}}
            for mode in ("reduced", "production")
        },
        "guard_control": guard_control,
    }
    try:
        if sha256(binary) != binary_sha256:
            raise ValueError("selected Cargo test artifact changed during capture")
        if load_json_strict(MANIFEST) != build_manifest() or sha256(MANIFEST) != manifest_sha256:
            raise ValueError("resource source or manifest changed during capture")
        final_head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        final_dirty = subprocess.run(
            ["git", "-C", str(ROOT), "status", "--porcelain"],
            check=True, capture_output=True, text=True,
        ).stdout
        if final_head != source_sha or final_dirty:
            raise ValueError("source checkout changed during capture")
        check_guard_control(report_view, manifest, evidence_dir)
        sources = capture_fiber_source(metadata_path, evidence_dir)
    except Exception as error:
        with failure_path.open("x") as destination:
            json.dump({"error": str(error), "guard_control": guard_control},
                      destination, indent=2, sort_keys=True)
            destination.write("\n")
        raise
    fragment = {
        "manifest_sha256": manifest_sha256,
        "source_sha": source_sha,
        "binary_path": str(binary),
        "binary_sha256": binary_sha256,
        "cargo_artifact": artifact,
        "cargo_artifacts": {"path": "cargo-artifacts.jsonl",
                            "sha256": artifacts_sha256},
        "cargo_metadata": {"path": "cargo-metadata.json",
                           "sha256": metadata_sha256},
        "guard_control": guard_control,
        "wasmtime_source_files": sources,
    }
    with fragment_path.open("x") as destination:
        json.dump(fragment, destination, indent=2, sort_keys=True)
        destination.write("\n")
    return fragment_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo-artifacts", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=90)
    args = parser.parse_args()
    if args.timeout_seconds <= 0 or args.timeout_seconds > 600:
        parser.error("timeout must be between 1 and 600 seconds")
    path = capture(args.cargo_artifacts, args.metadata,
                   args.source_sha, args.evidence_dir, args.timeout_seconds)
    print(json.dumps({"capture_path": str(path), "sha256": sha256(path)}, sort_keys=True))


if __name__ == "__main__":
    main()
