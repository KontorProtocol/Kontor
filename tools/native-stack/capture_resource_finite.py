#!/usr/bin/env python3
"""Capture bounded real paid finite-stack children in both worker configurations."""

import argparse
import json
import os
import platform
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from capture_resource_chain import verify_final_closure
from capture_resource_chain_v2 import copy_control
from capture_resource_control import run_bounded_process
from capture_resource_diagnostic import validate_control
from resource_boundary_evidence import validate_cell_identity
from resource_evidence import load_json_strict, require, sha256
from resource_finite_evidence import (CASES, CONFIGURATIONS, ROLES, WORKER_TEST,
                                      expected_case_env, parse_worker_log, run_name,
                                      validate_bundle)
from resource_manifest import MANIFEST, build_manifest


def capture(cell, control_path, control_sha256, evidence_dir, timeout_seconds):
    require(sys.platform in {"linux", "darwin"},
            "finite stack child capture requires a supported guard control")
    require(1 <= timeout_seconds <= 1200, "finite stack timeout must be 1 to 1200 seconds")
    host_os = "macOS" if sys.platform == "darwin" else "Linux"
    host_arch = {"aarch64": "ARM64", "arm64": "ARM64",
                 "x86_64": "X64"}.get(platform.machine())
    require(cell.startswith(f"{host_os}-{host_arch}/")
            and cell.split("/", 1)[1] in {"dev", "release"},
            "finite stack cell differs from local host or profile")
    manifest = build_manifest()
    require(load_json_strict(MANIFEST) == manifest,
            "finite stack source manifest changed")
    control, binary = validate_control(control_path, control_sha256, manifest)
    validate_cell_identity(cell, control["cargo_artifact"])
    require(not evidence_dir.exists() or not any(evidence_dir.iterdir()),
            "finite stack evidence output directory is not empty")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    control_dir, control_copy = copy_control(
        control_path, control_sha256, evidence_dir, control)
    runs = {}
    failure_path = evidence_dir / "finite-stack-failure.json"
    active_name = None
    active_process = None
    active_log = None
    try:
        for case_id in sorted(CASES):
            for role in ROLES:
                for configuration in CONFIGURATIONS:
                    name = run_name(case_id, role, configuration)
                    active_name = name
                    active_process = None
                    active_log = None
                    case_env = expected_case_env(case_id, role, configuration)
                    environment = {key: value for key, value in os.environ.items()
                                   if not key.startswith("KONTOR_")}
                    environment.update(case_env)
                    command = [str(binary), "--ignored", "--exact", WORKER_TEST,
                               "--nocapture"]
                    before = sha256(binary)
                    child, started, ended, output, timed_out = run_bounded_process(
                        command, timeout_seconds, environment)
                    raw_path = evidence_dir / f"{name}.log"
                    with raw_path.open("xb") as destination:
                        destination.write(output)
                    process = {
                        "pid": child.pid, "command": command,
                        "started_unix_ns": started, "ended_unix_ns": ended,
                        "exit_code": child.returncode if child.returncode >= 0 else None,
                        "signal": -child.returncode if child.returncode < 0 else None,
                        "timed_out": timed_out,
                        "complete": not timed_out and child.returncode == 0,
                        "test_harness_passed": not timed_out and child.returncode == 0,
                    }
                    raw = {"path": raw_path.name, "sha256": sha256(raw_path)}
                    active_process, active_log = process, raw
                    after = sha256(binary)
                    require(before == after == control["binary_sha256"],
                            f"{name}: binary changed during child")
                    require(process["complete"], f"{name}: child failed or timed out")
                    parsed = parse_worker_log(raw_path)
                    runs[name] = {
                        "run_id": name, "case_id": case_id,
                        "process_role": role, "configuration": configuration,
                        "cell": cell, "argv": command, "case_env": case_env,
                        "process": process, "raw_log": raw,
                        "binary_sha256_before": before,
                        "binary_sha256_after": after,
                        "source_sha": control["source_sha"],
                        **parsed,
                    }
                    active_name = None
        verify_final_closure(control, binary, control_dir, control_copy,
                             control_sha256)
        bundle = {
            "schema_version": 1,
            "qualification_status": "missing",
            "cell": cell,
            "manifest_sha256": sha256(MANIFEST),
            "source_sha": control["source_sha"],
            "binary_path": str(binary),
            "binary_sha256": control["binary_sha256"],
            "control_capture": {
                "path": "control/resource-control-capture.json",
                "sha256": control_sha256,
            },
            "runs": runs,
        }
        destination = evidence_dir / "finite-stack-capture.json"
        with destination.open("x") as output:
            json.dump(bundle, output, indent=2, sort_keys=True)
            output.write("\n")
        validate_bundle(bundle, evidence_dir)
    except Exception as error:
        with failure_path.open("x") as output:
            json.dump({"error": str(error), "active_run": active_name,
                       "active_process": active_process, "active_log": active_log,
                       "completed_runs": sorted(runs)}, output, indent=2, sort_keys=True)
            output.write("\n")
        raise
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell", required=True)
    parser.add_argument("--control-capture", type=Path, required=True)
    parser.add_argument("--control-sha256", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    args = parser.parse_args()
    path = capture(args.cell, args.control_capture, args.control_sha256,
                   args.evidence_dir, args.timeout_seconds)
    print(json.dumps({"capture_path": str(path), "sha256": sha256(path)},
                     sort_keys=True))


if __name__ == "__main__":
    main()
