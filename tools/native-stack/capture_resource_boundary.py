#!/usr/bin/env python3
"""Capture isolated Pulley boundary and deepest host-call worker children."""

import argparse
import json
import os
import platform
import shutil
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from capture_resource_chain import verify_final_closure
from capture_resource_chain_v2 import copy_control
from capture_resource_control import run_bounded_process
from capture_resource_diagnostic import validate_control
from resource_boundary_evidence import (TEST_NAME, expected_case_env,
                                        parse_worker_log, run_name,
                                        validate_bundle, validate_cell_identity,
                                        validate_reviewed_discovery)
from resource_boundary_manifest import (CONFIGURATIONS, DISCOVERY_CELL,
                                        DISCOVERY_ROLE, FINAL_ROLES, MANIFEST,
                                        build_boundary_manifest)
from resource_evidence import load_json_strict, require, sha256
from resource_manifest import MANIFEST as V1_MANIFEST
from resource_manifest import build_manifest


def capture(phase, cell, discovery_path, discovery_sha256,
            reviewed_path, reviewed_sha256,
            control_path, control_sha256,
            evidence_dir, timeout_seconds):
    require(sys.platform in {"linux", "darwin"},
            "boundary child capture requires a supported guard control")
    require(cell in {"Linux-ARM64/dev", "Linux-ARM64/release",
                     "Linux-X64/dev", "Linux-X64/release",
                     "macOS-ARM64/dev", "macOS-ARM64/release"},
            "unsupported local boundary cell")
    actual_arch = {"aarch64": "ARM64", "arm64": "ARM64",
                   "x86_64": "X64"}.get(platform.machine())
    actual_os = "macOS" if sys.platform == "darwin" else "Linux"
    require(cell.startswith(f"{actual_os}-{actual_arch}/"),
            "boundary cell architecture differs from local host")
    require(1 <= timeout_seconds <= 1200,
            "boundary child timeout must be 1 to 1200 seconds")
    require(phase == "final" or cell == DISCOVERY_CELL,
            "development discovery and pilot require Linux-ARM64/dev")
    v1_manifest = build_manifest()
    manifest = build_boundary_manifest()
    require(load_json_strict(V1_MANIFEST) == v1_manifest
            and load_json_strict(MANIFEST) == manifest,
            "source and boundary manifests differ")
    require(phase != "final" or manifest["claim_status"] == "candidate_only",
            "final capture requires reviewed frozen depths")
    require((discovery_path is not None and discovery_sha256 is not None)
            == (phase == "pilot_replay"),
            "pilot replay alone requires a pinned discovery capture")
    require((reviewed_path is not None and reviewed_sha256 is not None)
            == (phase == "final"),
            "final capture requires a reviewed discovery archive")
    control, binary = validate_control(
        control_path, control_sha256, v1_manifest)
    validate_cell_identity(cell, control["cargo_artifact"])
    if reviewed_path is not None:
        validate_reviewed_discovery(reviewed_path, reviewed_sha256,
                                    manifest, control["source_sha"])
    pilot_depths = {}
    if discovery_path is not None:
        require(sha256(discovery_path) == discovery_sha256,
                "pilot discovery capture hash differs")
        development = load_json_strict(discovery_path)
        require(development["phase"] == "pilot_discovery"
                and development["source_sha"] == control["source_sha"]
                and development["binary_sha256"] == control["binary_sha256"]
                and development["manifest_sha256"] == sha256(MANIFEST),
                "pilot discovery source or binary differs")
        validate_bundle(development, discovery_path.parent)
        pilot_depths = development["discovered_depths"]
    require(not evidence_dir.exists() or not any(evidence_dir.iterdir()),
            "boundary evidence output directory is not empty")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    control_dir, control_copy = copy_control(
        control_path, control_sha256, evidence_dir, control)
    discovery_binary = None
    if phase in ("discovery", "pilot_discovery"):
        snapshot = evidence_dir / "discovery-indexer-test"
        with binary.open("rb") as original, snapshot.open("xb") as target:
            shutil.copyfileobj(original, target)
        require(sha256(snapshot) == control["binary_sha256"],
                "discovery binary snapshot differs from Cargo artifact")
        discovery_binary = {"path": snapshot.name,
                            "sha256": control["binary_sha256"]}
    discovery_reference = None
    if discovery_path is not None:
        nested = evidence_dir / "development_discovery"
        require(not evidence_dir.resolve().is_relative_to(
            discovery_path.parent.resolve()),
            "pilot replay output cannot be inside discovery archive")
        shutil.copytree(discovery_path.parent, nested)
        discovery_copy = nested / discovery_path.name
        require(sha256(discovery_copy) == discovery_sha256,
                "archived pilot discovery capture changed")
        discovery_reference = {
            "path": str(Path("development_discovery") / discovery_path.name),
            "sha256": discovery_sha256,
        }
    reviewed_reference = None
    if reviewed_path is not None:
        nested = evidence_dir / "reviewed_discovery"
        require(not evidence_dir.resolve().is_relative_to(
            reviewed_path.parent.resolve()),
            "final output cannot be inside reviewed discovery archive")
        shutil.copytree(reviewed_path.parent, nested)
        reviewed_copy = nested / reviewed_path.name
        require(sha256(reviewed_copy) == reviewed_sha256,
                "archived reviewed discovery changed")
        reviewed_reference = {
            "path": str(Path("reviewed_discovery") / reviewed_path.name),
            "sha256": reviewed_sha256,
        }
    frozen = {
        case["case_id"]: (case["last_success"], case["first_failure"])
        for case in manifest["boundary_cases"]
    }
    frozen["deepest_frame_host_call"] = (
        manifest["leaf_case"]["last_success"],
        manifest["leaf_case"]["first_failure"],
    )
    if phase in ("pilot_discovery", "discovery"):
        selected = (["pulley_plain_paid", "pulley_wide_paid",
                     "deepest_frame_host_call"]
                    if phase == "pilot_discovery" else sorted(frozen))
        matrix = [(case_id, DISCOVERY_ROLE, "production")
                  for case_id in selected]
    elif phase == "pilot_replay":
        matrix = [(case_id, role, configuration)
                  for case_id in sorted(pilot_depths)
                  for configuration in CONFIGURATIONS for role in FINAL_ROLES]
    else:
        matrix = [(case_id, role, configuration)
                  for case_id in sorted(frozen)
                  for configuration in CONFIGURATIONS for role in FINAL_ROLES]
    runs = {}
    discovered = dict(pilot_depths)
    active_name = None
    active_process = None
    active_log = None
    try:
        for case_id, role, configuration in matrix:
            name = run_name(case_id, role, configuration)
            active_name = name
            active_process = None
            active_log = None
            if role == DISCOVERY_ROLE:
                depths = None
            elif phase == "pilot_replay":
                values = pilot_depths[case_id]
                depths = (values["last_success"], values["first_failure"])
            else:
                depths = frozen[case_id]
            env_values = expected_case_env(case_id, role, configuration, depths)
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith("KONTOR_")}
            environment.update(env_values)
            command = [str(binary), "--ignored", "--exact", TEST_NAME, "--nocapture"]
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
            if role == DISCOVERY_ROLE:
                summary = parsed["summary"]
                discovered[case_id] = {
                    "last_success": summary["last_success"],
                    "first_failure": summary["first_failure"],
                }
            runs[name] = {
                "run_id": name, "case_id": case_id,
                "process_role": role, "configuration": configuration,
                "cell": cell, "argv": command, "case_env": env_values,
                "process": process, "raw_log": raw,
                "binary_sha256_before": before,
                "binary_sha256_after": after,
                "source_sha": control["source_sha"],
                "manifest_sha256": sha256(MANIFEST),
                "timeout_seconds": timeout_seconds,
                "summary": parsed["summary"],
                "runtime": parsed["runtime"],
                "thread_trace": parsed["thread_trace"],
                "attempts": parsed["attempts"],
                "timings": parsed["timings"],
            }
            active_name = None
        verify_final_closure(control, binary, control_dir, control_copy,
                             control_sha256)
        remaining = {case["id"] for case in v1_manifest["cases"]
                     if case["family"] != "distinct_contract_chain"}
        if phase == "final":
            remaining -= set(frozen)
            discovered = {}
        bundle = {
            "schema_version": 1,
            "phase": phase,
            "qualification_status": "missing",
            "cell": cell,
            "manifest_sha256": sha256(MANIFEST),
            "source_sha": control["source_sha"],
            "binary_path": str(binary),
            "binary_sha256": control["binary_sha256"],
            "timeout_seconds": timeout_seconds,
            "control_capture": {
                "path": "control/resource-control-capture.json",
                "sha256": control_sha256,
            },
            "development_discovery": discovery_reference,
            "reviewed_discovery": reviewed_reference,
            "discovery_binary": discovery_binary,
            "runs": runs,
            "discovered_depths": discovered,
            "remaining_case_bindings": sorted(remaining),
        }
        destination = evidence_dir / "resource-boundary-capture.json"
        with destination.open("x") as output:
            json.dump(bundle, output, indent=2, sort_keys=True)
            output.write("\n")
        validate_bundle(bundle, evidence_dir)
        return destination
    except Exception as error:
        with (evidence_dir / "resource-boundary-failure.json").open("x") as output:
            json.dump({"error": str(error), "failed_run": active_name,
                       "failed_process": active_process,
                       "failed_log": active_log,
                       "completed_runs": runs}, output,
                      indent=2, sort_keys=True)
            output.write("\n")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", required=True,
                        choices=("pilot_discovery", "discovery",
                                 "pilot_replay", "final"))
    parser.add_argument("--cell", default=DISCOVERY_CELL)
    parser.add_argument("--pilot-discovery-capture", type=Path)
    parser.add_argument("--pilot-discovery-sha256")
    parser.add_argument("--reviewed-discovery-capture", type=Path)
    parser.add_argument("--reviewed-discovery-sha256")
    parser.add_argument("--control-capture", required=True, type=Path)
    parser.add_argument("--control-sha256", required=True)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    args = parser.parse_args()
    path = capture(args.phase, args.cell,
                   args.pilot_discovery_capture,
                   args.pilot_discovery_sha256,
                   args.reviewed_discovery_capture,
                   args.reviewed_discovery_sha256,
                   args.control_capture,
                   args.control_sha256, args.evidence_dir,
                   args.timeout_seconds)
    print(json.dumps({"capture_path": str(path), "sha256": sha256(path)},
                     sort_keys=True))


if __name__ == "__main__":
    main()
