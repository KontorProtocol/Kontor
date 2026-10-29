#!/usr/bin/env python3
"""Capture candidate v2 chain evidence with one registry record per child."""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from capture_resource_chain import (CROSS_MODE_FIXTURE_REASONS, STACK_MODES,
                                    WORKER_TEST, cross_mode_initial_states,
                                    parse_worker, verify_final_closure)
from capture_resource_control import run_bounded_process
from capture_resource_diagnostic import validate_control
from resource_evidence import file_evidence, load_json_strict, require, sha256
from resource_evidence_v2 import (HISTORICAL_BUNDLE_SHA256, expected_case_env,
                                  marker_positions, run_name, validate_bundle,
                                  validate_teardown)
from resource_manifest import MANIFEST as V1_MANIFEST
from resource_manifest import ROOT, build_manifest
from resource_manifest_v2 import MANIFEST, build_manifest_v2


def copy_control(control_path, control_sha256, evidence_dir, control):
    control_dir = evidence_dir / "control"
    control_dir.mkdir()
    entries = [control["cargo_artifacts"], control["cargo_metadata"],
               control["guard_control"]["raw_log"],
               *control["wasmtime_source_files"].values()]
    for entry in entries:
        source = control_path.parent / entry["path"]
        target = control_dir / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as original, target.open("xb") as destination:
            shutil.copyfileobj(original, destination)
        file_evidence(control_dir, entry)
    target = control_dir / "resource-control-capture.json"
    with control_path.open("rb") as original, target.open("xb") as destination:
        shutil.copyfileobj(original, destination)
    require(sha256(target) == control_sha256, "control copy changed")
    return control_dir, target


def capture(control_path, control_sha256, historical_path, evidence_dir,
            timeout_seconds, pilot):
    require(sys.platform == "linux", "v2 chain capture is Linux-only")
    require(platform.machine() == "aarch64", "this v2 slice requires Linux ARM64")
    require(1 <= timeout_seconds <= 1200, "timeout must be 1 to 1200 seconds")
    v1_manifest = build_manifest()
    v2_manifest = build_manifest_v2()
    require(load_json_strict(V1_MANIFEST) == v1_manifest
            and load_json_strict(MANIFEST) == v2_manifest,
            "source and resource manifests differ")
    require((v2_manifest["auxiliary_count_status"] == "pilot_pending") == pilot,
            "pilot flag differs from reviewed auxiliary fixture status")
    require(sha256(historical_path) == HISTORICAL_BUNDLE_SHA256,
            "historical phase10 bundle hash differs")
    control, binary = validate_control(control_path, control_sha256, v1_manifest)
    require(not evidence_dir.exists() or not any(evidence_dir.iterdir()),
            "evidence output directory is not empty")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    control_dir, control_copy = copy_control(
        control_path, control_sha256, evidence_dir, control)
    historical_copy = evidence_dir / "phase10-resource-chain-capture.json"
    with historical_path.open("rb") as original, historical_copy.open("xb") as destination:
        shutil.copyfileobj(original, destination)
    require(sha256(historical_copy) == HISTORICAL_BUNDLE_SHA256,
            "historical copy changed")
    v1_schema = load_json_strict(V1_MANIFEST.with_name("resource-evidence-schema-v1.json"))
    run_registry = {}
    failure_path = evidence_dir / "resource-chain-v2-failure.json"
    active_name = None
    active_process = None
    active_log = None
    try:
        for binding in v2_manifest["case_roles"]:
            case_id = binding["case_id"]
            role = binding["process_role"]
            stores = int(case_id.split("_")[1])
            chain_mode = case_id.split("_")[2]
            trap_control = role.startswith("trap_control")
            observed = role.endswith("observed")
            for configuration in STACK_MODES:
                name = run_name(case_id, role, configuration)
                active_name = name
                active_process = None
                active_log = None
                env_values = expected_case_env(case_id, role, configuration)
                environment = {key: value for key, value in os.environ.items()
                               if not key.startswith("KONTOR_")}
                environment.update(env_values)
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
                active_process = process
                active_log = raw
                after = sha256(binary)
                require(before == after == control["binary_sha256"],
                        f"{name}: binary changed during child")
                require(process["complete"], f"{name}: child failed or timed out")
                parsed = parse_worker(raw_path, configuration, stores, child.pid,
                                      v1_manifest, v1_schema, chain_mode,
                                      trap_control)
                report = parsed["report"]
                require(report["teardown_probe_mode"] ==
                        ("on" if observed else "off"),
                        f"{name}: probe role differs from child")
                role_counts = []
                for trial, observation in zip(report["trials"], parsed["observations"],
                                              strict=True):
                    if observed:
                        result = validate_teardown(trial["teardown_events"],
                                                   min(stores, 64), int(stores == 65))
                        observation["resource_cleanup"]["invocation_table_released"] = True
                    else:
                        require(trial["teardown_events"] is None,
                                f"{name}: probe-off child emitted teardown events")
                        result = None
                    role_counts.append(result)
                page = os.sysconf("SC_PAGE_SIZE")
                requested = report["async_stack_size"]
                run_registry[name] = {
                    "run_id": name, "case_id": case_id, "process_role": role,
                    "cell": "Linux-ARM64/dev", "configuration": configuration,
                    "process_attempt_index": 0, "argv": command,
                    "case_env": env_values, "process": process,
                    "timeout_seconds": timeout_seconds, "raw_log": raw,
                    "binary_sha256_before": before,
                    "binary_sha256_after": after,
                    "source_sha": control["source_sha"],
                    "manifest_sha256": sha256(MANIFEST),
                    "report": report, "runtime": parsed["runtime"],
                    "thread_trace": parsed["thread_trace"],
                    "worker_execution": parsed["worker_execution"],
                    "observations": parsed["observations"],
                    "markers": marker_positions(raw_path, report, role,
                                                configuration, child.pid),
                    "role_counts": role_counts,
                    "engine": {
                        "target": report["engine_target"],
                        "pulley_stack_bytes": report["max_wasm_stack"],
                        "fiber_requested_bytes": requested,
                        "page_size_bytes": page,
                        "fiber_effective_writable_bytes":
                            (requested + page - 1) // page * page,
                        "derivation_rule": "round_up_requested_bytes_to_host_page",
                    },
                }
                active_name = None
        verify_final_closure(control, binary, control_dir, control_copy, control_sha256)
        captured = {}
        for case_id in (item["id"] for item in v1_manifest["cases"]
                        if item["family"] == "distinct_contract_chain"):
            for configuration in STACK_MODES:
                key = run_name(case_id, "target_observed", configuration)
                captured[f"{case_id}_{configuration}"] = run_registry[key]
        cross_initial = cross_mode_initial_states(
            captured, CROSS_MODE_FIXTURE_REASONS)
        bundle = {
            "schema_version": 2, "status": "candidate_actual_binding",
            "qualification_status": "missing", "cell": "Linux-ARM64/dev",
            "source_sha": control["source_sha"],
            "manifest_sha256": sha256(MANIFEST),
            "binary_path": str(binary),
            "binary_sha256": control["binary_sha256"],
            "timeout_seconds": timeout_seconds,
            "control_capture": {"path": "control/resource-control-capture.json",
                                "sha256": control_sha256},
            "historical_reference": {"path": historical_copy.name,
                                     "sha256": HISTORICAL_BUNDLE_SHA256},
            "runs": run_registry,
            "remaining_case_bindings": v2_manifest["remaining_case_ids"],
            "auxiliary_count_status": v2_manifest["auxiliary_count_status"],
            "auxiliary_expected_counts": v2_manifest["auxiliary_expected_counts"],
            "cross_mode_initial_states": cross_initial,
        }
        destination = evidence_dir / "resource-chain-v2-capture.json"
        with destination.open("x") as output:
            json.dump(bundle, output, indent=2, sort_keys=True)
            output.write("\n")
        validate_bundle(bundle, evidence_dir, allow_pilot=pilot)
        return destination
    except Exception as error:
        with failure_path.open("x") as destination:
            json.dump({"error": str(error), "failed_run": active_name,
                       "failed_process": active_process, "failed_log": active_log,
                       "completed_runs": run_registry},
                      destination, indent=2, sort_keys=True)
            destination.write("\n")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-capture", type=Path, required=True)
    parser.add_argument("--control-sha256", required=True)
    parser.add_argument("--historical-bundle", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("--pilot", action="store_true")
    args = parser.parse_args()
    path = capture(args.control_capture, args.control_sha256,
                   args.historical_bundle, args.evidence_dir,
                   args.timeout_seconds, args.pilot)
    print(json.dumps({"capture_path": str(path), "sha256": sha256(path)},
                     sort_keys=True))


if __name__ == "__main__":
    main()
