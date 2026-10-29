#!/usr/bin/env python3
"""Archive paired real paid worker diagnostics beside the guard/source closure."""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from capture_resource_control import (run_bounded_process, selected_binary,
                                      validate_build_attestation)
from resource_evidence import (check_guard_control, file_evidence, load_json_strict,
                               no_duplicate_keys, no_nonfinite_constants, require,
                               sha256, thread_capacities)
from resource_manifest import FIBER_SOURCE_FILES, MANIFEST, ROOT, build_manifest


TEST_NAME = "runtime::call::tests::native_stack_resource::real_paid_large_frame_on_tokio_worker"
PHASE_NAMES = (
    "fixture_preparation_entry", "publication_entry", "publication_exit",
    "fixture_preparation_exit", "sample_preparation_entry", "sample_preparation_exit",
    "operation_entry", "operation_exit", "postcall_observation_entry",
    "postcall_observation_exit", "teardown_entry", "teardown_exit",
)
PAIRS = (("compiler_entry", "compiler_exit", "tokio_worker"),
         ("blocking_decode_entry", "blocking_decode_exit", "blocking_pool"))


def one_marker(lines, marker):
    matches = [(index, line.split(marker, 1)[1]) for index, line in enumerate(lines)
               if marker in line]
    require(len(matches) == 1, f"expected one {marker} record")
    return matches[0][0], json.loads(matches[0][1], object_pairs_hook=no_duplicate_keys,
                                      parse_constant=no_nonfinite_constants)


def parse_worker_log(raw_path, mode, pid, os_name="linux"):
    lines = raw_path.read_text().splitlines()
    require(sum(line.strip() == "running 1 test" for line in lines) == 1,
            f"{mode}: worker transcript lacks one selected test")
    harness = [index for index, line in enumerate(lines)
               if re.fullmatch(
                   r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s",
                   line)]
    require(len(harness) == 1, f"{mode}: worker test harness did not pass")
    trace_pos, trace = one_marker(lines, "KONTOR_RESOURCE_THREAD_TRACE=")
    runtime_pos, runtime = one_marker(lines, "KONTOR_RESOURCE_RUNTIME=")
    require(trace_pos < runtime_pos < harness[0],
            f"{mode}: runtime or trace marker is out of order")
    require(isinstance(runtime, dict) and set(runtime) == {
        "scope", "mode", "pid", "flavor", "worker_count", "worker_requested_bytes",
        "thread_observations", "blocking_pool_observed", "block_on_caller_observed",
    } and runtime["scope"] == "diagnostic_only" and runtime["mode"] == mode
            and runtime["pid"] == pid, f"{mode}: runtime identity differs from process")
    capacities = {key: value for key, value in runtime.items()
                  if key not in {"scope", "mode", "pid"}}
    by_category = thread_capacities(capacities, mode, os.sysconf("SC_PAGE_SIZE"),
                                    os_name, pid)
    workers = {thread["thread_id"]: thread["os_thread_id"]
               for thread in by_category["tokio_worker"]}
    blocking = {thread["thread_id"]: thread["os_thread_id"]
                for thread in by_category["blocking_pool"]}
    require(isinstance(trace, dict) and set(trace) == {
        "scope", "mode", "compiler_internal_threads", "events",
    } and trace["scope"] == "diagnostic_only" and trace["mode"] == mode
            and trace["compiler_internal_threads"] == "unobserved"
            and isinstance(trace["events"], list),
            f"{mode}: thread trace identity is incomplete")
    allowed = set(PHASE_NAMES) | {name for entry, exit, _ in PAIRS for name in (entry, exit)}
    for event in trace["events"]:
        require(isinstance(event, dict) and set(event) == {
            "name", "rust_thread_id", "category", "os_thread_id",
        } and event["name"] in allowed
                and isinstance(event["rust_thread_id"], str)
                and type(event["os_thread_id"]) is int and event["os_thread_id"] > 0,
                f"{mode}: thread trace has an unclassified event")
        if event["category"] == "tokio_worker":
            require(workers.get(event["rust_thread_id"]) == event["os_thread_id"],
                    f"{mode}: trace worker differs from measured capacity")
        else:
            require(event["category"] == "blocking_pool"
                    and event["rust_thread_id"] not in workers
                    and event["os_thread_id"] not in workers.values(),
                    f"{mode}: blocking trace overlaps measured workers")
    names = [event["name"] for event in trace["events"]]
    positions = []
    for name in PHASE_NAMES:
        require(names.count(name) == 1, f"{mode}: {name} is missing or duplicated")
        index = names.index(name)
        require(trace["events"][index]["category"] == "tokio_worker",
                f"{mode}: {name} escaped Tokio worker")
        positions.append(index)
    require(positions == sorted(positions), f"{mode}: worker phases are out of order")
    for entry, exit, category in PAIRS:
        require(names.count(entry) > 0 and names.count(entry) == names.count(exit),
                f"{mode}: {entry}/{exit} count differs")
        in_flight = {}
        for event in trace["events"]:
            if event["name"] == entry:
                thread = event["rust_thread_id"]
                require(thread not in in_flight and event["category"] == category,
                        f"{mode}: overlapping or misplaced {entry}")
                in_flight[thread] = event["os_thread_id"]
            elif event["name"] == exit:
                thread = event["rust_thread_id"]
                require(in_flight.pop(thread, None) == event["os_thread_id"]
                        and event["category"] == category,
                        f"{mode}: unmatched or misplaced {exit}")
        require(not in_flight, f"{mode}: unclosed {entry}")
    uncovered = sorted({event["os_thread_id"] for event in trace["events"]
                        if event["category"] == "blocking_pool"
                        and blocking.get(event["rust_thread_id"]) != event["os_thread_id"]})
    return runtime, trace, uncovered


def validate_control(path, expected_sha256, manifest, page_size=None):
    require(sys.platform in ("linux", "darwin"), "unsupported resource diagnostic host")
    os_name = "macos" if sys.platform == "darwin" else "linux"
    require(sha256(path) == expected_sha256, "control capture hash changed")
    control = load_json_strict(path)
    require(set(control) == {
        "manifest_sha256", "source_sha", "binary_path", "binary_sha256",
        "cargo_artifact", "cargo_artifacts", "cargo_metadata",
        "build_attestation", "build_log", "fastnum_files", "guard_control",
        "wasmtime_source_files",
    } and control["manifest_sha256"] == sha256(MANIFEST),
            "control capture differs from resource manifest")
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"],
                           check=True, capture_output=True, text=True).stdout
    require(control["source_sha"] == head and not dirty,
            "control source revision differs from checkout")
    directory = path.parent
    for entry in (control["cargo_artifacts"], control["cargo_metadata"],
                  control["build_attestation"], control["build_log"],
                  control["guard_control"]["raw_log"],
                  *control["fastnum_files"].values()):
        file_evidence(directory, entry)
    require(set(control["wasmtime_source_files"]) == set(FIBER_SOURCE_FILES),
            "control capture lacks pinned fiber sources")
    for relative, entry in control["wasmtime_source_files"].items():
        require(entry["sha256"] == FIBER_SOURCE_FILES[relative],
                f"fiber source hash differs: {relative}")
        file_evidence(directory, entry)
    paths = [entry["path"] for entry in (control["cargo_artifacts"],
             control["cargo_metadata"], control["build_attestation"],
             control["build_log"], control["guard_control"]["raw_log"],
             *control["fastnum_files"].values(),
             *control["wasmtime_source_files"].values())]
    require(len(paths) == len(set(paths)) and path.name not in paths,
            "control evidence file paths overlap")
    metadata = load_json_strict(directory / control["cargo_metadata"]["path"])
    require(metadata["workspace_root"] == str(ROOT / "core"),
            "control Cargo workspace differs from checkout")
    binary, artifact = selected_binary(directory / control["cargo_artifacts"]["path"], metadata)
    require(str(binary) == control["binary_path"] and artifact == control["cargo_artifact"]
            and sha256(binary) == control["binary_sha256"],
            "control Cargo artifact or binary differs")
    attestation, build_log = validate_build_attestation(
        directory / control["build_attestation"]["path"],
        directory / control["cargo_artifacts"]["path"],
        directory / control["cargo_metadata"]["path"],
        control["source_sha"], manifest, binary, artifact)
    require(build_log == directory / control["build_log"]["path"],
            "control Cargo build log path differs from attestation")
    require(control["fastnum_files"] == {
        "build_script": attestation["fastnum_build_script"],
        **attestation["fastnum_generated"],
    }, "control fastnum source or generated setting differs from build")
    page = page_size if page_size is not None else os.sysconf("SC_PAGE_SIZE")
    report_view = {
        "host": {"os": os_name}, "binary_path": str(binary),
        "binary_sha256": control["binary_sha256"], "source_sha": control["source_sha"],
        "configurations": {mode: {"engine": {"page_size_bytes": page},
                                 "process_log": {"path": f"{mode}-worker.log"}}
                           for mode in ("reduced", "production")},
        "guard_control": control["guard_control"],
    }
    check_guard_control(report_view, manifest, directory)
    return control, binary


def capture(control_path, control_sha256, evidence_dir, timeout_seconds):
    if sys.platform not in ("linux", "darwin"):
        raise ValueError("paired resource diagnostic is unsupported on this host")
    os_name = "macos" if sys.platform == "darwin" else "linux"
    manifest = build_manifest()
    require(load_json_strict(MANIFEST) == manifest, "resource manifest changed")
    control, binary = validate_control(control_path, control_sha256, manifest)
    if evidence_dir.exists() and any(evidence_dir.iterdir()):
        raise ValueError("diagnostic evidence output directory is not empty")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    control_dir = evidence_dir / "control"
    control_dir.mkdir()
    control_entries = [control["cargo_artifacts"], control["cargo_metadata"],
                       control["build_attestation"], control["build_log"],
                       control["guard_control"]["raw_log"],
                       *control["fastnum_files"].values(),
                       *control["wasmtime_source_files"].values()]
    for entry in control_entries:
        source = control_path.parent / entry["path"]
        destination = control_dir / entry["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as original, destination.open("xb") as target:
            shutil.copyfileobj(original, target)
        file_evidence(control_dir, entry)
    control_copy = control_dir / "resource-control-capture.json"
    with control_path.open("rb") as original, control_copy.open("xb") as target:
        shutil.copyfileobj(original, target)
    require(sha256(control_copy) == control_sha256, "control capture copy changed")
    modes = {}
    failure_path = evidence_dir / "resource-diagnostic-failure.json"
    for mode in ("reduced", "production"):
        command = [str(binary), "--ignored", "--exact", TEST_NAME, "--nocapture"]
        environment = os.environ.copy()
        environment["KONTOR_RESOURCE_MODE"] = mode
        child, started, ended, output, timed_out = run_bounded_process(
            command, timeout_seconds, environment,
        )
        raw_path = evidence_dir / f"{mode}-worker.log"
        with raw_path.open("xb") as destination:
            destination.write(output)
        process = {
            "pid": child.pid, "command": command,
            "started_unix_ns": started, "ended_unix_ns": ended,
            "exit_code": child.returncode if child.returncode >= 0 else None,
            "signal": -child.returncode if child.returncode < 0 else None,
            "timed_out": timed_out, "complete": not timed_out and child.returncode == 0,
            "test_harness_passed": not timed_out and child.returncode == 0,
        }
        try:
            require(not timed_out and child.returncode == 0,
                    f"{mode}: worker process failed or timed out")
            runtime, trace, uncovered = parse_worker_log(raw_path, mode, child.pid, os_name)
            require(sha256(binary) == control["binary_sha256"],
                    f"{mode}: selected binary changed during diagnostic")
            modes[mode] = {
                "process": process,
                "raw_log": {"path": raw_path.name, "sha256": sha256(raw_path)},
                "runtime": runtime,
                "thread_trace": trace,
                "blocking_trace_unmeasured_os_thread_ids": uncovered,
            }
        except Exception as error:
            with failure_path.open("x") as destination:
                json.dump({"error": str(error), "failed_mode": mode,
                           "process": process, "raw_log": {"path": raw_path.name,
                           "sha256": sha256(raw_path)}, "completed_modes": modes},
                          destination, indent=2, sort_keys=True)
                destination.write("\n")
            raise
    try:
        processes = [control["guard_control"]["process"],
                     modes["reduced"]["process"], modes["production"]["process"]]
        require(len({(process["pid"], process["started_unix_ns"])
                     for process in processes}) == 3,
                "guard and worker controls did not use distinct processes")
        final_head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                                    check=True, capture_output=True, text=True).stdout.strip()
        final_dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"],
                                     check=True, capture_output=True, text=True).stdout
        require(final_head == control["source_sha"] and not final_dirty
                and sha256(MANIFEST) == control["manifest_sha256"],
                "source closure changed during paired diagnostic")
    except Exception as error:
        with failure_path.open("x") as destination:
            json.dump({"error": str(error), "completed_modes": modes},
                      destination, indent=2, sort_keys=True)
            destination.write("\n")
        raise
    bundle = {
        "status": "diagnostic_only",
        "qualification_status": "missing",
        "source_sha": control["source_sha"],
        "binary_path": str(binary),
        "binary_sha256": control["binary_sha256"],
        "manifest_sha256": sha256(MANIFEST),
        "control_capture": {"path": "control/resource-control-capture.json",
                            "sha256": control_sha256},
        "configurations": modes,
        "unmet_requirements": {
            "paired_case_bindings": sum(case["paired_worker_status"] != "ready"
                                        for case in manifest["cases"]),
            "workload_plan": manifest["workload_plan"]["status"],
            "attestation": manifest["attestation_status"],
            "macos_guard": "diagnostic_only" if os_name == "macos" else "missing",
            "production_memory_profiles": "missing",
        },
    }
    destination = evidence_dir / "resource-diagnostic-capture.json"
    with destination.open("x") as target:
        json.dump(bundle, target, indent=2, sort_keys=True)
        target.write("\n")
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-capture", type=Path, required=True)
    parser.add_argument("--control-sha256", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 600:
        parser.error("timeout must be between 1 and 600 seconds")
    path = capture(args.control_capture, args.control_sha256,
                   args.evidence_dir, args.timeout_seconds)
    print(json.dumps({"capture_path": str(path), "sha256": sha256(path)}, sort_keys=True))


if __name__ == "__main__":
    main()
