#!/usr/bin/env python3
"""Preserve VM-region output from the existing macOS suspended-64 child."""

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path

from capture_resource_control import run_bounded_process
from resource_evidence import (load_json_strict, no_duplicate_keys,
                               no_nonfinite_constants, require, sha256)
from resource_finite_evidence import WORKER_TEST
from resource_manifest import build_manifest
from resource_pending_evidence import (MEMORY_PLAN, parse_worker_log,
                                       validate_suspended_64)


MARKER = "SUSPENDED_64_VMMAP:"
CELL = "macOS-ARM64/release"


CASE_ENV = {
    "KONTOR_FINITE_STACK_CASE": "pending_host_io",
    "KONTOR_FINITE_STACK_ROLE": "target_observed",
    "KONTOR_RESOURCE_MODE": "production",
    "KONTOR_RESOURCE_TEARDOWN_PROBE": "on",
    "KONTOR_SUSPENDED_64_VMMAP": "1",
}


def extract(log_path, control_path, binary_path, output_dir, expected_pid=None):
    control = load_json_strict(control_path)
    require(sha256(binary_path) == control["binary_sha256"],
            "diagnostic binary differs from guard control")
    parsed = parse_worker_log(log_path)
    runtime = parsed["runtime"]
    require(runtime["embedded_source_sha"] == control["source_sha"]
            and runtime["binary_sha256"] == control["binary_sha256"]
            and runtime["process_role"] == "target_observed"
            and runtime["configuration"] == "production",
            "diagnostic child source, binary, or production role differs")
    baseline = parsed["memory_baseline"]
    peak = parsed["memory_peak"]["memory"]
    require(baseline["os"] == peak["os"] == "macos"
            and baseline["pid"] == peak["pid"] == runtime["pid"]
            and (expected_pid is None or runtime["pid"] == expected_pid),
            "diagnostic memory PID or OS differs")
    lines = log_path.read_text().splitlines()
    markers = [(index, json.loads(line.split(MARKER, 1)[1],
                                  object_pairs_hook=no_duplicate_keys,
                                  parse_constant=no_nonfinite_constants))
               for index, line in enumerate(lines) if MARKER in line]
    records = [record for _, record in markers]
    memory_positions = {
        phase: [index for index, line in enumerate(lines)
                if line.startswith(f"SUSPENDED_64_{phase.upper()}:")]
        for phase in ("baseline", "peak", "completion")
    }
    require(len(records) == 2
            and [record.get("phase") for record in records] == ["baseline", "peak"]
            and all(len(positions) == 1 for positions in memory_positions.values())
            and memory_positions["baseline"][0] < markers[0][0]
            < memory_positions["peak"][0] < markers[1][0]
            < memory_positions["completion"][0],
            "diagnostic must contain ordered baseline and peak VM maps")
    output_dir.mkdir(parents=True, exist_ok=True)
    maps = {}
    for record in records:
        phase = record["phase"]
        require(set(record) == {"phase", "pid", "command", "exit_code",
                                "stdout_base64", "stdout_sha256",
                                "stderr_base64", "stderr_sha256"}
                and record["pid"] == runtime["pid"]
                and record["command"] == ["/usr/bin/vmmap", str(runtime["pid"])]
                and record["exit_code"] == 0,
                "diagnostic VM map identity or command differs")
        try:
            stdout = base64.b64decode(record["stdout_base64"], validate=True)
            stderr = base64.b64decode(record["stderr_base64"], validate=True)
        except binascii.Error as error:
            raise ValueError("diagnostic VM map encoding is invalid") from error
        require(0 < len(stdout) <= 16 * 1024 * 1024
                and hashlib.sha256(stdout).hexdigest() == record["stdout_sha256"]
                and hashlib.sha256(stderr).hexdigest() == record["stderr_sha256"],
                "diagnostic VM map raw bytes or digest differ")
        path = output_dir / f"vmmap-{phase}.txt"
        with path.open("xb") as output:
            output.write(stdout)
        stderr_path = output_dir / f"vmmap-{phase}.stderr"
        with stderr_path.open("xb") as output:
            output.write(stderr)
        maps[phase] = {"path": path.name, "sha256": sha256(path),
                       "stderr_path": stderr_path.name,
                       "stderr_sha256": sha256(stderr_path)}
    plan = load_json_strict(MEMORY_PLAN)
    mapped_peak = peak["mapped_reservation"]["bytes"]
    mapped_limit = plan["mapped_reservation_allowance_bytes"]
    run = {"process": {"pid": runtime["pid"]}, **parsed}
    try:
        validate_suspended_64(run, build_manifest(), CELL)
        gate = "passed"
    except ValueError as error:
        require(str(error) == "suspended-64 private, mapped, resident, or charged allowance exceeded"
                and mapped_peak > mapped_limit
                and max(0, peak["private"]["bytes"] - baseline["private"]["bytes"])
                    <= (plan["per_root_private_growth_allowance_bytes"]
                        + plan["shared_private_growth_allowance_bytes"])
                and peak["resident"]["bytes"] <= plan["resident_allowance_bytes"]
                and peak["accounted_scope"]["bytes"] <=
                    plan["accounted_scope_allowance_bytes"],
                f"diagnostic found an unexpected suspended-64 failure: {error}")
        gate = "absolute_mapped_allowance_exceeded"
    report = {
        "source_sha": control["source_sha"],
        "capture_script_sha256": sha256(Path(__file__)),
        "binary_sha256": control["binary_sha256"],
        "qualification_status": "missing",
        "cell": CELL,
        "pid": runtime["pid"],
        "raw_log": {"path": log_path.name, "sha256": sha256(log_path)},
        "vmmap": maps,
        "mapped_reservation": {
            "baseline_bytes": baseline["mapped_reservation"]["bytes"],
            "peak_bytes": mapped_peak,
            "completion_bytes": parsed["memory_completion"]["memory"]
                ["mapped_reservation"]["bytes"],
            "absolute_allowance_bytes": mapped_limit,
            "existing_gate_result": gate,
        },
    }
    path = output_dir / "suspended-64-vmmap-diagnostic.json"
    with path.open("x") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    return path


def capture(control_path, binary_path, output_dir, timeout_seconds):
    require(1 <= timeout_seconds <= 1200,
            "diagnostic child timeout must be 1 to 1200 seconds")
    control = load_json_strict(control_path)
    require(sha256(binary_path) == control["binary_sha256"],
            "diagnostic binary differs from guard control")
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / "suspended-64-vmmap.log"
    require(not log_path.exists(), "diagnostic raw log already exists")
    command = [str(binary_path.resolve()), "--ignored", "--exact",
               WORKER_TEST, "--nocapture"]
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("KONTOR_")}
    environment.update(CASE_ENV)
    child, started, ended, raw, timed_out = run_bounded_process(
        command, timeout_seconds, environment)
    with log_path.open("xb") as output:
        output.write(raw)
    process = {
        "command": command, "case_env": CASE_ENV, "pid": child.pid,
        "source_sha": control["source_sha"],
        "binary_sha256": control["binary_sha256"],
        "started_unix_ns": started, "ended_unix_ns": ended,
        "exit_code": child.returncode if child.returncode >= 0 else None,
        "signal": -child.returncode if child.returncode < 0 else None,
        "timed_out": timed_out, "timeout_seconds": timeout_seconds,
        "raw_log": {"path": log_path.name, "sha256": sha256(log_path)},
    }
    process_path = output_dir / "suspended-64-vmmap-process.json"
    with process_path.open("x") as output:
        json.dump(process, output, indent=2, sort_keys=True)
        output.write("\n")
    require(not timed_out and child.returncode == 0,
            "diagnostic child failed or timed out; raw log and process record preserved")
    return extract(log_path, control_path, binary_path, output_dir, child.pid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--control-capture", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=1200)
    args = parser.parse_args()
    if args.log is None:
        path = capture(args.control_capture, args.binary,
                       args.output_dir, args.timeout_seconds)
    else:
        path = extract(args.log, args.control_capture,
                       args.binary, args.output_dir)
    print(json.dumps({"path": str(path), "sha256": sha256(path)}, sort_keys=True))


if __name__ == "__main__":
    main()
