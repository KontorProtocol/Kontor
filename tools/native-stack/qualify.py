#!/usr/bin/env python3
"""Measure native Wasm stack outcomes through Kontor's real contract runtime."""

import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
from pathlib import Path


TEST_NAME = "runtime::call::tests::native_stack::qualification_probe"
DEFAULT_CASES = (
    "paid_recurse",
    "paid_wide",
    "view_recurse",
    "view_wide",
    "system_recurse",
    "system_wide",
    "core_recurse",
    "core_wide",
    "paid_reenter",
    "paid_huge",
)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_probe(binary, kind, depth, output, timeout):
    environment = os.environ.copy()
    environment["KONTOR_STACK_KIND"] = kind
    environment["KONTOR_STACK_DEPTH"] = str(depth)
    command = [str(binary), "--ignored", "--exact", TEST_NAME, "--nocapture"]
    log = output / f"{kind}-{depth}.log"
    try:
        completed = subprocess.run(
            command,
            env=environment,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        log.write_bytes(stdout + stderr)
        return {"kind": kind, "depth": depth, "outcome": "timeout", "log": log.name}
    log.write_text(completed.stdout + completed.stderr)
    reports = [
        line.split("KONTOR_STACK_REPORT:", 1)[1]
        for line in completed.stdout.splitlines()
        if "KONTOR_STACK_REPORT:" in line
    ]
    if completed.returncode == 0 and len(reports) == 1:
        result = json.loads(reports[0])
        result["log"] = log.name
        return result
    if completed.returncode < 0:
        try:
            name = signal.Signals(-completed.returncode).name
        except ValueError:
            name = f"SIG{-completed.returncode}"
        outcome = "process_signal"
    else:
        name = None
        outcome = "test_failure"
    return {
        "kind": kind,
        "depth": depth,
        "outcome": outcome,
        "returncode": completed.returncode,
        "signal": name,
        "log": log.name,
    }


def find_boundary(binary, kind, output, max_depth, initial_depth, timeout):
    observations = []

    def observe(depth):
        result = run_probe(binary, kind, depth, output, timeout)
        observations.append(result)
        print(f"{kind} depth={depth} outcome={result['outcome']}", flush=True)
        return result

    initial = observe(0)
    if initial["outcome"] != "ok":
        return {"kind": kind, "boundary": "failed_at_zero", "observations": observations}
    if max_depth == 0:
        return {
            "kind": kind,
            "boundary": "no_failure_up_to_limit",
            "last_success": 0,
            "observations": observations,
        }
    last_success = 0
    depth = min(initial_depth, max_depth)
    while depth <= max_depth:
        result = observe(depth)
        if result["outcome"] != "ok":
            first_failure = depth
            break
        last_success = depth
        depth *= 2
    else:
        if last_success < max_depth:
            result = observe(max_depth)
            if result["outcome"] != "ok":
                first_failure = max_depth
            else:
                last_success = max_depth
        if last_success == max_depth:
            return {
                "kind": kind,
                "boundary": "no_failure_up_to_limit",
                "last_success": last_success,
                "observations": observations,
            }
    while first_failure - last_success > 1:
        midpoint = (first_failure + last_success) // 2
        result = observe(midpoint)
        if result["outcome"] == "ok":
            last_success = midpoint
        else:
            first_failure = midpoint
    return {
        "kind": kind,
        "boundary": "first_failure",
        "last_success": last_success,
        "first_failure": first_failure,
        "first_failure_outcome": next(
            result["outcome"]
            for result in reversed(observations)
            if result["depth"] == first_failure
        ),
        "observations": observations,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--case", action="append", choices=DEFAULT_CASES)
    parser.add_argument("--max-depth", type=int, default=32768)
    parser.add_argument("--max-reentry-depth", type=int, default=32)
    parser.add_argument("--initial-depth", type=int, default=1024)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.initial_depth < 1 or args.max_depth < 0 or args.max_reentry_depth < 0:
        parser.error("depth limits must be nonnegative and initial depth must be positive")
    args.output.mkdir(parents=True, exist_ok=True)
    cases = args.case or DEFAULT_CASES
    results = []
    for kind in cases:
        if kind == "paid_huge":
            result = run_probe(args.binary, kind, 0, args.output, args.timeout)
            print(f"{kind} outcome={result['outcome']}", flush=True)
        else:
            max_depth = args.max_reentry_depth if kind == "paid_reenter" else args.max_depth
            result = find_boundary(
                args.binary, kind, args.output, max_depth, args.initial_depth, args.timeout
            )
        results.append(result)
    report = {
        "binary": str(args.binary),
        "binary_sha256": sha256_file(args.binary),
        "rustc_version_verbose": subprocess.check_output(
            ["rustc", "--version", "--verbose"], text=True
        ),
        "host": platform.platform(),
        "cases": results,
    }
    (args.output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    if any(result.get("boundary") == "failed_at_zero" for result in results):
        return 1
    if any(
        observation["outcome"] not in {"ok", "stack_overflow", "out_of_fuel"}
        for result in results
        for observation in result.get("observations", [result])
    ):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
