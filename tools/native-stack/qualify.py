#!/usr/bin/env python3
"""Measure native Wasm stack outcomes through Kontor's real contract runtime."""

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

from sweep import REPORT_PREFIX, parse_transcript, validate_pair


TEST_NAME = "runtime::call::tests::native_stack::qualification_probe"
OWNED_TEST_NAME = "runtime::call::tests::native_stack::owned_stack_control"
OWNERSHIP_TESTS = (
    "canonical_lease_drains_native_guest_before_releasing_runtime",
    "canonical_and_simulation_children_keep_no_yield_policy",
    "nested_api_children_inherit_actual_fuel_yields",
    "cancelling_nested_yielding_api_guest_joins_before_runtime_reuse",
    "cancelling_fuel_yielding_guest_joins_before_pool_reuse",
)
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
TARGETS = {
    "Linux-X64": "x86_64-unknown-linux-gnu",
    "Linux-ARM64": "aarch64-unknown-linux-gnu",
    "macOS-ARM64": "aarch64-apple-darwin",
}


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_identity():
    source_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if subprocess.check_output(["git", "status", "--porcelain"], text=True).strip():
        raise ValueError("qualification source worktree is dirty")
    return source_sha


def resolved_features(target, edges, output):
    command = [
        "cargo", "tree", "--locked", "--offline", "--manifest-path", "core/Cargo.toml",
        "-p", "indexer", "-e", edges, "-i", "wasmtime", "-f", "{f}",
        "--depth", "0", "--target", target,
    ]
    raw = subprocess.check_output(command, text=True)
    output.write_text(raw)
    lines = raw.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise ValueError(f"unexpected Wasmtime feature resolution for {edges}")
    features = lines[0].split(",")
    if len(features) != len(set(features)) or any(not feature for feature in features):
        raise ValueError(f"invalid Wasmtime feature resolution for {edges}")
    return sorted(features)


def run_sweep(binary, kind, role, output, timeout, max_depth, initial_depth, depths=None):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("KONTOR_STACK_")}
    environment.update({
        "KONTOR_STACK_MODE": role,
        "KONTOR_STACK_KIND": kind,
        "KONTOR_STACK_MAX_DEPTH": str(max_depth),
        "KONTOR_STACK_INITIAL_DEPTH": str(initial_depth),
    })
    if depths is not None:
        environment["KONTOR_STACK_CONTROL_DEPTHS"] = ",".join(map(str, depths))
    command = [str(binary), "--ignored", "--exact", TEST_NAME, "--nocapture"]
    log = output / f"{kind}-{role}.log"
    try:
        completed = subprocess.run(
            command, env=environment, text=True, capture_output=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout or b"", error.stderr or b""
        log.write_bytes(
            (stdout.encode() if isinstance(stdout, str) else stdout)
            + (stderr.encode() if isinstance(stderr, str) else stderr)
        )
        raise ValueError(f"{kind} {role}: process timed out; see {log}") from error
    raw = completed.stdout + completed.stderr
    log.write_text(raw)
    if completed.returncode != 0:
        raise ValueError(f"{kind} {role}: process exited {completed.returncode}; see {log}")
    observations, summary = parse_transcript(raw, kind, role)
    for sample in observations:
        sample_log = output / f"{kind}-{role}-{sample['sample_index']:04}.log"
        sample_log.write_text(REPORT_PREFIX + json.dumps(sample) + "\n")
        sample["log"] = sample_log.name
    print(f"{kind} {role}: {len(observations)} samples, {summary['boundaries']}", flush=True)
    return observations, summary, log.name


def qualify_case(binary, kind, output, timeout, max_depth, initial_depth):
    observations, summary, worker_log = run_sweep(
        binary, kind, "worker", output, timeout, max_depth, initial_depth,
    )
    boundaries = summary["boundaries"]
    depths = [0] if kind == "paid_huge" else [boundaries["last_success"], boundaries["first_failure"]]
    control, control_summary, control_log = run_sweep(
        binary, kind, "control", output, timeout, max_depth, initial_depth, depths,
    )
    validate_pair(observations, summary, control, control_summary)
    owned_observations, owned_summary, owned_log = run_owned_control(
        binary, kind, depths, output, timeout,
    )
    return {
        "kind": kind, "boundary": "bounded" if kind == "paid_huge" else "first_failure",
        **({} if kind == "paid_huge" else boundaries),
        "observations": observations, "worker_summary": summary, "worker_log": worker_log,
        "control_observations": control, "control_summary": control_summary, "control_log": control_log,
        "owned_observations": owned_observations, "owned_summary": owned_summary, "owned_log": owned_log,
    }


def run_owned_control(binary, kind, depths, output, timeout):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("KONTOR_")}
    environment.update({
        "KONTOR_STACK_KIND": kind,
        "KONTOR_OWNED_DEPTHS": ",".join(map(str, depths)),
    })
    log = output / f"{kind}-owned.log"
    try:
        completed = subprocess.run(
            [str(binary), "--ignored", "--exact", OWNED_TEST_NAME, "--nocapture"],
            env=environment, text=True, capture_output=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout or b"", error.stderr or b""
        log.write_bytes(
            (stdout.encode() if isinstance(stdout, str) else stdout)
            + (stderr.encode() if isinstance(stderr, str) else stderr)
        )
        raise ValueError(f"{kind} owned: process timed out; see {log}") from error
    raw = completed.stdout + completed.stderr
    log.write_text(raw)
    if completed.returncode != 0:
        raise ValueError(f"{kind} owned: process exited {completed.returncode}; see {log}")
    observations = [
        json.loads(line.split("KONTOR_OWNED_STACK_REPORT:", 1)[1])
        for line in raw.splitlines() if line.startswith("KONTOR_OWNED_STACK_REPORT:")
    ]
    summaries = [
        json.loads(line.split("KONTOR_OWNED_STACK_SUMMARY:", 1)[1])
        for line in raw.splitlines() if line.startswith("KONTOR_OWNED_STACK_SUMMARY:")
    ]
    if len(observations) != len(depths) or len(summaries) != 1:
        raise ValueError(f"{kind} owned: missing or duplicate evidence")
    summary = summaries[0]
    if summary != {
        "kind": kind, "depths": depths,
        "outcomes": [sample["outcome"] for sample in observations], "owned": True,
    }:
        raise ValueError(f"{kind} owned: summary differs from observations")
    return observations, summary, log.name


def acceptable_results(results):
    if any(result.get("boundary") == "failed_at_zero" for result in results):
        return False
    for case in results:
        expected = "invocation_limit" if case["kind"] == "paid_reenter" else "stack_overflow"
        if case["kind"] == "paid_huge":
            if case["observations"][0]["outcome"] != "ok":
                return False
        elif case.get("boundary") != "first_failure" or case.get("first_failure_outcome") != expected:
            return False
        elif case["first_failure"] != case["last_success"] + 1:
            return False
        if case["kind"] == "paid_reenter" and case["last_success"] != 63:
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--cell", required=True)
    parser.add_argument("--lockfile", type=Path, default=Path("core/Cargo.lock"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--case", action="append", choices=DEFAULT_CASES)
    parser.add_argument("--chain-log", type=Path, help="successful chain-matrix raw output to include in qualification")
    parser.add_argument("--owned-chain-log", type=Path, help="owned chain boundary raw output")
    parser.add_argument("--ownership-log", type=Path, help="selected ownership lifecycle tests")
    parser.add_argument("--max-depth", type=int, default=32768)
    parser.add_argument("--max-reentry-depth", type=int, default=64)
    parser.add_argument("--initial-depth", type=int, default=1024)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    args.binary = args.binary.absolute()
    if args.initial_depth < 1 or args.max_depth < 0 or args.max_reentry_depth < 0:
        parser.error("depth limits must be nonnegative and initial depth must be positive")
    if args.cell not in {
        f"{runner}-{arch}/{profile}"
        for runner, arch in (("Linux", "X64"), ("Linux", "ARM64"), ("macOS", "ARM64"))
        for profile in ("dev", "release")
    }:
        parser.error("cell must be one of the six production target/profile keys")
    args.output.mkdir(parents=True, exist_ok=True)
    source_sha = source_identity()
    binary_sha256 = sha256_file(args.binary)
    target = TARGETS[args.cell.split("/", 1)[0]]
    feature_logs = {
        "production": "wasmtime-production-features.txt",
        "qualification": "wasmtime-qualification-features.txt",
    }
    features = {
        "production": resolved_features(target, "no-dev", args.output / feature_logs["production"]),
        "qualification": resolved_features(target, "all", args.output / feature_logs["qualification"]),
    }
    cases = args.case or DEFAULT_CASES
    results = []
    for kind in cases:
        max_depth = args.max_reentry_depth if kind == "paid_reenter" else args.max_depth
        result = qualify_case(args.binary, kind, args.output, args.timeout, max_depth, args.initial_depth)
        results.append(result)
    with args.lockfile.open("rb") as source:
        packages = tomllib.load(source)["package"]
    wasmtime = next(package for package in packages if package["name"] == "wasmtime")
    revision = wasmtime["source"].rsplit("#", 1)[-1]
    if wasmtime["version"] != "51.0.0-kontor.2" or revision != "0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7":
        raise ValueError("qualification requires the exact approved Wasmtime fork revision")
    chains = []
    chain_log = None
    logs = [
        args.output / sample["log"]
        for case in results
        for sample in case["observations"] + case["control_observations"]
    ]
    logs.extend(args.output / case[field] for case in results for field in ("worker_log", "control_log", "owned_log"))
    logs.extend(args.output / name for name in feature_logs.values())
    cargo_log = "cargo.json" if (args.output / "cargo.json").is_file() else None
    if cargo_log is not None:
        logs.append(args.output / cargo_log)
    if args.chain_log is not None:
        destination = args.output / "chain-matrix.log"
        if args.chain_log.resolve() != destination.resolve():
            shutil.copyfile(args.chain_log, destination)
        chains = [
            json.loads(line.split("CHAIN_PROBE_REPORT:", 1)[1])
            for line in destination.read_text().splitlines()
            if line.startswith("CHAIN_PROBE_REPORT:")
        ]
        chain_log = destination.name
        logs.append(destination)
    if args.owned_chain_log is None or args.ownership_log is None:
        raise ValueError("owned chain and ownership lifecycle logs are required")
    owned_chain_destination = args.output / "owned-chain-matrix.log"
    if args.owned_chain_log.resolve() != owned_chain_destination.resolve():
        shutil.copyfile(args.owned_chain_log, owned_chain_destination)
    owned_chains = [
        json.loads(line.split("CHAIN_OWNED_PROBE_REPORT:", 1)[1])
        for line in owned_chain_destination.read_text().splitlines()
        if line.startswith("CHAIN_OWNED_PROBE_REPORT:")
    ]
    if len(owned_chains) != 6:
        raise ValueError("owned chain matrix lacks six boundary reports")
    logs.append(owned_chain_destination)
    ownership_destination = args.output / "ownership-controls.log"
    if args.ownership_log.resolve() != ownership_destination.resolve():
        shutil.copyfile(args.ownership_log, ownership_destination)
    ownership_raw = ownership_destination.read_text()
    if ownership_raw.count("test result: ok. 1 passed;") != len(OWNERSHIP_TESTS) or any(
        f"runtime::ownership::tests::{test} ... ok" not in ownership_raw
        for test in OWNERSHIP_TESTS
    ):
        raise ValueError("ownership lifecycle controls are incomplete")
    logs.append(ownership_destination)
    if source_identity() != source_sha or sha256_file(args.binary) != binary_sha256:
        raise ValueError("qualification source or test binary changed during capture")
    report = {
        "schema_version": 6,
        "cell": args.cell,
        "source_sha": source_sha,
        "lockfile_sha256": sha256_file(args.lockfile),
        "wasmtime_revision": revision,
        "wasmtime_features": features,
        "feature_logs": feature_logs,
        "cargo_log": cargo_log,
        "binary": str(args.binary),
        "binary_sha256": binary_sha256,
        "rustc_version_verbose": subprocess.check_output(
            ["rustc", "--version", "--verbose"], text=True
        ),
        "host": platform.platform(),
        "cases": results,
        "chains": chains,
        "chain_log": chain_log,
        "owned_chains": owned_chains,
        "owned_chain_log": owned_chain_destination.name,
        "ownership_log": ownership_destination.name,
        "log_sha256": {path.name: sha256_file(path) for path in logs},
    }
    (args.output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if acceptable_results(results) else 1


if __name__ == "__main__":
    sys.exit(main())
