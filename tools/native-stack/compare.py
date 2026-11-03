#!/usr/bin/env python3
"""Validate and compare the six production Pulley qualification cells."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from sweep import IDENTITY_FIELDS, SWEEP_FIELDS, parse_transcript, _run as stack_evidence


FORK_REVISION = "0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7"
STACK_SIZES = (524288, 2097152)
PRODUCTION_FEATURES = set("""
    anyhow async backtrace component-model component-model-async cranelift gc gc-copying
    gc-drc gc-null once_cell pooling-allocator pulley runtime std threads
    wasmtime-jit-icache-coherence wat wave wit-parser
""".split())
QUALIFICATION_FEATURES = PRODUCTION_FEATURES | {"call-hook"}
FORBIDDEN_FEATURES = {"cache", "profiling", "debug-builtins"}
FEATURE_LOGS = {
    "production": "wasmtime-production-features.txt",
    "qualification": "wasmtime-qualification-features.txt",
}
OWNERSHIP_TESTS = (
    "canonical_lease_drains_native_guest_before_releasing_runtime",
    "canonical_and_simulation_children_keep_no_yield_policy",
    "nested_api_children_inherit_actual_fuel_yields",
    "cancelling_nested_yielding_api_guest_joins_before_runtime_reuse",
    "cancelling_fuel_yielding_guest_joins_before_pool_reuse",
)
CELLS = {
    f"native-stack-{runner}-{profile}": (f"{os_name}-{arch}/{profile}", target_os, target_arch)
    for runner, os_name, arch, target_os, target_arch in (
        ("ubuntu-24.04", "Linux", "X64", "linux", "x86_64"),
        ("ubuntu-24.04-arm", "Linux", "ARM64", "linux", "aarch64"),
        ("macos-15", "macOS", "ARM64", "macos", "aarch64"),
    )
    for profile in ("dev", "release")
}
RECURSION = {
    f"{mode}_{shape}"
    for mode in ("paid", "view", "system", "core")
    for shape in ("recurse", "wide")
}
CASES = RECURSION | {"paid_reenter", "paid_huge"}
REPORT_FIELDS = {
    "schema_version", "cell", "source_sha", "lockfile_sha256",
    "wasmtime_revision", "binary", "binary_sha256", "rustc_version_verbose", "host", "cases",
    "chains", "chain_log", "owned_chains", "owned_chain_log", "ownership_log",
    "log_sha256", "wasmtime_features", "feature_logs", "cargo_log",
}
OWNED_STACK_SEMANTICS = {
    "kind", "depth", "outcome", "value", "receipt", "last_depth",
    "child_markers", "rolled_back", "fuel", "reset", "fixture_contracts",
    "call_hook_installed", "gas_limit", "paid_fuel_limit", "view_gas_limit",
    "view_fuel_limit", "system_fuel_ceiling", "gas_to_fuel_multiplier",
    "max_wasm_stack", "async_stack_size", "engine_target", "component_sha256",
}
OBSERVATION_FIELDS = {
    "kind", "depth", "outcome", "value", "receipt", "last_depth",
    "child_markers", "rolled_back", "fuel", "gas_limit", "paid_fuel_limit",
    "view_gas_limit", "view_fuel_limit", "system_fuel_ceiling",
    "gas_to_fuel_multiplier", "max_wasm_stack", "async_stack_size",
    "engine_target", "component_sha256", "target_os", "target_arch", "log",
}
OBSERVATION_FIELDS |= SWEEP_FIELDS
SIGNATURE_FIELDS = OBSERVATION_FIELDS - {"target_os", "target_arch", "log"} - IDENTITY_FIELDS
HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")


def check(condition, message):
    if not condition:
        raise ValueError(message)


def signature(observation):
    return {field: observation[field] for field in sorted(SIGNATURE_FIELDS)}


def reports_in_log(path, prefix):
    return [json.loads(line[len(prefix):]) for line in path.read_text().splitlines() if line.startswith(prefix)]


def validate_success(value, kind):
    depth = value["depth"]
    expected_value = 32640 if kind == "paid_huge" else 496 * depth if kind.endswith("_wide") else depth
    check(value["value"] == str(expected_value), f"{kind}: incorrect successful value")
    marker = 0 if kind.startswith(("view_", "system_")) else 1 if kind == "paid_huge" else depth
    check(value["last_depth"] == marker and not value["rolled_back"], f"{kind}: incorrect successful state")
    expected_children = list(range(depth - 1, -1, -1)) + [0] * (64 - depth) if kind == "paid_reenter" else []
    check(value["child_markers"] == expected_children, f"{kind}: incorrect child state")


def validate_observation(value, kind, target_os, target_arch, directory):
    check(isinstance(value, dict), f"{kind}: observation is not an object")
    check(OBSERVATION_FIELDS <= value.keys(), f"{kind}: missing observation fields {sorted(OBSERVATION_FIELDS - value.keys())}")
    check(value["kind"] == kind, f"{kind}: mismatched observation kind")
    check(type(value["depth"]) is int and value["depth"] >= 0, f"{kind}: invalid depth")
    check(value["outcome"] in {"ok", "stack_overflow", "invocation_limit"}, f"{kind}: invalid outcome")
    check((value["target_os"], value["target_arch"]) == (target_os, target_arch), f"{kind}: target mismatch")
    check(value["engine_target"] == "pulley64-unknown-unknown-elf", f"{kind}: wrong engine")
    check((value["max_wasm_stack"], value["async_stack_size"]) == STACK_SIZES, f"{kind}: wrong stack settings")
    check(isinstance(value["component_sha256"], str) and HEX_64.fullmatch(value["component_sha256"]), f"{kind}: invalid component hash")
    check(type(value["last_depth"]) is int and value["last_depth"] >= 0, f"{kind}: invalid marker")
    check(isinstance(value["child_markers"], list) and all(type(item) is int for item in value["child_markers"]), f"{kind}: invalid child markers")
    check(type(value["rolled_back"]) is bool, f"{kind}: invalid rollback flag")
    check(isinstance(value["fuel"], dict) and set(value["fuel"]) == {"user", "system", "deposit"}, f"{kind}: invalid fuel")
    check(all(type(item) is int and item >= 0 for item in value["fuel"].values()), f"{kind}: invalid fuel value")
    for field in ("gas_limit", "paid_fuel_limit", "view_gas_limit", "view_fuel_limit", "system_fuel_ceiling", "gas_to_fuel_multiplier"):
        check(type(value[field]) is int and value[field] >= 0, f"{kind}: invalid {field}")
    receipt = value["receipt"]
    check(receipt is None or (
        isinstance(receipt, dict) and set(receipt) == {"status", "gas"}
        and isinstance(receipt["status"], str) and type(receipt["gas"]) is int and receipt["gas"] >= 0
    ), f"{kind}: invalid receipt")
    if kind.startswith(("view_", "system_")):
        check(receipt is None, f"{kind}: view call persisted a receipt")
    else:
        expected_status = {"ok": "Ok", "stack_overflow": "Trap", "invocation_limit": "Other"}[value["outcome"]]
        check(receipt is not None and receipt["status"] == expected_status and receipt["gas"] > 0, f"{kind}: wrong receipt")
    check(value["value"] is None or isinstance(value["value"], str), f"{kind}: invalid value")
    log = value["log"]
    check(isinstance(log, str) and Path(log).name == log and (directory / log).is_file(), f"{kind}: missing raw log")
    raw = reports_in_log(directory / log, "KONTOR_STACK_REPORT:")
    check(len(raw) == 1 and raw[0] == {key: item for key, item in value.items() if key != "log"}, f"{kind}: raw log disagrees with observation")
    if value["outcome"] != "ok":
        check(value["value"] is None, f"{kind}: failed call returned a value")
        check(value["rolled_back"], f"{kind}: failed call did not roll back")
        check(value["last_depth"] == 0 and all(marker == 0 for marker in value["child_markers"]), f"{kind}: failed call retained state")
        check(len(value["child_markers"]) == (64 if kind == "paid_reenter" else 0), f"{kind}: missing child state")
    else:
        validate_success(value, kind)


def validate_case(case, target_os, target_arch, directory):
    check(isinstance(case, dict) and {"kind", "boundary", "observations"} <= case.keys(), "case missing fields")
    kind = case["kind"]
    check(kind in CASES, f"unexpected case {kind}")
    observations = case["observations"]
    check(isinstance(observations, list) and observations, f"{kind}: no observations")
    controls = case.get("control_observations")
    check(isinstance(controls, list) and controls, f"{kind}: missing fresh-process control")
    summaries = []
    for role, samples in (("worker", observations), ("control", controls)):
        log = case.get(f"{role}_log")
        check(isinstance(log, str) and Path(log).name == log and (directory / log).is_file(), f"{kind}: missing {role} transcript")
        raw, summary = parse_transcript((directory / log).read_text(), kind, role)
        check(summary == case.get(f"{role}_summary"), f"{kind}: {role} summary disagrees with raw log")
        check(raw == [{key: value for key, value in sample.items() if key != "log"} for sample in samples], f"{kind}: {role} samples disagree with raw transcript")
        summaries.append(summary)
    check(summaries[0]["boundaries"] == summaries[1]["boundaries"], f"{kind}: fresh control boundary differs")
    check(summaries[0]["baseline_digest_sha256"] == summaries[1]["baseline_digest_sha256"], f"{kind}: fresh control baseline differs")
    expected_boundary = {"bounded_depth": 0} if kind == "paid_huge" else {
        key: case.get(key) for key in ("last_success", "first_failure", "first_failure_outcome")
    }
    check(summaries[0]["boundaries"] == expected_boundary, f"{kind}: summary boundary differs from report")
    by_depth = defaultdict(list)
    for observation in observations:
        validate_observation(observation, kind, target_os, target_arch, directory)
        by_depth[observation["depth"]].append(observation)
    for control in controls:
        validate_observation(control, kind, target_os, target_arch, directory)
        check(any(signature(control) == signature(sample) for sample in by_depth[control["depth"]]), f"{kind}: fresh control observation differs")
    for depth, samples in by_depth.items():
        check(all(signature(sample) == signature(samples[0]) for sample in samples), f"{kind}: repeat mismatch at {depth}")
    if kind == "paid_huge":
        check(case["boundary"] == "bounded" and len(observations) == 1, f"{kind}: invalid bounded case")
        check(observations[0]["depth"] == 0 and observations[0]["outcome"] == "ok", f"{kind}: fixed frame failed")
    else:
        success, failure = case.get("last_success"), case.get("first_failure")
        expected = "invocation_limit" if kind == "paid_reenter" else "stack_overflow"
        check(case["boundary"] == "first_failure", f"{kind}: no measured boundary")
        check(type(success) is int and type(failure) is int and failure == success + 1, f"{kind}: nonadjacent boundary")
        check(case.get("first_failure_outcome") == expected, f"{kind}: wrong boundary class")
        check(len(by_depth[success]) >= 3 and len(by_depth[failure]) >= 3, f"{kind}: boundary lacks repeat samples")
        check(all(sample["outcome"] == "ok" for sample in by_depth[success]), f"{kind}: last success failed")
        check(all(sample["outcome"] == expected for sample in by_depth[failure]), f"{kind}: first failure changed")
        if kind == "paid_reenter":
            check((success, failure) == (63, 64), "reentry must admit 64 Stores and reject 65")
            check(all(len(by_depth[depth]) >= 3 for depth in (62, 63, 64)), "missing 63/64/65 Store samples")
            check(all(sample["outcome"] == "ok" for depth in (62, 63) for sample in by_depth[depth]), "63/64 Store samples must succeed")
    return {
        "boundary": case["boundary"],
        "last_success": case.get("last_success"),
        "first_failure": case.get("first_failure"),
        "first_failure_outcome": case.get("first_failure_outcome"),
        "observations": [signature(value) for value in observations],
        "control_observations": [signature(value) for value in controls],
    }


def validate_owned_stack(case, directory):
    kind = case["kind"]
    expected_depths = [0] if kind == "paid_huge" else [case["last_success"], case["first_failure"]]
    samples = case.get("owned_observations")
    check(isinstance(samples, list) and len(samples) == len(expected_depths), f"{kind}: missing owned stack samples")
    check(case.get("owned_summary") == {
        "kind": kind, "depths": expected_depths,
        "outcomes": [sample.get("outcome") for sample in samples], "owned": True,
    }, f"{kind}: invalid owned stack summary")
    log = case.get("owned_log")
    check(isinstance(log, str) and Path(log).name == log and (directory / log).is_file(), f"{kind}: missing owned stack log")
    check(reports_in_log(directory / log, "KONTOR_OWNED_STACK_REPORT:") == samples, f"{kind}: raw owned stack evidence differs")
    controls = {sample["depth"]: sample for sample in case["control_observations"]}
    normalized = []
    for index, (depth, sample) in enumerate(zip(expected_depths, samples)):
        check(isinstance(sample, dict) and OWNED_STACK_SEMANTICS <= sample.keys(), f"{kind}: incomplete owned stack sample")
        check(sample["role"] == "owned" and sample["sample_index"] == index and sample["sample_id"] == f"owned:{kind}:{index:04}", f"{kind}: wrong owned sample identity")
        check(sample["kind"] == kind and sample["depth"] == depth, f"{kind}: wrong owned stack boundary")
        owner = sample.get("ownership")
        expected_kind = "api" if kind.startswith("view_") else "canonical"
        check(isinstance(owner, dict) and set(owner) == {"kind", "fuel_yield_interval", "registered_peak"}, f"{kind}: missing owner evidence")
        check(owner["kind"] == expected_kind and owner["fuel_yield_interval"] == (100_000 if expected_kind == "api" else None), f"{kind}: wrong owner policy")
        peak = owner["registered_peak"]
        check(type(peak) is int and 1 <= peak <= 64, f"{kind}: no registered guest Store")
        if kind == "paid_reenter":
            check(peak == min(depth + 1, 64), f"{kind}: descendant Stores were not registered")
        oracle = controls[depth]
        check(sample.get("cache_mode") == ("fresh_api_pool_cache" if expected_kind == "api" else "warm_compiled_cache"), f"{kind}: wrong owned cache provenance")
        check((sample.get("target_os"), sample.get("target_arch")) == (oracle["target_os"], oracle["target_arch"]), f"{kind}: owned target differs")
        if expected_kind == "api":
            check(sample.get("state_after_sha256") == sample["reset"]["post"]["persistent_digest_sha256"], f"{kind}: owned API state digest differs")
        check({field: sample[field] for field in OWNED_STACK_SEMANTICS} == {
            field: oracle[field] for field in OWNED_STACK_SEMANTICS
        }, f"{kind}: owned output, receipt, fuel, or rollback differs from unowned control")
        normalized.append({
            "semantics": {field: sample[field] for field in sorted(OWNED_STACK_SEMANTICS)},
            "ownership": owner,
        })
    return normalized


CHAIN_KEYS = {(mode, stores) for mode in ("paid", "view", "core") for stores in (33, 63, 64, 65)}
OWNED_CHAIN_KEYS = {(mode, stores) for mode in ("paid", "view", "core") for stores in (64, 65)}


def validate_chains(chains, target_os, target_arch):
    return stack_evidence({"operation": "chains", "chains": chains,
                           "target_os": target_os, "target_arch": target_arch})


def validate_owned_chains(owned_chains, chains, target_os, target_arch):
    return stack_evidence({"operation": "owned_chains", "owned_chains": owned_chains,
                           "chains": chains, "target_os": target_os, "target_arch": target_arch})


def validate_build_provenance(report, directory, binary):
    stack_evidence({"operation": "build_provenance", "report": report,
                    "directory": str(directory.resolve()), "binary": binary})


def validate_report(path, cell):
    report = json.loads(path.read_text())
    check(isinstance(report, dict), f"{path}: invalid report")
    check(REPORT_FIELDS <= report.keys(), f"{path}: missing report fields {sorted(REPORT_FIELDS - report.keys())}")
    name, target_os, target_arch = cell
    check(report["schema_version"] == 6 and report["cell"] == name, f"{name}: mislabeled report")
    for field, pattern in (("source_sha", HEX_40), ("lockfile_sha256", HEX_64), ("binary_sha256", HEX_64)):
        check(isinstance(report[field], str) and pattern.fullmatch(report[field]), f"{name}: invalid {field}")
    binary = report["binary"]
    profile_dir = "release" if name.endswith("/release") else "debug"
    check(isinstance(binary, str) and Path(binary).name.startswith("indexer-") and profile_dir in Path(binary).parts, f"{name}: invalid binary provenance")
    check(report["wasmtime_revision"] == FORK_REVISION, f"{name}: wrong fork")
    validate_build_provenance(report, path.parent, binary)
    check(isinstance(report["rustc_version_verbose"], str) and report["rustc_version_verbose"].split()[:2] == ["rustc", "1.99.1"], f"{name}: wrong compiler")
    check(isinstance(report["host"], str) and report["host"], f"{name}: missing host")
    cases = report["cases"]
    check(isinstance(cases, list), f"{name}: invalid cases")
    kinds = [case.get("kind") if isinstance(case, dict) else None for case in cases]
    check(len(kinds) == len(CASES) and set(kinds) == CASES, f"{name}: missing or duplicate case")
    normalized_cases = {case["kind"]: validate_case(case, target_os, target_arch, path.parent) for case in cases}
    normalized_owned_cases = {case["kind"]: validate_owned_stack(case, path.parent) for case in cases}
    logs = [
        sample["log"] for case in cases
        for sample in case["observations"] + case["control_observations"]
    ]
    logs.extend(case[field] for case in cases for field in ("worker_log", "control_log", "owned_log"))
    check(len(logs) == len(set(logs)), "duplicate probe sample log")
    chain_log = report["chain_log"]
    check(isinstance(chain_log, str) and Path(chain_log).name == chain_log and chain_log not in logs, "invalid chain log")
    check(reports_in_log(path.parent / chain_log, "CHAIN_PROBE_REPORT:") == report["chains"], "raw chain log disagrees with report")
    owned_chain_log = report["owned_chain_log"]
    check(isinstance(owned_chain_log, str) and Path(owned_chain_log).name == owned_chain_log and owned_chain_log not in logs, "invalid owned chain log")
    check(reports_in_log(path.parent / owned_chain_log, "CHAIN_OWNED_PROBE_REPORT:") == report["owned_chains"], "raw owned chain log disagrees with report")
    ownership_log = report["ownership_log"]
    check(isinstance(ownership_log, str) and Path(ownership_log).name == ownership_log and ownership_log not in logs, "invalid ownership lifecycle log")
    ownership_raw = (path.parent / ownership_log).read_text()
    check(ownership_raw.count("test result: ok. 1 passed;") == len(OWNERSHIP_TESTS), "ownership lifecycle controls incomplete")
    for test in OWNERSHIP_TESTS:
        check(f"runtime::ownership::tests::{test} ... ok" in ownership_raw, f"ownership lifecycle control missing: {test}")
    manifest = report["log_sha256"]
    check(isinstance(manifest, dict) and set(manifest) == set(logs) | {chain_log, owned_chain_log, ownership_log, report["cargo_log"]} | set(FEATURE_LOGS.values()), "incomplete raw log manifest")
    for log, digest in manifest.items():
        check(isinstance(digest, str) and HEX_64.fullmatch(digest), "invalid raw log hash")
        check(hashlib.sha256((path.parent / log).read_bytes()).hexdigest() == digest, "raw log hash mismatch")
    validated_chains = validate_chains(report["chains"], target_os, target_arch)
    validated_owned_chains = validate_owned_chains(report["owned_chains"], report["chains"], target_os, target_arch)
    return report, {
        "probes": normalized_cases, "owned_probes": normalized_owned_cases,
        "chains": validated_chains, "owned_chains": validated_owned_chains,
    }


def compare(directory, upstream_status, source_sha=None, lockfile_sha256=None, component_hashes=None, profiles="full"):
    check(upstream_status == "success", f"upstream qualification jobs: {upstream_status}")
    check(profiles in {"release", "full"}, "unknown qualification profile policy")
    expected = {key: cell for key, cell in CELLS.items() if profiles == "full" or key.endswith("-release")}
    directories = {path.name for path in directory.iterdir() if path.is_dir()}
    check(directories == set(expected), f"cell keys differ: missing={sorted(set(expected) - directories)} extra={sorted(directories - set(expected))}")
    reports = {}
    cases = {}
    for artifact, cell in sorted(expected.items()):
        path = directory / artifact / "qualification.json"
        check(path.is_file(), f"missing report: {path}")
        reports[cell[0]], cases[cell[0]] = validate_report(path, cell)
    check(len({value["source_sha"] for value in reports.values()}) == 1, "source heads differ")
    check(len({value["lockfile_sha256"] for value in reports.values()}) == 1, "lockfiles differ")
    if source_sha is not None:
        check(all(value["source_sha"] == source_sha for value in reports.values()), "reports are stale for this source head")
    if lockfile_sha256 is not None:
        check(all(value["lockfile_sha256"] == lockfile_sha256 for value in reports.values()), "reports are stale for this lockfile")
    components = {
        observation["component_sha256"]
        for report in reports.values()
        for case in report["cases"]
        for observation in case["observations"]
    }
    check(len(components) == 1, "component binaries differ")
    if component_hashes is not None:
        check(components == {component_hashes["stack_probe"]}, "stack probe differs from source artifact")
        expected_chain = {name: component_hashes[name] for name in ("error_test", "proxy")}
        check(all(chain["component_sha256"] == expected_chain for report in reports.values() for chain in report["chains"]), "chain probes differ from source artifacts")
    baseline = next(iter(cases.values()))
    check(all(value == baseline for value in cases.values()), "cross-cell observations differ")
    return {
        "schema_version": 6, "cells": sorted(reports), "profile_policy": profiles,
        "source_sha": next(iter(reports.values()))["source_sha"],
        "lockfile_sha256": next(iter(reports.values()))["lockfile_sha256"],
        "wasmtime_revision": FORK_REVISION,
        "wasmtime_features": next(iter(reports.values()))["wasmtime_features"],
        "component_sha256": next(iter(components)),
        "cases": baseline,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--upstream-status", required=True)
    parser.add_argument("--profiles", choices=("release", "full"), default="full")
    parser.add_argument("--smoke-directory", type=Path)
    parser.add_argument("--lockfile", type=Path, default=Path("core/Cargo.lock"))
    args = parser.parse_args()
    try:
        source_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        lockfile_sha256 = hashlib.sha256(args.lockfile.read_bytes()).hexdigest()
        component_hashes = {
            name: hashlib.sha256(Path(f"test-contracts/binaries/{name}.wasm.br").read_bytes()).hexdigest()
            for name in ("stack_probe", "error_test", "proxy")
        }
        result = compare(args.directory, args.upstream_status, source_sha, lockfile_sha256, component_hashes, args.profiles)
        if args.profiles == "release":
            check(args.smoke_directory is not None, "release policy requires dev smoke evidence")
            result["dev_smoke"] = stack_evidence({
                "operation": "smoke_set", "directory": str(args.smoke_directory.resolve()),
                "source_sha": source_sha, "lockfile_sha256": lockfile_sha256,
            })
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as error:
        print(f"native stack qualification rejected: {error}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
