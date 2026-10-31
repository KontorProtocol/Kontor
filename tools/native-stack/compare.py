#!/usr/bin/env python3
"""Validate and compare the six production Pulley qualification cells."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import defaultdict
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import Path

from sweep import IDENTITY_FIELDS, SWEEP_FIELDS, parse_transcript


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
    "chains", "chain_log", "log_sha256", "wasmtime_features", "feature_logs", "cargo_log",
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


CHAIN_FIELDS = {
    "mode", "stores", "trials", "component_sha256", "engine_target", "max_wasm_stack",
    "async_stack_size", "target_os", "target_arch", "call_hook_installed",
}
TRIAL_FIELDS = {
    "outcome", "fuel", "receipt", "receipt_count", "value", "storage_state", "rolled_back",
    "resource_count", "baseline_resource_count", "savepoint_restored", "stack_empty",
    "host_io_suspended", "leaf_callback_seen", "rollback_clean", "balances",
    "repeat_index", "state_before_sha256", "state_after_sha256",
}
BALANCE_FIELDS = {
    "before", "after", "restored", "burned_before", "burned_after", "supply_before",
    "supply_after", "floor_before", "floor_after", "floor_restored",
}
CHAIN_KEYS = {(mode, stores) for mode in ("paid", "view", "core") for stores in (33, 63, 64, 65)}


def decimal_fraction(value):
    check(isinstance(value, str), "chain balances must be decimal strings")
    try:
        number = Decimal(value)
        check(number.is_finite() and number >= 0, "invalid chain balance")
        return Fraction(number)
    except InvalidOperation as error:
        raise ValueError("invalid chain decimal") from error


def validate_chains(chains, target_os, target_arch):
    check(isinstance(chains, list) and len(chains) == len(CHAIN_KEYS), "missing chain cells")
    seen = set()
    normalized = []
    for chain in chains:
        check(isinstance(chain, dict) and CHAIN_FIELDS <= chain.keys(), "missing chain fields")
        mode, stores = chain["mode"], chain["stores"]
        check(isinstance(mode, str) and type(stores) is int, "invalid chain key")
        key = (mode, stores)
        check(key in CHAIN_KEYS and key not in seen, "duplicate or unexpected chain key")
        seen.add(key)
        check((chain["target_os"], chain["target_arch"]) == (target_os, target_arch), "chain target mismatch")
        check(chain["engine_target"] == "pulley64-unknown-unknown-elf", "chain engine mismatch")
        check(chain["call_hook_installed"] is False, "chain enabled a test-only call hook")
        check((chain["max_wasm_stack"], chain["async_stack_size"]) == STACK_SIZES, "chain stack settings mismatch")
        hashes = chain["component_sha256"]
        check(isinstance(hashes, dict) and set(hashes) == {"error_test", "proxy"}, "missing chain component hashes")
        check(all(isinstance(value, str) and HEX_64.fullmatch(value) for value in hashes.values()), "invalid chain component hash")
        trials = chain["trials"]
        check(isinstance(trials, list) and len(trials) == 3, "chain requires three trials")
        expected = ["invocation_limit"] * 3 if stores == 65 else ["ok", "trap", "ok"]
        for repeat_index, (trial, outcome) in enumerate(zip(trials, expected)):
            check(isinstance(trial, dict) and TRIAL_FIELDS <= trial.keys(), "missing chain trial fields")
            check(type(trial["repeat_index"]) is int and trial["repeat_index"] == repeat_index, "wrong chain repeat index")
            before, after = trial["state_before_sha256"], trial["state_after_sha256"]
            check(isinstance(before, str) and HEX_64.fullmatch(before) and after == before, "chain persisted state was not restored")
            check(trial["outcome"] == outcome, "wrong chain outcome")
            check(trial["value"] == ("42" if outcome == "ok" else None), "wrong chain result")
            state = "[2, 0, 0, 0]" if mode != "view" and outcome == "ok" else "[0, 0, 0, 0]"
            check(trial["storage_state"] == state, "wrong chain state")
            for field in ("rolled_back", "rollback_clean", "savepoint_restored", "stack_empty"):
                check(trial[field] is True, f"chain cleanup failed: {field}")
            for field in ("host_io_suspended", "leaf_callback_seen"):
                check(trial[field] is (stores != 65), f"chain host callback mismatch: {field}")
            for field in ("resource_count", "baseline_resource_count", "receipt_count"):
                check(type(trial[field]) is int and trial[field] >= 0, f"invalid chain {field}")
            check(trial["resource_count"] == trial["baseline_resource_count"], "chain resources leaked")
            check(trial["receipt_count"] == (0 if mode == "view" else stores if outcome == "ok" else 1), "wrong chain receipt count")
            receipt = trial["receipt"]
            if mode == "view":
                check(receipt is None, "view chain persisted a receipt")
            else:
                check(isinstance(receipt, dict) and set(receipt) == {"contract_id", "status", "gas", "value"}, "invalid chain receipt")
                check(type(receipt["contract_id"]) is int and receipt["contract_id"] >= 0, "invalid chain receipt contract")
                check(receipt["status"] == ("Ok" if outcome == "ok" else "Other"), "wrong chain receipt status")
                check(type(receipt["gas"]) is int and receipt["gas"] > 0, "invalid chain receipt gas")
                check(receipt["value"] == ("42" if outcome == "ok" else None), "wrong chain receipt value")
            fuel = trial["fuel"]
            check(isinstance(fuel, dict) and set(fuel) == {"user", "system", "deposit"}, "missing chain fuel")
            check(all(type(value) is int and value >= 0 for value in fuel.values()), "invalid chain fuel")
            check(fuel["user" if mode == "paid" else "system"] > 0, "chain fuel missing from expected category")
            balances = trial["balances"]
            check(isinstance(balances, dict) and set(balances) == BALANCE_FIELDS, "missing chain balances")
            amounts = {field: decimal_fraction(value) for field, value in balances.items()}
            paid = amounts["before"] - amounts["after"]
            check(paid == amounts["burned_after"] - amounts["burned_before"] == amounts["supply_before"] - amounts["supply_after"], "chain accounting mismatch")
            check(paid > 0 if mode == "paid" else paid == 0, "wrong chain payer charge")
            check(amounts["restored"] == amounts["before"] and amounts["floor_restored"] == amounts["floor_before"], "chain rollback changed balances")
            if mode == "core" and outcome == "ok":
                check(amounts["floor_after"] < amounts["floor_before"], "Core overwrite did not remove prior deposit")
            else:
                check(amounts["floor_after"] == amounts["floor_before"], "unexpected chain deposit change")
        if stores == 65:
            repeated = [{field: value for field, value in trial.items() if field != "repeat_index"} for trial in trials]
            check(repeated[0] == repeated[1] == repeated[2], "over-cap chain trials differ")
        normalized.append({field: value for field, value in chain.items() if field not in {"target_os", "target_arch"}})
    return sorted(normalized, key=lambda chain: (chain["mode"], chain["stores"]))


def validate_build_provenance(report, directory, binary):
    features = report["wasmtime_features"]
    check(isinstance(features, dict) and set(features) == set(FEATURE_LOGS), "missing Wasmtime feature closures")
    for graph, expected in (("production", PRODUCTION_FEATURES), ("qualification", QUALIFICATION_FEATURES)):
        resolved = features[graph]
        check(isinstance(resolved, list) and all(isinstance(value, str) for value in resolved), f"invalid {graph} Wasmtime features")
        check(not FORBIDDEN_FEATURES.intersection(resolved), f"{graph}: forbidden Wasmtime feature")
        check(resolved == sorted(expected), f"{graph}: unexpected Wasmtime feature closure")
    check(set(features["qualification"]) - set(features["production"]) == {"call-hook"}, "unexpected test-only Wasmtime feature delta")
    check(report["feature_logs"] == FEATURE_LOGS, "missing Wasmtime feature logs")
    for graph, log in FEATURE_LOGS.items():
        check((directory / log).is_file(), f"{graph}: missing feature log")
        check((directory / log).read_text() == ",".join(features[graph]) + "\n", f"{graph}: feature log disagrees with report")
    cargo_log = report["cargo_log"]
    check(cargo_log == "cargo.json" and (directory / cargo_log).is_file(), "missing Cargo build log")
    artifacts = []
    compiled_features = []
    build_finished = []
    item = None
    for line in (directory / cargo_log).read_text().splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError("invalid Cargo build log") from error
        if not isinstance(item, dict):
            raise ValueError("invalid Cargo build log entry")
        if item.get("reason") == "build-finished":
            build_finished.append(item.get("success"))
        if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "indexer" and "lib" in item["target"].get("kind", []) and item.get("profile", {}).get("test") is True and item.get("executable") is not None:
            artifacts.append(item["executable"])
        if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "wasmtime" and "lib" in item["target"].get("kind", []):
            source = f"git+https://github.com/wilfreddenton/wasmtime?rev={FORK_REVISION}#"
            check(item.get("package_id") in {source + "wasmtime@51.0.0-kontor.2", source + "51.0.0-kontor.2"}, "compiled Wasmtime package identity mismatch")
            actual_features = item.get("features")
            check(isinstance(actual_features, list) and all(isinstance(value, str) for value in actual_features), "missing compiled Wasmtime features")
            check(len(actual_features) == len(set(actual_features)), "duplicate compiled Wasmtime feature")
            compiled_features.append(sorted(actual_features))
    check(artifacts == [binary], "Cargo build log disagrees with test binary")
    check(compiled_features == [features["qualification"]], "compiled Wasmtime features disagree with resolution")
    check(len(build_finished) == 1 and build_finished[0] is True and item.get("reason") == "build-finished", "Cargo build log lacks successful terminal completion")


def validate_report(path, cell):
    report = json.loads(path.read_text())
    check(isinstance(report, dict), f"{path}: invalid report")
    check(REPORT_FIELDS <= report.keys(), f"{path}: missing report fields {sorted(REPORT_FIELDS - report.keys())}")
    name, target_os, target_arch = cell
    check(report["schema_version"] == 5 and report["cell"] == name, f"{name}: mislabeled report")
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
    logs = [
        sample["log"] for case in cases
        for sample in case["observations"] + case["control_observations"]
    ]
    logs.extend(case[field] for case in cases for field in ("worker_log", "control_log"))
    check(len(logs) == len(set(logs)), "duplicate probe sample log")
    chain_log = report["chain_log"]
    check(isinstance(chain_log, str) and Path(chain_log).name == chain_log and chain_log not in logs, "invalid chain log")
    check(reports_in_log(path.parent / chain_log, "CHAIN_PROBE_REPORT:") == report["chains"], "raw chain log disagrees with report")
    manifest = report["log_sha256"]
    check(isinstance(manifest, dict) and set(manifest) == set(logs) | {chain_log, report["cargo_log"]} | set(FEATURE_LOGS.values()), "incomplete raw log manifest")
    for log, digest in manifest.items():
        check(isinstance(digest, str) and HEX_64.fullmatch(digest), "invalid raw log hash")
        check(hashlib.sha256((path.parent / log).read_bytes()).hexdigest() == digest, "raw log hash mismatch")
    return report, {"probes": normalized_cases, "chains": validate_chains(report["chains"], target_os, target_arch)}


def compare(directory, upstream_status, source_sha=None, lockfile_sha256=None, component_hashes=None):
    check(upstream_status == "success", f"upstream qualification jobs: {upstream_status}")
    directories = {path.name for path in directory.iterdir() if path.is_dir()}
    check(directories == set(CELLS), f"cell keys differ: missing={sorted(set(CELLS) - directories)} extra={sorted(directories - set(CELLS))}")
    reports = {}
    cases = {}
    for artifact, cell in sorted(CELLS.items()):
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
        "schema_version": 5, "cells": sorted(reports),
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
    parser.add_argument("--lockfile", type=Path, default=Path("core/Cargo.lock"))
    args = parser.parse_args()
    try:
        source_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        lockfile_sha256 = hashlib.sha256(args.lockfile.read_bytes()).hexdigest()
        component_hashes = {
            name: hashlib.sha256(Path(f"test-contracts/binaries/{name}.wasm.br").read_bytes()).hexdigest()
            for name in ("stack_probe", "error_test", "proxy")
        }
        result = compare(args.directory, args.upstream_status, source_sha, lockfile_sha256, component_hashes)
    except (ValueError, OSError, json.JSONDecodeError) as error:
        print(f"native stack qualification rejected: {error}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
