"""Run bounded dev-profile regressions without discovering stack boundaries."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

import compare
from qualify import resolved_features, sha256_file, source_identity


TESTS = tuple("runtime::ownership::tests::" + name for name in (
    "owned_paid_call_matches_direct_value_fuel_receipt_and_settlement",
    "canonical_and_simulation_children_keep_no_yield_policy",
    "nested_api_children_inherit_actual_fuel_yields",
    "cancelling_nested_yielding_api_guest_joins_before_runtime_reuse",
    "cancelling_fuel_yielding_guest_joins_before_pool_reuse",
    "canonical_drain_waits_for_supervisor_runtime_release",
)) + (
    "runtime::sequential_tests::invocation_budget_counts_the_root_and_releases_each_store",
    "runtime::call::tests::guest_memory::published_nested_calls_share_and_release_memory_across_cold_and_warm_loads",
)
CELLS = {
    "native-smoke-ubuntu-24.04": ("Linux-X64/dev", "x86_64-unknown-linux-gnu"),
    "native-smoke-ubuntu-24.04-arm": ("Linux-ARM64/dev", "aarch64-unknown-linux-gnu"),
    "native-smoke-macos-15": ("macOS-ARM64/dev", "aarch64-apple-darwin"),
}


def validate_test(raw, name):
    compare.check(len(re.findall(r"^test result:.*$", raw, re.MULTILINE)) == 1, "missing or duplicate test summary")
    compare.check(re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", raw, re.MULTILINE) is not None,
                  "smoke must execute exactly one successful test")
    compare.check(len(re.findall(r"^test " + re.escape(name) + r" \.\.\. ok$", raw, re.MULTILINE)) == 1,
                  f"intended smoke test did not pass: {name}")


def validate_report(path, cell, source_sha, lockfile_sha256):
    report = json.loads(path.read_text())
    compare.check(report["schema_version"] == 1 and report["cell"] == cell[0], "wrong dev smoke cell")
    compare.check(report["source_sha"] == source_sha and report["lockfile_sha256"] == lockfile_sha256,
                  "stale dev smoke source or lockfile")
    compare.check(report["wasmtime_revision"] == compare.FORK_REVISION, "wrong dev smoke fork")
    compare.check(compare.HEX_64.fullmatch(report["binary_sha256"]) is not None, "invalid smoke binary hash")
    binary = report["binary"]
    compare.check(Path(binary).name.startswith("indexer-") and "debug" in Path(binary).parts, "smoke is not a dev test binary")
    compare.check(report["rustc_version_verbose"].split()[:2] == ["rustc", "1.99.1"], "wrong smoke compiler")
    compare.check(f"host: {cell[1]}" in report["rustc_version_verbose"].splitlines(), "wrong smoke compiler host")
    compare.validate_build_provenance(report, path.parent, binary)
    build = [json.loads(line) for line in (path.parent / report["cargo_log"]).read_text().splitlines()]
    artifact = next(entry for entry in build if entry.get("executable") == binary)
    compare.check(artifact["profile"].get("debug_assertions") is True, "smoke binary lacks debug assertions")
    compare.check(set(report["tests"]) == set(TESTS), "missing or extra dev smoke test")
    expected_logs = {f"test-{index}.log" for index in range(len(TESTS))}
    expected_logs |= {report["cargo_log"], *compare.FEATURE_LOGS.values()}
    compare.check(set(report["log_sha256"]) == expected_logs, "incomplete dev smoke log manifest")
    for name, digest in report["log_sha256"].items():
        compare.check(Path(name).name == name and sha256_file(path.parent / name) == digest, "dev smoke log hash mismatch")
    for index, name in enumerate(TESTS):
        compare.check(report["tests"][name] == f"test-{index}.log", "wrong smoke test log")
        validate_test((path.parent / report["tests"][name]).read_text(), name)
    return {"cell": cell[0], "tests": list(TESTS), "binary_sha256": report["binary_sha256"],
            "report_sha256": sha256_file(path)}


def validate_set(directory, source_sha, lockfile_sha256):
    compare.check({p.name for p in directory.iterdir() if p.is_dir()} == set(CELLS), "dev smoke cells differ")
    return [validate_report(directory / name / "smoke.json", cell, source_sha, lockfile_sha256)
            for name, cell in sorted(CELLS.items())]


def capture(binary, cell, output):
    target = dict(CELLS.values())[cell]
    source_sha = source_identity()
    binary = binary.resolve()
    binary_hash = sha256_file(binary)
    lock_hash = sha256_file(Path("core/Cargo.lock"))
    output.mkdir(parents=True, exist_ok=True)
    features = {graph: resolved_features(target, edges, output / compare.FEATURE_LOGS[graph])
                for graph, edges in (("production", "no-dev"), ("qualification", "all"))}
    report = {
        "schema_version": 1, "cell": cell, "source_sha": source_sha,
        "lockfile_sha256": lock_hash, "wasmtime_revision": compare.FORK_REVISION,
        "binary": str(binary), "binary_sha256": binary_hash, "cargo_log": "cargo.json",
        "rustc_version_verbose": subprocess.check_output(["rustc", "-Vv"], text=True),
        "host": platform.platform(), "wasmtime_features": features,
        "feature_logs": compare.FEATURE_LOGS, "tests": {},
    }
    compare.validate_build_provenance(report, output, str(binary))
    environment = {key: value for key, value in os.environ.items() if not key.startswith("KONTOR_")}
    for index, name in enumerate(TESTS):
        log = output / f"test-{index}.log"
        # A typo can make libtest return success after running zero tests.
        with log.open("w") as stream:
            result = subprocess.run([str(binary), "--exact", name, "--nocapture"],
                                    env=environment, stdout=stream, stderr=subprocess.STDOUT, timeout=180)
        compare.check(result.returncode == 0, f"dev smoke failed: {name}, see {log}")
        validate_test(log.read_text(), name)
        report["tests"][name] = log.name
        print(f"Passed {name}", flush=True)
    compare.check(source_identity() == source_sha and sha256_file(binary) == binary_hash
                  and sha256_file(Path("core/Cargo.lock")) == lock_hash, "smoke inputs changed during execution")
    logs = {"cargo.json", *compare.FEATURE_LOGS.values(), *report["tests"].values()}
    report["log_sha256"] = {name: sha256_file(output / name) for name in sorted(logs)}
    path = output / "smoke.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    validate_report(path, (cell, target), source_sha, lock_hash)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--cell", required=True, choices=[cell[0] for cell in CELLS.values()])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        capture(args.binary, args.cell, args.output)
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(f"dev smoke rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
