#!/usr/bin/env python3
"""Pin the Pulley boundary family separately from the accepted chain evidence."""

import argparse
import json
from pathlib import Path

from resource_evidence import load_json_strict, require, sha256
from resource_manifest import MANIFEST as V1_MANIFEST
from resource_manifest import ROOT, build_manifest


DIRECTORY = Path(__file__).parent
MANIFEST = DIRECTORY / "resource-boundary-manifest-v1.json"
DEPTHS = DIRECTORY / "resource-boundary-depths-v1.json"
SCHEMA = DIRECTORY / "resource-boundary-evidence-schema-v1.json"
DISCOVERY_CELL = "Linux-ARM64/dev"
DISCOVERY_ROLE = "discovery_production_observed"
FINAL_ROLES = ("target_observed", "probe_off_control")
CONFIGURATIONS = ("reduced", "production")
AUXILIARY_EXPECTED_COUNTS = {
    mode: {
        "pre_observation": 0,
        "post_observation": 5,
        "rollback_observation": 4,
        "target_native_auxiliary": 2 if mode == "paid" else 0,
    }
    for mode in ("paid", "view", "system", "core")
}
SOURCES = {
    "manifest_builder": "tools/native-stack/resource_boundary_manifest.py",
    "capture": "tools/native-stack/capture_resource_boundary.py",
    "validator": "tools/native-stack/resource_boundary_evidence.py",
    "tests": "tools/native-stack/test_resource_boundary_evidence.py",
    "composition_tests": "tools/native-stack/test_resource_boundary_composition.py",
    "synthetic_guard_tests": "tools/native-stack/test_resource_report.py",
    "schema": "tools/native-stack/resource-boundary-evidence-schema-v1.json",
    "depths": "tools/native-stack/resource-boundary-depths-v1.json",
    "plan": "tools/native-stack/resource-boundary-family.md",
    "worker": "core/indexer/src/runtime/call/tests/native_stack_resource.rs",
    "sweep": "core/indexer/src/runtime/call/tests/native_stack/sweep.rs",
    "fixture_source": "test-contracts/stack-probe/src/lib.rs",
    "fixture_wit": "test-contracts/stack-probe/wit/contract.wit",
    "fixture_binary": "test-contracts/binaries/stack_probe.wasm.br",
}


def boundary_cases():
    cases = [case for case in build_manifest()["cases"]
             if case["family"] == "pulley_boundary"]
    require(len(cases) == 8, "v1 manifest no longer has eight Pulley cases")
    return cases


def frozen_depths():
    record = load_json_strict(DEPTHS)
    require(isinstance(record, dict)
            and set(record) == {"discovery_capture_sha256", "cases"},
            "frozen depth record has unexpected fields")
    values = record["cases"]
    cases = boundary_cases()
    case_ids = {case["id"] for case in cases} | {"deepest_frame_host_call"}
    require(isinstance(values, dict)
            and set(values) == case_ids,
            "frozen depth map has missing or extra cases")
    frozen = []
    for case_id in sorted(case_ids):
        item = values[case_id]
        if item is None:
            continue
        require(isinstance(item, dict)
                and set(item) == {"last_success", "first_failure"}
                and type(item["last_success"]) is int
                and type(item["first_failure"]) is int
                and 0 < item["last_success"] < 32768
                and item["first_failure"] == item["last_success"] + 1,
                f"invalid frozen Pulley depths: {case_id}")
        frozen.append(case_id)
    require(len(frozen) in (0, 9),
            "partial boundary freeze cannot become a candidate manifest")
    discovery_sha256 = record["discovery_capture_sha256"]
    require((isinstance(discovery_sha256, str)
             and len(discovery_sha256) == 64
             and all(character in "0123456789abcdef"
                     for character in discovery_sha256))
            if len(frozen) == 9 else discovery_sha256 is None,
            "frozen depths lack one reviewed discovery capture hash")
    return values, len(frozen) == 9, discovery_sha256


def build_boundary_manifest():
    v1 = build_manifest()
    values, all_frozen, discovery_sha256 = frozen_depths()
    cases = boundary_cases()
    leaf = next(case for case in v1["cases"]
                if case["id"] == "deepest_frame_host_call")
    require(leaf["parameters"] == {"adjacent_leaf_boundary": True,
                                   "host_call_at_leaf": True},
            "leaf host call requirement changed")
    return {
        "schema_version": 1,
        "claim_status": "candidate_only" if all_frozen else "pending_discovery",
        "reviewed_discovery_sha256": discovery_sha256,
        "parent_manifest_sha256": sha256(V1_MANIFEST),
        "schema_sha256": sha256(SCHEMA),
        "source_baseline_commit": v1["source_baseline_commit"],
        "discovery": {
            "cell": DISCOVERY_CELL,
            "configuration": "production",
            "process_role": DISCOVERY_ROLE,
            "initial_depth": 1024,
            "max_depth": 32768,
        },
        "final_roles": list(FINAL_ROLES),
        "configurations": list(CONFIGURATIONS),
        "auxiliary_expected_counts_by_mode": AUXILIARY_EXPECTED_COUNTS,
        "boundary_cases": [{
            "case_id": case["id"],
            "shape": case["parameters"]["shape"],
            "mode": case["parameters"]["mode"],
            "repeats": case["parameters"]["repeats"],
            "last_success": None if values[case["id"]] is None
            else values[case["id"]]["last_success"],
            "first_failure": None if values[case["id"]] is None
            else values[case["id"]]["first_failure"],
        } for case in cases],
        "leaf_case": {
            "case_id": leaf["id"],
            "own_adjacent_boundary": True,
            "repeats": 2,
            "last_success": None if values[leaf["id"]] is None
            else values[leaf["id"]]["last_success"],
            "first_failure": None if values[leaf["id"]] is None
            else values[leaf["id"]]["first_failure"],
        },
        "sources": {name: {"path": path, "sha256": sha256(ROOT / path)}
                    for name, path in sorted(SOURCES.items())},
        "remaining_case_ids": [case["id"] for case in v1["cases"]
                               if case["family"] != "distinct_contract_chain"],
        "remaining_requirements": {
            "case_bindings": "missing_29",
            "six_cell_qualification": "missing",
            "macos_guard": "missing",
            "production_memory_profiles": "missing",
            "workload_plan": v1["workload_plan"]["status"],
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    expected = build_boundary_manifest()
    if args.write:
        MANIFEST.write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n")
    else:
        require(load_json_strict(MANIFEST) == expected,
                "boundary manifest differs from reviewed source and depths")
    print(json.dumps({"path": str(MANIFEST), "sha256": sha256(MANIFEST),
                      "claim_status": expected["claim_status"]}, sort_keys=True))


if __name__ == "__main__":
    main()
