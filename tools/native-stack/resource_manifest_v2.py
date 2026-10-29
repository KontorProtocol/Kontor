#!/usr/bin/env python3
"""Pin the candidate v2 chain process and teardown evidence inputs."""

import argparse
import json
from pathlib import Path

from resource_manifest import MANIFEST as V1_MANIFEST
from resource_manifest import ROOT, build_manifest, sha256


MANIFEST = Path(__file__).with_name("resource-manifest-v2.json")
SCHEMA = Path(__file__).with_name("resource-evidence-schema-v2.json")
SOURCES = {
    "v2_manifest_builder": "tools/native-stack/resource_manifest_v2.py",
    "v2_validator": "tools/native-stack/resource_evidence_v2.py",
    "v2_capture": "tools/native-stack/capture_resource_chain_v2.py",
    "v2_tests": "tools/native-stack/test_resource_evidence_v2.py",
    "v2_schema": "tools/native-stack/resource-evidence-schema-v2.json",
    "v1_chain_capture": "tools/native-stack/capture_resource_chain.py",
    "v1_validator": "tools/native-stack/resource_evidence.py",
    "worker": "core/indexer/src/runtime/call/tests/native_stack_resource.rs",
    "chain_fixture": "core/indexer/src/runtime/call/tests/sequential_chains.rs",
    "invocation": "core/indexer/src/runtime/invocation.rs",
    "runtime": "core/indexer/src/runtime/mod.rs",
    "call": "core/indexer/src/runtime/call.rs",
    "fees": "core/indexer/src/runtime/fees.rs",
    "token": "core/indexer/src/runtime/token.rs",
}
ROLES = (
    "target_observed", "trap_control_observed",
    "target_probe_off_control", "trap_control_probe_off_control",
)
# Populate only after an archived pilot trace and independent count review.
AUXILIARY_EXPECTED_COUNTS = {}
AUXILIARY_CALLSITES = {
    "target_native_auxiliary": [
        "core/indexer/src/runtime/fees.rs::with_payment: token::api::hold and token::api::release around paid calls",
        "core/indexer/src/runtime/token.rs::address: token_0_0 is the only target-phase native address",
    ],
    "pre_observation": [
        "core/indexer/src/runtime/call/tests/sequential_chains.rs::run_chain_probe: balance, floor, supply before target",
    ],
    "post_observation": [
        "core/indexer/src/runtime/call/tests/sequential_chains.rs::run_chain_probe: storage-state, balance, floor, supply after target",
    ],
    "rollback_observation": [
        "core/indexer/src/runtime/call/tests/sequential_chains.rs::run_chain_probe: balance, floor, supply, storage-state after rollback",
    ],
}


def expected_trials(stores, process_role):
    if process_role.startswith("trap_control"):
        if stores != 64:
            return None
        return [{"sample_key": key, "repeat_index": index}
                for index, key in enumerate(("target", "trap_control", "target"))]
    return [{"sample_key": "target", "repeat_index": index} for index in range(3)]


def build_manifest_v2():
    v1 = build_manifest()
    chain_cases = [case for case in v1["cases"]
                   if case["family"] == "distinct_contract_chain"]
    remaining = [case["id"] for case in v1["cases"]
                 if case["family"] != "distinct_contract_chain"]
    expected = []
    for case in chain_cases:
        stores = case["parameters"]["simultaneous_stores"]
        for role in ROLES:
            trials = expected_trials(stores, role)
            if trials is not None:
                expected.append({"case_id": case["id"], "process_role": role,
                                 "trials": trials, "nested_chain_created": min(stores, 64)})
    expected_auxiliary_keys = {
        f"{item['case_id']}/{item['process_role']}/{configuration}/{index}"
        for item in expected if item["process_role"].endswith("observed")
        for configuration in ("reduced", "production")
        for index, _ in enumerate(item["trials"])
    }
    if AUXILIARY_EXPECTED_COUNTS:
        assert set(AUXILIARY_EXPECTED_COUNTS) == expected_auxiliary_keys
        assert all(set(counts) == set(AUXILIARY_CALLSITES)
                   and all(type(count) is int and count >= 0
                           for count in counts.values())
                   for counts in AUXILIARY_EXPECTED_COUNTS.values())
    return {
        "schema_version": 2,
        "claim_status": "candidate_only",
        "source_baseline_commit": v1["source_baseline_commit"],
        "parent_manifest_sha256": sha256(V1_MANIFEST),
        "schema_sha256": sha256(SCHEMA),
        "sources": {name: {"path": path, "sha256": sha256(ROOT / path)}
                    for name, path in sorted(SOURCES.items())},
        "case_roles": expected,
        "auxiliary_count_status": (
            "frozen" if AUXILIARY_EXPECTED_COUNTS else "pilot_pending"),
        "auxiliary_expected_counts": AUXILIARY_EXPECTED_COUNTS,
        "auxiliary_callsite_citations": AUXILIARY_CALLSITES,
        "remaining_case_ids": remaining,
        "remaining_requirements": {
            "case_bindings": "missing_29",
            "macos_guard": "missing",
            "production_memory_profiles": "missing",
            "workload_plan": v1["workload_plan"]["status"],
            "attestation": v1["attestation_status"],
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    encoded = json.dumps(build_manifest_v2(), indent=2, sort_keys=True) + "\n"
    if args.write:
        MANIFEST.write_text(encoded)
    elif not MANIFEST.is_file() or MANIFEST.read_text() != encoded:
        parser.error("v2 resource manifest differs from pinned sources")
    print("v2 resource manifest: 12 candidate chain cases; 29 case bindings remain")


if __name__ == "__main__":
    main()
