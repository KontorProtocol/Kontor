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
    "historical_phase10_gzip": "tools/native-stack/fixtures/phase10-resource-chain-capture.json.gz",
    "historical_phase10_materializer": "tools/native-stack/materialize_phase10_fixture.py",
    "historical_phase10_materializer_tests": "tools/native-stack/test_materialize_phase10_fixture.py",
    "v1_chain_capture": "tools/native-stack/capture_resource_chain.py",
    "v1_validator": "tools/native-stack/resource_evidence.py",
    "worker": "core/indexer/src/runtime/call/tests/native_stack_resource.rs",
    "chain_fixture": "core/indexer/src/runtime/call/tests/sequential_chains.rs",
    "invocation": "core/indexer/src/runtime/invocation.rs",
    "runtime": "core/indexer/src/runtime/mod.rs",
    "retained_fuel_policy": "core/indexer/src/protocol/v1/fuel.rs",
    "retained_deposit_policy": "core/indexer/src/protocol/v1/deposit.rs",
    "retained_error_policy": "core/indexer/src/protocol/v1/errors.rs",
    "retained_native_policy": "core/indexer/src/protocol/v1/native.rs",
    "retained_engine": "core/indexer/src/protocol/v1/engine.rs",
    "retained_resource_policy": "core/indexer/src/protocol/v1/resources.rs",
    "retained_gas_policy": "core/indexer/src/protocol/v1/gas.rs",
    "retained_pricing_policy": "core/indexer/src/protocol/v1/pricing.rs",
    "selected_policy_binding": "core/indexer/src/runtime/selected.rs",
    "call": "core/indexer/src/runtime/call.rs",
    "fees": "core/indexer/src/protocol/v1/fees.rs",
    "token": "core/indexer/src/runtime/token.rs",
}
ROLES = (
    "target_observed", "trap_control_observed",
    "target_probe_off_control", "trap_control_probe_off_control",
)
AUXILIARY_EXPECTED_COUNTS = {
    f"chain_{stores}_{mode}/{role}/{configuration}/{index}": {
        "pre_observation": 4,
        "post_observation": 5,
        "rollback_observation": 5,
        "target_native_auxiliary": 2 if mode == "paid" else 0,
    }
    for stores in (33, 63, 64, 65)
    for mode in ("core", "paid", "view")
    for role in ROLES
    if stores == 64 or not role.startswith("trap_control")
    if role.endswith("observed")
    for configuration in ("reduced", "production")
    for index in range(3)
}
AUXILIARY_CALLSITES = {
    "target_native_auxiliary": [
        "core/indexer/src/protocol/v1/fees.rs:25,50: with_payment calls token::api::hold and token::api::release around paid deterministic outcomes, including traps and depth rejection",
        "core/indexer/src/runtime/invocation.rs:73-77: target-phase token calls are classified separately from chain Stores",
    ],
    "pre_observation": [
        "core/indexer/src/runtime/call/tests/sequential_chains.rs:722-725: actor balance, burner balance, floor, and supply each create one native Store before the target",
    ],
    "post_observation": [
        "core/indexer/src/runtime/call/tests/sequential_chains.rs:854-857,916-924: storage-state, actor balance, burner balance, supply, and floor each create one Store after the target",
    ],
    "rollback_observation": [
        "core/indexer/src/runtime/call/tests/sequential_chains.rs:960-969: actor balance, floor, burner balance, supply, and storage-state each execute after rollback; asserted rollback_clean proves no short-circuit skipped a call",
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
    if set(AUXILIARY_EXPECTED_COUNTS) != expected_auxiliary_keys:
        raise ValueError("frozen auxiliary counts do not cover each observed trial")
    if not all(set(counts) == set(AUXILIARY_CALLSITES)
               and all(type(count) is int and count >= 0
                       for count in counts.values())
               for counts in AUXILIARY_EXPECTED_COUNTS.values()):
        raise ValueError("frozen auxiliary counts contain an invalid role or value")
    return {
        "schema_version": 2,
        "claim_status": "candidate_only",
        "source_baseline_commit": v1["source_baseline_commit"],
        "parent_manifest_sha256": sha256(V1_MANIFEST),
        "schema_sha256": sha256(SCHEMA),
        "sources": {name: {"path": path, "sha256": sha256(ROOT / path)}
                    for name, path in sorted(SOURCES.items())},
        "case_roles": expected,
        "auxiliary_count_status": "frozen",
        "auxiliary_expected_counts": AUXILIARY_EXPECTED_COUNTS,
        "auxiliary_callsite_citations": AUXILIARY_CALLSITES,
        "persistent_digest_rules": {
            "format": "row_multiset_and_logical_schema_v2",
            "row_value_projection": {
                "receipt_stream_state.epoch": "fixed_local_epoch_placeholder",
            },
            "schema_fields": ["type", "name", "tbl_name", "sql"],
            "schema_order": ["type", "name"],
            "schema_exclusions": ["sqlite_sequence", "sqlite_stat*"],
            "physical_rootpage": "omitted",
            "historical_full_digest_comparison": "excluded_source_provenance_and_format",
        },
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
