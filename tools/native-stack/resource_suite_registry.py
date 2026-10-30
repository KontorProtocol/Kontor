#!/usr/bin/env python3
"""Freeze the source registry for all 41 S2 resource cases."""

import argparse
import json
from pathlib import Path

from resource_boundary_manifest import MANIFEST as BOUNDARY_MANIFEST
from resource_boundary_manifest import build_boundary_manifest
from resource_evidence import load_json_strict, require, sha256
from resource_manifest import CELLS, MANIFEST as V1_MANIFEST, ROOT, build_manifest
from resource_manifest_v2 import MANIFEST as V2_MANIFEST
from resource_manifest_v2 import build_manifest_v2


MANIFEST = Path(__file__).with_name("resource-suite-registry-v1.json")
GROUPS = (
    ("chain_v2", tuple(f"chain_{stores}_{mode}" for stores in (33, 63, 64, 65)
                       for mode in ("core", "paid", "view")),
     ("distinct_contract_chain",), "capture_resource_chain_v2.py",
     "resource_evidence_v2.py", "v2"),
    ("pulley_boundary", tuple(f"pulley_{shape}_{mode}"
                              for shape in ("plain", "wide")
                              for mode in ("core", "paid", "system", "view"))
     + ("deepest_frame_host_call",),
     ("pulley_boundary", "pulley_host_callback"),
     "capture_resource_boundary.py", "resource_boundary_evidence.py", "boundary"),
    ("finite_paid", ("large_frame_paid", "max_gas_paid"),
     ("large_frame", "paid_limit"),
     "capture_resource_finite.py", "resource_finite_evidence.py", "v1"),
    ("canonical_abi", ("canonical_lift_lower", "canonical_realloc",
                       "canonical_post_return"), ("canonical_abi",),
     "capture_resource_canonical.py", "resource_canonical_evidence.py", "v1"),
    ("canonical_type_value", ("canonical_type_value_recursion",),
     ("canonical_abi",), "capture_resource_type_value.py",
     "resource_type_value_evidence.py", "v1"),
    ("resource_lifecycle", ("explicit_resource_drop",
                            "failed_instantiation_cleanup"),
     ("resource_lifecycle",), "capture_resource_lifecycle.py",
     "resource_lifecycle_evidence.py", "v1"),
    ("foreign_wave", ("foreign_wave_parse_print",), ("foreign_call",),
     "capture_resource_foreign_wave.py", "resource_foreign_wave_evidence.py", "v1"),
    ("initialization", ("generated_initialization",), ("initialization",),
     "capture_resource_initialization.py", "resource_initialization_evidence.py", "v1"),
    ("native_staking", ("native_staking_rewards",), ("native_core",),
     "capture_resource_native_staking_rewards.py",
     "resource_native_staking_rewards_evidence.py", "v1"),
    ("native_filestorage", ("native_filestorage_lifecycle",), ("native_core",),
     "capture_resource_native_filestorage_lifecycle.py",
     "resource_native_filestorage_lifecycle_evidence.py", "v1"),
    ("pending_host_io", ("pending_host_io",), ("suspension",),
     "capture_resource_pending.py", "resource_pending_evidence.py", "v1"),
    ("sqlite_pagination", ("sqlite_pagination",), ("sqlite",),
     "capture_resource_sqlite_pagination.py",
     "resource_sqlite_pagination_evidence.py", "v1"),
    ("sqlite_ranges", ("sqlite_ranges",), ("sqlite",),
     "capture_resource_sqlite_ranges.py", "resource_sqlite_ranges_evidence.py", "v1"),
    ("sqlite_large_values", ("sqlite_large_values",), ("sqlite",),
     "capture_resource_sqlite_large_values.py",
     "resource_sqlite_large_values_evidence.py", "v1"),
    ("brotli_ceiling", ("brotli_raw_ceiling",), ("blocking_decode",),
     "capture_resource_brotli_raw_ceiling.py",
     "resource_brotli_raw_ceiling_evidence.py", "v1"),
    ("cold_publication", ("cold_publish_br_table",
                          "cold_publish_control_nesting",
                          "cold_publish_large_function"), ("cold_compile",),
     "capture_resource_cold_publication.py",
     "resource_cold_publication_evidence.py", "v1"),
)
CAPTURE_NAMES = {
    "chain_v2": "resource-chain-v2-capture.json",
    "pulley_boundary": "resource-boundary-capture.json",
    "finite_paid": "finite-stack-capture.json",
    "canonical_abi": "canonical-stack-capture.json",
    "canonical_type_value": "type-value-capture.json",
    "resource_lifecycle": "resource-lifecycle-capture.json",
    "foreign_wave": "foreign-wave-capture.json",
    "initialization": "generated-initialization-capture.json",
    "native_staking": "native-staking-rewards-capture.json",
    "native_filestorage": "native-filestorage-lifecycle-capture.json",
    "pending_host_io": "pending-host-io-capture.json",
    "sqlite_pagination": "sqlite-pagination-capture.json",
    "sqlite_ranges": "sqlite-ranges-capture.json",
    "sqlite_large_values": "sqlite-large-values-capture.json",
    "brotli_ceiling": "brotli-raw-ceiling-capture.json",
    "cold_publication": "cold-publication-capture.json",
}


def validate_group_coverage(groups, cases):
    expected = {case["id"]: case["family"] for case in cases}
    require(len(expected) == len(cases) == 41, "S2 case count or IDs changed")
    seen = {}
    group_ids = set()
    for group_id, case_ids, families, capture, validator, manifest in groups:
        require(group_id not in group_ids and case_ids
                and manifest in {"v1", "v2", "boundary"},
                "suite group ID, cases, or manifest is invalid")
        group_ids.add(group_id)
        for case_id in case_ids:
            require(case_id in expected and case_id not in seen
                    and expected[case_id] in families,
                    f"suite case is missing, duplicated, or in the wrong family: {case_id}")
            seen[case_id] = group_id
        for name in (capture, validator):
            require((ROOT / "tools/native-stack" / name).is_file(),
                    f"suite capture or validator source is missing: {name}")
    require(set(seen) == set(expected),
            "suite registry omits required S2 cases")
    require(set(group_ids) == set(CAPTURE_NAMES),
            "suite capture file registry omits a group")
    return seen


def build_registry():
    v1 = build_manifest()
    v2 = build_manifest_v2()
    boundary = build_boundary_manifest()
    require(load_json_strict(V1_MANIFEST) == v1
            and load_json_strict(V2_MANIFEST) == v2
            and load_json_strict(BOUNDARY_MANIFEST) == boundary,
            "suite parent manifests differ from source")
    mapping = validate_group_coverage(GROUPS, v1["cases"])
    parents = {"v1": sha256(V1_MANIFEST), "v2": sha256(V2_MANIFEST),
               "boundary": sha256(BOUNDARY_MANIFEST)}
    groups = {}
    for group_id, case_ids, families, capture, validator, manifest in GROUPS:
        groups[group_id] = {
            "case_ids": list(case_ids), "families": list(families),
            "manifest": manifest, "manifest_sha256": parents[manifest],
            "capture_name": CAPTURE_NAMES[group_id],
            "capture": {"path": f"tools/native-stack/{capture}",
                        "sha256": sha256(ROOT / "tools/native-stack" / capture)},
            "validator": {"path": f"tools/native-stack/{validator}",
                          "sha256": sha256(ROOT / "tools/native-stack" / validator)},
        }
    return {
        "schema_version": 1,
        "claim_status": "source_registry_only",
        "cells": list(CELLS),
        "case_count": len(mapping),
        "case_to_group": dict(sorted(mapping.items())),
        "parent_manifests": parents,
        "groups": groups,
        "remaining_gates": {
            "boundary_discovery": boundary["claim_status"],
            "macos_guard_capture": "missing",
            "suspended_64_capacity": "required_in_pending_host_io",
            "production_memory_profiles": "missing",
            "common_head_six_cell_capture": "missing",
            "offline_archive_validation": "source_ready_unmeasured",
            "cross_cell_semantic_comparison": "source_ready_unmeasured",
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    expected = build_registry()
    encoded = json.dumps(expected, indent=2, sort_keys=True) + "\n"
    if args.write:
        MANIFEST.write_text(encoded)
    else:
        require(MANIFEST.is_file() and MANIFEST.read_text() == encoded,
                "suite registry differs from pinned sources")
    print(json.dumps({"claim_status": expected["claim_status"],
                      "cases": expected["case_count"],
                      "groups": len(expected["groups"])}, sort_keys=True))


if __name__ == "__main__":
    main()
