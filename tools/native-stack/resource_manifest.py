#!/usr/bin/env python3
"""Freeze the S2 resource experiment's required cases and source identities."""

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("resource-manifest-v1.json")
AMENDMENT = "docs/design/protocol-upgrades/native-stack-s2-resource-amendment-v1.md"
AMENDMENT_SHA256 = "923f6ddf0e5646e140242d11fc48995f69e2929d34930609a82ac13a4fce337c"
WASMTIME_REVISION = "0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7"
BASE_COMMIT = "67a52fed58a893ce2c1c05483f86f4fffa02a675"
INPUTS = {
    "stack_probe": "test-contracts/binaries/stack_probe.wasm.br",
    "stack_probe_source": "test-contracts/stack-probe/src/lib.rs",
    "error_test": "test-contracts/binaries/error_test.wasm.br",
    "proxy": "test-contracts/binaries/proxy.wasm.br",
    "stack_probe_tests": "core/indexer/src/runtime/call/tests/native_stack.rs",
    "stack_sweep": "core/indexer/src/runtime/call/tests/native_stack/sweep.rs",
    "chain_tests": "core/indexer/src/runtime/call/tests/sequential_chains.rs",
    "callback_tests": "core/indexer/src/runtime/sequential_tests.rs",
    "guest_error_tests": "core/indexer/src/runtime/call/tests/canonical_guest_errors.rs",
    "token_pages": "core/indexer/src/runtime/token/query_tests.rs",
    "nft_pages": "core/indexer/src/runtime/nft/query_tests.rs",
}
CELLS = (
    "Linux-X64/dev",
    "Linux-X64/release",
    "Linux-ARM64/dev",
    "Linux-ARM64/release",
    "macOS-ARM64/dev",
    "macOS-ARM64/release",
)
THREAD_CATEGORIES = ("tokio_worker", "blocking_pool", "block_on_caller")
CAPACITY_FIELDS = (
    "requested_bytes", "mapped_bytes", "guard_bytes", "usable_bytes",
    "measurement_api", "thread_id", "thread_category",
)
OBSERVATION_FIELDS = (
    "case_id", "sample_key", "outcome", "error_class", "trap", "value", "fuel",
    "receipts", "state", "rollback", "live_stores", "reservations",
    "resource_cleanup", "fresh_store", "suspended", "reused",
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def case(case_id, family, parameters, fixtures, binding=None, sample_keys=("target",)):
    return {
        "id": case_id,
        "family": family,
        "parameters": parameters,
        "sample_keys": list(sample_keys),
        "fixtures": fixtures,
        "existing_unpaired_binding": binding,
        "paired_worker_status": "missing",
    }


def cases():
    result = []
    for shape in ("plain", "wide"):
        for mode in ("paid", "view", "system", "core"):
            result.append(case(
                f"pulley_{shape}_{mode}", "pulley_boundary",
                {"mode": mode, "shape": shape, "adjacent_boundary": True, "repeats": 3},
                ["stack_probe", "stack_probe_source", "stack_probe_tests", "stack_sweep"],
                "runtime::call::tests::native_stack::qualification_probe",
                ("last_success", "first_failure"),
            ))
    result.append(case(
        "large_frame_paid", "large_frame",
        {"mode": "paid", "live_u64_values": 256, "repeats": 3},
        ["stack_probe", "stack_probe_source", "stack_probe_tests", "stack_sweep"],
        "runtime::call::tests::native_stack::qualification_probe",
    ))
    for stores in (33, 63, 64, 65):
        for mode in ("paid", "view", "core"):
            result.append(case(
                f"chain_{stores}_{mode}", "distinct_contract_chain",
                {"mode": mode, "simultaneous_stores": stores, "repeats": 3,
                 "root_included": True, "failure_expected": stores == 65},
                ["error_test", "proxy", "chain_tests"],
                "runtime::call::tests::sequential_chains::chain_probe_child",
            ))
    result.extend((
        case("pending_host_io", "suspension", {"pending_import": True, "repeats": 2},
             ["callback_tests"], "runtime::sequential_tests::pending_host_io_suspends_guest_and_leaves_executor_available",
             ("suspended", "resumed")),
        case("max_gas_paid", "paid_limit", {"gas_limit": 100_000, "repeats": 2},
             ["stack_probe", "stack_probe_tests"], "runtime::call::tests::native_stack::qualification_probe"),
        case("real_native_core", "native_core", {"mode": "core", "repeats": 2}, [],
             sample_keys=("success", "failure")),
        case("canonical_lift_lower", "canonical_abi", {"shape": "string_and_resource", "repeats": 2},
             ["callback_tests"], "runtime::sequential_tests::hostile_canonical_callbacks_are_framed_and_clean_up",
             ("success", "failure")),
        case("canonical_realloc", "canonical_abi", {"string_bytes": 16_384, "repeats": 2},
             ["callback_tests"], "runtime::sequential_tests::hostile_canonical_callbacks_are_framed_and_clean_up",
             ("success_lowering", "realloc_trap", "forbidden_import")),
        case("canonical_post_return", "canonical_abi", {"callback_loop_iterations": 16_384, "repeats": 2},
             ["callback_tests"], "runtime::sequential_tests::paid_post_return_callback_work_charges_fuel_gas_and_burn",
             ("light", "heavy")),
        case("generated_initialization", "initialization",
             {"start_free": True, "active_data": True, "active_element": True,
              "out_of_bounds_variants": True, "fuel_failure": True, "repeats": 2},
             ["callback_tests"],
             sample_keys=("active_data_success", "active_element_success", "active_data_oob",
                          "active_element_oob", "fuel_failure")),
        case("explicit_resource_drop", "resource_lifecycle", {"success_trap_success": True},
             ["callback_tests"], "runtime::sequential_tests::explicit_guest_resource_drop_invokes_host_callback_and_cleans_up",
             ("success_before_trap", "trap", "success_after_trap")),
        case("failed_instantiation_cleanup", "resource_lifecycle", {"out_of_bounds_data": True, "repeats": 2},
             ["callback_tests"], "runtime::sequential_tests::partial_instantiation_does_not_invoke_registered_destructors",
             ("failed_init", "valid_control")),
        case("sqlite_pagination", "sqlite", {"page_sizes": [1, 7, 100], "rows": 1_024},
             ["token_pages", "nft_pages"], "runtime::token::query_tests::balance_pages_cover_the_ledger_and_bound_scan_work",
             ("first", "middle", "final")),
        case("sqlite_ranges", "sqlite", {"rows": 1_024, "range_lengths": [0, 1, 256, 1_024]}, [],
             sample_keys=("empty", "single", "page", "full")),
        case("sqlite_large_values", "sqlite", {"value_bytes": [16_384, 1_048_576]}, [],
             sample_keys=("16k", "1m")),
        case("deepest_frame_host_call", "pulley_host_callback",
             {"depth": "last_success_from_plain_boundary", "host_call_at_leaf": True}, []),
        case("canonical_type_value_recursion", "canonical_abi",
             {"wave_expression_max_depth": 64, "wave_string_literal_max_bytes": 16_384,
              "shapes": ["nested_record", "nested_variant", "list_of_records", "large_result"]}, [],
             sample_keys=("nested_record", "nested_variant", "list_of_records", "large_result")),
    ))
    return sorted(result, key=lambda item: item["id"])


def build_manifest():
    if sha256(ROOT / AMENDMENT) != AMENDMENT_SHA256:
        raise ValueError("approved resource amendment bytes changed")
    artifacts = {
        name: {"path": path, "sha256": sha256(ROOT / path)}
        for name, path in sorted(INPUTS.items())
    }
    return {
        "schema_version": 1,
        "claim_status": "preflight_only",
        "amendment": {"path": AMENDMENT, "sha256": AMENDMENT_SHA256},
        "source_baseline_commit": BASE_COMMIT,
        "wasmtime_revision": WASMTIME_REVISION,
        "cells": list(CELLS),
        "configurations": {
            "production": {"pulley_stack_bytes": 524_288, "fiber_requested_bytes": 2_097_152,
                           "test_only": False},
            "reduced": {"pulley_stack_bytes": 524_288, "fiber_requested_bytes": 1_048_576,
                        "test_only": True},
        },
        "runtime": {"flavor": "multi_thread", "worker_count": 2,
                    "reduced_worker_stack_requested_bytes": 1_048_576,
                    "thread_categories": list(THREAD_CATEGORIES),
                    "capacity_fields": list(CAPACITY_FIELDS),
                    "production_to_reduced_worker_usable_min_ratio": 2},
        "type_value_limits": {
            "wave_expression_depth": 64,
            "wave_string_literal_bytes": 16_384,
            "canonical_result_type_depth": "unproven",
            "canonical_result_value_bytes": "unproven",
        },
        "memory_profiles": [
            {"id": "suspended_64", "simultaneous_stores": 64, "view_roots": 0,
             "reactor_roots": 1, "production_capacity_only": True},
            {"id": "overlap_2cpu_12gib", "reference_cpus": 2, "reference_memory_bytes": 12 * 1024**3,
             "view_roots": 8, "reactor_roots": 1, "production_capacity_only": True},
            {"id": "overlap_8cpu_16gib", "reference_cpus": 8, "reference_memory_bytes": 16 * 1024**3,
             "view_roots": 8, "reactor_roots": 1, "production_capacity_only": True},
        ],
        "required_observation_fields": list(OBSERVATION_FIELDS),
        "artifacts": artifacts,
        "cases": cases(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the review manifest")
    args = parser.parse_args()
    manifest = build_manifest()
    encoded = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.write:
        MANIFEST.write_text(encoded)
    elif not MANIFEST.is_file() or MANIFEST.read_text() != encoded:
        parser.error("resource manifest is missing or its inputs/parameters changed")
    print(f"resource manifest: {len(manifest['cases'])} required cases, "
          f"{len(manifest['artifacts'])} pinned inputs, status preflight_only")


if __name__ == "__main__":
    main()
