#!/usr/bin/env python3
"""Freeze the S2 resource experiment's required cases and source identities."""

import argparse
import hashlib
import json
from pathlib import Path

from compare import PRODUCTION_FEATURES, QUALIFICATION_FEATURES


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("resource-manifest-v1.json")
AMENDMENT = "docs/design/protocol-upgrades/native-stack-s2-resource-amendment-v1.md"
AMENDMENT_SHA256 = "923f6ddf0e5646e140242d11fc48995f69e2929d34930609a82ac13a4fce337c"
WASMTIME_REVISION = "0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7"
FIBER_SOURCE_FILES = {
    "crates/wasmtime/src/config.rs": "681d6d278c7c0da051672c2c0acf0e658cab8338a5d461dba5f1596978336b8a",
    "crates/wasmtime/src/runtime/fiber.rs": "6cb7d27f82be901b663a8ef54d9cf9ee2c797f937c59544403e82cae27b2cf4e",
    "crates/wasmtime/src/runtime/store/async_.rs": "d06e41cc5ea602367d4286a54a5efd0672ef9503e4e55aff5a2a55885ac996e4",
    "crates/wasmtime/src/runtime/vm/instance/allocator/on_demand.rs": "b2399776ffd454560d13182c410ed9cb280b22a9278a2ed94c009e4d350b4867",
    "crates/fiber/src/lib.rs": "1d747766d66be57bc530917505a2469993a0dabb64c28a3cc4fe38fd597991b7",
    "crates/fiber/src/unix.rs": "83121bc6a5becaeae393b99848f6c1fd169e44c1b7857b3b862f74c64b950c4c",
}
BASE_COMMIT = "67a52fed58a893ce2c1c05483f86f4fffa02a675"
INPUTS = {
    "core_lockfile": "core/Cargo.lock",
    "indexer_build_script": "core/indexer/build.rs",
    "stack_probe": "test-contracts/binaries/stack_probe.wasm.br",
    "stack_probe_source": "test-contracts/stack-probe/src/lib.rs",
    "error_test": "test-contracts/binaries/error_test.wasm.br",
    "proxy": "test-contracts/binaries/proxy.wasm.br",
    "stack_probe_tests": "core/indexer/src/runtime/call/tests/native_stack.rs",
    "stack_sweep": "core/indexer/src/runtime/call/tests/native_stack/sweep.rs",
    "resource_worker_diagnostic": "core/indexer/src/runtime/call/tests/native_stack_resource.rs",
    "chain_tests": "core/indexer/src/runtime/call/tests/sequential_chains.rs",
    "invocation_budget": "core/indexer/src/runtime/invocation.rs",
    "callback_tests": "core/indexer/src/runtime/sequential_tests.rs",
    "guest_error_tests": "core/indexer/src/runtime/call/tests/canonical_guest_errors.rs",
    "token_pages": "core/indexer/src/runtime/token/query_tests.rs",
    "nft_pages": "core/indexer/src/runtime/nft/query_tests.rs",
    "publish_path": "core/indexer/src/runtime/mod.rs",
    "resource_thread_trace": "core/indexer/src/runtime/resource_diagnostics.rs",
    "brotli_path": "core/indexer/src/runtime/storage.rs",
    "call_input": "core/indexer/src/runtime/call.rs",
    "call_output": "core/indexer/src/runtime/call/result.rs",
    "runner_module": "core/indexer/src/runtime/call/tests.rs",
    "test_runtime_setup": "core/indexer/src/test_utils.rs",
    "staking_costs": "core/indexer/src/runtime/staking/transition_costs.rs",
    "filestorage_costs": "core/indexer/src/runtime/filestorage/reward_costs.rs",
    "filestorage_settlement": "core/indexer/src/runtime/filestorage/settlement_tests.rs",
    "native_staking": "native-contracts/staking/src/lib.rs",
    "native_filestorage": "native-contracts/filestorage/src/lib.rs",
    "production_qualification": "tools/native-stack/compare.py",
    "resource_manifest_source": "tools/native-stack/resource_manifest.py",
    "fiber_source_capture": "tools/native-stack/capture_fiber_source.py",
    "resource_control_capture": "tools/native-stack/capture_resource_control.py",
    "resource_diagnostic_capture": "tools/native-stack/capture_resource_diagnostic.py",
    "resource_chain_capture": "tools/native-stack/capture_resource_chain.py",
    "resource_validator_source": "tools/native-stack/resource_evidence.py",
    "resource_schema": "tools/native-stack/resource-evidence-schema-v1.json",
    "resource_comparator_source": "tools/native-stack/compare_resource.py",
    "resource_python_requirements": "tools/native-stack/requirements-resource.txt",
    "qualification_workflow": ".github/workflows/native-stack.yml",
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
    "thread_category", "thread_id", "process_id", "os_thread_id", "identity_api",
    "page_size_bytes", "requested_bytes", "mapped_bytes", "guard_bytes",
    "guard_start", "guard_end", "guard_verification", "usable_bytes",
    "mapped_start", "mapped_end", "usable_start", "usable_end",
    "measurement_api", "guard_treatment", "guard_verified",
)
OBSERVATION_FIELDS = (
    "case_id", "sample_key", "outcome", "error_class", "trap", "value", "fuel",
    "receipts", "state", "rollback", "live_stores", "reservations",
    "resource_cleanup", "fresh_store", "suspended", "reused", "observed_depth",
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def case(case_id, family, parameters, fixtures, binding=None, sample_keys=("target",),
         expected_outcomes=None, expected_traps=None):
    expected_outcomes = expected_outcomes or {}
    expected_traps = expected_traps or {}
    return {
        "id": case_id,
        "family": family,
        "parameters": parameters,
        "sample_keys": list(sample_keys),
        "expected_outcomes": {key: expected_outcomes.get(key, "ok") for key in sample_keys},
        "expected_traps": {key: expected_traps.get(key) for key in sample_keys},
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
                {"first_failure": "stack_overflow"},
                {"first_failure": "StackOverflow"},
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
                expected_outcomes={"target": "invocation_limit"} if stores == 65 else None,
            ))
    result.extend((
        case("pending_host_io", "suspension", {"pending_import": True, "repeats": 2},
             ["callback_tests"], "runtime::sequential_tests::pending_host_io_suspends_guest_and_leaves_executor_available",
             ("suspended", "resumed")),
        case("max_gas_paid", "paid_limit", {"gas_limit": 100_000, "repeats": 2},
             ["stack_probe", "stack_probe_tests"], "runtime::call::tests::native_stack::qualification_probe"),
        case("native_staking_rewards", "native_core",
             {"operation": "reward", "validator_populations": [0, 4, 32, 128],
              "zero_population_emission": "zero", "source_population_cap": None,
              "exact_budget_status": "awaiting_frozen_workload_plan", "repeats": 2},
             ["staking_costs", "native_staking"], sample_keys=("population_0", "population_4",
                                             "population_32", "population_128")),
        case("native_filestorage_lifecycle", "native_core",
             {"operations": ["expiry", "penalty", "cleanup"],
              "separate_per_call_budgets": {"expiry": 32, "penalty": 32,
                                            "cleanup": 32},
              "exact_budget_status": "awaiting_frozen_workload_plan", "repeats": 2},
             ["filestorage_costs", "filestorage_settlement", "native_filestorage"],
             sample_keys=("expiry", "penalty", "cleanup")),
        case("canonical_lift_lower", "canonical_abi", {"shape": "string_and_resource", "repeats": 2},
             ["callback_tests"], "runtime::sequential_tests::hostile_canonical_callbacks_are_framed_and_clean_up",
             ("success", "failure"), {"failure": "trap"},
             {"failure": "CannotLeaveComponent"}),
        case("canonical_realloc", "canonical_abi", {"string_bytes": 16_384, "repeats": 2},
             ["callback_tests"], "runtime::sequential_tests::hostile_canonical_callbacks_are_framed_and_clean_up",
             ("success_lowering", "realloc_trap", "forbidden_import"),
             {"realloc_trap": "trap", "forbidden_import": "trap"},
             {"realloc_trap": "UnreachableCodeReached",
              "forbidden_import": "CannotLeaveComponent"}),
        case("canonical_post_return", "canonical_abi", {"callback_loop_iterations": 16_384, "repeats": 2},
             ["callback_tests"], "runtime::sequential_tests::paid_post_return_callback_work_charges_fuel_gas_and_burn",
             ("light", "heavy"), {"light": "trap", "heavy": "trap"},
             {"light": "CannotLeaveComponent", "heavy": "CannotLeaveComponent"}),
        case("generated_initialization", "initialization",
             {"start_free": True, "active_data": True, "active_element": True,
              "out_of_bounds_variants": True, "fuel_failure": True, "repeats": 2},
             ["callback_tests"],
             sample_keys=("active_data_success", "active_element_success", "active_data_oob",
                          "active_element_oob", "fuel_failure"),
             expected_outcomes={"active_data_oob": "deterministic_error",
                                "active_element_oob": "deterministic_error",
                                "fuel_failure": "out_of_fuel"},
             expected_traps={"fuel_failure": "OutOfFuel"}),
        case("explicit_resource_drop", "resource_lifecycle", {"success_trap_success": True},
             ["callback_tests"], "runtime::sequential_tests::explicit_guest_resource_drop_invokes_host_callback_and_cleans_up",
             ("success_before_trap", "trap", "success_after_trap"), {"trap": "trap"},
             {"trap": "UnreachableCodeReached"}),
        case("failed_instantiation_cleanup", "resource_lifecycle", {"out_of_bounds_data": True, "repeats": 2},
             ["callback_tests"], "runtime::sequential_tests::partial_instantiation_does_not_invoke_registered_destructors",
             ("failed_init", "valid_control"), {"failed_init": "deterministic_error"}),
        case("sqlite_pagination", "sqlite", {"page_sizes": [1, 7, 100], "rows": 1_024},
             ["token_pages", "nft_pages"], "runtime::token::query_tests::balance_pages_cover_the_ledger_and_bound_scan_work",
             tuple(f"{source}_{size}_{position}" for source in ("token", "nft")
                   for size in (1, 7, 100) for position in ("first", "middle", "final"))),
        case("sqlite_ranges", "sqlite",
             {"rows": 1_024, "page_sizes": [1, 7, 100],
              "range_lengths": [0, 1, 256, 1_024]}, [],
             sample_keys=tuple(f"page_{page}_range_{length}" for page in (1, 7, 100)
                               for length in (0, 1, 256, 1_024))),
        case("sqlite_large_values", "sqlite",
             {"value_bytes": [16_384, 1_048_576], "page_sizes": [1, 7, 100]}, [],
             sample_keys=tuple(f"value_{size}_page_{page}" for size in (16_384, 1_048_576)
                               for page in (1, 7, 100))),
        case("deepest_frame_host_call", "pulley_host_callback",
             {"adjacent_leaf_boundary": True, "host_call_at_leaf": True}, []),
        case("canonical_type_value_recursion", "canonical_abi",
             {"component_type_depth_limit": 100, "wave_result_value_depth_limit": 64,
              "wave_expression_max_depth": 64, "wave_string_literal_max_bytes": 16_384,
              "shapes": ["nested_record", "nested_variant", "list_of_records", "large_result"],
              "repeats": 2}, ["call_input", "call_output"],
             sample_keys=("nested_record", "nested_variant", "list_of_records", "large_result",
                          "result_depth_64", "result_depth_65_rejected"),
             expected_outcomes={"result_depth_65_rejected": "deterministic_error"}),
        case("foreign_wave_parse_print", "foreign_call",
             {"via": "foreign.call", "expression_depth_limit": 64,
              "string_literal_byte_limit": 16_384, "repeats": 2},
             ["call_input", "call_output"],
             sample_keys=("depth_64", "depth_65_rejected", "literal_16384",
                          "literal_16385_rejected", "print_depth_64", "print_depth_65_rejected"),
             expected_outcomes={"depth_65_rejected": "deterministic_error",
                                "literal_16385_rejected": "deterministic_error",
                                "print_depth_65_rejected": "deterministic_error"}),
        case("cold_publish_large_function", "cold_compile",
             {"source_function_size_limit_bytes": 7_654_321,
              "fixture_function_size_bytes": None,
              "fixture_admission_status": "unverified",
              "cold_cache": True, "repeats": 2},
             ["publish_path"], sample_keys=("accepted", "over_limit_rejected"),
             expected_outcomes={"over_limit_rejected": "deterministic_error"}),
        case("cold_publish_control_nesting", "cold_compile",
             {"source_effective_depth_limit": "unresolved",
              "fixture_control_depth": None,
              "fixture_admission_status": "unverified",
              "cold_cache": True, "repeats": 2},
             ["publish_path"], sample_keys=("accepted",)),
        case("cold_publish_br_table", "cold_compile",
             {"source_br_table_limit_entries": 7_654_321,
              "fixture_br_table_entries": None,
              "fixture_admission_status": "unverified",
              "cold_cache": True, "repeats": 2},
             ["publish_path"], sample_keys=("accepted", "over_limit_rejected"),
             expected_outcomes={"over_limit_rejected": "deterministic_error"}),
        case("brotli_raw_ceiling", "blocking_decode",
             {"raw_ceiling_bytes": 67_108_864, "blocking_pool": True, "repeats": 2},
             ["brotli_path"], sample_keys=("at_ceiling", "one_byte_over_rejected"),
             expected_outcomes={"one_byte_over_rejected": "deterministic_error"}),
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
        "wasmtime_features": {"production": sorted(PRODUCTION_FEATURES),
                              "qualification": sorted(QUALIFICATION_FEATURES)},
        "build_policy": {"rustc_release": "1.99.1", "cargo_features": [],
                         "rustflags": [], "rustc_wrapper": "",
                         "stack_probing_configuration":
                         "target default; native probe coverage not verified by disassembly",
                         "compile_env": {"RUSTUP_TOOLCHAIN": "1.99.1",
                                         "RUSTC_WRAPPER": "", "RUSTC": "",
                                         "CARGO_BUILD_RUSTC": "", "CCACHE_DISABLE": "1",
                                         "RUSTFLAGS": "", "CARGO_ENCODED_RUSTFLAGS": "",
                                         "CARGO_BUILD_RUSTFLAGS": ""}},
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
            "component_type_depth": 100,
            "wave_result_value_depth": 64,
            "wave_result_bytes": "bounded_by_remaining_fuel",
            "legal_shapes_not_covered": ["all combinations of component type constructors",
                                         "all permitted list lengths and element values",
                                         "all 100-deep type graphs with shallow values"],
        },
        "publication_constraints": {
            "decompressed_component_bytes": 67_108_864,
            "function_body_bytes": 7_654_321,
            "br_table_entries": 7_654_321,
            "serialized_transaction_and_wit_admission": "unresolved",
            "near_boundary_accepted_fixture": "unverified",
        },
        "attestation_status": {
            "cargo_binary_capture": "unimplemented",
            "source_revision_capture": "unimplemented",
            "per_cell_guard_fault_control": "missing",
            "macos_thread_guard_capacity": "unimplemented",
            "wasmtime_fiber_effective_capacity": "missing",
        },
        "guard_control_runner": {
            "status": "diagnostic_only",
            "test_name": "runtime::call::tests::native_stack_resource::linux_worker_guard_fault_control",
            "source_sha256": sha256(ROOT / "core/indexer/src/runtime/call/tests/native_stack_resource.rs"),
        },
        "fiber_source_proof": {
            "wasmtime_revision": WASMTIME_REVISION,
            "source_files": FIBER_SOURCE_FILES,
            "allocation_path": "on_demand_without_custom_stack_creator",
            "sanitizer_path": "none",
            "effective_writable_rule": "round_up_requested_bytes_to_host_page",
            "guard_rule": "one_separate_inaccessible_host_page",
        },
        "workload_plan": {"status": "awaiting_frozen_workload_plan",
                          "path": "tools/native-stack/resource-workload-plan-v1.json",
                          "sha256": None},
        "worker_runner": {"status": "smoke_only", "path":
                          "core/indexer/src/runtime/call/tests/native_stack_resource.rs",
                          "test_name": "runtime::call::tests::native_stack_resource::resource_qualification",
                          "sha256": sha256(ROOT / "core/indexer/src/runtime/call/tests/native_stack_resource.rs")},
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
