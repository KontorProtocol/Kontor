#!/usr/bin/env python3
"""Freeze the S2 resource experiment's required cases and source identities."""

import argparse
import hashlib
import json
import tomllib
from pathlib import Path

from compare import PRODUCTION_FEATURES, QUALIFICATION_FEATURES


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("resource-manifest-v1.json")
AMENDMENT = "docs/design/protocol-upgrades/native-stack-s2-resource-amendment-v1.md"
AMENDMENT_SHA256 = "923f6ddf0e5646e140242d11fc48995f69e2929d34930609a82ac13a4fce337c"
WASMTIME_REVISION = "0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7"
FASTNUM_BUILD_SCRIPT_SHA256 = "12dc45339dbf31bebb484721803e4ffd264f6e8cd66b97df851f4754d6297b97"
FASTNUM_GENERATED = {
    "default_rounding_mode.rs":
        "const DEFAULT_ROUNDING_MODE: RoundingMode = RoundingMode::HalfUp;",
    "exponential_format_threshold.rs":
        "const EXPONENTIAL_FORMAT_LEADING_ZERO_THRESHOLD: usize = 5;\n"
        "const EXPONENTIAL_FORMAT_TRAILING_ZERO_THRESHOLD: usize = 15;\n"
        "const FMT_MAX_INTEGER_PADDING: usize = 1000;",
    "serde_deserialize_mode.rs":
        "const SERDE_DESERIALIZE_MODE: DeserializeMode = DeserializeMode::Strict;",
}
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
    "indexer_manifest": "core/indexer/Cargo.toml",
    "testlib_manifest": "core/testlib/Cargo.toml",
    "testing_host_imports": "core/indexer/src/runtime/host_files.rs",
    "indexer_build_script": "core/indexer/build.rs",
    "stack_probe": "test-contracts/binaries/stack_probe.wasm.br",
    "stack_probe_source": "test-contracts/stack-probe/src/lib.rs",
    "crypto_component": "test-contracts/binaries/crypto.wasm.br",
    "crypto_source": "test-contracts/crypto/src/lib.rs",
    "crypto_wit": "test-contracts/crypto/wit/contract.wit",
    "canonical_probe_wat": "test-contracts/canonical-probe/fixture.wat",
    "canonical_probe_wit": "test-contracts/canonical-probe/wit/contract.wit",
    "canonical_probe_builtin_wit": "core/indexer/src/runtime/wit/deps/built-in/common.wit",
    "canonical_probe_tests": "core/indexer/src/runtime/call/tests/native_stack/canonical.rs",
    "canonical_capture": "tools/native-stack/capture_resource_canonical.py",
    "canonical_validator": "tools/native-stack/resource_canonical_evidence.py",
    "canonical_validator_tests": "tools/native-stack/test_resource_canonical_evidence.py",
    "error_test": "test-contracts/binaries/error_test.wasm.br",
    "arith_guest": "test-contracts/binaries/arith.wasm.br",
    "arith_guest_source": "test-contracts/arith/src/lib.rs",
    "arith_guest_wit": "test-contracts/arith/wit/contract.wit",
    "arith_guest_manifest": "test-contracts/arith/Cargo.toml",
    "counter_guest": "test-contracts/binaries/counter.wasm.br",
    "counter_guest_source": "test-contracts/counter/src/lib.rs",
    "counter_guest_wit": "test-contracts/counter/wit/contract.wit",
    "counter_guest_manifest": "test-contracts/counter/Cargo.toml",
    "guest_lockfile": "test-contracts/Cargo.lock",
    "guest_build_metadata": "test-contracts/binaries/build.json",
    "proxy": "test-contracts/binaries/proxy.wasm.br",
    "stack_probe_tests": "core/indexer/src/runtime/call/tests/native_stack.rs",
    "stack_sweep": "core/indexer/src/runtime/call/tests/native_stack/sweep.rs",
    "initialization_adapter": "core/indexer/src/runtime/call/tests/native_stack/initialization.rs",
    "resource_worker_diagnostic": "core/indexer/src/runtime/call/tests/native_stack_resource.rs",
    "macos_worker_capacity_guard": "core/indexer/src/runtime/call/tests/native_stack_resource/macos.rs",
    "chain_tests": "core/indexer/src/runtime/call/tests/sequential_chains.rs",
    "invocation_budget": "core/indexer/src/runtime/invocation.rs",
    "callback_tests": "core/indexer/src/runtime/sequential_tests.rs",
    "guest_error_tests": "core/indexer/src/runtime/call/tests/canonical_guest_errors.rs",
    "token_pages": "core/indexer/src/runtime/token/query_tests.rs",
    "nft_pages": "core/indexer/src/runtime/nft/query_tests.rs",
    "publish_path": "core/indexer/src/runtime/mod.rs",
    "fee_settlement": "core/indexer/src/runtime/fees.rs",
    "pricing_source": "core/indexer/src/runtime/pricing.rs",
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
    "native_staking_wit": "native-contracts/staking/wit/contract.wit",
    "native_staking_binary": "native-contracts/binaries/staking.wasm.br",
    "native_token": "native-contracts/token/src/lib.rs",
    "native_token_wit": "native-contracts/token/wit/contract.wit",
    "native_token_binary": "native-contracts/binaries/token.wasm.br",
    "native_build_metadata": "native-contracts/binaries/build.json",
    "native_filestorage": "native-contracts/filestorage/src/lib.rs",
    "native_filestorage_cleanup": "native-contracts/filestorage/src/cleanup.rs",
    "native_filestorage_rewards": "native-contracts/filestorage/src/rewards.rs",
    "native_filestorage_wit": "native-contracts/filestorage/wit/contract.wit",
    "native_filestorage_binary": "native-contracts/binaries/filestorage.wasm.br",
    "production_qualification": "tools/native-stack/compare.py",
    "resource_manifest_source": "tools/native-stack/resource_manifest.py",
    "fiber_source_capture": "tools/native-stack/capture_fiber_source.py",
    "resource_control_capture": "tools/native-stack/capture_resource_control.py",
    "resource_test_builder": "tools/native-stack/build_resource_test.py",
    "resource_test_builder_tests": "tools/native-stack/test_resource_build_attestation.py",
    "resource_diagnostic_capture": "tools/native-stack/capture_resource_diagnostic.py",
    "finite_stack_capture": "tools/native-stack/capture_resource_finite.py",
    "finite_stack_validator": "tools/native-stack/resource_finite_evidence.py",
    "finite_stack_tests": "tools/native-stack/test_resource_finite_evidence.py",
    "initialization_capture": "tools/native-stack/capture_resource_initialization.py",
    "initialization_validator": "tools/native-stack/resource_initialization_evidence.py",
    "initialization_validator_tests": "tools/native-stack/test_resource_initialization_evidence.py",
    "resource_lifecycle_wat": "test-contracts/resource-lifecycle/fixture.wat",
    "resource_lifecycle_wit": "test-contracts/resource-lifecycle/wit/contract.wit",
    "resource_lifecycle_adapter": "core/indexer/src/runtime/call/tests/native_stack/lifecycle.rs",
    "resource_lifecycle_capture": "tools/native-stack/capture_resource_lifecycle.py",
    "resource_lifecycle_validator": "tools/native-stack/resource_lifecycle_evidence.py",
    "resource_lifecycle_validator_tests": "tools/native-stack/test_resource_lifecycle_evidence.py",
    "foreign_wave_target_wit": "test-contracts/foreign-wave/target.wit",
    "foreign_wave_target_wat": "test-contracts/foreign-wave/target.wat",
    "foreign_wave_caller_wit": "test-contracts/foreign-wave/caller.wit",
    "foreign_wave_caller_wat": "test-contracts/foreign-wave/caller.wat",
    "foreign_wave_adapter": "core/indexer/src/runtime/call/tests/native_stack/foreign_wave.rs",
    "foreign_wave_capture": "tools/native-stack/capture_resource_foreign_wave.py",
    "foreign_wave_validator": "tools/native-stack/resource_foreign_wave_evidence.py",
    "foreign_wave_validator_tests": "tools/native-stack/test_resource_foreign_wave_evidence.py",
    "type_value_wit": "test-contracts/type-value/fixture.wit",
    "type_value_wat": "test-contracts/type-value/fixture.wat",
    "type_value_adapter": "core/indexer/src/runtime/call/tests/native_stack/type_value.rs",
    "type_value_capture": "tools/native-stack/capture_resource_type_value.py",
    "type_value_validator": "tools/native-stack/resource_type_value_evidence.py",
    "type_value_validator_tests": "tools/native-stack/test_resource_type_value_evidence.py",
    "sqlite_pagination_adapter": "core/indexer/src/runtime/call/tests/native_stack/sqlite_pagination.rs",
    "sqlite_pagination_capture": "tools/native-stack/capture_resource_sqlite_pagination.py",
    "sqlite_pagination_validator": "tools/native-stack/resource_sqlite_pagination_evidence.py",
    "sqlite_pagination_validator_tests": "tools/native-stack/test_resource_sqlite_pagination_evidence.py",
    "sqlite_ranges_adapter": "core/indexer/src/runtime/call/tests/native_stack/sqlite_ranges.rs",
    "sqlite_ranges_capture": "tools/native-stack/capture_resource_sqlite_ranges.py",
    "sqlite_ranges_validator": "tools/native-stack/resource_sqlite_ranges_evidence.py",
    "sqlite_ranges_validator_tests": "tools/native-stack/test_resource_sqlite_ranges_evidence.py",
    "sqlite_large_values_adapter": "core/indexer/src/runtime/call/tests/native_stack/sqlite_large_values.rs",
    "sqlite_large_values_capture": "tools/native-stack/capture_resource_sqlite_large_values.py",
    "sqlite_large_values_validator": "tools/native-stack/resource_sqlite_large_values_evidence.py",
    "sqlite_large_values_validator_tests": "tools/native-stack/test_resource_sqlite_large_values_evidence.py",
    "native_staking_rewards_adapter": "core/indexer/src/runtime/call/tests/native_stack/native_staking_rewards.rs",
    "native_staking_rewards_capture": "tools/native-stack/capture_resource_native_staking_rewards.py",
    "native_staking_rewards_validator": "tools/native-stack/resource_native_staking_rewards_evidence.py",
    "native_staking_rewards_validator_tests": "tools/native-stack/test_resource_native_staking_rewards_evidence.py",
    "native_filestorage_lifecycle_adapter": "core/indexer/src/runtime/call/tests/native_stack/native_filestorage_lifecycle.rs",
    "native_filestorage_lifecycle_capture": "tools/native-stack/capture_resource_native_filestorage_lifecycle.py",
    "native_filestorage_lifecycle_validator": "tools/native-stack/resource_native_filestorage_lifecycle_evidence.py",
    "native_filestorage_lifecycle_validator_tests": "tools/native-stack/test_resource_native_filestorage_lifecycle_evidence.py",
    "brotli_ceiling_adapter": "core/indexer/src/runtime/call/tests/native_stack/brotli_ceiling.rs",
    "brotli_ceiling_capture": "tools/native-stack/capture_resource_brotli_raw_ceiling.py",
    "brotli_ceiling_validator": "tools/native-stack/resource_brotli_raw_ceiling_evidence.py",
    "brotli_ceiling_validator_tests": "tools/native-stack/test_resource_brotli_raw_ceiling_evidence.py",
    "pending_host_capture": "tools/native-stack/capture_resource_pending.py",
    "pending_host_validator": "tools/native-stack/resource_pending_evidence.py",
    "pending_host_tests": "tools/native-stack/test_resource_pending_evidence.py",
    "finite_stack_control_copy": "tools/native-stack/capture_resource_chain_v2.py",
    "finite_stack_teardown_validator": "tools/native-stack/resource_evidence_v2.py",
    "finite_stack_boundary_validator": "tools/native-stack/resource_boundary_evidence.py",
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
             ["crypto_component", "crypto_source", "crypto_wit", "stack_probe_tests",
              "stack_sweep", "resource_worker_diagnostic", "pending_host_capture",
              "pending_host_validator", "pending_host_tests"],
             "runtime::call::tests::native_stack_resource::finite_stack_worker_case",
             ("suspended", "resumed")),
        case("max_gas_paid", "paid_limit", {"gas_limit": 100_000, "repeats": 2},
             ["stack_probe", "stack_probe_tests"], "runtime::call::tests::native_stack::qualification_probe"),
        case("native_staking_rewards", "native_core",
             {"operation": "reward", "validator_populations": [0, 4, 32, 128],
              "zero_population_emission": "zero", "source_population_cap": None,
              "exact_budget_status": "awaiting_frozen_workload_plan", "repeats": 2},
             ["staking_costs", "native_staking", "native_staking_wit",
              "native_staking_binary", "native_token", "native_token_wit",
              "native_token_binary", "native_build_metadata",
              "native_staking_rewards_adapter",
              "resource_worker_diagnostic", "native_staking_rewards_capture",
              "native_staking_rewards_validator", "native_staking_rewards_validator_tests"], sample_keys=("population_0", "population_4",
                                             "population_32", "population_128")),
        case("native_filestorage_lifecycle", "native_core",
             {"operations": ["expiry", "penalty", "cleanup"],
              "separate_per_call_budgets": {"expiry": 32, "penalty": 32,
                                            "cleanup": 32},
              "exact_budget_status": "awaiting_frozen_workload_plan", "repeats": 2},
             ["filestorage_costs", "filestorage_settlement", "native_filestorage",
              "native_filestorage_cleanup", "native_filestorage_rewards",
              "native_filestorage_wit", "native_filestorage_binary",
              "native_staking", "native_staking_wit", "native_staking_binary",
              "native_token", "native_token_wit", "native_token_binary",
              "native_build_metadata",
              "native_filestorage_lifecycle_adapter", "resource_worker_diagnostic",
              "resource_thread_trace", "macos_worker_capacity_guard",
              "native_filestorage_lifecycle_capture",
              "native_filestorage_lifecycle_validator",
              "native_filestorage_lifecycle_validator_tests"],
             sample_keys=("expiry", "penalty", "cleanup")),
        case("canonical_lift_lower", "canonical_abi", {"shape": "string_and_resource", "repeats": 2},
             ["callback_tests", "canonical_probe_wat", "canonical_probe_wit",
              "canonical_probe_tests", "canonical_capture", "canonical_validator",
              "canonical_validator_tests", "fee_settlement", "pricing_source"],
             "runtime::sequential_tests::hostile_canonical_callbacks_are_framed_and_clean_up",
             ("success", "failure"), {"failure": "trap"},
             {"failure": "CannotLeaveComponent"}),
        case("canonical_realloc", "canonical_abi", {"string_bytes": 16_384, "repeats": 2},
             ["callback_tests", "canonical_probe_wat", "canonical_probe_wit",
              "canonical_probe_tests", "canonical_capture", "canonical_validator",
              "canonical_validator_tests", "fee_settlement", "pricing_source"],
             "runtime::sequential_tests::hostile_canonical_callbacks_are_framed_and_clean_up",
             ("success_lowering", "realloc_trap", "forbidden_import"),
             {"realloc_trap": "trap", "forbidden_import": "trap"},
             {"realloc_trap": "UnreachableCodeReached",
              "forbidden_import": "CannotLeaveComponent"}),
        case("canonical_post_return", "canonical_abi", {"callback_loop_iterations": 16_384, "repeats": 2},
             ["callback_tests", "canonical_probe_wat", "canonical_probe_wit",
              "canonical_probe_tests", "canonical_capture", "canonical_validator",
              "canonical_validator_tests", "fee_settlement", "pricing_source"],
             "runtime::sequential_tests::paid_post_return_callback_work_charges_fuel_gas_and_burn",
             ("light", "heavy"), {"light": "trap", "heavy": "trap"},
             {"light": "CannotLeaveComponent", "heavy": "CannotLeaveComponent"}),
        case("generated_initialization", "initialization",
             {"start_free": True, "active_data": True, "active_element": True,
              "out_of_bounds_variants": True, "fuel_failure": True, "repeats": 2},
             ["callback_tests", "initialization_adapter", "resource_worker_diagnostic",
              "initialization_capture", "initialization_validator",
              "initialization_validator_tests"],
             sample_keys=("active_data_success", "active_element_success", "active_data_oob",
                          "active_element_oob", "fuel_failure"),
             expected_outcomes={"active_data_oob": "deterministic_error",
                                "active_element_oob": "deterministic_error",
                                "fuel_failure": "out_of_fuel"},
             expected_traps={"fuel_failure": "OutOfFuel"}),
        case("explicit_resource_drop", "resource_lifecycle", {"success_trap_success": True},
             ["callback_tests", "resource_lifecycle_wat", "resource_lifecycle_wit",
              "resource_lifecycle_adapter", "resource_worker_diagnostic",
              "resource_lifecycle_capture", "resource_lifecycle_validator",
              "resource_lifecycle_validator_tests"],
             "runtime::sequential_tests::explicit_guest_resource_drop_invokes_host_callback_and_cleans_up",
             ("success_before_trap", "trap", "success_after_trap"), {"trap": "trap"},
             {"trap": "UnreachableCodeReached"}),
        case("failed_instantiation_cleanup", "resource_lifecycle",
             {"out_of_bounds_data": True, "repeats": 2},
             ["callback_tests", "resource_lifecycle_wat", "resource_lifecycle_wit",
              "resource_lifecycle_adapter", "resource_worker_diagnostic",
              "resource_lifecycle_capture", "resource_lifecycle_validator",
              "resource_lifecycle_validator_tests"],
             "runtime::sequential_tests::partial_instantiation_does_not_invoke_registered_destructors",
             ("failed_init", "valid_control"),
             {"failed_init": "deterministic_error"},
             {"failed_init": "MemoryOutOfBounds"}),
        case("sqlite_pagination", "sqlite", {"page_sizes": [1, 7, 100], "rows": 1_024},
             ["token_pages", "nft_pages", "sqlite_pagination_adapter",
              "resource_worker_diagnostic", "sqlite_pagination_capture",
              "sqlite_pagination_validator", "sqlite_pagination_validator_tests"],
             "runtime::token::query_tests::balance_pages_cover_the_ledger_and_bound_scan_work",
             tuple(f"{source}_{size}_{position}" for source in ("token", "nft")
                   for size in (1, 7, 100) for position in ("first", "middle", "final"))),
        case("sqlite_ranges", "sqlite",
             {"rows": 1_024, "page_sizes": [1, 7, 100],
              "range_lengths": [0, 1, 256, 1_024]},
             ["arith_guest", "arith_guest_source", "arith_guest_wit",
              "arith_guest_manifest", "guest_lockfile", "guest_build_metadata",
              "sqlite_ranges_adapter", "resource_worker_diagnostic",
              "sqlite_ranges_capture", "sqlite_ranges_validator",
              "sqlite_ranges_validator_tests"],
             sample_keys=tuple(f"page_{page}_range_{length}" for page in (1, 7, 100)
                               for length in (0, 1, 256, 1_024))),
        case("sqlite_large_values", "sqlite",
             {"value_bytes": [16_384, 1_048_576], "page_sizes": [1, 7, 100]},
             ["counter_guest", "counter_guest_source", "counter_guest_wit",
              "counter_guest_manifest", "guest_lockfile", "guest_build_metadata",
              "sqlite_large_values_adapter", "resource_worker_diagnostic",
              "sqlite_large_values_capture", "sqlite_large_values_validator",
              "sqlite_large_values_validator_tests"],
             sample_keys=tuple(f"value_{size}_page_{page}" for size in (16_384, 1_048_576)
                               for page in (1, 7, 100))),
        case("deepest_frame_host_call", "pulley_host_callback",
             {"adjacent_leaf_boundary": True, "host_call_at_leaf": True}, []),
        case("canonical_type_value_recursion", "canonical_abi",
             {"component_type_depth_limit": 100, "wave_result_value_depth_limit": 64,
              "wave_expression_max_depth": 64, "wave_string_literal_max_bytes": 16_384,
              "shapes": ["nested_record", "nested_variant", "list_of_records", "large_result"],
              "repeats": 2},
             ["call_input", "call_output", "type_value_wit", "type_value_wat",
              "type_value_adapter", "resource_worker_diagnostic", "type_value_capture",
              "type_value_validator", "type_value_validator_tests"],
             sample_keys=("nested_record", "nested_variant", "list_of_records", "large_result",
                          "result_depth_64", "result_depth_65_rejected"),
             expected_outcomes={"result_depth_65_rejected": "deterministic_error"}),
        case("foreign_wave_parse_print", "foreign_call",
             {"via": "foreign.call", "expression_depth_limit": 64,
              "string_literal_byte_limit": 16_384, "repeats": 2},
             ["call_input", "call_output", "foreign_wave_target_wit",
              "foreign_wave_target_wat", "foreign_wave_caller_wit",
              "foreign_wave_caller_wat", "foreign_wave_adapter",
              "resource_worker_diagnostic", "foreign_wave_capture",
              "foreign_wave_validator", "foreign_wave_validator_tests"],
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
    indexer = tomllib.loads((ROOT / INPUTS["indexer_manifest"]).read_text())
    testlib = tomllib.loads((ROOT / INPUTS["testlib_manifest"]).read_text())
    if (indexer.get("features", {}).get("testing") != []
            or indexer.get("features", {}).get("default", []) != []
            or testlib.get("dependencies", {}).get("indexer", {}).get("features") != ["testing"]):
        raise ValueError("test-only indexer feature path differs from frozen policy")
    compile_env = {"RUSTUP_TOOLCHAIN": "1.99.1",
                   "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": "",
                   "RUSTC": None, "CARGO_TARGET_DIR": None,
                   "CARGO_BUILD_RUSTC": None, "CCACHE_DISABLE": "1",
                   "RUSTFLAGS": "", "CARGO_ENCODED_RUSTFLAGS": "",
                   "CARGO_BUILD_RUSTFLAGS": "",
                   "RUST_FASTNUM_FMT_EXPONENTIAL_LOWER_THRESHOLD": None,
                   "RUST_FASTNUM_FMT_EXPONENTIAL_UPPER_THRESHOLD": None,
                   "RUST_FASTNUM_FMT_MAX_INTEGER_PADDING": None}
    native_environment_keys = sorted({name for name, value in compile_env.items()
                                      if value is not None} | {
        "PATH", "HOME", "TMPDIR", "CARGO_HOME", "RUSTUP_HOME",
        "CARGO_TARGET_DIR", "CARGO_INCREMENTAL", "LC_ALL", "LANG", "TZ",
        "SOURCE_DATE_EPOCH",
        "CC", "CXX", "AR", "CMAKE_C_COMPILER", "CMAKE_CXX_COMPILER",
        "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "ARFLAGS",
    })
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
                         "fastnum_build_script_sha256": FASTNUM_BUILD_SCRIPT_SHA256,
                         "fastnum_generated": FASTNUM_GENERATED,
                         "resolved_indexer_test_features": ["testing"],
                         "production_indexer_features": [],
                         "testing_host_imports": ["host-error", "host-panic"],
                         "rustflags": [], "rustc_wrapper": "",
                         "stack_probing_configuration":
                         "target default; native probe coverage not verified by disassembly",
                         "compile_env": compile_env,
                         "native_environment_keys": native_environment_keys},
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
            "macos_thread_guard_capacity": "capture_pending",
            "wasmtime_fiber_effective_capacity": "missing",
        },
        "guard_control_runner": {
            "status": "diagnostic_only",
            "test_name": "runtime::call::tests::native_stack_resource::linux_worker_guard_fault_control",
            "macos_test_name": "runtime::call::tests::native_stack_resource::macos_worker_guard_fault_control",
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
