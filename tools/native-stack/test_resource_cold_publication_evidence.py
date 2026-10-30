#!/usr/bin/env python3
"""Check that cold publication evidence rejects false gates and state claims."""

import copy
import unittest

from resource_cold_publication_evidence import (FUNCTION_LIMIT, RAW_MODULES,
                                                expected_address,
                                                expected_shape,
                                                validate_observation)


def teardown_events():
    return [{"id": 0, "role": "nested_chain", "kind": kind,
             "table_alive": False if kind == "table_destroyed" else None}
            for kind in ("reserved", "store_created", "table_destroyed",
                         "lease_released")]


def attempt(case_id, sample):
    accepted = sample == "accepted"
    body_bytes, entries, depth = expected_shape(case_id, sample)
    raw_bytes, raw_sha256 = RAW_MODULES[case_id, sample]
    name, address = expected_address(case_id, sample)
    observation = {
        "sample_key": sample,
        "outcome": "ok" if accepted else "deterministic_error",
        "error_kind": None if accepted else "function_body_size_exceeded",
        "error_text": None if accepted else
            "function body size count exceeds limit of 7654321",
        "result_value": address if accepted else None,
        "function_body_bytes": body_bytes,
        "function_body_limit_bytes": FUNCTION_LIMIT,
        "br_table_entries": entries,
        "br_table_source_limit_entries":
            FUNCTION_LIMIT if entries is not None else None,
        "br_table_fixture_max_entries":
            FUNCTION_LIMIT - 13 if entries is not None else None,
        "control_depth": depth,
        "raw_module_bytes": raw_bytes,
        "raw_module_sha256": raw_sha256,
        "compressed_bytes": 90_000,
        "compressed_sha256": "b" * 64,
        "serialized_instruction_bytes": 91_000,
        "publication_path": "Runtime::publish/Storage::decode_component_bytes/"
                            "ComponentEncoder/Component::from_binary",
        "state_before_sha256": "c" * 64,
        "state_after_sha256": ("d" if accepted else "c") * 64,
        "state_restored_sha256": "c" * 64,
        "receipts_before": 4,
        "receipts_after": 5 if accepted else 4,
        "measured_receipts": ([{
            "contract": name, "function": "init", "status": "Ok", "gas": 7,
            "size": len(address.encode()), "value": address,
            "signer_id": 1, "payer_signer_id": 1, "height": 1,
            "tx_id": None, "input_index": 0, "op_index": 0,
            "result_index": 0,
        }] if accepted else []),
        "receipts_restored": 4,
        "resources_before": 0,
        "resources_after": 0,
        "system_fuel": 100 if accepted else 0,
        "user_fuel": 0,
        "deposit_fuel": 0,
        "stack_empty": True,
        "savepoint_empty": True,
        "live_invocations": 0,
        "teardown_probe_on": True,
        "teardown_events": teardown_events() if accepted else [],
        "engine_target": "pulley64-unknown-unknown-elf",
        "max_wasm_stack": 524_288,
        "async_stack_size": 2_097_152,
    }
    return {"case_id": case_id, "configuration": "production",
            "process_role": "target_observed", "sample_key": sample,
            "repeat_index": 0, "pid": 123, "observation": observation}


class ColdPublicationEvidenceTests(unittest.TestCase):
    def test_distinct_accepted_and_rejected_transitions(self):
        for case_id, samples in (
                ("cold_publish_large_function", ("accepted", "over_limit_rejected")),
                ("cold_publish_control_nesting", ("accepted",)),
                ("cold_publish_br_table", ("accepted", "over_limit_rejected"))):
            for sample in samples:
                with self.subTest(case_id=case_id, sample=sample):
                    validate_observation(attempt(case_id, sample), case_id, sample, 0,
                                         "target_observed", "production", 123)

    def test_rejects_false_br_table_parser_gate_or_missing_rollback(self):
        case_id = "cold_publish_br_table"
        sample = "over_limit_rejected"
        for key, invalid in (
                ("error_kind", "br_table_entry_limit_exceeded"),
                ("error_text", "br_table count exceeds limit of 7654321"),
                ("function_body_bytes", FUNCTION_LIMIT),
                ("raw_module_sha256", "a" * 64),
                ("br_table_entries", FUNCTION_LIMIT),
                ("state_after_sha256", "d" * 64),
                ("state_restored_sha256", "d" * 64),
                ("measured_receipts", [{"status": "Ok"}]),
                ("teardown_events", teardown_events())):
            with self.subTest(key=key):
                forged = copy.deepcopy(attempt(case_id, sample))
                forged["observation"][key] = invalid
                with self.assertRaises(ValueError):
                    validate_observation(forged, case_id, sample, 0,
                                         "target_observed", "production", 123)


if __name__ == "__main__":
    unittest.main()
