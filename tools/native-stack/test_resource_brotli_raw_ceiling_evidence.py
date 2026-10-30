#!/usr/bin/env python3
"""Check the Brotli evidence rejects forged boundary and lifecycle claims."""

import copy
import unittest
from unittest.mock import patch

from resource_brotli_raw_ceiling_evidence import (CASE_ID, RAW_CEILING, RAW_SHA256,
                                                  validate_observation, validate_trace)


def teardown_events():
    return [{"id": 0, "role": "nested_chain", "kind": kind,
             "table_alive": False if kind == "table_destroyed" else None}
            for kind in ("reserved", "store_created", "table_destroyed",
                         "lease_released")]


def attempt(sample):
    accepted = sample == "at_ceiling"
    observation = {
        "sample_key": sample,
        "outcome": "ok" if accepted else "deterministic_error",
        "error_kind": None if accepted else "raw_ceiling_exceeded",
        "result_value": "brotli-ceiling-0_1_0" if accepted else None,
        "raw_bytes": RAW_CEILING + int(not accepted),
        "raw_sha256": RAW_SHA256[sample],
        "compressed_bytes": 2500,
        "compressed_sha256": "b" * 64,
        "publication_path":
            "Runtime::publish/Storage::decode_component_bytes/spawn_blocking",
        "state_before_sha256": "c" * 64,
        "state_after_sha256": ("d" if accepted else "c") * 64,
        "state_restored_sha256": "c" * 64,
        "receipts_before": 4,
        "receipts_after": 5 if accepted else 4,
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
    return {"case_id": CASE_ID, "configuration": "production",
            "process_role": "target_observed", "sample_key": sample,
            "repeat_index": 0, "pid": 123, "observation": observation}


class BrotliCeilingEvidenceTests(unittest.TestCase):
    def test_acceptance_and_rejection_have_distinct_state_transitions(self):
        for sample in ("at_ceiling", "one_byte_over_rejected"):
            with self.subTest(sample=sample):
                validate_observation(attempt(sample), sample, 0,
                                     "target_observed", "production", 123)

    def test_rejects_false_boundary_or_rollback_claims(self):
        for sample, key, invalid in (
                ("at_ceiling", "raw_bytes", RAW_CEILING - 1),
                ("one_byte_over_rejected", "raw_bytes", RAW_CEILING),
                ("at_ceiling", "raw_sha256", "a" * 64),
                ("one_byte_over_rejected", "state_after_sha256", "d" * 64),
                ("at_ceiling", "state_restored_sha256", "d" * 64),
                ("one_byte_over_rejected", "teardown_events", teardown_events()),
                ("at_ceiling", "teardown_events", [])):
            with self.subTest(sample=sample, key=key):
                forged = copy.deepcopy(attempt(sample))
                forged["observation"][key] = invalid
                with self.assertRaises(ValueError):
                    validate_observation(forged, sample, 0,
                                         "target_observed", "production", 123)

    def test_decode_must_run_on_a_measured_blocking_thread(self):
        def event(name):
            blocking = name.startswith("blocking_decode_")
            return {"name": name, "thread_id": "b" if blocking else "w",
                    "os_thread_id": 2 if blocking else 1,
                    "category": "blocking_pool" if blocking else "tokio_worker"}

        names = ["fixture_preparation_entry", "fixture_preparation_exit"]
        attempts = []
        for sample in ("at_ceiling", "at_ceiling",
                       "one_byte_over_rejected", "one_byte_over_rejected"):
            attempts.append(attempt(sample))
            names.extend(("finite_stack_attempt_start", "publication_entry",
                          "blocking_decode_entry", "blocking_decode_exit"))
            if sample == "at_ceiling":
                names.extend(("compiler_entry", "compiler_exit"))
            names.extend(("publication_exit", "finite_stack_attempt_end"))
        trace = {"scope": "paired_finite_stack_worker",
                 "configuration": "production", "case_id": CASE_ID,
                 "process_role": "target_observed",
                 "events": [event(name) for name in names]}
        runtime = {"scope": trace["scope"],
                   "configuration": trace["configuration"],
                   "case_id": CASE_ID, "process_role": "target_observed",
                   "thread_observations": [{"page_size_bytes": 4096}], "pid": 123}
        capacities = {"tokio_worker": [{"thread_id": "w", "os_thread_id": 1}],
                      "blocking_pool": [{"thread_id": "b", "os_thread_id": 2}]}
        with patch("resource_brotli_raw_ceiling_evidence.thread_capacities",
                   return_value=capacities):
            validate_trace(trace, runtime, attempts, "linux")
            forged = copy.deepcopy(trace)
            decode = next(item for item in forged["events"]
                          if item["name"] == "blocking_decode_entry")
            decode.update(thread_id="w", os_thread_id=1, category="tokio_worker")
            with self.assertRaises(ValueError):
                validate_trace(forged, runtime, attempts, "linux")


if __name__ == "__main__":
    unittest.main()
