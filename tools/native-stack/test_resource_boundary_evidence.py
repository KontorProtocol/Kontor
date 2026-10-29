import copy
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from resource_boundary_evidence import (parse_worker_log,
                                        validate_discovery_sequence,
                                        validate_replay_order, validate_trace)
from resource_boundary_manifest import SCHEMA
from resource_evidence import load_json_strict
from resource_evidence_v2 import validate_teardown


def attempt(depth, outcome, sample_key="calibration", repeat_index=0):
    return {
        "depth": depth,
        "sample_key": sample_key,
        "repeat_index": repeat_index,
        "observation": {"outcome": outcome},
    }


class BoundaryEvidenceTests(unittest.TestCase):
    def test_trace_binds_phase_and_compiler_to_measured_threads(self):
        def thread(category, number, base, requested):
            guard = 4096 if category == "tokio_worker" else 0
            mapped = 2_097_152
            mapped_start = base + guard
            return {
                "thread_category": category,
                "thread_id": f"ThreadId({number})",
                "process_id": 123,
                "os_thread_id": number,
                "identity_api": "linux_gettid",
                "page_size_bytes": 4096,
                "requested_bytes": requested,
                "mapped_bytes": mapped,
                "guard_bytes": guard,
                "guard_start": base if guard else 0,
                "guard_end": base + guard if guard else 0,
                "guard_verification": ("linux_maps_prot_none" if guard
                                       else "pthread_reports_none"),
                "usable_bytes": mapped,
                "mapped_start": mapped_start,
                "mapped_end": mapped_start + mapped,
                "usable_start": mapped_start,
                "usable_end": mapped_start + mapped,
                "measurement_api": "pthread_getattr_np",
                "guard_treatment": "separate_protected_page",
                "guard_verified": True,
            }
        runtime = {
            "scope": "paired_pulley_boundary_worker",
            "configuration": "production",
            "case_id": "pulley_plain_paid",
            "process_role": "target_observed",
            "pid": 123,
            "flavor": "multi_thread",
            "worker_count": 2,
            "worker_requested_bytes": None,
            "thread_observations": [
                thread("tokio_worker", 1, 0x1000000, None),
                thread("tokio_worker", 2, 0x2000000, None),
                thread("blocking_pool", 3, 0x3000000, None),
                thread("block_on_caller", 4, 0x4000000, None),
            ],
            "blocking_pool_observed": True,
            "block_on_caller_observed": True,
            "embedded_source_sha": "0" * 40,
            "binary_sha256": "0" * 64,
        }
        def event(name, number=1, category="tokio_worker"):
            return {
                "name": name,
                "thread_id": f"ThreadId({number})",
                "os_thread_id": number,
                "category": category,
            }
        events = [
            event("fixture_preparation_entry"),
            event("publication_entry"),
            event("compiler_entry"), event("compiler_exit"),
            event("blocking_decode_entry", 3, "blocking_pool"),
            event("blocking_decode_exit", 3, "blocking_pool"),
            event("publication_exit"),
            event("fixture_preparation_exit"),
            event("boundary_attempt_start"),
            event("sample_preparation_entry"),
            event("sample_preparation_exit"),
            event("operation_entry"),
            event("canonical_input_entry"), event("canonical_input_exit"),
            event("canonical_output_entry"), event("canonical_output_exit"),
            event("operation_exit"),
            event("postcall_observation_entry"),
            event("postcall_observation_exit"),
            event("teardown_entry"), event("teardown_exit"),
            event("boundary_attempt_end"),
        ]
        trace = {
            "scope": runtime["scope"],
            "configuration": runtime["configuration"],
            "case_id": runtime["case_id"],
            "process_role": runtime["process_role"],
            "events": events,
        }
        self.assertEqual(validate_trace(trace, runtime, [{}])["compiler_entry"], 1)
        wrong_worker = copy.deepcopy(trace)
        wrong_worker["events"][11]["thread_id"] = "ThreadId(3)"
        wrong_worker["events"][11]["os_thread_id"] = 3
        with self.assertRaises(ValueError):
            validate_trace(wrong_worker, runtime, [{}])
        missing_phase = copy.deepcopy(trace)
        missing_phase["events"] = [item for item in events
                                   if item["name"] != "teardown_exit"]
        with self.assertRaises(ValueError):
            validate_trace(missing_phase, runtime, [{}])

    def test_discovery_reconstructs_exact_adaptive_search(self):
        threshold = 1723
        attempts = [attempt(0, "ok")]
        depth = 1024
        last = 0
        while True:
            outcome = "ok" if depth < threshold else "stack_overflow"
            attempts.append(attempt(depth, outcome))
            if outcome != "ok":
                first = depth
                break
            last = depth
            depth *= 2
        while first - last > 1:
            middle = last + (first - last) // 2
            outcome = "ok" if middle < threshold else "stack_overflow"
            attempts.append(attempt(middle, outcome))
            if outcome == "ok":
                last = middle
            else:
                first = middle
        summary = {"last_success": last, "first_failure": first}
        validate_discovery_sequence(attempts, summary)
        for mutated in (
            attempts[:-1],
            [*attempts[:2], attempt(1777, "ok"), *attempts[3:]],
            [*attempts[:2], attempt(attempts[2]["depth"], "out_of_fuel"),
             *attempts[3:]],
        ):
            with self.assertRaises(ValueError):
                validate_discovery_sequence(mutated, summary)
        with self.assertRaises(ValueError):
            validate_discovery_sequence(attempts, {
                "last_success": last - 1, "first_failure": first,
            })

    def test_replay_rejects_reordered_duplicate_and_wrong_trap(self):
        depths = (1722, 1723)
        valid = [
            attempt(1722, "ok", "last_success", 0),
            attempt(1723, "stack_overflow", "first_failure", 0),
            attempt(1723, "stack_overflow", "first_failure", 1),
            attempt(1722, "ok", "last_success", 1),
            attempt(1722, "ok", "last_success", 2),
            attempt(1723, "stack_overflow", "first_failure", 2),
        ]
        validate_replay_order(valid, depths)
        wrong_order = copy.deepcopy(valid)
        wrong_order[1], wrong_order[2] = wrong_order[2], wrong_order[1]
        wrong_trap = copy.deepcopy(valid)
        wrong_trap[1]["observation"]["outcome"] = "out_of_fuel"
        for mutated in (valid[:-1], wrong_order, wrong_trap):
            with self.assertRaises(ValueError):
                validate_replay_order(mutated, depths)
        leaf = [attempt(1722, "ok", "target", index) for index in range(2)]
        validate_replay_order(leaf, depths, leaf=True)
        leaf[1]["depth"] = 1721
        with self.assertRaises(ValueError):
            validate_replay_order(leaf, depths, leaf=True)

    def test_teardown_requires_table_before_lease_and_no_retention(self):
        events = [
            {"id": 0, "role": "nested_chain", "kind": "reserved",
             "table_alive": None},
            {"id": 0, "role": "nested_chain", "kind": "store_created",
             "table_alive": None},
            {"id": 0, "role": "nested_chain", "kind": "table_destroyed",
             "table_alive": False},
            {"id": 0, "role": "nested_chain", "kind": "lease_released",
             "table_alive": None},
        ]
        self.assertEqual(validate_teardown(events, 1, 0)["created"]["nested_chain"], 1)
        retained = copy.deepcopy(events)
        retained[2]["table_alive"] = True
        reordered = [*events[:2], events[3], events[2]]
        missing = events[:-1]
        for mutated in (retained, reordered, missing):
            with self.assertRaises(ValueError):
                validate_teardown(mutated, 1, 0)

    def test_raw_transcript_rejects_duplicate_terminal(self):
        markers = [
            'running 1 test',
            'KONTOR_STACK_TIMING:{"total_sample_ms":1}',
            'BOUNDARY_PROBE_ATTEMPT:{"depth":1}',
            'BOUNDARY_WORKER_RUNTIME={"pid":1}',
            'BOUNDARY_WORKER_TRACE={"events":[]}',
            'BOUNDARY_PROBE_SUMMARY:{"attempt_count":1}',
            'BOUNDARY_PROBE_TERMINAL:{"complete":true}',
            'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s',
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "child.log"
            path.write_text("\n".join(markers) + "\n")
            self.assertEqual(len(parse_worker_log(path)["attempts"]), 1)
            path.write_text("\n".join(markers[:7] + [markers[6]] +
                                      markers[7:]) + "\n")
            with self.assertRaises(ValueError):
                parse_worker_log(path)

    def test_schema_rejects_unknown_top_level_field(self):
        schema = load_json_strict(SCHEMA)
        self.assertTrue(Draft202012Validator.check_schema(schema) is None)
        minimal = {
            "schema_version": 1, "phase": "pilot_discovery",
            "qualification_status": "missing", "cell": "Linux-ARM64/dev",
            "manifest_sha256": "0" * 64, "source_sha": "0" * 40,
            "binary_path": "/tmp/indexer-test", "binary_sha256": "0" * 64,
            "timeout_seconds": 600,
            "control_capture": {"path": "control.json", "sha256": "0" * 64},
            "development_discovery": None,
            "runs": {"x": {}}, "discovered_depths": {},
            "remaining_case_bindings": [],
        }
        baseline_errors = list(Draft202012Validator(schema).iter_errors(minimal))
        changed = {**minimal, "unexpected": True}
        errors = list(Draft202012Validator(schema).iter_errors(changed))
        self.assertGreater(len(errors), len(baseline_errors))


if __name__ == "__main__":
    unittest.main()
