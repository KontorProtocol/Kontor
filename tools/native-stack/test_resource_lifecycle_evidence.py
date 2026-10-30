"""Check resource lifecycle trap and teardown evidence boundaries."""

import copy
import unittest
from unittest.mock import patch

from resource_lifecycle_evidence import validate_observation, validate_trace


EVENTS = [
    {"id": 0, "role": "nested_chain", "kind": "reserved", "table_alive": None},
    {"id": 0, "role": "nested_chain", "kind": "store_created", "table_alive": None},
    {"id": 0, "role": "nested_chain", "kind": "table_destroyed", "table_alive": False},
    {"id": 0, "role": "nested_chain", "kind": "lease_released", "table_alive": None},
]


def attempt(sample, case_id, repeat=0):
    failed = sample == "failed_init"
    address = ("resource-lifecycle-explicit:1:0" if case_id ==
               "explicit_resource_drop" else
               "resource-lifecycle-failed:1:0" if failed else
               "resource-lifecycle-control:1:1")
    trap = {"trap": "UnreachableCodeReached",
            "failed_init": "MemoryOutOfBounds"}.get(sample)
    outcome = ("trap" if sample == "trap" else
               "deterministic_error" if failed else "ok")
    return {"case_id": case_id, "configuration": "production",
            "process_role": "target_observed", "sample_key": sample,
            "repeat_index": repeat, "pid": 7,
            "observation": {
                "sample_key": sample, "outcome": outcome,
                "typed_trap": trap, "result_value": None if trap else "1",
                "module_sha256": "a" * 64, "component_address": address,
                "execution_path": "Runtime::publish/init" if failed else
                                  "Runtime::execute",
                "published": not failed,
                "system_fuel": 1_250, "user_fuel": 0, "deposit_fuel": 0,
                "state_before_sha256": "b" * 64,
                "state_after_sha256": "b" * 64,
                "receipts_before": 0, "receipts_after": 0,
                "resources_before": 0, "resources_after": 0,
                "stack_empty": True, "savepoint_empty": True,
                "live_invocations": 0, "teardown_probe_on": True,
                "teardown_events": copy.deepcopy(EVENTS),
                "engine_target": "pulley64-unknown-unknown-elf",
                "max_wasm_stack": 524_288, "async_stack_size": 2_097_152,
            }}


class ResourceLifecycleEvidenceTests(unittest.TestCase):
    def validate(self, value):
        return validate_observation(value, value["case_id"], value["sample_key"],
                                    value["repeat_index"], "target_observed",
                                    "production", 7)

    def test_accepts_explicit_drop_trap_and_failed_instantiation(self):
        for case_id, sample in (
            ("explicit_resource_drop", "success_before_trap"),
            ("explicit_resource_drop", "trap"),
            ("explicit_resource_drop", "success_after_trap"),
            ("failed_instantiation_cleanup", "failed_init"),
            ("failed_instantiation_cleanup", "valid_control"),
        ):
            with self.subTest(sample=sample):
                self.validate(attempt(sample, case_id))

    def test_rejects_failure_before_the_active_data_segment(self):
        value = attempt("failed_init", "failed_instantiation_cleanup")
        value["observation"]["typed_trap"] = "UnreachableCodeReached"
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_rejects_missing_destructor_result_and_retained_store(self):
        baseline = attempt("success_after_trap", "explicit_resource_drop")
        for field, replacement in (("result_value", "0"),
                                   ("resources_after", 1),
                                   ("state_after_sha256", "c" * 64),
                                   ("live_invocations", 1),
                                   ("receipts_after", 1)):
            with self.subTest(field=field):
                value = copy.deepcopy(baseline)
                value["observation"][field] = replacement
                with self.assertRaises(ValueError):
                    self.validate(value)
        baseline["observation"]["teardown_events"].pop()
        with self.assertRaises(ValueError):
            self.validate(baseline)

    def test_failed_publication_must_be_inside_measured_attempt(self):
        def event(name, blocking=False):
            return {"name": name, "thread_id": "blocking" if blocking else "worker",
                    "os_thread_id": 2 if blocking else 1,
                    "category": "blocking_pool" if blocking else "tokio_worker"}

        events = []
        samples = ["failed_init", "failed_init", "valid_control", "valid_control"]

        def publication():
            events.extend((event("publication_entry"), event("compiler_entry"),
                           event("blocking_decode_entry", True),
                           event("blocking_decode_exit", True),
                           event("compiler_exit"), event("publication_exit")))

        for index, sample in enumerate(samples):
            if index == 2:
                publication()
            events.append(event("finite_stack_attempt_start"))
            if sample != "valid_control":
                publication()
            else:
                events.extend((event("canonical_input_entry"),
                               event("canonical_input_exit"),
                               event("canonical_output_entry"),
                               event("canonical_output_exit")))
            events.append(event("finite_stack_attempt_end"))
        runtime = {"scope": "paired_finite_stack_worker",
                   "configuration": "production",
                   "case_id": "failed_instantiation_cleanup",
                   "process_role": "target_observed", "pid": 7,
                   "thread_observations": [{"page_size_bytes": 4096}],
                   "embedded_source_sha": "a" * 64,
                   "binary_sha256": "b" * 64}
        trace = {key: runtime[key] for key in
                 ("scope", "configuration", "case_id", "process_role")}
        trace["events"] = events
        attempts = [{"sample_key": sample} for sample in samples]
        capacities = {"tokio_worker": [{"thread_id": "worker", "os_thread_id": 1}],
                      "blocking_pool": [{"thread_id": "blocking", "os_thread_id": 2}]}
        with patch("resource_lifecycle_evidence.thread_capacities",
                   return_value=capacities):
            validate_trace(trace, runtime, attempts, "linux")
            changed = copy.deepcopy(trace)
            start = next(index for index, item in enumerate(changed["events"])
                         if item["name"] == "finite_stack_attempt_start")
            changed["events"].insert(start,
                                     changed["events"].pop(start + 1))
            with self.assertRaises(ValueError):
                validate_trace(changed, runtime, attempts, "linux")


if __name__ == "__main__":
    unittest.main()
