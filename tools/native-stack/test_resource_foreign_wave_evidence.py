"""Check nested foreign WAVE boundary and teardown evidence."""

import copy
import hashlib
import unittest
from unittest.mock import patch

from resource_foreign_wave_evidence import (EXPECTED, SAMPLES, expression,
                                            validate_observation, validate_trace)


EVENTS = [
    {"id": index, "role": "nested_chain", "kind": kind, "table_alive": alive}
    for index in range(2)
    for kind, alive in (("reserved", None), ("store_created", None),
                        ("table_destroyed", False), ("lease_released", None))
]


def attempt(sample, repeat=0):
    outcome, error_kind, result = EXPECTED[sample]
    if sample == "print_depth_64":
        result = "513"
    expr = expression(sample)
    return {"case_id": "foreign_wave_parse_print", "configuration": "production",
            "process_role": "target_observed", "sample_key": sample,
            "repeat_index": repeat, "pid": 7,
            "observation": {
                "sample_key": sample, "outcome": outcome,
                "error_kind": error_kind, "typed_trap": None,
                "result_value": result,
                "inner_expression_sha256": hashlib.sha256(expr.encode()).hexdigest(),
                "inner_expression_bytes": len(expr.encode()),
                "caller_module_sha256": "a" * 64,
                "target_module_sha256": "b" * 64,
                "caller_address": "wave-caller:1:1",
                "target_address": "wave-target:1:0",
                "execution_path": "Runtime::execute/foreign.call/Runtime::invoke",
                "system_fuel": 2_500, "user_fuel": 0, "deposit_fuel": 0,
                "state_before_sha256": "c" * 64,
                "state_after_sha256": "c" * 64,
                "receipts_before": 0, "receipts_after": 0,
                "resources_before": 0, "resources_after": 0,
                "stack_empty": True, "savepoint_empty": True,
                "live_invocations": 0, "teardown_probe_on": True,
                "teardown_events": copy.deepcopy(EVENTS),
                "engine_target": "pulley64-unknown-unknown-elf",
                "max_wasm_stack": 524_288,
                "async_stack_size": 2_097_152,
            }}


class ForeignWaveEvidenceTests(unittest.TestCase):
    def validate(self, item):
        return validate_observation(item, item["sample_key"],
                                    item["repeat_index"], "target_observed",
                                    "production", 7)

    def test_frozen_expression_boundaries(self):
        self.assertEqual(len(expression("depth_64")), 517)
        self.assertEqual(len(expression("depth_65_rejected")), 525)
        self.assertEqual(len(expression("literal_16384")), 16_400)
        self.assertEqual(len(expression("literal_16385_rejected")), 16_401)
        self.assertEqual(expression("depth_64").count("{child:"), 63)
        self.assertEqual(expression("depth_65_rejected").count("{child:"), 64)

    def test_accepts_all_boundary_samples(self):
        for sample in SAMPLES:
            with self.subTest(sample=sample):
                self.validate(attempt(sample))

    def test_rejects_wrong_boundary_or_unclosed_store(self):
        baseline = attempt("depth_65_rejected")
        for field, replacement in (("error_kind", "result_value_depth"),
                                   ("inner_expression_bytes", 516),
                                   ("inner_expression_sha256", "d" * 64),
                                   ("state_after_sha256", "d" * 64),
                                   ("live_invocations", 1)):
            with self.subTest(field=field):
                item = copy.deepcopy(baseline)
                item["observation"][field] = replacement
                with self.assertRaises(ValueError):
                    self.validate(item)
        baseline["observation"]["teardown_events"].pop()
        with self.assertRaises(ValueError):
            self.validate(baseline)

    def test_rejects_outer_only_parse_trace(self):
        def event(name, blocking=False):
            return {"name": name, "thread_id": "blocking" if blocking else "worker",
                    "os_thread_id": 2 if blocking else 1,
                    "category": "blocking_pool" if blocking else "tokio_worker"}

        events = []
        for _ in range(2):
            events.extend((event("publication_entry"), event("compiler_entry"),
                           event("blocking_decode_entry", True),
                           event("blocking_decode_exit", True),
                           event("compiler_exit"), event("publication_exit")))
        attempts = []
        for sample in SAMPLES:
            for _ in range(2):
                attempts.append({"sample_key": sample})
                events.append(event("finite_stack_attempt_start"))
                if sample in {"depth_65_rejected", "literal_16385_rejected"}:
                    inputs, outputs = 1, 0
                elif sample == "print_depth_65_rejected":
                    inputs, outputs = 2, 1
                else:
                    inputs, outputs = 2, 2
                for _ in range(inputs):
                    events.extend((event("canonical_input_entry"),
                                   event("canonical_input_exit")))
                for _ in range(outputs):
                    events.extend((event("canonical_output_entry"),
                                   event("canonical_output_exit")))
                events.append(event("finite_stack_attempt_end"))
        runtime = {"scope": "paired_finite_stack_worker",
                   "configuration": "production", "case_id": "foreign_wave_parse_print",
                   "process_role": "target_observed", "pid": 7,
                   "thread_observations": [{"page_size_bytes": 4096}],
                   "embedded_source_sha": "a" * 64,
                   "binary_sha256": "b" * 64}
        trace = {key: runtime[key] for key in
                 ("scope", "configuration", "case_id", "process_role")}
        trace["events"] = events
        capacities = {"tokio_worker": [{"thread_id": "worker", "os_thread_id": 1}],
                      "blocking_pool": [{"thread_id": "blocking", "os_thread_id": 2}]}
        with patch("resource_foreign_wave_evidence.thread_capacities",
                   return_value=capacities):
            validate_trace(trace, runtime, attempts, "linux")
            changed = copy.deepcopy(trace)
            first = next(index for index, item in enumerate(changed["events"])
                         if item["name"] == "finite_stack_attempt_start")
            del changed["events"][first + 1:first + 3]
            with self.assertRaises(ValueError):
                validate_trace(changed, runtime, attempts, "linux")


if __name__ == "__main__":
    unittest.main()
