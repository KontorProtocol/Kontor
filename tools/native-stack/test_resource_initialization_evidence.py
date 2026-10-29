"""Check generated initialization outcome and state evidence."""

import copy
import unittest

from resource_initialization_evidence import validate_observation


class InitializationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.attempt = {
            "case_id": "generated_initialization",
            "configuration": "production",
            "process_role": "target_observed",
            "sample_key": "active_data_success",
            "repeat_index": 0,
            "pid": 7,
            "observation": {
                "sample_key": "active_data_success",
                "outcome": "ok",
                "typed_trap": None,
                "module_sha256": "a" * 64,
                "fuel_limit": 1_000_000,
                "fuel_used": 1,
                "host_callback_count": 0,
                "state_before_sha256": "b" * 64,
                "state_after_sha256": "b" * 64,
                "store_closed": True,
                "teardown_probe_on": True,
                "store_close_count": 1,
                "engine_target": "pulley64-unknown-unknown-elf",
                "max_wasm_stack": 524_288,
                "async_stack_size": 2_097_152,
            },
        }

    def validate(self):
        return validate_observation(self.attempt, "active_data_success", 0,
                                    "target_observed", "production", 7)

    def test_accepts_complete_store_and_state_evidence(self):
        signature = self.validate()
        self.assertEqual(signature["state_sha256"], "b" * 64)

    def test_rejects_changed_outcome_or_lifecycle(self):
        baseline = copy.deepcopy(self.attempt)
        for field, value in (("typed_trap", "OutOfFuel"),
                             ("host_callback_count", 1),
                             ("state_after_sha256", "c" * 64),
                             ("store_close_count", 0)):
            with self.subTest(field=field):
                self.attempt = copy.deepcopy(baseline)
                self.attempt["observation"][field] = value
                with self.assertRaises(ValueError):
                    self.validate()


if __name__ == "__main__":
    unittest.main()
