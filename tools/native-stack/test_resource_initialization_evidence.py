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
                "result_value": "",
                "module_sha256": "a" * 64,
                "component_address": "generated-active-data-success:1:0",
                "execution_path": "Runtime::execute",
                "published": True,
                "input_precharge_fuel": 410,
                "view_fuel_limit": 100_000_000,
                "fuel_control": None,
                "user_fuel": 0,
                "system_fuel": 1_231,
                "deposit_fuel": 0,
                "state_before_sha256": "b" * 64,
                "state_after_sha256": "b" * 64,
                "receipts_before": 0,
                "receipts_after": 0,
                "resources_before": 0,
                "resources_after": 0,
                "stack_empty": True,
                "savepoint_empty": True,
                "live_invocations": 0,
                "teardown_probe_on": True,
                "teardown_events": [
                    {"id": 0, "role": "nested_chain", "kind": "reserved", "table_alive": None},
                    {"id": 0, "role": "nested_chain", "kind": "store_created", "table_alive": None},
                    {"id": 0, "role": "nested_chain", "kind": "table_destroyed", "table_alive": False},
                    {"id": 0, "role": "nested_chain", "kind": "lease_released", "table_alive": None},
                ],
                "engine_target": "pulley64-unknown-unknown-elf",
                "max_wasm_stack": 524_288,
                "async_stack_size": 2_097_152,
            },
        }

    def validate(self):
        return validate_observation(self.attempt, "active_data_success", 0,
                                    "target_observed", "production", 7)

    def test_accepts_complete_runtime_and_state_evidence(self):
        signature = self.validate()
        self.assertEqual(signature["state_sha256"], "b" * 64)

    def test_rejects_changed_outcome_or_lifecycle(self):
        baseline = copy.deepcopy(self.attempt)
        for field, value in (("typed_trap", "OutOfFuel"),
                             ("published", False),
                             ("system_fuel", 410),
                             ("state_after_sha256", "c" * 64),
                             ("live_invocations", 1),
                             ("receipts_after", 1)):
            with self.subTest(field=field):
                self.attempt = copy.deepcopy(baseline)
                self.attempt["observation"][field] = value
                with self.assertRaises(ValueError):
                    self.validate()

    def test_rejects_incomplete_store_teardown(self):
        self.attempt["observation"]["teardown_events"].pop()
        with self.assertRaises(ValueError):
            self.validate()

    def test_fuel_failure_requires_budget_beyond_input_precharge(self):
        self.attempt["sample_key"] = "fuel_failure"
        value = self.attempt["observation"]
        value.update(sample_key="fuel_failure", outcome="out_of_fuel",
                     typed_trap="OutOfFuel", result_value=None,
                     component_address="generated-fuel-failure:1:4",
                     input_precharge_fuel=340, view_fuel_limit=1_000,
                     system_fuel=1_000,
                     fuel_control={
                         "component_address": "generated-fuel-failure:1:4",
                         "module_sha256": "a" * 64,
                         "result_value": "",
                         "view_fuel_limit": 100_000_000,
                         "system_fuel": 5_000,
                         "state_before_sha256": "b" * 64,
                         "state_after_sha256": "b" * 64,
                         "receipts_before": 0,
                         "receipts_after": 0,
                         "resources_before": 0,
                         "resources_after": 0,
                         "live_invocations": 0,
                         "teardown_probe_on": True,
                         "teardown_events": copy.deepcopy(value["teardown_events"]),
                     })
        validate_observation(self.attempt, "fuel_failure", 0,
                             "target_observed", "production", 7)
        value["input_precharge_fuel"] = 1_000
        with self.assertRaises(ValueError):
            validate_observation(self.attempt, "fuel_failure", 0,
                                 "target_observed", "production", 7)

    def test_rejects_fuel_control_without_sufficient_success(self):
        self.attempt["sample_key"] = "fuel_failure"
        value = self.attempt["observation"]
        value.update(sample_key="fuel_failure", outcome="out_of_fuel",
                     typed_trap="OutOfFuel", result_value=None,
                     component_address="generated-fuel-failure:1:4",
                     input_precharge_fuel=340, view_fuel_limit=1_000,
                     system_fuel=1_000)
        value["fuel_control"] = {
            "component_address": "generated-fuel-failure:1:4",
            "module_sha256": "a" * 64,
            "result_value": "", "view_fuel_limit": 100_000_000,
            "system_fuel": 900, "state_before_sha256": "b" * 64,
            "state_after_sha256": "b" * 64, "receipts_before": 0,
            "receipts_after": 0, "resources_before": 0,
            "resources_after": 0, "live_invocations": 0,
            "teardown_probe_on": True,
            "teardown_events": copy.deepcopy(value["teardown_events"]),
        }
        with self.assertRaises(ValueError):
            validate_observation(self.attempt, "fuel_failure", 0,
                                 "target_observed", "production", 7)


if __name__ == "__main__":
    unittest.main()
