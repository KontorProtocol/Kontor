import json
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import resource_evidence
import resource_manifest


class ResourceManifestTests(unittest.TestCase):
    def setUp(self):
        self.manifest = resource_manifest.build_manifest()
        self.schema = json.loads(
            Path(__file__).with_name("resource-evidence-schema-v1.json").read_text()
        )

    def test_frozen_inputs_and_mandatory_surfaces(self):
        cases = {item["id"]: item for item in self.manifest["cases"]}
        self.assertEqual(len(cases), 41)
        self.assertEqual(len(cases), len(self.manifest["cases"]))
        self.assertEqual(set(self.manifest["cells"]), set(resource_manifest.CELLS))
        self.assertEqual(
            self.manifest["amendment"]["sha256"], resource_manifest.AMENDMENT_SHA256
        )
        self.assertTrue(all(item["paired_worker_status"] == "missing" for item in cases.values()))
        self.assertTrue(all(item["sample_keys"] and
                            len(item["sample_keys"]) == len(set(item["sample_keys"]))
                            for item in cases.values()))
        self.assertTrue(all(set(item["expected_outcomes"]) == set(item["sample_keys"])
                            and set(item["expected_traps"]) == set(item["sample_keys"])
                            for item in cases.values()))
        self.assertEqual(cases["canonical_post_return"]["expected_traps"],
                         {"light": "CannotLeaveComponent", "heavy": "CannotLeaveComponent"})
        self.assertEqual(cases["canonical_post_return"]["expected_outcomes"],
                         {"light": "trap", "heavy": "trap"})
        self.assertEqual(cases["canonical_lift_lower"]["expected_traps"]["failure"],
                         "CannotLeaveComponent")
        self.assertEqual(cases["canonical_realloc"]["expected_traps"],
                         {"success_lowering": None,
                          "realloc_trap": "UnreachableCodeReached",
                          "forbidden_import": "CannotLeaveComponent"})
        generated = cases["generated_initialization"]
        self.assertIsNone(generated["existing_unpaired_binding"])
        self.assertEqual(set(generated["sample_keys"]), {
            "active_data_success", "active_element_success", "active_data_oob",
            "active_element_oob", "fuel_failure",
        })
        for name, identity in self.manifest["artifacts"].items():
            self.assertEqual(identity["path"], resource_manifest.INPUTS[name])
            self.assertEqual(
                identity["sha256"],
                resource_manifest.sha256(resource_manifest.ROOT / identity["path"]),
            )
        for surface in (
            "pending_host_io", "max_gas_paid", "canonical_lift_lower",
            "canonical_realloc", "canonical_post_return", "generated_initialization",
            "explicit_resource_drop", "failed_instantiation_cleanup", "sqlite_pagination",
            "sqlite_ranges", "sqlite_large_values", "deepest_frame_host_call",
            "canonical_type_value_recursion",
            "native_staking_rewards", "native_filestorage_lifecycle",
            "foreign_wave_parse_print", "cold_publish_large_function",
            "cold_publish_control_nesting", "cold_publish_br_table",
            "brotli_raw_ceiling",
        ):
            self.assertIn(surface, cases)
        self.assertEqual(self.manifest["type_value_limits"]["component_type_depth"], 100)
        self.assertEqual(self.manifest["type_value_limits"]["wave_result_value_depth"], 64)
        self.assertEqual(self.manifest["workload_plan"]["status"],
                         "awaiting_frozen_workload_plan")
        self.assertEqual(self.manifest["worker_runner"]["status"], "smoke_only")
        for stores in (33, 63, 64, 65):
            for mode in ("paid", "view", "core"):
                self.assertIn(f"chain_{stores}_{mode}", cases)
        for shape in ("plain", "wide"):
            for mode in ("paid", "view", "system", "core"):
                self.assertIn(f"pulley_{shape}_{mode}", cases)
        self.assertEqual(len(cases["sqlite_pagination"]["sample_keys"]), 18)
        self.assertEqual(len(cases["sqlite_ranges"]["sample_keys"]), 12)
        self.assertEqual(len(cases["sqlite_large_values"]["sample_keys"]), 6)

    def test_manifest_and_evidence_schema_cannot_drift(self):
        self.assertEqual(
            json.loads(resource_manifest.MANIFEST.read_text()), self.manifest
        )
        self.assertEqual(
            set(self.schema["$defs"]["observation"]["required"]),
            set(resource_manifest.OBSERVATION_FIELDS),
        )
        self.assertEqual(
            self.schema["$defs"]["configuration"]["properties"]["cases"]["minItems"],
            len(self.manifest["cases"]),
        )
        self.assertEqual(
            set(self.schema["properties"]["cell"]["enum"]), set(resource_manifest.CELLS)
        )

    def test_pending_case_blocks_acceptance(self):
        with self.assertRaisesRegex(ValueError, "without paired worker bindings"):
            resource_evidence.validate({}, Path("."))

    def test_schema_and_duplicate_keys_are_enforced_after_bindings(self):
        ready = copy.deepcopy(self.manifest)
        for item in ready["cases"]:
            item["paired_worker_status"] = "ready"
            if item["family"] == "native_core":
                item["parameters"]["exact_budget_status"] = "frozen"
            if item["family"] == "cold_compile":
                item["parameters"]["fixture_admission_status"] = "verified"
                for key, value in item["parameters"].items():
                    if key.startswith("fixture_") and value is None:
                        item["parameters"][key] = 1000
        ready["publication_constraints"]["near_boundary_accepted_fixture"] = "verified"
        ready["publication_constraints"]["serialized_transaction_and_wit_admission"] = "verified"
        ready["attestation_status"] = {name: "ready" for name in
                                       ready["attestation_status"]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            blocked = copy.deepcopy(ready)
            blocked["attestation_status"]["wasmtime_fiber_stack_range"] = "unimplemented"
            path.write_text(json.dumps(blocked))
            with patch.object(resource_evidence, "MANIFEST", path), patch.object(
                resource_evidence, "build_manifest", return_value=blocked
            ):
                with self.assertRaisesRegex(ValueError, "Wasmtime fiber attestation is missing"):
                    resource_evidence.validate({}, path.parent)
            path.write_text(json.dumps(ready))
            with patch.object(resource_evidence, "MANIFEST", path), patch.object(
                resource_evidence, "build_manifest", return_value=ready
            ):
                with self.assertRaisesRegex(ValueError, "violates schema"):
                    resource_evidence.validate({"schema_version": 1, "extra": 1}, path.parent)
            path.write_text('{"outer":{"field":1,"field":2}}')
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                resource_evidence.load_json_strict(path)

    def test_child_transcript_requires_terminal_and_unique_attempts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "child.jsonl"
            attempt = {"kind": "attempt", "case_id": "sample", "sample_key": "target",
                       "repeat_index": 0, "observation": {}, "worker_attempt": {}}
            terminal = {"kind": "terminal", "pid": 123, "case_count": 1,
                        "attempt_count": 1, "complete": True, "test_harness_passed": True,
                        "executable_path": "/tmp/indexer-test",
                        "executable_sha256": "0" * 64,
                        "embedded_source_sha": "1" * 40}
            path.write_text(json.dumps(attempt) + "\n" + json.dumps(terminal) + "\n")
            resource_evidence.read_process_events(path, {"pid": 123}, 1,
                                                  "/tmp/indexer-test", "0" * 64,
                                                  "1" * 40)
            terminal["complete"] = False
            path.write_text(json.dumps(attempt) + "\n" + json.dumps(terminal) + "\n")
            with self.assertRaisesRegex(ValueError, "terminal status"):
                resource_evidence.read_process_events(path, {"pid": 123}, 1,
                                                      "/tmp/indexer-test", "0" * 64,
                                                      "1" * 40)

    def test_expected_results_and_boundaries_reject_matching_wrong_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "child.jsonl"
            raw.write_text("test transcript\n")
            log = {"path": raw.name, "sha256": resource_evidence.sha256(raw)}
            configuration = {
                "process_log": log, "raw_logs": [log],
                "runtime": {"thread_observations": [
                    {"thread_id": "worker", "thread_category": "tokio_worker"},
                    {"thread_id": "blocking", "thread_category": "blocking_pool"},
                ]},
                "cases": [],
            }
            transcript = {}
            for definition in self.manifest["cases"]:
                case_id = definition["id"]
                observations = []
                attempts = []
                repeats = definition["parameters"].get("repeats", 2)
                for sample in definition["sample_keys"]:
                    outcome = definition["expected_outcomes"][sample]
                    for index in range(repeats):
                        during = min(definition["parameters"].get("simultaneous_stores", 1), 64)
                        depth = (10 if sample == "last_success" else 11) if (
                            definition["family"] == "pulley_boundary"
                        ) else (10 if case_id == "deepest_frame_host_call" else None)
                        observation = {
                            "case_id": case_id, "sample_key": sample, "outcome": outcome,
                            "error_class": None if outcome == "ok" else "deterministic",
                            "trap": definition["expected_traps"][sample],
                            "value": None, "fuel": {"user": 0, "system": 0, "deposit": 0},
                            "receipts": [], "state": {"before_sha256": "0" * 64,
                                "after_sha256": "0" * 64, "marker": None,
                                "balances_sha256": "0" * 64},
                            "rollback": outcome != "ok",
                            "live_stores": {"before": 0, "during": during, "after": 0},
                            "reservations": {"before": 0, "during": during, "after": 0},
                            "resource_cleanup": {"table_before": 0, "table_after": 0,
                                "savepoint_restored": True, "stack_empty": True,
                                "invocation_table_released": True},
                            "fresh_store": True, "suspended": case_id == "pending_host_io",
                            "reused": (case_id == "pending_host_io" and sample == "resumed") or
                                      (case_id == "explicit_resource_drop" and
                                       sample == "success_after_trap"),
                            "observed_depth": depth,
                        }
                        attempt = {"sample_key": sample, "repeat_index": index,
                            "phase_threads": {phase: ["worker"] for phase in
                                              ("preparation", "operation", "conversion", "teardown")},
                            "blocking_thread_ids": ["blocking"] if
                                definition["family"] == "blocking_decode" else [],
                            "cache_state": "cold" if definition["family"] == "cold_compile"
                                else "warm"}
                        observations.append(observation)
                        attempts.append(attempt)
                        transcript[(case_id, sample, index)] = {
                            "kind": "attempt", "case_id": case_id, "sample_key": sample,
                            "repeat_index": index, "observation": observation,
                            "worker_attempt": attempt,
                        }
                configuration["cases"].append({"id": case_id,
                    "parameters": definition["parameters"], "raw_log": log,
                    "observations": observations,
                    "worker_execution": {"whole_operation_spawned": True,
                        "source_sha256": "1" * 64, "attempts": attempts}})
            manifest = copy.deepcopy(self.manifest)
            manifest["worker_runner"]["sha256"] = "1" * 64
            resource_evidence.check_cases(configuration, manifest, "production",
                                          Path(directory), transcript)
            case = next(item for item in configuration["cases"] if item["id"] == "large_frame_paid")
            for observation in case["observations"]:
                observation["outcome"] = "nondeterministic_error"
                observation["error_class"] = "nondeterministic"
            with self.assertRaisesRegex(ValueError, "wrong expected outcome"):
                resource_evidence.check_cases(configuration, manifest, "production",
                                              Path(directory), transcript)
            for observation in case["observations"]:
                observation["outcome"] = "ok"
                observation["error_class"] = None
            boundary = next(item for item in configuration["cases"]
                            if item["id"] == "pulley_plain_paid")
            for observation in boundary["observations"]:
                if observation["sample_key"] == "first_failure":
                    observation["observed_depth"] = 12
            with self.assertRaisesRegex(ValueError, "nonadjacent Pulley boundary"):
                resource_evidence.check_cases(configuration, manifest, "production",
                                              Path(directory), transcript)

    def test_worker_range_must_match_actual_measured_capacity(self):
        def thread(category, identifier):
            index = {"worker-1": 1, "worker-2": 2, "blocking-1": 3,
                     "caller-1": 4}[identifier]
            base = index * 4_194_304
            return {
                "thread_category": category, "thread_id": identifier,
                "process_id": 100, "os_thread_id": 1000 + index,
                "identity_api": "linux_gettid", "page_size_bytes": 4096,
                "requested_bytes": 1_048_576 if category == "tokio_worker" else None,
                "mapped_bytes": 1_048_576, "guard_bytes": 4_096,
                "guard_start": base, "guard_end": base + 4096,
                "guard_verification": "linux_maps_prot_none",
                "usable_bytes": 1_044_480, "mapped_start": base,
                "mapped_end": base + 1_048_576, "usable_start": base + 4096,
                "usable_end": base + 1_048_576, "measurement_api": "pthread stack attributes",
                "guard_treatment": "guard excluded from usable interval",
                "guard_verified": True,
            }

        runtime = {
            "flavor": "multi_thread", "worker_count": 2,
            "worker_requested_bytes": 1_048_576,
            "thread_observations": [
                thread("tokio_worker", "worker-1"),
                thread("tokio_worker", "worker-2"),
                thread("blocking_pool", "blocking-1"),
                thread("block_on_caller", "caller-1"),
            ],
            "blocking_pool_observed": True, "block_on_caller_observed": True,
        }
        resource_evidence.thread_capacities(runtime, "reduced", 4096, "linux", 100)
        runtime["thread_observations"][0]["usable_end"] -= 1
        with self.assertRaisesRegex(ValueError, "actual usable worker range"):
            resource_evidence.thread_capacities(runtime, "reduced", 4096, "linux", 100)

    def test_removed_case_or_changed_hash_blocks_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory) / "manifest.json"
            for mutation in ("case", "hash"):
                altered = json.loads(json.dumps(self.manifest))
                if mutation == "case":
                    altered["cases"].pop()
                else:
                    altered["artifacts"]["stack_probe"]["sha256"] = "0" * 64
                temporary.write_text(json.dumps(altered))
                with patch.object(resource_evidence, "MANIFEST", temporary):
                    with self.assertRaisesRegex(ValueError, "manifest changed"):
                        resource_evidence.validate({}, Path(directory))


if __name__ == "__main__":
    unittest.main()
