import json
import unittest
from pathlib import Path

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
        lifecycle = cases["failed_instantiation_cleanup"]
        self.assertEqual(lifecycle["sample_keys"], ["failed_init", "valid_control"])
        self.assertEqual(lifecycle["expected_traps"]["failed_init"],
                         "MemoryOutOfBounds")
        foreign = cases["foreign_wave_parse_print"]
        self.assertEqual(foreign["sample_keys"], [
            "depth_64", "depth_65_rejected", "literal_16384",
            "literal_16385_rejected", "print_depth_64",
            "print_depth_65_rejected"])
        self.assertEqual(foreign["parameters"]["via"], "foreign.call")
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

    def test_worker_range_must_match_actual_measured_capacity(self):
        def thread(category, identifier):
            index = {"worker-1": 1, "worker-2": 2, "blocking-1": 3,
                     "caller-1": 4}[identifier]
            base = index * 4_194_304
            return {
                "thread_category": category, "thread_id": identifier,
                "process_id": 100, "os_thread_id": 1000 + index,
                "identity_api": "linux_gettid", "page_size_bytes": 4096,
                "requested_bytes": 1_015_808 if category == "tokio_worker" else None,
                "mapped_bytes": 1_015_808, "guard_bytes": 4_096,
                "guard_start": base, "guard_end": base + 4096,
                "guard_verification": "linux_maps_prot_none",
                "usable_bytes": 1_011_712, "mapped_start": base,
                "mapped_end": base + 1_015_808, "usable_start": base + 4096,
                "usable_end": base + 1_015_808, "measurement_api": "pthread stack attributes",
                "guard_treatment": "guard excluded from usable interval",
                "guard_verified": True,
            }

        runtime = {
            "flavor": "multi_thread", "worker_count": 2,
            "worker_requested_bytes": 1_015_808,
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


if __name__ == "__main__":
    unittest.main()
