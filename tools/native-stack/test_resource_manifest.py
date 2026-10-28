import json
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
        self.assertEqual(len(cases), 35)
        self.assertEqual(len(cases), len(self.manifest["cases"]))
        self.assertEqual(set(self.manifest["cells"]), set(resource_manifest.CELLS))
        self.assertEqual(
            self.manifest["amendment"]["sha256"], resource_manifest.AMENDMENT_SHA256
        )
        self.assertTrue(all(item["paired_worker_status"] == "missing" for item in cases.values()))
        self.assertTrue(all(item["sample_keys"] and
                            len(item["sample_keys"]) == len(set(item["sample_keys"]))
                            for item in cases.values()))
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
            "pending_host_io", "max_gas_paid", "real_native_core", "canonical_lift_lower",
            "canonical_realloc", "canonical_post_return", "generated_initialization",
            "explicit_resource_drop", "failed_instantiation_cleanup", "sqlite_pagination",
            "sqlite_ranges", "sqlite_large_values", "deepest_frame_host_call",
            "canonical_type_value_recursion",
        ):
            self.assertIn(surface, cases)
        for stores in (33, 63, 64, 65):
            for mode in ("paid", "view", "core"):
                self.assertIn(f"chain_{stores}_{mode}", cases)
        for shape in ("plain", "wide"):
            for mode in ("paid", "view", "system", "core"):
                self.assertIn(f"pulley_{shape}_{mode}", cases)

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
