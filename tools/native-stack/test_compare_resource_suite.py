#!/usr/bin/env python3
"""Reject semantic drift after six-cell archive closure."""

import json
import inspect
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from compare_resource_suite import compare_suite, signature_sha256, validator_for
from resource_manifest import CELLS
from resource_suite_closure import collect
from resource_suite_registry import build_registry
from test_resource_suite_closure import SOURCE, fixture


def semantic_validator(_group):
    return lambda bundle, _directory, archive_binary: {
        "cases": tuple(sorted({run["case_id"] for run in bundle["runs"].values()})),
        "marker": bundle.get("semantic_marker", "same"),
        "binary_present": archive_binary.is_file(),
    }


class SuiteComparisonTests(unittest.TestCase):
    def test_every_group_exposes_archived_binary_validation(self):
        registry = build_registry()
        for group_id, group in registry["groups"].items():
            with self.subTest(group=group_id):
                validator = validator_for(group)
                self.assertIn("archive_binary", inspect.signature(validator).parameters)

    def test_tuple_key_signature_hash_is_stable(self):
        first = {("case", "role"): {"fuel": 19, "receipts": ["ok"]}}
        second = {("case", "role"): {"receipts": ["ok"], "fuel": 19}}
        self.assertEqual(signature_sha256(first), signature_sha256(second))

    def test_one_drifted_cell_fails_after_full_archive_closure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            registry = fixture(root)
            with (patch("resource_suite_closure.checkout_source",
                        return_value=SOURCE),
                  patch("compare_resource_suite.validator_for",
                        side_effect=semantic_validator)):
                index = collect(root, SOURCE)
                result = compare_suite(index, root)
                self.assertEqual(result["status"], "case_semantics_equal")
                self.assertEqual(result["case_count"], 41)
                group = registry["groups"]["cold_publication"]
                path = (root / CELLS[1].replace("/", "_") / "cold_publication"
                        / group["capture_name"])
                bundle = json.loads(path.read_text())
                bundle["semantic_marker"] = "different-receipt"
                path.write_text(json.dumps(bundle))
                index = collect(root, SOURCE)
                with self.assertRaisesRegex(ValueError,
                                            "deterministic execution semantics differ"):
                    compare_suite(index, root)


if __name__ == "__main__":
    unittest.main()
