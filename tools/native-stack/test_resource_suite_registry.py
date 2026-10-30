#!/usr/bin/env python3
"""Reject missing, duplicated, and misclassified S2 capture bindings."""

import unittest

from resource_manifest import build_manifest
from resource_suite_registry import GROUPS, build_registry, validate_group_coverage


class SuiteRegistryTests(unittest.TestCase):
    def test_all_cases_have_one_capture_and_validator_group(self):
        registry = build_registry()
        self.assertEqual(registry["case_count"], 41)
        self.assertEqual(len(registry["case_to_group"]), 41)
        self.assertEqual(len(registry["groups"]), 16)
        self.assertEqual(registry["claim_status"], "source_registry_only")

    def test_missing_duplicate_or_wrong_family_cannot_close_registry(self):
        cases = build_manifest()["cases"]
        for mutation in ("missing", "duplicate", "wrong_family"):
            with self.subTest(mutation=mutation):
                groups = list(GROUPS)
                group_id, case_ids, families, capture, validator, manifest = groups[-1]
                if mutation == "missing":
                    case_ids = case_ids[:-1]
                elif mutation == "duplicate":
                    case_ids = case_ids + (case_ids[0],)
                else:
                    families = ("sqlite",)
                groups[-1] = (group_id, case_ids, families,
                              capture, validator, manifest)
                with self.assertRaises(ValueError):
                    validate_group_coverage(groups, cases)


if __name__ == "__main__":
    unittest.main()
