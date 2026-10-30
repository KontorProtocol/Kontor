#!/usr/bin/env python3
"""Reject incomplete or mixed-source six-cell archive indexes."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from resource_manifest import CELLS
from resource_suite_closure import collect, validate_index
from resource_suite_registry import build_registry


SOURCE = "a" * 40
BINARY = "b" * 64
CONTROL = "c" * 64


def fixture(root):
    registry = build_registry()
    for cell in CELLS:
        for group_id, group in registry["groups"].items():
            directory = root / cell.replace("/", "_") / group_id
            directory.mkdir(parents=True)
            bundle = {
                "cell": cell, "source_sha": SOURCE,
                "manifest_sha256": group["manifest_sha256"],
                "qualification_status": "missing",
                "binary_path": f"/build/{cell.replace('/', '-')}/indexer-test",
                "binary_sha256": BINARY,
                "control_capture": {"sha256": CONTROL},
                "runs": {case_id: {"case_id": case_id, "cell": cell,
                                   "source_sha": SOURCE}
                         for case_id in group["case_ids"]},
            }
            if group["manifest"] == "boundary":
                bundle["phase"] = "final"
            if group["manifest"] == "v2":
                bundle["schema_version"] = 2
            (directory / group["capture_name"]).write_text(json.dumps(bundle))
    return registry


class SuiteClosureTests(unittest.TestCase):
    def test_complete_common_head_registry_is_closure_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture(root)
            index = collect(root, SOURCE)
            self.assertEqual(validate_index(index, root, check_checkout=False),
                             {"status": "closure_only", "cells": 6,
                              "groups_per_cell": 16, "case_count": 41})
            forged = copy.deepcopy(index)
            forged["cells"][CELLS[0]]["groups"].pop("cold_publication")
            with self.assertRaisesRegex(ValueError, "incomplete"):
                validate_index(forged, root, check_checkout=False)
            forged = copy.deepcopy(index)
            forged["cells"][CELLS[0]]["groups"]["cold_publication"]["path"] = \
                "../outside.json"
            with self.assertRaisesRegex(ValueError, "path or digest"):
                validate_index(forged, root, check_checkout=False)

    def test_mixed_source_or_missing_case_cannot_close(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            registry = fixture(root)
            group = registry["groups"]["cold_publication"]
            path = (root / CELLS[2].replace("/", "_") / "cold_publication"
                    / group["capture_name"])
            bundle = json.loads(path.read_text())
            bundle["source_sha"] = "d" * 40
            path.write_text(json.dumps(bundle))
            with self.assertRaisesRegex(ValueError, "source, control, or case coverage"):
                collect(root, SOURCE)
            bundle["source_sha"] = SOURCE
            bundle["runs"].pop(group["case_ids"][0])
            path.write_text(json.dumps(bundle))
            with self.assertRaisesRegex(ValueError, "source, control, or case coverage"):
                collect(root, SOURCE)

    def test_groups_must_share_binary_and_guard_control_in_each_cell(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            registry = fixture(root)
            group = registry["groups"]["cold_publication"]
            path = (root / CELLS[0].replace("/", "_") / "cold_publication"
                    / group["capture_name"])
            bundle = json.loads(path.read_text())
            bundle["binary_sha256"] = "d" * 64
            path.write_text(json.dumps(bundle))
            with self.assertRaisesRegex(ValueError, "different binaries or guard controls"):
                collect(root, SOURCE)
            bundle["binary_sha256"] = BINARY
            bundle["control_capture"]["sha256"] = "d" * 64
            path.write_text(json.dumps(bundle))
            with self.assertRaisesRegex(ValueError, "different binaries or guard controls"):
                collect(root, SOURCE)


if __name__ == "__main__":
    unittest.main()
