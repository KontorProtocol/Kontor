#!/usr/bin/env python3
"""Check S2 suite fanout and prerequisite gating without running workers."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from capture_resource_suite import capture_commands, preflight
from resource_manifest import CELLS
from resource_suite_registry import build_registry


class SuiteCaptureTests(unittest.TestCase):
    def test_every_group_uses_one_cell_control_and_special_inputs(self):
        registry = build_registry()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            control = root / "control.json"
            historical = root / "historical.json"
            reviewed = root / "reviewed.json"
            cell = CELLS[0]
            commands = capture_commands(registry, cell, control, "a" * 64,
                                        historical, reviewed, "b" * 64, root)
            self.assertEqual(set(commands), set(registry["groups"]))
            for group_id, command in commands.items():
                self.assertEqual(command[command.index("--cell") + 1], cell)
                self.assertEqual(command[command.index("--control-capture") + 1],
                                 str(control))
                self.assertEqual(command[command.index("--control-sha256") + 1],
                                 "a" * 64)
                self.assertEqual(command[command.index("--evidence-dir") + 1],
                                 str(root / cell.replace("/", "_") / group_id))
            self.assertEqual(commands["chain_v2"][
                commands["chain_v2"].index("--historical-bundle") + 1],
                str(historical))
            self.assertEqual(commands["pulley_boundary"][
                commands["pulley_boundary"].index("--phase") + 1], "final")
            self.assertEqual(commands["pulley_boundary"][
                commands["pulley_boundary"].index(
                    "--reviewed-discovery-sha256") + 1], "b" * 64)
            with self.assertRaisesRegex(ValueError, "unknown suite cell"):
                capture_commands(registry, "Linux-PPC/dev", control, "a" * 64,
                                 historical, reviewed, "b" * 64, root)

    def test_unfrozen_boundary_blocks_before_child_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            missing = root / "missing.json"
            with (patch("capture_resource_suite.checkout_source",
                        return_value="a" * 40),
                  patch("capture_resource_suite.validate_control") as control):
                with self.assertRaisesRegex(ValueError, "not frozen"):
                    preflight(CELLS[0], missing, "b" * 64, missing,
                              missing, "c" * 64, root)
                control.assert_not_called()


if __name__ == "__main__":
    unittest.main()
