import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import macos_diagnostics as diagnostics


class MacOSDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.reports = self.root / "DiagnosticReports"
        self.reports.mkdir()
        self.output = self.root / "output"
        self.roots = {"user": self.reports}

    def test_waits_for_delayed_reports_and_recopies_growing_reports(self):
        (self.reports / "historical.ips").write_text("old report")
        diagnostics.prepare(self.output, self.roots)
        nested = self.reports / "Retired"
        nested.mkdir()
        report = nested / "unexpected-process-name.ips"
        report.write_text("partial")

        def finish_reports(_seconds):
            report.write_text("complete crash report")
            (self.reports / "another-test.crash").write_text("second crash")

        with patch.object(diagnostics.time, "monotonic", side_effect=[0, 0, 2]), \
                patch.object(diagnostics.time, "sleep", side_effect=finish_reports):
            count = diagnostics.collect_reports(self.output, self.roots, wait_seconds=2)

        self.assertEqual(count, 2)
        captured = self.output / "reports/user"
        self.assertEqual((captured / "Retired" / report.name).read_text(), "complete crash report")
        self.assertEqual((captured / "another-test.crash").read_text(), "second crash")
        self.assertFalse((captured / "historical.ips").exists())

    def test_collects_changed_existing_reports_and_ignores_symlinks(self):
        report = self.reports / "existing.ips"
        report.write_text("old")
        diagnostics.prepare(self.output, self.roots)
        report.write_text("updated report")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "secret").write_text("not a report")
        (self.reports / "linked-file").symlink_to(outside / "secret")
        (self.reports / "linked-directory").symlink_to(outside, target_is_directory=True)

        self.assertEqual(diagnostics.collect_reports(self.output, self.roots, wait_seconds=0), 1)
        inventory = json.loads((self.output / "reports.json").read_text())
        self.assertEqual(list(inventory["copied"]), ["user/existing.ips"])

    def test_missing_report_directory_is_recorded_without_losing_other_reports(self):
        self.roots["system"] = self.root / "missing"
        diagnostics.prepare(self.output, self.roots)
        (self.reports / "crash.ips").write_text("report")
        self.assertEqual(diagnostics.collect_reports(self.output, self.roots, wait_seconds=0), 1)
        inventory = json.loads((self.output / "reports.json").read_text())
        self.assertTrue(any("missing" in error for error in inventory["collection_errors"]))

    def test_copy_failure_is_recorded(self):
        diagnostics.prepare(self.output, self.roots)
        (self.reports / "crash.ips").write_text("report")
        with patch.object(diagnostics.shutil, "copy2", side_effect=PermissionError("denied")):
            self.assertEqual(diagnostics.collect_reports(self.output, self.roots, wait_seconds=0), 0)
        inventory = json.loads((self.output / "reports.json").read_text())
        self.assertTrue(any("denied" in error for error in inventory["collection_errors"]))

    def test_no_reports_still_produces_inventory(self):
        diagnostics.prepare(self.output, self.roots)
        self.assertEqual(diagnostics.collect_reports(self.output, self.roots, wait_seconds=0), 0)
        inventory = json.loads((self.output / "reports.json").read_text())
        self.assertEqual(inventory["copied"], {})
        self.assertEqual(inventory["collection_errors"], [])

    def test_missing_baseline_does_not_upload_historical_reports(self):
        self.output.mkdir()
        (self.reports / "historical.ips").write_text("old report")
        self.assertEqual(diagnostics.collect_reports(self.output, self.roots, wait_seconds=0), 0)
        inventory = json.loads((self.output / "reports.json").read_text())
        self.assertIn("Cannot read baseline", inventory["collection_errors"][0])

    def test_command_failures_keep_output_and_exit_status(self):
        path = self.root / "command.log"
        diagnostics.capture_command(path, [
            sys.executable, "-c", "import sys; print('diagnostic'); sys.exit(7)",
        ])
        self.assertIn("diagnostic", path.read_text())
        self.assertIn("Exit status: 7", path.read_text())
        diagnostics.capture_command(path, [str(self.root / "missing-command")])
        self.assertIn("Collection error:", path.read_text())

    def test_command_timeout_preserves_partial_output(self):
        path = self.root / "command.log"
        diagnostics.capture_command(path, [
            sys.executable, "-c", "import time; print('partial', flush=True); time.sleep(30)",
        ], timeout=1)
        self.assertIn("partial", path.read_text())
        self.assertIn("Collection error:", path.read_text())

    def test_logged_command_preserves_output_and_exit_code(self):
        log = self.root / "tests.log"
        command = [
            sys.executable, diagnostics.__file__, "run", str(log),
            sys.executable, "-c",
            "import sys; print('stdout'); print('stderr', file=sys.stderr); sys.exit(101)",
        ]
        result = subprocess.run(command, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 101)
        self.assertEqual(result.stdout, log.read_bytes())
        self.assertIn(b"stdout", result.stdout)
        self.assertIn(b"stderr", result.stdout)

    def test_logged_command_does_not_wait_for_descendants_to_close_output(self):
        log = self.root / "tests.log"
        pid_file = self.root / "child.pid"
        script = (
            "import pathlib, subprocess, sys; "
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
            f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid)); "
            "print('parent failed', flush=True); sys.exit(101)"
        )
        try:
            result = subprocess.run([
                sys.executable, diagnostics.__file__, "run", str(log),
                sys.executable, "-c", script,
            ], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 101)
            self.assertIn(b"parent failed", result.stdout)
            os.kill(int(pid_file.read_text()), 0)
        finally:
            if pid_file.exists():
                try:
                    os.kill(int(pid_file.read_text()), signal.SIGTERM)
                except ProcessLookupError:
                    pass


if __name__ == "__main__":
    unittest.main()
