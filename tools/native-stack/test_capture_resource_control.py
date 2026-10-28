"""Failure controls for native stack source and guard capture."""

import json
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path

from capture_resource_control import run_guard_control, selected_binary


class ResourceControlCaptureTests(unittest.TestCase):
    def test_cargo_terminal_must_be_unique_successful_and_final(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "indexer-abc123"
            binary.touch()
            stream = root / "artifacts.jsonl"
            artifact = {
                "reason": "compiler-artifact", "package_id": "indexer-id",
                "target": {"name": "indexer", "kind": ["lib"]},
                "profile": {"test": True}, "executable": str(binary),
            }
            success = {"reason": "build-finished", "success": True}
            failure = {"reason": "build-finished", "success": False}
            metadata = {"packages": [{"name": "indexer", "id": "indexer-id"}]}

            def write(records):
                stream.write_text("\n".join(json.dumps(record) for record in records) + "\n")

            write([artifact, success])
            self.assertEqual(selected_binary(stream, metadata)[0], binary)
            for records in ([artifact, success, failure], [artifact, success, success],
                            [artifact, success, {"reason": "compiler-message"}],
                            [artifact, failure]):
                with self.subTest(records=records):
                    write(records)
                    with self.assertRaises(ValueError):
                        selected_binary(stream, metadata)

    @unittest.skipUnless(sys.platform == "linux", "Linux process groups are required")
    def test_timeout_kills_descendant_that_retains_stdout(self):
        script = (
            "import pathlib,subprocess,sys; "
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
            "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); "
            "print(child.pid,flush=True)"
        )
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "descendant-pid"
            start = time.monotonic()
            parent, _, _, output, timed_out = run_guard_control(
                [sys.executable, "-c", script, str(pid_path)], 0.3,
            )
            descendant_pid = int(pid_path.read_text())

            def state():
                try:
                    status = Path(f"/proc/{descendant_pid}/stat").read_text()
                except FileNotFoundError:
                    return None
                return status[status.rfind(")") + 2:].split()[0]

            try:
                self.assertTrue(timed_out)
                self.assertEqual(parent.returncode, 0)
                self.assertEqual(output.strip(), str(descendant_pid).encode())
                self.assertLess(time.monotonic() - start, 6)
                deadline = time.monotonic() + 1
                while state() not in (None, "Z", "X", "x") and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertIn(state(), (None, "Z", "X", "x"))
            finally:
                if state() not in (None, "Z", "X", "x"):
                    try:
                        os.kill(descendant_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == "__main__":
    unittest.main()
