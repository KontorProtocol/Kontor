import json
import os
import shutil
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from workload_bitcoin import RpcError, rpc, verify_separation


class Reply:
    def __init__(self, value):
        self.value = json.dumps(value).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def read(self):
        return self.value


class ExternalBitcoinChecks(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux" and shutil.which("sleep"), "Linux process lifetime check")
    def test_supervisor_death_kills_its_disposable_child(self):
        helper = str(Path(__file__).with_name("workload_bitcoin.py"))
        sleeper = shutil.which("sleep")
        program = ("import os,subprocess,sys; "
                   "p=subprocess.Popen([sys.executable,sys.argv[1],'--owned-child',"
                   "str(os.getpid()),sys.argv[2],'30']); print(p.pid,flush=True); p.wait()")
        parent = subprocess.Popen([sys.executable, "-c", program, helper, sleeper],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        child = None
        try:
            child = int(parent.stdout.readline())
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    if (Path("/proc") / str(child) / "exe").resolve(strict=True) == Path(sleeper).resolve():
                        break
                except FileNotFoundError:
                    pass
                time.sleep(0.01)
            else:
                self.fail("owned child did not exec the requested command")
            parent.kill()
            parent.wait(timeout=5)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    state = (Path("/proc") / str(child) / "stat").read_text().rsplit(")", 1)[1].split()[0]
                except FileNotFoundError:
                    state = "gone"
                if state in ("gone", "Z"):
                    child = None
                    break
                time.sleep(0.01)
            self.assertIsNone(child, "daemon survived supervisor death")
        finally:
            if parent.poll() is None:
                parent.kill()
            parent.wait(timeout=5)
            parent.stdout.close()
            parent.stderr.close()
            if child is not None:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_process_reuse_and_cgroup_overlap_are_rejected(self):
        expected = {"pid": 15, "start_ticks": 30, "executable": "/bitcoind",
                    "binary_sha256": "a" * 64, "cgroup": "/sys/fs/cgroup/bitcoin"}
        measured = Path("/sys/fs/cgroup/node")
        with patch("workload_bitcoin.process_identity", return_value=expected):
            self.assertEqual(verify_separation(expected, measured), expected)
        for field, bad in (("start_ticks", 31), ("binary_sha256", "b" * 64),
                           ("cgroup", "/sys/fs/cgroup/moved")):
            with self.subTest(field=field), patch("workload_bitcoin.process_identity",
                                                  return_value=dict(expected, **{field: bad})):
                with self.assertRaisesRegex(ValueError, "identity changed"):
                    verify_separation(expected, measured)
        for location in (str(measured), str(measured / "child")):
            inside = dict(expected, cgroup=location)
            with patch("workload_bitcoin.process_identity", return_value=inside):
                with self.assertRaisesRegex(ValueError, "inside the measured"):
                    verify_separation(inside, measured)

    def test_rpc_rejects_error_responses_instead_of_treating_them_as_readiness(self):
        with patch("workload_bitcoin.urlopen", return_value=Reply({"error": None, "result": {"blocks": 0}})):
            self.assertEqual(rpc("http://127.0.0.1:1234", "getblockchaininfo"), {"blocks": 0})
        with patch("workload_bitcoin.urlopen", return_value=Reply({"error": {"code": -28}, "result": None})):
            with self.assertRaises(RpcError) as caught:
                rpc("http://127.0.0.1:1234", "getblockchaininfo")
            self.assertEqual(caught.exception.code, -28)


if __name__ == "__main__":
    unittest.main()
