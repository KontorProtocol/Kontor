import json
from pathlib import Path
import socket
import tempfile
import time
import unittest

from workload_arrivals import ArrivalService


class ArrivalChecks(unittest.TestCase):
    def test_emits_while_consumer_does_not_read_and_stops_after_disconnect(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "arrivals.json"
            service = ArrivalService(output)
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.connect(service.path)
                    request = {"schema_version": 1, "epoch_ns": time.monotonic_ns(),
                               "events": [{"ordinal": n, "at_ns": n * 20_000_000}
                                          for n in range(3)] + [{"ordinal": 3, "at_ns": 60_000_000_000}]}
                    connection.sendall((json.dumps(request) + "\n").encode())
                    deadline = time.monotonic() + 2
                    while (not service.trials or len(service.trials[0]["sent"]) < 3) and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertEqual(len(service.trials[0]["sent"]), 3)
                    for emitted, intended in zip(service.trials[0]["sent"], request["events"]):
                        self.assertEqual(emitted["ordinal"], intended["ordinal"])
                        self.assertGreaterEqual(emitted["enqueued_ns"], intended["at_ns"])
                deadline = time.monotonic() + 2
                while service.trials[0]["status"] == "running" and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(service.trials[0]["status"], "consumer_finished")
            finally:
                service.close()
            self.assertTrue(json.loads(output.read_text())["thread_stopped"])
            self.assertFalse(Path(service.path).exists())

    def test_invalid_epoch_fails_service_instead_of_shifting_schedule(self):
        with tempfile.TemporaryDirectory() as directory:
            service = ArrivalService(Path(directory) / "arrivals.json")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.connect(service.path)
                connection.sendall((json.dumps({"schema_version": 1, "epoch_ns": 0,
                                               "events": [{"ordinal": 0, "at_ns": 0}]}) + "\n").encode())
                deadline = time.monotonic() + 2
                while service.error is None and time.monotonic() < deadline:
                    time.sleep(0.01)
            with self.assertRaisesRegex(ValueError, "epoch"):
                service.close()


if __name__ == "__main__":
    unittest.main()
