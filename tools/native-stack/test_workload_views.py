from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

from workload_views import ViewService, receive, send


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        value = str(self.server.counter) if self.path == "/view/counter" else self.server.page
        raw = json.dumps({"result": {"type": "Ok", "value": value}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
        self.wfile.flush()

    def log_message(self, *_):
        pass


class ViewChecks(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.service = ViewService(Path(self.directory.name) / "views.json")
        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.http.counter, self.http.page = 0, "[]"
        self.http_thread = threading.Thread(target=self.http.serve_forever)
        self.http_thread.start()

    def tearDown(self):
        try:
            self.service.close()
        finally:
            self.http.shutdown()
            self.http.server_close()
            self.http_thread.join()
            self.directory.cleanup()

    def connect(self):
        control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        control.settimeout(10)
        control.connect(self.service.path)
        reader = control.makefile("rb")
        self.addCleanup(reader.close)
        self.addCleanup(control.close)
        send(control, {"schema_version": 1, "clients": 8, "port": self.http.server_port,
                       "restore": "trial.db", "maximum": 10, "pages": "pages", "counter": "counter",
                       "samples": [{"expr": "page()", "expected": "[]"}] * 5})
        self.assertEqual(receive(reader)[0], {"ready": True})
        send(control, {"start": True})
        self.assertEqual(receive(reader)[0], {"started": True})
        return control, reader

    def test_clients_observe_progress_and_drain_with_fresh_final_counter(self):
        control, reader = self.connect()
        time.sleep(0.3)
        self.http.counter = 10
        send(control, {"succeeded": True, "completed": 10})
        result, _ = receive(reader)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["completed_counter"], 10)
        self.assertEqual(len(result["workers"]), 8)
        self.assertTrue(all(worker["completed_during_writer"] > 0 for worker in result["workers"]))

    def failure(self, pattern):
        self.service.thread.join(timeout=5)
        self.assertFalse(self.service.thread.is_alive())
        self.assertEqual(self.service.trials[0]["status"], "failed")
        with self.assertRaisesRegex(ValueError, pattern):
            self.service.close()
        # Cleanup is already checked, avoid deliberately raising again in tearDown.
        self.service.error = None

    def test_control_disconnect_stops_workers(self):
        control, reader = self.connect()
        reader.close()
        control.close()
        self.failure("disconnected")

    def test_wrong_page_is_not_accepted_as_a_successful_view(self):
        control, reader = self.connect()
        self.http.page = "wrong"
        self.failure("client failed")
        reader.close()
        control.close()

    def test_stale_final_counter_fails(self):
        control, reader = self.connect()
        time.sleep(0.3)
        send(control, {"succeeded": True, "completed": 10})
        self.failure("stale committed counter")
        reader.close()
        control.close()


if __name__ == "__main__":
    unittest.main()
