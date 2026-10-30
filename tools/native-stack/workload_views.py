"""Drive competing contract views outside the measured node cgroup."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import os
from pathlib import Path
import select
import socket
import tempfile
import threading
import time
from urllib.parse import quote

from workload_bitcoin import process_identity, require


def send(connection, value):
    connection.sendall((json.dumps(value, separators=(",", ":")) + "\n").encode())


def receive(reader):
    raw = reader.readline(1024 * 1024 + 1)
    require(raw.endswith(b"\n") and len(raw) <= 1024 * 1024,
            "view control disconnected or exceeded its message limit")
    return json.loads(raw), raw


def view(connection, address, expression):
    connection.request("POST", "/view/" + quote(address, safe=""),
                       json.dumps({"expr": expression}), {"Content-Type": "application/json"})
    response = connection.getresponse()
    raw = response.read(1024 * 1024 + 1)
    require(response.status == 200 and len(raw) <= 1024 * 1024,
            "contract view HTTP response failed or exceeded its limit")
    result = json.loads(raw)["result"]
    require(result["type"] == "Ok", f"contract view failed: {result}")
    return result["value"]


def overlapping_calls(intervals, begin, end):
    return sum(begin <= started <= finished <= end for started, finished in intervals)


class ViewService:
    def __init__(self, output):
        self.output = output
        self.identity = process_identity(os.getpid())
        self.directory = tempfile.TemporaryDirectory(prefix="kontor-views-")
        self.path = str(Path(self.directory.name) / "socket")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.stopping = threading.Event()
        self.trials = []
        self.error = None
        self.thread = threading.Thread(target=self.serve, daemon=True)
        try:
            self.listener.bind(self.path)
            self.listener.listen(1)
            self.listener.settimeout(0.1)
            self.thread.start()
        except BaseException:
            self.listener.close()
            self.directory.cleanup()
            raise

    def serve(self):
        try:
            while not self.stopping.is_set():
                try:
                    connection, _ = self.listener.accept()
                except TimeoutError:
                    continue
                with connection, connection.makefile("rb") as reader:
                    connection.settimeout(60)
                    self.trial(connection, reader)
        except BaseException as error:
            self.error = repr(error)

    def trial(self, control, reader):
        request, raw = receive(reader)
        require(request["schema_version"] == 1 and request["clients"] == 8,
                "view request schema or concurrency differs")
        require(type(request["port"]) is int and 0 < request["port"] < 65536,
                "view request port is invalid")
        require(type(request["maximum"]) is int and request["maximum"] >= 0,
                "view counter maximum is invalid")
        require(len(request["samples"]) == 5 and all(
            isinstance(sample["expr"], str) and isinstance(sample["expected"], str)
            for sample in request["samples"]), "view samples are invalid")
        trial = {"request_sha256": hashlib.sha256(raw).hexdigest(),
                 "restore": request["restore"], "status": "running", "workers": []}
        self.trials.append(trial)
        stopped, start = threading.Event(), threading.Event()
        ready = threading.Barrier(9, timeout=60)
        finish = {}

        def client(index):
            completed = 0
            page_intervals = []
            last = 0
            transport = http.client.HTTPConnection("127.0.0.1", request["port"], timeout=30)
            try:
                require(view(transport, request["counter"], "get()") == "0",
                        "view counter was nonzero before writer")
                ready.wait()
                while not start.wait(0.1):
                    if stopped.is_set() or self.stopping.is_set():
                        return None
                while not stopped.is_set() and not self.stopping.is_set():
                    sample = request["samples"][(index + completed) % 5]
                    page_started = time.monotonic_ns()
                    value = view(transport, request["pages"], sample["expr"])
                    page_intervals.append((page_started, time.monotonic_ns()))
                    require(len(page_intervals) <= 100_000, "view call count exceeded finite harness limit")
                    require(value == sample["expected"], "pagination response differs from fixture oracle")
                    value = view(transport, request["counter"], "get()")
                    require(value.isascii() and value.isdecimal(), "counter is not an unsigned integer")
                    value = int(value)
                    require(last <= value <= request["maximum"], "view counter regressed or exceeded work")
                    last = value
                    completed += 1
                if finish.get("succeeded"):
                    require(view(transport, request["counter"], "get()") == str(finish["completed"]),
                            "view retained stale committed counter")
                return {"client": index, "completed": completed,
                        "completed_during_writer": overlapping_calls(
                            page_intervals, finish.get("writer_started_ns", 0),
                            finish.get("writer_finished_ns", 0)),
                        "last_counter_during_work": last}
            except BaseException:
                ready.abort()
                stopped.set()
                raise
            finally:
                transport.close()

        with ThreadPoolExecutor(max_workers=8, thread_name_prefix="kontor-view") as executor:
            futures = [executor.submit(client, index) for index in range(8)]
            try:
                ready.wait()
                send(control, {"ready": True})
                message, _ = receive(reader)
                require(message == {"start": True}, "view start control differs")
                trial["start_ns"] = time.monotonic_ns()
                start.set()
                send(control, {"started": True})
                while not select.select([control], [], [], 0.1)[0]:
                    require(not self.stopping.is_set(), "view supervisor stopped during writer")
                    require(not stopped.is_set(), "view client failed during writer")
                finish.update(receive(reader)[0])
                require(type(finish.get("succeeded")) is bool
                        and type(finish.get("completed")) is int
                        and 0 <= finish["completed"] <= request["maximum"],
                        "view finish control differs")
                trial["stop_ns"] = time.monotonic_ns()
                begin, end = finish.get("writer_started_ns"), finish.get("writer_finished_ns")
                require(type(begin) is int and type(end) is int
                        and trial["start_ns"] <= begin <= end <= trial["stop_ns"],
                        "writer timestamps differ from local monotonic clock")
                trial["writer_started_ns"], trial["writer_finished_ns"] = begin, end
                trial["writer_clock"] = "CLOCK_MONOTONIC"
                stopped.set()
                trial["workers"] = [future.result() for future in futures]
                require(finish["succeeded"], "canonical writer did not succeed")
                require(all(worker and worker["completed_during_writer"] > 0
                            for worker in trial["workers"]), "not every view client overlapped writer")
                trial["completed_counter"] = finish["completed"]
                trial["status"] = "passed"
                send(control, trial)
            except BaseException as error:
                trial.update(status="failed", error=repr(error))
                raise
            finally:
                stopped.set()
                start.set()
                ready.abort()

    def close(self):
        self.stopping.set()
        # Control reads and HTTP requests are bounded even when the node dies.
        self.thread.join(timeout=95)
        self.listener.close()
        self.directory.cleanup()
        data = {"identity": self.identity, "trials": self.trials, "error": self.error,
                "thread_stopped": not self.thread.is_alive(),
                "scope": "HTTP clients and response oracles outside measured node cgroup"}
        self.output.write_text(json.dumps(data, indent=2) + "\n")
        require(data["thread_stopped"] and self.error is None,
                f"external view service failed: {self.error}")
