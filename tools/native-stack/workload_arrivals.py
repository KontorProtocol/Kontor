"""Schedule finite workload arrivals outside the measured node service."""

import hashlib
import json
import os
from pathlib import Path
import select
import socket
import tempfile
import threading
import time

from workload_bitcoin import process_identity, require


class ArrivalService:
    def __init__(self, output):
        self.output = output
        self.identity = process_identity(os.getpid())
        self.directory = tempfile.TemporaryDirectory(prefix="kontor-arrivals-")
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
                with connection:
                    self.trial(connection)
        except BaseException as error:
            self.error = repr(error)

    def trial(self, connection):
        connection.settimeout(5)
        with connection.makefile("rb") as reader:
            raw = reader.readline(4 * 1024 * 1024 + 1)
        require(raw.endswith(b"\n") and len(raw) <= 4 * 1024 * 1024,
                "arrival request is missing or too large")
        request = json.loads(raw)
        require(request["schema_version"] == 1, "arrival request schema differs")
        epoch = request["epoch_ns"]
        require(type(epoch) is int and 0 <= time.monotonic_ns() - epoch < 5_000_000_000,
                "arrival epoch differs from local monotonic clock")
        events = request["events"]
        require(events and len(events) <= 100_000, "invalid finite arrival count")
        previous = (-1, -1)
        for event in events:
            ordinal, at_ns = event["ordinal"], event["at_ns"]
            require(type(ordinal) is int and type(at_ns) is int
                    and ordinal > previous[0] and at_ns >= max(0, previous[1]),
                    "arrival schedule is unordered")
            previous = ordinal, at_ns
        trial = {"request_sha256": hashlib.sha256(raw).hexdigest(),
                 "epoch_ns": epoch, "event_count": len(events), "sent": [],
                 "status": "running"}
        self.trials.append(trial)
        try:
            for event in events:
                while True:
                    if self.stopping.is_set():
                        trial["status"] = "supervisor_stopped"
                        return
                    remaining = epoch + event["at_ns"] - time.monotonic_ns()
                    if remaining <= 0:
                        break
                    readable, _, _ = select.select([connection], [], [], min(0.1, remaining / 1e9))
                    if readable:
                        require(connection.recv(1) == b"", "unexpected arrival client data")
                        trial["status"] = "consumer_finished"
                        return
                emitted = time.monotonic_ns() - epoch
                record = {"ordinal": event["ordinal"], "enqueued_ns": emitted}
                connection.sendall((json.dumps(record, separators=(",", ":")) + "\n").encode())
                trial["sent"].append(record)
            trial["status"] = "exhausted"
        except (BrokenPipeError, ConnectionResetError):
            trial["status"] = "consumer_finished"

    def close(self):
        self.stopping.set()
        self.thread.join(timeout=6)
        self.listener.close()
        self.directory.cleanup()
        data = {"identity": self.identity, "trials": self.trials,
                "error": self.error, "thread_stopped": not self.thread.is_alive(),
                "scope": "arrival scheduler in supervisor, outside measured cgroup"}
        self.output.write_text(json.dumps(data, indent=2) + "\n")
        require(data["thread_stopped"] and self.error is None,
                f"external arrival service failed: {self.error}")
