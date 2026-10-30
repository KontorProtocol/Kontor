"""Own a fresh Bitcoin regtest service outside the measured node cgroup."""

import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def process_identity(pid):
    process = Path("/proc") / str(pid)
    executable = (process / "exe").resolve(strict=True)
    stat = (process / "stat").read_text().rsplit(")", 1)[1].split()
    entries = [line.removeprefix("0::") for line in
               (process / "cgroup").read_text().splitlines() if line.startswith("0::")]
    require(len(entries) == 1 and ".." not in Path(entries[0]).parts,
            "Bitcoin process requires an unambiguous cgroup v2 path")
    return {"pid": pid, "start_ticks": int(stat[19]), "executable": str(executable),
            "binary_sha256": digest(executable),
            "cgroup": str(Path("/sys/fs/cgroup") / entries[0].lstrip("/"))}


def verify_separation(expected, measured):
    actual = process_identity(expected["pid"])
    require(actual == expected, "external Bitcoin process identity changed")
    service = Path(actual["cgroup"])
    require(not service.is_relative_to(measured),
            "external Bitcoin is inside the measured node cgroup")
    return actual


def process_memory(pid):
    path = Path("/proc") / str(pid) / "status"
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None
    fields = {}
    for line in text.splitlines():
        name, _, value = line.partition(":")
        if name in ("VmRSS", "VmHWM", "VmSize"):
            count, unit = value.split()
            require(unit == "kB", "Bitcoin process memory unit changed")
            fields[name] = int(count) * 1024
    return fields


def owns_rpc_listener(pid, port):
    process = Path("/proc") / str(pid)
    sockets = set()
    for fd in (process / "fd").iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        if target.startswith("socket:["):
            sockets.add(target[8:-1])
    for line in (process / "net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        if fields[1] == f"0100007F:{port:04X}" and fields[3] == "0A" and fields[9] in sockets:
            return True
    return False


class RpcError(Exception):
    def __init__(self, error):
        self.code = error["code"]
        super().__init__(str(error))


def rpc(url, method):
    request = Request(url, json.dumps({"jsonrpc": "1.0", "id": 1,
                                      "method": method, "params": []}).encode(),
                      {"Content-Type": "application/json",
                       "Authorization": "Basic " + base64.b64encode(b"rpc:rpc").decode()})
    try:
        response = urlopen(request, timeout=2)
    except HTTPError as error:
        response = error
    with response:
        result = json.load(response)
    if result.get("error") is not None:
        raise RpcError(result["error"])
    return result["result"]


class BitcoinService:
    def __init__(self, binary, output):
        self.binary = binary.resolve(strict=True)
        self.output = output
        self.child = None
        self.log = None
        self.record = {"status": "preparing", "binary": str(self.binary),
                       "binary_sha256": digest(self.binary), "attempts": []}

    def save(self):
        (self.output / "service.json").write_text(json.dumps(self.record, indent=2) + "\n")

    def start(self):
        self.output.mkdir(parents=True, exist_ok=False)
        data = self.output / "data"
        data.mkdir()
        self.log = (self.output / "bitcoin.log").open("xb")
        try:
            for _ in range(8):
                port = 10_000 + secrets.randbelow(22_000)
                self.url = f"http://127.0.0.1:{port}"
                command = [str(self.binary), f"-datadir={data}", "-regtest=1", "-server=1",
                           "-txindex=1", "-prune=0", "-dbcache=4000", "-listen=0",
                           "-rpcuser=rpc", "-rpcpassword=rpc", "-rpcbind=127.0.0.1",
                           "-rpcallowip=127.0.0.1", f"-rpcport={port}",
                           "-limitancestorcount=500", "-limitdescendantcount=500"]
                self.child = subprocess.Popen(
                    [sys.executable, "-B", str(Path(__file__).resolve()), "--owned-child",
                     str(os.getpid()), *command], stdout=self.log, stderr=subprocess.STDOUT)
                attempt = {"pid": self.child.pid, "command": command, "rpc_url": self.url}
                self.record["attempts"].append(attempt)
                self.record["status"] = "starting"
                self.save()
                started = time.monotonic()
                while self.child.poll() is None:
                    require(time.monotonic() - started < 65,
                            "external Bitcoin stayed alive without becoming ready")
                    try:
                        if not owns_rpc_listener(self.child.pid, port):
                            time.sleep(0.1)
                            continue
                        info = rpc(self.url, "getblockchaininfo")
                    except (URLError, TimeoutError, ConnectionError, FileNotFoundError):
                        time.sleep(0.1)
                        continue
                    except RpcError as error:
                        if error.code != -28:
                            raise
                        time.sleep(0.1)
                        continue
                    require(info["chain"] == "regtest" and info["blocks"] == 0,
                            "external Bitcoin must be fresh regtest")
                    self.identity = process_identity(self.child.pid)
                    require(self.identity["binary_sha256"] == self.record["binary_sha256"],
                            "Bitcoin executable differs from requested binary")
                    self.record.update(status="running", identity=self.identity,
                                       network=rpc(self.url, "getnetworkinfo"),
                                       memory_at_ready=process_memory(self.child.pid),
                                       memory_scope="Bitcoin process RSS/HWM/virtual size; cgroup may be shared")
                    self.save()
                    return self
                attempt["exit_code"] = self.child.returncode
                self.save()
            raise ValueError("external Bitcoin exited on all eight startup attempts")
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.child is not None:
            try:
                self.record["memory_before_shutdown"] = process_memory(self.child.pid)
            except OSError as error:
                self.record["memory_shutdown_error"] = str(error)
            if self.child.poll() is None:
                self.child.terminate()
                try:
                    self.child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.record["forced_kill"] = True
                    self.child.kill()
                    self.child.wait(timeout=5)
            self.record.update(status="terminal", exit_code=self.child.returncode)
        if self.log is not None:
            self.log.close()
            self.log = None
            self.record["log_sha256"] = digest(self.output / "bitcoin.log")
        self.save()


def owned_child(parent, command):
    # A killed supervisor cannot run finally. Bind this disposable daemon's
    # lifetime to that process before exec, then close the parent-death race.
    library = ctypes.CDLL(None, use_errno=True)
    library.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                             ctypes.c_ulong, ctypes.c_ulong]
    library.prctl.restype = ctypes.c_int
    require(library.prctl(1, signal.SIGKILL, 0, 0, 0) == 0,
            f"PR_SET_PDEATHSIG failed: {ctypes.get_errno()}")
    require(os.getppid() == parent, "Bitcoin supervisor exited before child setup")
    os.execv(command[0], command)


if __name__ == "__main__":
    require(len(sys.argv) >= 5 and sys.argv[1] == "--owned-child", "invalid service invocation")
    owned_child(int(sys.argv[2]), sys.argv[3:])
