#!/usr/bin/env python3
"""Run a local workload under measured Linux CPU and memory constraints."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time
import uuid

from workload_bitcoin import BitcoinService, verify_separation


PROFILES = {"conservative": (2, 12 * 1024**3), "burst": (8, 16 * 1024**3)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def counters(path):
    return {key: int(value) for key, value in
            (line.split() for line in path.read_text().splitlines())}


def limits(directory, cpus, memory):
    quota, period = (directory / "cpu.max").read_text().split()
    require(quota != "max" and int(period) > 0
            and int(quota) == cpus * int(period), "CPU quota differs from profile")
    require((directory / "memory.max").read_text().strip() == str(memory),
            "memory limit differs from profile")
    require((directory / "memory.swap.max").read_text().strip() == "0",
            "swap must be disabled for the measurement")
    return {"cpu.max": f"{quota} {period}", "memory.max": memory,
            "memory.swap.max": 0}


def cgroup():
    entries = [line.removeprefix("0::") for line in
               Path("/proc/self/cgroup").read_text().splitlines()
               if line.startswith("0::")]
    require(len(entries) == 1, "requires unified cgroup v2")
    return Path("/sys/fs/cgroup") / entries[0].lstrip("/")


def ancestor_limits(directory):
    result = {}
    while directory != Path("/sys/fs/cgroup"):
        result[str(directory)] = {
            name: (directory / name).read_text().strip()
            for name in ("cpu.max", "memory.max", "memory.swap.max")
            if (directory / name).is_file()
        }
        directory = directory.parent
    return result


def check_ancestors(ancestors, cpus, memory):
    for path, values in ancestors.items():
        quota, period = values.get("cpu.max", "max 100000").split()
        require(quota == "max" or int(quota) >= cpus * int(period),
                f"ancestor CPU quota is below profile: {path}")
        maximum = values.get("memory.max", "max")
        require(maximum == "max" or int(maximum) >= memory,
                f"ancestor memory limit is below profile: {path}")


def check_result(log, before, after):
    require("running 1 test\n" in log
            and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", log),
            "workload must execute exactly one passing, non-ignored test")
    require(all(after.get(key, 0) == before.get(key, 0)
                for key in ("oom", "oom_kill", "oom_group_kill")),
            "workload incurred an out-of-memory event")


def host_resources():
    environment = dict(os.environ, LC_ALL="C", LANG="C")

    def query(command):
        result = subprocess.run(command, env=environment, check=True,
                                capture_output=True, text=True, timeout=15)
        return json.loads(result.stdout)

    paths = {"checkout": Path.cwd(), "temporary": Path(tempfile.gettempdir())}
    return {
        "cpu": query(["lscpu", "--json"]),
        "memory_info": Path("/proc/meminfo").read_text(),
        "page_size_bytes": os.sysconf("SC_PAGE_SIZE"),
        "filesystems": {
            name: {"path": str(path.resolve()),
                   "mount": query(["findmnt", "--json", "--target", str(path),
                                   "--output", "TARGET,SOURCE,FSTYPE,OPTIONS"])}
            for name, path in paths.items()
        },
        "block_devices": query(["lsblk", "--json", "--bytes", "--output",
                                 "NAME,TYPE,SIZE,ROTA,TRAN,MODEL"]),
    }


def worker(spec_path):
    spec = json.loads(spec_path.read_text())
    output = spec_path.parent
    cpus, memory = PROFILES[spec["profile"]]
    available = sorted(os.sched_getaffinity(0))
    require(len(available) >= cpus, "host affinity cannot satisfy profile")
    os.sched_setaffinity(0, available[:cpus])
    directory = cgroup()
    enforced = limits(directory, cpus, memory)
    ancestors = ancestor_limits(directory.parent)
    check_ancestors(ancestors, cpus, memory)
    binary = Path(spec["binary"])
    require(digest(binary) == spec["binary_sha256"], "binary changed before launch")
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("KONTOR_WORKLOAD_")}
    environment.update(spec["environment"])
    resources = host_resources()
    external = spec.get("external_bitcoin")
    external_identity = (verify_separation(external["identity"], directory)
                         if external else None)
    started = time.monotonic()
    before_cpu = counters(directory / "cpu.stat")
    before_events = counters(directory / "memory.events")
    command = [str(binary), spec["test"], "--exact", "--ignored",
               "--nocapture", "--test-threads=1"]
    observation = {
        "profile": spec["profile"], "limits": enforced,
        "affinity": sorted(os.sched_getaffinity(0)),
        "ancestor_limits": ancestors,
        "host": platform.uname()._asdict(), "command": command,
        "host_resources": resources,
        "claim": "local constrained measurement; not production hardware equivalence",
        "binary_sha256_before": digest(binary), "status": "running",
        "external_bitcoin": external_identity,
        "measurement_scope": ("test process and in-process harness/oracles; external Bitcoin excluded"
                              if external else "whole service including test children and setup"),
    }
    record = output / "measurement.json"
    with (output / "workload.log").open("xb") as log:
        child = subprocess.Popen(command, env=environment, stdout=log,
                                 stderr=subprocess.STDOUT)
        observation["pid"] = child.pid
        record.write_text(json.dumps(observation, indent=2) + "\n")
        code = child.wait()
    observation.update(
        status="terminal", exit_code=code, elapsed_seconds=time.monotonic() - started,
        cpu_before=before_cpu, cpu_after=counters(directory / "cpu.stat"),
        memory_events_before=before_events,
        memory_events_after=counters(directory / "memory.events"),
        memory_peak_bytes=int((directory / "memory.peak").read_text()),
        binary_sha256_after=digest(binary), log_sha256=digest(output / "workload.log"),
    )
    observation["validation"] = "failed"
    try:
        require(observation["binary_sha256_after"] == spec["binary_sha256"],
                "binary changed during measurement")
        limits(directory, cpus, memory)
        if code == 0:
            transcript = (output / "workload.log").read_text()
            check_result(transcript, before_events,
                         observation["memory_events_after"])
            require(not external or "workload_external_bitcoin=true\n" in transcript,
                    "workload did not confirm use of the external Bitcoin service")
            observation["validation"] = "passed"
    except ValueError as error:
        observation["validation_error"] = str(error)
        raise
    finally:
        record.write_text(json.dumps(observation, indent=2) + "\n")
    return code


def run(args):
    require(sys.platform == "linux", "reference profiles require Linux cgroup v2")
    require(args.timeout > 0, "timeout must be positive")
    environment = json.loads(args.environment.read_text())
    require(isinstance(environment, dict)
            and all(isinstance(key, str) and key.startswith("KONTOR_WORKLOAD_")
                    and isinstance(value, str) for key, value in environment.items()),
            "environment must contain only string KONTOR_WORKLOAD_ settings")
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    require("KONTOR_WORKLOAD_BITCOIN_RPC_URL" not in environment,
            "external Bitcoin must be owned and verified by this supervisor")
    bitcoin = None
    try:
        if args.bitcoin_binary:
            bitcoin = BitcoinService(args.bitcoin_binary, output / "bitcoin").start()
            environment["KONTOR_WORKLOAD_BITCOIN_RPC_URL"] = bitcoin.url
        return run_service(args, environment, binary, output, bitcoin)
    finally:
        if bitcoin:
            bitcoin.close()


def run_service(args, environment, binary, output, bitcoin):
    cpus, memory = PROFILES[args.profile]
    spec = {"profile": args.profile, "binary": str(binary),
            "binary_sha256": digest(binary), "test": args.test,
            "environment": environment}
    if bitcoin:
        spec["external_bitcoin"] = {"identity": bitcoin.identity, "rpc_url": bitcoin.url}
    spec_path = output / "request.json"
    spec_path.write_text(json.dumps(spec, indent=2) + "\n")
    unit = f"kontor-workload-{uuid.uuid4().hex}"
    command = ["systemd-run", "--user", "--quiet", "--wait", "--pipe", "--collect",
               f"--unit={unit}", "--service-type=exec",
               f"--property=CPUQuota={cpus * 100}%", f"--property=MemoryMax={memory}",
               "--property=MemorySwapMax=0", "--property=KillMode=control-group",
               "--property=TimeoutStopSec=5", f"--property=RuntimeMaxSec={args.timeout}",
               f"--working-directory={Path.cwd()}", f"--setenv=PATH={os.environ['PATH']}",
               sys.executable, str(Path(__file__).resolve()), "--worker", str(spec_path)]
    # The service manager kills the complete process tree on timeout or failure,
    # including bitcoind and detached runtime workers owned by the test process.
    with (output / "supervisor.log").open("xb") as log:
        try:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=args.timeout + 30)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
        finally:
            subprocess.run(["systemctl", "--user", "stop", unit],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=15, check=False)
    (output / "supervisor.json").write_text(json.dumps({
        "command": command, "exit_code": code,
        "request_sha256": digest(spec_path), "runner_sha256": digest(Path(__file__)),
        "measurement_present": (output / "measurement.json").is_file(),
    }, indent=2) + "\n")
    print(json.dumps({"output": str(output), "exit_code": code}), flush=True)
    return code


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        return worker(Path(sys.argv[2]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--test", required=True)
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("--bitcoin-binary", type=Path,
                        help="start fresh regtest outside the measured service, owned by this supervisor")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
