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
from workload_arrivals import ArrivalService
from workload_views import ViewService


PROFILES = {"conservative": (2, 12 * 1024**3), "burst": (8, 16 * 1024**3)}
HISTORICAL_REPLAY = "reactor::workload_tests::smoke::populated::timed::archive::workload_saved_timed_historical_replay"
TIMED_REPLAYS = (
    HISTORICAL_REPLAY,
    "reactor::workload_tests::smoke::populated::timed::archive::workload_saved_timed_events_replay",
)
BOUNDARY_REPLAYS = (
    "reactor::workload_tests::smoke::populated::workload_aggregate_operation_limit_preserves_accounting",
    "reactor::workload_tests::smoke::populated::workload_full_block_capacity_preserves_accounting",
    "reactor::workload_tests::smoke::populated::workload_full_block_gas_exhaustion_preserves_accounting",
)
BOUNDARY_DELIVERIES = dict(zip(BOUNDARY_REPLAYS,
                               ("AggregateBoundary", "BlockCapacity", "MaxGasBlock"), strict=True))
BLOCK_SERVICE_TARGET_NS = 60 * 1_000_000_000


def view_restores(test):
    if test == HISTORICAL_REPLAY:
        return ["timed-one.db", "timed-two.db"]
    if test in BOUNDARY_REPLAYS:
        return ["first.db", "second.db"]
    raise ValueError("external views require a supported two-restore workload")


def memory_restores(test):
    if test in TIMED_REPLAYS:
        return ["timed-one.db", "timed-two.db"]
    if test in BOUNDARY_REPLAYS:
        return ["first.db", "second.db"]
    raise ValueError("trial memory requires a supported two-restore workload")


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


def boundary_service(log, test):
    prefix = "workload_boundary_service="
    samples = [json.loads(line.removeprefix(prefix)) for line in log.splitlines()
               if line.startswith(prefix)]
    require([sample.get("restore") for sample in samples] == ["first.db", "second.db"],
            "boundary service requires exactly two ordered restores")
    for sample in samples:
        require(sample.get("delivery") == BOUNDARY_DELIVERIES[test],
                "boundary service delivery differs from selected test")
        require(type(sample.get("height")) is int and sample["height"] > 0
                and type(sample.get("elapsed_ns")) is int and sample["elapsed_ns"] > 0,
                "boundary service height or duration is invalid")
        require(sample.get("scope") == (
            "canonical block execution and lifecycle; fixture setup and semantic oracle excluded"),
            "boundary service measurement scope differs")
    require(samples[0]["height"] == samples[1]["height"],
            "boundary restores measured different heights")
    maximum = max(sample["elapsed_ns"] for sample in samples)
    return {
        "samples": samples,
        "maximum_ns": maximum,
        "target_ns": BLOCK_SERVICE_TARGET_NS,
        "requires_explicit_disposition": maximum > BLOCK_SERVICE_TARGET_NS,
        "performance_approval": "not_established",
        "limitation": "two diagnostic restores; paired release trials and full qualification remain required",
    }


def trial_measurements(log, pid, directory, enforced, restores=("timed-one.db", "timed-two.db")):
    prefix = "workload_trial_memory="
    trials = [json.loads(line.removeprefix(prefix)) for line in log.splitlines()
              if line.startswith(prefix)]
    require([trial["restore"] for trial in trials] == list(restores),
            "expected exactly two ordered trial memory records")
    for trial in trials:
        require(trial["schema_version"] == 1 and trial["pid"] == pid
                and trial["cgroup"] == str(directory)
                and trial["peak_reset"] == "same_open_file_description",
                "trial memory identity or reset method differs")
        require(trial["limits"] == {key: str(value) for key, value in enforced.items()},
                "trial limits differ from enforced profile")
        require(type(trial["elapsed_ns"]) is int and trial["elapsed_ns"] > 0
                and type(trial["peak_bytes"]) is int and trial["peak_bytes"] > 0,
                "trial has no measured duration or peak")
        before, after = trial["before"], trial["after"]
        roots = trial["stores_after"]
        require(0 <= roots["live_roots"] <= roots["live_stores"]
                and roots["live_roots"] <= roots["peak_roots"]
                and roots["live_stores"] <= roots["peak_stores"]
                and 0 < roots["peak_roots"] <= roots["peak_stores"]
                and 0 < roots["created_roots"] <= roots["created_stores"],
                "trial Store telemetry is missing or inconsistent")
        for sample in (before, after):
            require(sample["swap_current_bytes"] == 0,
                    "trial used swap")
            require(sample["memory_current_bytes"] > 0 and sample["process_rss_bytes"] > 0,
                    "trial memory sample is empty")
        require(trial["peak_bytes"] >= after["memory_current_bytes"],
                "trial peak is below its final memory sample")
        for key in ("high", "max", "oom", "oom_kill", "oom_group_kill"):
            require(key in before["memory_events"] and key in after["memory_events"]
                    and before["memory_events"][key] == after["memory_events"][key],
                    f"trial incurred memory pressure or lacks counter: {key}")
    return trials


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
    arrival_service = spec.get("external_arrivals")
    arrival_identity = (verify_separation(arrival_service["identity"], directory)
                        if arrival_service else None)
    view_service = spec.get("external_views")
    view_identity = (verify_separation(view_service["identity"], directory)
                     if view_service else None)
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
        "cgroup": str(directory),
        "external_bitcoin": external_identity,
        "external_arrivals": arrival_identity,
        "external_views": view_identity,
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
            if spec["test"] in BOUNDARY_REPLAYS:
                observation["boundary_service"] = boundary_service(transcript, spec["test"])
            if spec.get("trial_memory"):
                restores = memory_restores(spec["test"])
                observation["trials"] = trial_measurements(
                    transcript, child.pid, directory, enforced, restores)
                drained = [json.loads(line.split("=", 1)[1]) for line in transcript.splitlines()
                           if line.startswith("workload_drained_stores=")]
                require([item["restore"] for item in drained] == restores
                        and all(item["snapshot"]["live_roots"] == 0
                                and item["snapshot"]["live_stores"] == 0 for item in drained),
                        "workload Stores did not drain after both restores")
                observation["drained_stores"] = drained
                caches = [json.loads(line.split("=", 1)[1]) for line in transcript.splitlines()
                          if line.startswith("workload_replay_cache=")]
                require([item["restore"] for item in caches] == restores
                        and all((item["warm_simulation_cache"] or item["before"] == [0, 0])
                                and item["after"][0] > 0 and item["after"][1] > 0 for item in caches),
                        "replay cache state differs from declared setup")
                observation["replay_caches"] = caches
            if arrival_service:
                markers = [json.loads(line.split("=", 1)[1]) for line in transcript.splitlines()
                           if line.startswith("workload_external_arrivals=")]
                require(len(markers) == 2 and all(
                    item["socket"] == arrival_service["socket"]
                    and item["clock"] == "CLOCK_MONOTONIC" and item["api_only"]
                    for item in markers), "workload did not use both external arrival streams")
                observation["arrival_streams"] = markers
            if view_service:
                markers = [json.loads(line.split("=", 1)[1]) for line in transcript.splitlines()
                           if line.startswith("workload_external_views=")]
                require(len(markers) == 2 and all(
                    item["socket"] == view_service["socket"] and item["report"]["status"] == "passed"
                    for item in markers), "workload did not use both external view sessions")
                observation["view_sessions"] = markers
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
    require("KONTOR_WORKLOAD_TRIAL_MEMORY" not in environment,
            "use --trial-memory to require verified per-trial records")
    require("KONTOR_WORKLOAD_ARRIVAL_SOCKET" not in environment,
            "use --external-arrivals to supervise the external scheduler")
    require("KONTOR_WORKLOAD_VIEW_SOCKET" not in environment,
            "use --external-views to supervise the external HTTP clients")
    if args.trial_memory:
        memory_restores(args.test)
        require(args.bitcoin_binary,
                "trial memory requires external Bitcoin")
        environment["KONTOR_WORKLOAD_TRIAL_MEMORY"] = "1"
    if args.external_arrivals:
        require(args.test == HISTORICAL_REPLAY,
                "external arrivals currently require the frozen historical replay")
    if args.external_views:
        view_restores(args.test)
        require(args.bitcoin_binary, "external views require supervisor-owned Bitcoin")
    bitcoin = None
    arrivals = None
    views = None
    try:
        if args.bitcoin_binary:
            bitcoin = BitcoinService(args.bitcoin_binary, output / "bitcoin").start()
            environment["KONTOR_WORKLOAD_BITCOIN_RPC_URL"] = bitcoin.url
        if args.external_arrivals:
            arrivals = ArrivalService(output / "arrivals.json")
            environment["KONTOR_WORKLOAD_ARRIVAL_SOCKET"] = arrivals.path
        if args.external_views:
            views = ViewService(output / "views.json")
            environment["KONTOR_WORKLOAD_VIEW_SOCKET"] = views.path
        code = run_service(args, environment, binary, output, bitcoin, arrivals, views)
    finally:
        try:
            if views:
                views.close()
        finally:
            try:
                if arrivals:
                    arrivals.close()
            finally:
                if bitcoin:
                    bitcoin.close()
    if arrivals and code == 0:
        measurement = json.loads((output / "measurement.json").read_text())
        markers = measurement["arrival_streams"]
        require([item["epoch_ns"] for item in markers]
                == [trial["epoch_ns"] for trial in arrivals.trials],
                "external arrival sessions differ from measured sessions")
        reports = [json.loads(line.split("=", 1)[1])["report"]
                   for line in (output / "workload.log").read_text().splitlines()
                   if line.startswith("workload_historical_replay=")]
        require(len(reports) == 2, "missing external replay reports")
        for trial, report in zip(arrivals.trials, reports, strict=True):
            emitted = {item["ordinal"]: item["enqueued_ns"] for item in trial["sent"]}
            require(all(emitted.get(item["timing"]["event"]["ordinal"]) == item["enqueued_ns"]
                        for item in report["api"]), "reported arrival differs from external emission")
    if views and code == 0:
        measurement = json.loads((output / "measurement.json").read_text())
        require([item["report"] for item in measurement["view_sessions"]] == views.trials,
                "measured view reports differ from external client observations")
        require([trial["restore"] for trial in views.trials] == view_restores(args.test),
                "external view sessions differ from replay restores")
    return code


def run_service(args, environment, binary, output, bitcoin, arrivals, views):
    cpus, memory = PROFILES[args.profile]
    spec = {"profile": args.profile, "binary": str(binary), "trial_memory": args.trial_memory,
            "binary_sha256": digest(binary), "test": args.test,
            "environment": environment}
    if bitcoin:
        spec["external_bitcoin"] = {"identity": bitcoin.identity, "rpc_url": bitcoin.url}
    if arrivals:
        spec["external_arrivals"] = {"identity": arrivals.identity, "socket": arrivals.path}
    if views:
        spec["external_views"] = {"identity": views.identity, "socket": views.path}
    spec_path = output / "request.json"
    spec_path.write_text(json.dumps(spec, indent=2) + "\n")
    unit = f"kontor-workload-{uuid.uuid4().hex}"
    command = ["systemd-run", "--user", "--quiet", "--wait", "--pipe", "--collect",
               f"--unit={unit}", "--service-type=exec",
               f"--property=CPUQuota={cpus * 100}%", f"--property=MemoryMax={memory}",
               "--property=MemorySwapMax=0", "--property=KillMode=control-group",
               "--property=TimeoutStopSec=5", f"--property=RuntimeMaxSec={args.timeout}",
               f"--working-directory={Path.cwd()}", f"--setenv=PATH={os.environ['PATH']}",
               sys.executable, "-B", str(Path(__file__).resolve()), "--worker", str(spec_path)]
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
    parser.add_argument("--trial-memory", action="store_true",
                        help="require two replay-window memory records with individually reset peaks")
    parser.add_argument("--external-arrivals", action="store_true",
                        help="schedule historical replay API arrivals outside the measured cgroup")
    parser.add_argument("--external-views", action="store_true",
                        help="drive eight competing production HTTP view clients outside the measured cgroup")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
